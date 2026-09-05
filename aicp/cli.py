"""AICP 命令行接口。

命令:
  scan    新建并执行扫描任务
  resume  断点续传: 从最近未完成阶段恢复
  report  为任务生成报告 (HTML / JSON)
  list    列出所有任务
  show    查看单个任务详情

默认目录布局 (在当前工作目录下):
  .aicp/
    aicp.db           SQLite 数据库
    work/             工具工作目录 (临时文件)
    reports/          HTML / JSON 报告输出

合规要求:
  scan 命令必须显式提供 --authorized-by / --authorization-note / --scope，
  缺一不可。运行前会打印 ConfirmationBanner 警告。
"""

from __future__ import annotations

import atexit
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Sequence

import click

from .auth import AuthorizationVerifier, AuthorizationError, ConfirmationBanner
from .config import DEFAULT_CONFIG_PATH, env_override, load_config, merge_auth, merge_scan
from .models import Task, TaskStatus
from .observability import setup_logging
from .pipeline import Orchestrator, OrchestratorError
from .scheduler import Store
from .tools import Tool, CompletedProcess


logger = logging.getLogger(__name__)

# 全局标记: 是否已为某个 db_path 注册过 atexit 钩子 (避免重复注册)
_atexit_registered_db: set[str] = set()


def _register_atexit_cleanup(db_path: str) -> None:
    """为指定 db_path 注册 atexit 钩子, 进程退出时清理 RUNNING 任务。

    幂等: 同一 db_path 只注册一次。
    """
    if db_path in _atexit_registered_db:
        return
    _atexit_registered_db.add(db_path)

    def _cleanup():
        n = Store.cleanup_running_tasks(db_path)
        if n > 0:
            logger.info("atexit: 清理 %d 个未完成的 RUNNING 任务", n)

    atexit.register(_cleanup)


def _cleanup_running_on_startup(db_path: str) -> int:
    """启动时主动调用 cleanup_running_tasks, 清理上次崩溃残留的 RUNNING 任务。

    atexit 钩子在 kill -9 / 断电时不执行, 残留的 RUNNING 任务要等"下次优雅退出"才被清,
    等于得重启两次。本函数在 CLI 命令启动时立即清理一次, 让用户重启一次即可 resume。
    """
    n = Store.cleanup_running_tasks(db_path)
    if n > 0:
        logger.info("启动清理: 检测到 %d 个上次崩溃残留的 RUNNING 任务, 已标记为 FAILED", n)
    return n


def _register_and_cleanup(db_path: str) -> None:
    """注册 atexit 钩子并立即清理一次残留 RUNNING 任务; 初始化 JSON 文件日志。

    日志落盘 <db 同级>/logs/aicp.log (行动项 #7: 修复全部日志走 stderr
    重启即丢的取证盲点; 幂等, 重复调用不重复挂 handler)。
    """
    _register_atexit_cleanup(db_path)
    _cleanup_running_on_startup(db_path)
    log_file = Path(db_path).parent / "logs" / "aicp.log"
    setup_logging(log_file=str(log_file))


# ---------------- 默认路径 ----------------

DEFAULT_AICP_DIR = ".aicp"
DEFAULT_DB = f"{DEFAULT_AICP_DIR}/aicp.db"
DEFAULT_WORK_DIR = f"{DEFAULT_AICP_DIR}/work"
DEFAULT_REPORT_DIR = f"{DEFAULT_AICP_DIR}/reports"


# ---------------- 工具工厂 (可被测试 monkeypatch) ----------------

# 工具级子进程超时 (30 分钟); 测试可 monkeypatch 缩短
_SUBPROCESS_TIMEOUT_S = 1800

# Windows Job Object 句柄 (KILL_ON_JOB_CLOSE): 常驻到本进程退出。
# 句柄保持打开, 本进程死亡时内核自动终止 job 内整棵进程树;
# 提前关闭句柄会立即触发 kill-on-close, 故不主动 close。
_job_handles: set = set()


def _assign_to_kill_on_close_job(proc: subprocess.Popen) -> None:
    """Windows: 把子进程加入 KILL_ON_JOB_CLOSE 的 Job Object (行动项 #4 / ADR-2)。

    AICP 进程被强杀/崩溃 (kill -9 / 断电, 不走 atexit) 时, 内核自动终止
    整棵进程树 (含 OneForAll 等工具内部再起的孙进程), 杜绝孤儿孙进程
    继续对目标发包 —— 超出授权范围的流量是合规红线。
    非 Windows 平台 no-op (POSIX 由超时路径的 killpg 覆盖;
    父进程被 SIGKILL 的场景为已知局限, 记录于审查报告 ADR-2)。
    赋值失败不阻断执行 (返回非零 rc 由上层统一处理)。
    """
    if sys.platform != "win32":
        return
    import ctypes
    from ctypes import wintypes

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _BASIC_LIMITS(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),  # ULONG_PTR
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _EXTENDED_LIMITS(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BASIC_LIMITS),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.windll.kernel32
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return
    info = _EXTENDED_LIMITS()
    info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not kernel32.SetInformationJobObject(
        job, 9, ctypes.byref(info), ctypes.sizeof(info)
    ):
        return
    # proc._handle 是 Popen 的原生句柄 (int)
    if not kernel32.AssignProcessToJobObject(job, wintypes.HANDLE(proc._handle)):
        return
    _job_handles.add(job)


def _kill_process_tree(proc: subprocess.Popen) -> None:
    """终止子进程的整棵进程树 (父 + 全部孙进程), 行动项 #4 (ADR-2)。

    Windows 用 taskkill /T /F (原生按树终止); POSIX 上子进程以新会话启动
    (start_new_session), 对整个进程组发 SIGKILL。进程已死时静默通过。
    """
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True,
            )
        else:
            import signal
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass  # 进程已退出: 终止目标已达成


def _default_process_runner(cmd: List[str], work_dir: str) -> CompletedProcess:
    """生产环境默认进程执行器: 真实调用子进程 + 进程树托管 (行动项 #4 / ADR-2)。

    - 超时 (_SUBPROCESS_TIMEOUT_S, 默认 30 分钟) 终止整棵进程树
      (旧实现 subprocess.run 只 kill 直接子进程, 孙进程成孤儿继续扫描);
    - Windows 下子进程加入 KILL_ON_JOB_CLOSE Job Object: 本进程被强杀时
      内核终止其进程树, 封孤儿孙进程的合规风险;
    - 超时返回 returncode=-1, 由工具适配器统一处理。
    """
    Path(work_dir).mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(
        cmd,
        cwd=work_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        start_new_session=(sys.platform != "win32"),
    )
    _assign_to_kill_on_close_job(proc)
    try:
        stdout, stderr = proc.communicate(timeout=_SUBPROCESS_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        _kill_process_tree(proc)
        stdout, stderr = proc.communicate()
        return CompletedProcess(
            args=cmd,
            returncode=-1,
            stdout=stdout or "",
            stderr=f"子进程超时 ({_SUBPROCESS_TIMEOUT_S}s), 已终止整棵进程树: {' '.join(cmd)}",
        )
    return CompletedProcess(
        args=cmd,
        returncode=proc.returncode,
        stdout=stdout or "",
        stderr=stderr or "",
    )


def _default_tools(work_dir: str, names: Optional[Sequence[str]] = None) -> List[Tool]:
    """构建默认工具列表 (统一走 ToolRegistry, 消除手工 import 的双注册路径 P3)。

    - names=None 或空: 启用全部 6 个工具
    - names 指定子集: 只启用指定的

    工具依赖的真实二进制 (oneforall.py / nmap / httpx) 可能未安装，
    构造时不检查；运行时若失败由编排器捕获并标记阶段 FAILED。
    Wappalyzer 是 Python 库，导入失败时给出清晰错误。
    """
    from .tools.registry import tool_registry

    all_names = {"oneforall", "nmap", "httpx", "wappalyzer", "nuclei", "dirsearch"}
    name_set = set(names) if names else set(all_names)
    unknown = name_set - all_names
    if unknown:
        raise click.BadParameter(
            f"未知工具: {','.join(sorted(unknown))}，可选: {','.join(sorted(all_names))}"
        )

    runner = _default_process_runner
    extra_kwargs: dict[str, dict] = {}
    if "wappalyzer" in name_set:
        from .tools.wappalyzer import default_analyzer_factory

        try:
            extra_kwargs["wappalyzer"] = {"analyzer": default_analyzer_factory()}
        except Exception as e:
            click.echo(f"警告: Wappalyzer 初始化失败，已跳过: {e}", err=True)
            name_set.discard("wappalyzer")

    return tool_registry.create_tools(
        runner=runner, names=name_set, extra_kwargs=extra_kwargs
    )


# ---------------- 通用辅助 ----------------

def _open_store(db_path: str) -> Store:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    return Store(db_path)


def _ensure_task_dir(paths: dict) -> None:
    """确保 .aicp 目录树存在。"""
    for p in [paths["db"], paths["work_dir"], paths["report_dir"]]:
        Path(p).parent.mkdir(parents=True, exist_ok=True)


def _resolve_paths(db, work_dir, report_dir) -> dict:
    return {
        "db": db or DEFAULT_DB,
        "work_dir": work_dir or DEFAULT_WORK_DIR,
        "report_dir": report_dir or DEFAULT_REPORT_DIR,
    }


def _parse_tool_args(items) -> dict:
    """解析 --tool-args "name=args..." 为 {"name": [args...]}。"""
    import shlex

    result: dict[str, list[str]] = {}
    for item in items:
        if "=" not in item:
            raise click.BadParameter(f"--tool-args 格式应为 name=args: {item!r}")
        name, _, args_str = item.partition("=")
        result[name.strip()] = shlex.split(args_str)
    return result


def _format_status(status: str) -> str:
    """状态着色。"""
    colors = {
        "completed": "green",
        "failed": "red",
        "running": "cyan",
        "authorized": "yellow",
        "pending": "white",
        "paused": "magenta",
        "cancelled": "red",
        "auth_pending": "yellow",
    }
    color = colors.get(status, "white")
    return click.style(status, fg=color)


# ---------------- CLI 主入口 ----------------

@click.group()
@click.version_option(package_name="aicp")
@click.option("--verbose", "-v", is_flag=True, default=False, help="输出调试日志")
def main(verbose: bool) -> None:
    """自动化信息收集平台 (AICP)。

    仅可用于已获书面授权的目标。使用前请阅读 DISCLAIMER.md。
    """
    # 全局日志配置 (P3): 默认 INFO, -v 输出 DEBUG
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


# ---------------- scan ----------------

@main.command()
@click.argument("targets", nargs=-1, required=True)
@click.option("--authorized-by", default=None, help="授权人姓名 (默认读 config.toml)")
@click.option("--authorization-note", default=None, help="授权说明 (如授权书编号; 默认读 config.toml)")
@click.option("--scope", multiple=True, default=None,
              help="授权范围 (可多次指定，支持域名/IP/CIDR; 默认读 config.toml)")
@click.option("--config", "config_path", default=None,
              help=f"配置文件路径 (默认 {DEFAULT_CONFIG_PATH})")
@click.option("--db", default=None, help=f"SQLite 数据库路径 (默认 {DEFAULT_DB})")
@click.option("--work-dir", default=None, help=f"工具工作目录 (默认 {DEFAULT_WORK_DIR})")
@click.option("--report-dir", default=None, help=f"报告输出目录 (默认 {DEFAULT_REPORT_DIR})")
@click.option("--tools", "tool_names", default=None,
              help="启用工具子集 (逗号分隔: oneforall,nmap,httpx,wappalyzer,nuclei,dirsearch)")
@click.option("--no-report", is_flag=True, default=False, help="任务完成后不自动生成报告")
@click.option("--quiet", is_flag=True, default=False, help="减少控制台输出")
@click.option("--rate-limit", "rate_limit", default=None, type=int,
              help="全局速率限制 (req/s), 透传给支持的工具")
@click.option("--tool-args", "tool_args_raw", multiple=True, default=None,
              help="按工具透传额外参数, 如 --tool-args \"nuclei=-t /path/templates\" (可多次)")
@click.option("--allow-private", is_flag=True, default=False,
              help="允许扫描私有/保留 IP 段 (10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16 等)。"
                   "默认拒绝, 防 SSRF 与内网探测。仅在确有内网授权时使用。")
def scan(
    targets: tuple[str, ...],
    authorized_by: Optional[str],
    authorization_note: Optional[str],
    scope: Optional[tuple[str, ...]],
    config_path: Optional[str],
    db: Optional[str],
    work_dir: Optional[str],
    report_dir: Optional[str],
    tool_names: Optional[str],
    no_report: bool,
    quiet: bool,
    rate_limit: Optional[int],
    tool_args_raw: tuple[str, ...],
    allow_private: bool,
) -> None:
    """新建并执行扫描任务。

    TARGETS 是要扫描的目标列表 (域名 / IP / CIDR)，至少 1 个。
    所有目标必须在 --scope 范围内，否则拒绝执行。
    授权参数与部分扫描参数可从 .aicp/config.toml 读取 (见 `aicp config init`)。
    """
    # 合并配置: CLI 参数 > config.toml > 环境变量 > 默认值
    cli_authorized_by = authorized_by  # 合并前的 CLI 原始值 (审计 5.4 来源判断)
    cfg = load_config(config_path)
    auth = merge_auth(authorized_by, authorization_note, scope, cfg)
    scan_cfg = merge_scan(rate_limit, allow_private, work_dir, cfg)
    # 授权来源标注 (审计 5.4): 提示授权三要素实际来自哪里
    if cli_authorized_by:
        auth_source = "CLI 参数"
    elif (cfg.get("auth") or {}).get("authorized_by"):
        auth_source = "配置文件 (.aicp/config.toml)"
    elif env_override("AUTHORIZED_BY"):
        auth_source = "环境变量 (AICP_AUTHORIZED_BY)"
    else:
        auth_source = "CLI 参数"
    authorized_by = auth["authorized_by"]
    authorization_note = auth["authorization_note"]
    scope = auth["scope"]
    rate_limit = scan_cfg["rate_limit"]
    allow_private = scan_cfg["allow_private"]
    work_dir = scan_cfg["work_dir"]

    paths = _resolve_paths(db, work_dir, report_dir)
    _ensure_task_dir(paths)
    _register_and_cleanup(paths["db"])

    # 解析工具子集 + 参数校验 (不依赖工厂函数，便于 mock 测试)
    all_tool_names = {"oneforall", "nmap", "httpx", "wappalyzer", "nuclei", "dirsearch"}
    names = tool_names.split(",") if tool_names else None
    if names:
        names = [n.strip() for n in names if n.strip()]
        unknown = set(names) - all_tool_names
        if unknown:
            raise click.BadParameter(
                f"未知工具: {','.join(sorted(unknown))}，"
                f"可选: {','.join(sorted(all_tool_names))}"
            )

    # 构造任务
    task = Task(targets=list(targets))
    store = _open_store(paths["db"])
    with store:
        # 授权校验 (会校验所有 targets 都在 scope 内, 并默认拒绝私有 IP)
        try:
            AuthorizationVerifier().verify(
                task,
                authorized_by=authorized_by,
                authorization_note=authorization_note,
                authorized_scope=list(scope),
                allow_private=allow_private,
            )
        except AuthorizationError as e:
            raise click.UsageError(f"授权校验失败: {e}") from e
        store.save_task(task)

        # 打印合规横幅 (标注授权来源, 审计 5.4)
        if not quiet:
            click.echo(ConfirmationBanner(task, auth_source=auth_source).render())
            click.echo()

        # 构造工具
        tools = _default_tools(paths["work_dir"], names)
        tool_args = _parse_tool_args(tool_args_raw) if tool_args_raw else {}

        # 执行
        orchestrator = Orchestrator(
            store, tools, work_dir=paths["work_dir"],
            rate_limit=rate_limit, tool_args=tool_args,
        )
        try:
            task = orchestrator.run(task)
        except OrchestratorError as e:
            click.echo(f"任务执行失败: {e}", err=True)
            raise SystemExit(1)

        _print_task_summary(task, store)

        # 自动生成报告
        if not no_report and task.status == TaskStatus.COMPLETED:
            _generate_reports(task, store, paths["report_dir"], quiet=quiet)


# ---------------- resume ----------------

@main.command()
@click.argument("task_id")
@click.option("--db", default=None, help=f"SQLite 数据库路径 (默认 {DEFAULT_DB})")
@click.option("--work-dir", default=None, help=f"工具工作目录 (默认 {DEFAULT_WORK_DIR})")
@click.option("--report-dir", default=None, help=f"报告输出目录 (默认 {DEFAULT_REPORT_DIR})")
@click.option("--no-report", is_flag=True, default=False, help="任务完成后不自动生成报告")
@click.option("--quiet", is_flag=True, default=False, help="减少控制台输出")
@click.option("--rate-limit", "rate_limit", default=None, type=int,
              help="全局速率限制 (req/s), 透传给支持的工具")
@click.option("--tool-args", "tool_args_raw", multiple=True, default=None,
              help="按工具透传额外参数, 如 --tool-args \"nuclei=-t /path/templates\" (可多次)")
def resume(
    task_id: str,
    db: Optional[str],
    work_dir: Optional[str],
    report_dir: Optional[str],
    no_report: bool,
    quiet: bool,
    rate_limit: Optional[int],
    tool_args_raw: tuple[str, ...],
) -> None:
    """从最近未完成阶段恢复执行任务。

    TASK_ID 是要恢复的任务 ID (可用 `aicp list` 查看)。
    任务必须处于 PAUSED 或 FAILED 状态。
    """
    paths = _resolve_paths(db, work_dir, report_dir)
    _ensure_task_dir(paths)
    _register_and_cleanup(paths["db"])

    store = _open_store(paths["db"])
    with store:
        task = store.get_task(task_id)
        if task is None:
            raise click.UsageError(f"任务不存在: {task_id}")

        if task.status not in (TaskStatus.AUTHORIZED, TaskStatus.PAUSED, TaskStatus.FAILED, TaskStatus.RUNNING):
            raise click.UsageError(
                f"任务状态 {task.status.value} 不可恢复，需 AUTHORIZED / PAUSED / FAILED / RUNNING"
            )

        if not quiet:
            click.echo(f"恢复任务 {task.id} (当前状态: {task.status.value})")

        tools = _default_tools(paths["work_dir"])
        tool_args = _parse_tool_args(tool_args_raw) if tool_args_raw else {}
        orchestrator = Orchestrator(
            store, tools, work_dir=paths["work_dir"],
            rate_limit=rate_limit, tool_args=tool_args,
        )
        try:
            task = orchestrator.run(task)
        except OrchestratorError as e:
            click.echo(f"任务恢复失败: {e}", err=True)
            raise SystemExit(1)

        _print_task_summary(task, store)

        if not no_report and task.status == TaskStatus.COMPLETED:
            _generate_reports(task, store, paths["report_dir"], quiet=quiet)


# ---------------- report ----------------

@main.command()
@click.argument("task_id")
@click.option("--db", default=None, help=f"SQLite 数据库路径 (默认 {DEFAULT_DB})")
@click.option("--format", "fmt",
              type=click.Choice(["html", "json", "md", "csv", "all"]), default="all",
              help="报告格式 (默认 all, 生成 HTML+JSON+Markdown+CSV)")
@click.option("--output", "-o", default=None,
              help="输出文件路径 (单格式时有效，默认写到 report-dir)")
@click.option("--report-dir", default=None, help=f"报告输出目录 (默认 {DEFAULT_REPORT_DIR})")
def report(
    task_id: str,
    db: Optional[str],
    fmt: str,
    output: Optional[str],
    report_dir: Optional[str],
) -> None:
    """为任务生成报告。

    TASK_ID 是目标任务 ID。
    """
    paths = _resolve_paths(db, None, report_dir)
    store = _open_store(paths["db"])
    with store:
        task = store.get_task(task_id)
        if task is None:
            raise click.UsageError(f"任务不存在: {task_id}")

        outputs = _write_reports(task, store, paths["report_dir"], fmt, output)
        for p in outputs:
            click.echo(f"报告已生成: {p}")


# ---------------- config ----------------

@main.group()
def config():
    """配置文件管理 (.aicp/config.toml)。"""


@config.command("init")
@click.option("--force", is_flag=True, default=False, help="覆盖已存在的配置文件")
def config_init(force: bool) -> None:
    """生成示例配置文件 .aicp/config.toml。"""
    from .config import write_default_config

    path = Path(DEFAULT_CONFIG_PATH)
    if path.exists() and not force:
        raise click.UsageError(f"配置文件已存在: {path} (用 --force 覆盖)")
    write_default_config(force=force)
    click.echo(f"已生成配置文件: {path.resolve()}")


@config.command("show")
@click.option("--config", "config_path", default=None,
              help=f"配置文件路径 (默认 {DEFAULT_CONFIG_PATH})")
def config_show(config_path: Optional[str]) -> None:
    """显示当前配置 (配置文件 + 环境变量合并结果)。"""
    cfg = load_config(config_path)
    auth = merge_auth(None, None, None, cfg)
    scan = merge_scan(None, False, None, cfg)
    click.echo(f"配置文件  : {Path(config_path or DEFAULT_CONFIG_PATH).resolve()}")
    click.echo(f"授权人    : {auth['authorized_by'] or '(未设置)'}")
    click.echo(f"授权说明  : {auth['authorization_note'] or '(未设置)'}")
    click.echo(f"授权范围  : {', '.join(auth['scope']) or '(未设置)'}")
    click.echo(f"速率限制  : {scan['rate_limit'] if scan['rate_limit'] is not None else '(未设置)'}")
    click.echo(f"允许内网  : {scan['allow_private']}")
    click.echo(f"工作目录  : {scan['work_dir'] or DEFAULT_WORK_DIR}")


# ---------------- list ----------------

@main.command(name="list")
@click.option("--db", default=None, help=f"SQLite 数据库路径 (默认 {DEFAULT_DB})")
@click.option("--status", default=None,
              help="按状态过滤 (pending/authorized/running/completed/failed/paused/cancelled)")
def list_tasks(
    db: Optional[str],
    status: Optional[str],
) -> None:
    """列出所有任务。"""
    paths = _resolve_paths(db, None, None)
    store = _open_store(paths["db"])
    with store:
        tasks = store.list_tasks()
        if status:
            try:
                status_enum = TaskStatus(status)
            except ValueError as e:
                raise click.BadParameter(f"无效状态: {status}") from e
            tasks = [t for t in tasks if t.status == status_enum]

        if not tasks:
            click.echo("(无任务)")
            return

        click.echo(f"{'ID':<34} {'状态':<12} {'目标':<30} {'授权人':<10} {'创建时间'}")
        click.echo("-" * 100)
        for t in tasks:
            targets_str = ",".join(t.targets)
            if len(targets_str) > 28:
                targets_str = targets_str[:27] + "…"
            click.echo(
                f"{t.id:<34} {_format_status(t.status.value):<21} "
                f"{targets_str:<30} {(t.authorized_by or '-'):<10} "
                f"{t.created_at.strftime('%Y-%m-%d %H:%M:%S')}"
            )


# ---------------- show ----------------

@main.command()
@click.argument("task_id")
@click.option("--db", default=None, help=f"SQLite 数据库路径 (默认 {DEFAULT_DB})")
def show(task_id: str, db: Optional[str]) -> None:
    """查看任务详情。"""
    paths = _resolve_paths(db, None, None)
    store = _open_store(paths["db"])
    with store:
        task = store.get_task(task_id)
        if task is None:
            raise click.UsageError(f"任务不存在: {task_id}")

        click.echo("=" * 70)
        click.echo(f"任务 ID    : {task.id}")
        click.echo(f"状态       : {_format_status(task.status.value)}")
        click.echo(f"目标       : {', '.join(task.targets)}")
        click.echo(f"授权人     : {task.authorized_by or '-'}")
        click.echo(f"授权说明   : {task.authorization_note or '-'}")
        click.echo(f"授权范围   : {', '.join(task.authorized_scope) or '-'}")
        click.echo(f"授权时间   : {task.authorized_at or '-'}")
        click.echo(f"创建时间   : {task.created_at}")
        if task.started_at:
            click.echo(f"开始时间   : {task.started_at}")
        if task.finished_at:
            click.echo(f"完成时间   : {task.finished_at}")
        if task.error:
            click.echo(f"错误       : {task.error}")
        click.echo("=" * 70)
        click.echo("阶段执行:")
        stages = store.list_stages(task.id)
        if not stages:
            click.echo("  (无阶段记录)")
        else:
            for s in stages:
                line = f"  {s.name.value:<14} {_format_status(s.status.value):<21}"
                if s.started_at:
                    line += f" started={s.started_at.strftime('%H:%M:%S')}"
                if s.finished_at:
                    line += f" finished={s.finished_at.strftime('%H:%M:%S')}"
                if s.error:
                    line += f" err={s.error}"
                if s.attempt > 0:
                    line += f" attempt={s.attempt}"
                click.echo(line)

        # 资产统计
        assets = store.list_assets(task.id)
        click.echo("-" * 70)
        click.echo(f"资产总数: {len(assets)}")
        by_type: dict[str, int] = {}
        for a in assets:
            by_type[a.type] = by_type.get(a.type, 0) + 1
        for t, n in sorted(by_type.items()):
            click.echo(f"  {t:<14} {n}")


# ---------------- diff ----------------

@main.command()
@click.argument("task_a")
@click.argument("task_b")
@click.option("--db", default=None, help=f"SQLite 数据库路径 (默认 {DEFAULT_DB})")
def diff(task_a: str, task_b: str, db: Optional[str]) -> None:
    """比较两个任务的资产差异 (B 相对 A 的变化, 攻击面变更追踪)。"""
    from .diff import diff_tasks

    paths = _resolve_paths(db, None, None)
    store = _open_store(paths["db"])
    with store:
        ta = store.get_task(task_a)
        tb = store.get_task(task_b)
        if ta is None:
            raise click.UsageError(f"任务不存在: {task_a}")
        if tb is None:
            raise click.UsageError(f"任务不存在: {task_b}")
        result = diff_tasks(store, task_a, task_b)
        _print_diff(ta, tb, result)


def _print_diff(ta: Task, tb: Task, result: dict) -> None:
    click.echo("=" * 70)
    click.echo(f"资产差异 ({tb.id[:8]} 相对 {ta.id[:8]})")
    click.echo("=" * 70)
    click.echo(f"新增子域名 : {', '.join(result['added_domains']) or '(无)'}")
    click.echo(f"消失子域名 : {', '.join(result['removed_domains']) or '(无)'}")
    click.echo(f"新增 IP    : {', '.join(result['added_ips']) or '(无)'}")
    click.echo(f"消失 IP    : {', '.join(result['removed_ips']) or '(无)'}")
    click.echo(f"新开端口   : {', '.join(result['added_ports']) or '(无)'}")
    click.echo(f"关闭端口   : {', '.join(result['removed_ports']) or '(无)'}")
    click.echo(f"新增 URL   : {', '.join(result['added_urls']) or '(无)'}")
    click.echo(f"消失 URL   : {', '.join(result['removed_urls']) or '(无)'}")
    _print_vuln_table("新增漏洞", result["added_vulns"])
    _print_vuln_table("已修复漏洞", result["fixed_vulns"])


def _print_vuln_table(title: str, vulns) -> None:
    if not vulns:
        click.echo(f"{title}: (无)")
        return
    click.echo(f"{title}:")
    click.echo("  严重度     名称                          模板 ID                          目标")
    for a in vulns:
        raw = a.raw or {}
        severity = raw.get("severity", "unknown")
        name = raw.get("name", "")
        template = raw.get("template_id", "")
        url = a.value.split("|", 1)[0]
        click.echo(f"  {severity:<10} {name[:28]:<30} {template[:28]:<30} {url}")


@main.command()
@click.argument("task_id")
@click.option("--db", default=None, help=f"SQLite 数据库路径 (默认 {DEFAULT_DB})")
def cancel(task_id: str, db: Optional[str]) -> None:
    """请求取消正在运行的任务 (当前阶段结束后生效)。"""
    paths = _resolve_paths(db, None, None)
    store = _open_store(paths["db"])
    with store:
        task = store.get_task(task_id)
        if task is None:
            raise click.UsageError(f"任务不存在: {task_id}")
        if task.status != TaskStatus.RUNNING:
            click.echo(f"任务状态 {task.status.value}, 无需取消")
            return
        store.request_cancel(task_id)
        click.echo(f"已请求取消任务 {task_id} (将在当前阶段结束后生效)")


# ---------------- web ----------------

@main.command()
@click.option("--host", default="127.0.0.1", help="监听地址 (默认 127.0.0.1)")
@click.option("--port", default=5000, type=int, help="监听端口 (默认 5000)")
@click.option("--db", default=None, help=f"SQLite 数据库路径 (默认 {DEFAULT_DB})")
@click.option("--work-dir", default=None, help=f"工具工作目录 (默认 {DEFAULT_WORK_DIR})")
@click.option("--report-dir", default=None, help=f"报告输出目录 (默认 {DEFAULT_REPORT_DIR})")
@click.option("--auth-token", default=None,
              help="Web API 认证令牌 (设置后需带 Authorization 头访问)")
@click.option("--debug", is_flag=True, default=False, help="Flask 调试模式")
def web(
    host: str,
    port: int,
    db: Optional[str],
    work_dir: Optional[str],
    report_dir: Optional[str],
    auth_token: Optional[str],
    debug: bool,
) -> None:
    """启动 Web 界面。

    默认监听 127.0.0.1:5000，浏览器访问 http://127.0.0.1:5000/。
    出于安全考虑, 不建议用 --host 0.0.0.0 暴露到公网。
    如需暴露, 务必设置 --auth-token。
    """
    try:
        from .web import create_app
    except ImportError as e:
        raise click.UsageError(
            f"Flask 未安装，请运行: pip install flask ({e})"
        ) from e

    paths = _resolve_paths(db, work_dir, report_dir)
    _ensure_task_dir(paths)
    _register_and_cleanup(paths["db"])
    app = create_app(
        db_path=paths["db"],
        work_dir=paths["work_dir"],
        report_dir=paths["report_dir"],
        auth_token=auth_token,
    )
    click.echo(f"AICP Web 界面启动中: http://{host}:{port}/")
    if auth_token:
        # 脱敏显示后 4 位
        if len(auth_token) > 4:
            masked = "*" * (len(auth_token) - 4) + auth_token[-4:]
        else:
            masked = "****"
        click.echo(f"已启用认证, token: {masked}")
    else:
        click.echo("警告: 未启用认证, 任何人均可访问。如需暴露到网络, 请设置 --auth-token")
    click.echo("按 Ctrl+C 退出")
    app.run(host=host, port=port, debug=debug)


# ---------------- 内部辅助 ----------------

def _print_task_summary(task: Task, store: Store) -> None:
    """打印任务执行摘要。"""
    click.echo()
    click.echo("=" * 70)
    click.echo(f"任务 {task.id} -> {_format_status(task.status.value)}")
    if task.error:
        click.echo(f"错误: {task.error}")
    # 阶段时间线
    for s in store.list_stages(task.id):
        click.echo(f"  {s.name.value:<14} {_format_status(s.status.value)}")
        if s.error:
            click.echo(f"    └─ {s.error}")
    # 资产统计
    assets = store.list_assets(task.id)
    click.echo(f"资产总数: {len(assets)}")
    by_type: dict[str, int] = {}
    for a in assets:
        by_type[a.type] = by_type.get(a.type, 0) + 1
    if by_type:
        parts = [f"{t}={n}" for t, n in sorted(by_type.items())]
        click.echo("  " + " ".join(parts))
    click.echo("=" * 70)


def _generate_reports(
    task: Task, store: Store, report_dir: str, *, quiet: bool = False
) -> None:
    """任务完成后自动生成 HTML+JSON+Markdown 报告。"""
    outputs = _write_reports(task, store, report_dir, "all", None)
    if not quiet:
        for p in outputs:
            click.echo(f"报告已生成: {p}")


def _write_reports(
    task: Task,
    store: Store,
    report_dir: str,
    fmt: str,
    output: Optional[str],
) -> List[Path]:
    """根据格式生成报告，返回生成的文件路径列表。"""
    from .report.json_report import write_json_report
    from .report.html import write_html_report
    from .report.markdown import write_markdown_report
    from .report.csv_report import write_csv_report

    outputs: List[Path] = []

    if fmt in ("json", "all"):
        if output and fmt == "json":
            out_path = output
        else:
            out_path = str(Path(report_dir) / f"{task.id}.json")
        p = write_json_report(task, store, out_path)
        outputs.append(p)

    if fmt in ("html", "all"):
        if output and fmt == "html":
            out_path = output
        else:
            out_path = str(Path(report_dir) / f"{task.id}.html")
        p = write_html_report(task, store, out_path)
        outputs.append(p)

    if fmt in ("md", "all"):
        if output and fmt == "md":
            out_path = output
        else:
            out_path = str(Path(report_dir) / f"{task.id}.md")
        p = write_markdown_report(task, store, out_path)
        outputs.append(p)

    if fmt in ("csv", "all"):
        if output and fmt == "csv":
            out_path = output
        else:
            out_path = str(Path(report_dir) / f"{task.id}.csv")
        p = write_csv_report(task, store, out_path)
        outputs.append(p)

    return outputs


if __name__ == "__main__":
    main()
