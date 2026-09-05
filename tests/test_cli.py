"""CLI 单元测试。

测试策略:
- 用 click.testing.CliRunner 调用 CLI
- monkeypatch `aicp.cli._default_tools` 返回 mock 工具
- 不依赖真实 OneForAll / Nmap / httpx 二进制
- 每个测试用 tmp_path 隔离 .aicp 目录
"""

from __future__ import annotations

import json
from typing import List

import pytest
from click.testing import CliRunner

from aicp import cli as cli_module
from aicp.cli import main
from aicp.models import Asset, StageName, TaskStatus
from aicp.tools import Tool, ToolContext, ToolResult, ToolError


# ---------------- mock 工具 ----------------

class FakeSubdomainTool(Tool):
    """mock 子域名收集: 产出 sub.<input>。"""
    stage = StageName.SUBDOMAIN
    input_asset_types = ("domain",)
    output_asset_types = ("domain",)

    def run(self, inputs: List[Asset], ctx: ToolContext) -> ToolResult:
        assets = [
            Asset(type="domain", value=f"sub.{d.value}", source="fake",
                  task_id=ctx.task_id)
            for d in inputs if d.type == "domain"
        ]
        return ToolResult(assets=assets, stats={"produced": len(assets)})


class FakePortscanTool(Tool):
    """mock 端口扫描: 对每个 domain/ip 产出 ip + port。"""
    stage = StageName.PORTSCAN
    input_asset_types = ("domain", "ip")
    output_asset_types = ("ip", "port")

    def run(self, inputs: List[Asset], ctx: ToolContext) -> ToolResult:
        assets: List[Asset] = []
        for a in inputs:
            if a.type == "domain":
                ip = "1.2.3.4"
                assets.append(Asset(type="ip", value=ip, source="fake",
                                    task_id=ctx.task_id, raw={"domain": a.value}))
                assets.append(Asset(type="port", value=f"{ip}:80", source="fake",
                                    task_id=ctx.task_id,
                                    raw={"ip": ip, "port": 80}))
            elif a.type == "ip":
                assets.append(Asset(type="port", value=f"{a.value}:80", source="fake",
                                    task_id=ctx.task_id,
                                    raw={"ip": a.value, "port": 80}))
        return ToolResult(assets=assets, stats={"produced": len(assets)})


class FakeFingerprintTool(Tool):
    """mock Web 指纹: 对每个 port 产出 url + web_service。"""
    stage = StageName.FINGERPRINT
    input_asset_types = ("port", "ip", "domain")
    output_asset_types = ("url", "web_service")

    def run(self, inputs: List[Asset], ctx: ToolContext) -> ToolResult:
        assets: List[Asset] = []
        for a in inputs:
            if a.type != "port":
                continue
            url = f"http://{a.value}"
            assets.append(Asset(type="url", value=url, source="fake",
                                task_id=ctx.task_id, parent_id=a.id))
            assets.append(Asset(
                type="web_service", value=url, source="fake",
                task_id=ctx.task_id, parent_id=a.id,
                technologies=["Nginx"], status_code=200, title="Fake",
            ))
        return ToolResult(assets=assets, stats={"produced": len(assets)})


class FailingTool(Tool):
    """mock 失败工具: 抛 ToolError。"""
    stage = StageName.PORTSCAN
    input_asset_types = ("domain", "ip")
    output_asset_types = ("ip", "port")

    def run(self, inputs: List[Asset], ctx: ToolContext) -> ToolResult:
        raise ToolError("mock 失败")


def _fake_all_tools(work_dir, names=None):
    """返回 3 个 mock 工具 (覆盖 subdomain/portscan/fingerprint)。"""
    return [FakeSubdomainTool(), FakePortscanTool(), FakeFingerprintTool()]


# ---------------- 公共夹具 ----------------

@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def aicp_dir(tmp_path, monkeypatch):
    """切换 cwd 到临时目录，让 .aicp/ 落在 tmp_path 下。"""
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def patched_tools(monkeypatch):
    """替换 _default_tools 为 mock 实现。"""
    monkeypatch.setattr(cli_module, "_default_tools", _fake_all_tools)
    return _fake_all_tools


# ---------------- scan ----------------

def test_scan_completes_and_generates_reports(runner, aicp_dir, patched_tools):
    """scan 命令完整跑通 mock 流水线，自动生成 HTML+JSON+Markdown 报告。"""
    result = runner.invoke(main, [
        "scan", "example.com",
        "--authorized-by", "张三",
        "--authorization-note", "AUTH-001",
        "--scope", "example.com",
        "--scope", "1.2.3.4",
    ])
    assert result.exit_code == 0, result.output
    assert "任务" in result.output
    assert "completed" in result.output

    # 报告应已生成 (三种格式)
    report_dir = aicp_dir / ".aicp" / "reports"
    html_files = list(report_dir.glob("*.html"))
    json_files = list(report_dir.glob("*.json"))
    md_files = list(report_dir.glob("*.md"))
    assert len(html_files) == 1
    assert len(json_files) == 1
    assert len(md_files) == 1

    # JSON 报告应可解析
    data = json.loads(json_files[0].read_text(encoding="utf-8"))
    assert data["task"]["authorized_by"] == "张三"
    assert data["summary"]["total_domains"] >= 1

    # Markdown 报告应包含核心 section
    md_content = md_files[0].read_text(encoding="utf-8")
    assert "# AICP 资产报告" in md_content
    assert "## 任务信息" in md_content


def test_scan_missing_auth_params_fails(runner, aicp_dir, patched_tools):
    """缺授权参数且无 config 时, 授权校验应失败并给出友好错误。"""
    result = runner.invoke(main, ["scan", "example.com"])
    assert result.exit_code != 0
    assert "授权校验失败" in result.output or "授权人不能为空" in result.output


def test_scan_target_out_of_scope_rejected(runner, aicp_dir, patched_tools):
    """目标不在 scope 内应被授权校验拒绝。"""
    result = runner.invoke(main, [
        "scan", "evil.com",
        "--authorized-by", "张三",
        "--authorization-note", "AUTH-001",
        "--scope", "example.com",
    ])
    assert result.exit_code != 0
    assert "授权校验失败" in result.output or "不在授权范围" in result.output


def test_scan_with_no_report_flag(runner, aicp_dir, patched_tools):
    """--no-report 时不生成报告。"""
    result = runner.invoke(main, [
        "scan", "example.com",
        "--authorized-by", "张三",
        "--authorization-note", "AUTH-001",
        "--scope", "example.com",
        "--scope", "1.2.3.4",
        "--no-report",
    ])
    assert result.exit_code == 0, result.output
    report_dir = aicp_dir / ".aicp" / "reports"
    assert not list(report_dir.glob("*.html"))
    assert not list(report_dir.glob("*.json"))
    assert not list(report_dir.glob("*.md"))


def test_scan_with_tool_subset(runner, aicp_dir, monkeypatch):
    """--tools 指定子集时只启用对应工具。"""
    seen_names = {"called": []}

    def _tools(work_dir, names=None):
        seen_names["called"] = list(names) if names else []
        return _fake_all_tools(work_dir, names)

    monkeypatch.setattr(cli_module, "_default_tools", _tools)

    result = runner.invoke(main, [
        "scan", "example.com",
        "--authorized-by", "张三",
        "--authorization-note", "AUTH-001",
        "--scope", "example.com",
        "--scope", "1.2.3.4",
        "--tools", "oneforall,nmap",
    ])
    assert result.exit_code == 0, result.output
    assert seen_names["called"] == ["oneforall", "nmap"]


def test_scan_unknown_tool_name_rejected(runner, aicp_dir, patched_tools):
    """--tools 指定未知工具名应报错。"""
    result = runner.invoke(main, [
        "scan", "example.com",
        "--authorized-by", "张三",
        "--authorization-note", "AUTH-001",
        "--scope", "example.com",
        "--tools", "unknown-tool",
    ])
    assert result.exit_code != 0
    assert "未知工具" in result.output or "unknown-tool" in result.output


def test_scan_with_failing_tool_marks_task_failed(runner, aicp_dir, monkeypatch):
    """工具失败时任务应进入 FAILED 状态。"""
    def _failing_tools(work_dir, names=None):
        # subdomain 正常，portscan 失败
        return [FakeSubdomainTool(), FailingTool(), FakeFingerprintTool()]

    monkeypatch.setattr(cli_module, "_default_tools", _failing_tools)

    result = runner.invoke(main, [
        "scan", "example.com",
        "--authorized-by", "张三",
        "--authorization-note", "AUTH-001",
        "--scope", "example.com",
    ])
    # 任务失败但 CLI 退出码非 0 (我们用 SystemExit(1) 标记)
    # 但 OrchestratorError 会抛出来；当前实现是任务 FAILED 不抛 OrchestratorError
    # 任务进入 FAILED 但 CLI 正常退出 (exit_code 0)，输出含 failed
    assert "failed" in result.output


def test_scan_passes_rate_limit_and_tool_args(runner, aicp_dir, monkeypatch):
    """P1-1: --rate-limit / --tool-args 应透传到工具的 ToolContext。"""
    captured = {}

    class CaptureTool(Tool):
        stage = StageName.SUBDOMAIN
        input_asset_types = ("domain",)
        output_asset_types = ("domain",)
        name = "capture"

        def run(self, inputs, ctx):
            captured["rate_limit"] = ctx.rate_limit
            captured["extra_args"] = ctx.extra_args
            return ToolResult(assets=[])

    monkeypatch.setattr(cli_module, "_default_tools", lambda *a, **k: [CaptureTool()])

    result = runner.invoke(main, [
        "scan", "example.com",
        "--authorized-by", "张三",
        "--authorization-note", "AUTH-001",
        "--scope", "example.com",
        "--rate-limit", "50",
        "--tool-args", "capture=-t /tmp/x",
    ])
    assert result.exit_code == 0, result.output
    assert captured["rate_limit"] == 50
    assert captured["extra_args"] == ["-t", "/tmp/x"]


def test_scan_tool_args_invalid_format_rejected(runner, aicp_dir, monkeypatch):
    """P1-1: --tool-args 缺少 = 时应报错。"""
    monkeypatch.setattr(cli_module, "_default_tools", lambda *a, **k: [FakeSubdomainTool()])

    result = runner.invoke(main, [
        "scan", "example.com",
        "--authorized-by", "张三",
        "--authorization-note", "AUTH-001",
        "--scope", "example.com",
        "--tool-args", "no-equals-here",
    ])
    assert result.exit_code != 0
    assert "格式应为 name=args" in result.output


# ---------------- resume ----------------

def test_resume_failed_task(runner, aicp_dir, patched_tools):
    """resume 恢复 FAILED 任务: 应重新跑未完成阶段。"""
    # 先 scan 一次 (用失败工具)，再 resume (用 mock 工具)
    # 直接构造一个 FAILED 任务在 db 里
    db_path = aicp_dir / ".aicp" / "aicp.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    from aicp.scheduler import Store
    from aicp.auth import AuthorizationVerifier
    from aicp.models import Task, Stage, StageName, StageStatus

    # 构造 FAILED 任务: subdomain 完成，portscan 失败
    with Store(db_path) as store:
        t = Task(targets=["example.com"])
        AuthorizationVerifier().verify(
            t, authorized_by="张三", authorization_note="AUTH-001",
            authorized_scope=["example.com", "1.2.3.4"],
        )
        store.save_task(t)
        # 用 mock 工具跑一次会直接完成，所以手动构造 FAILED 状态
        store.transition_task(t.id, TaskStatus.RUNNING)
        for name in StageName:
            store.init_stage(Stage(task_id=t.id, name=name))
        store.transition_stage(t.id, StageName.SUBDOMAIN, StageStatus.RUNNING)
        store.transition_stage(t.id, StageName.SUBDOMAIN, StageStatus.COMPLETED)
        store.transition_stage(t.id, StageName.PORTSCAN, StageStatus.RUNNING)
        store.transition_stage(t.id, StageName.PORTSCAN, StageStatus.FAILED, error="mock")
        store.transition_task(t.id, TaskStatus.FAILED, error="portscan failed")
        task_id = t.id

    # 用 mock 工具 resume
    result = runner.invoke(main, [
        "resume", task_id,
    ])
    assert result.exit_code == 0, result.output
    assert "completed" in result.output


def test_resume_nonexistent_task(runner, aicp_dir, patched_tools):
    """resume 不存在的任务应报错。"""
    result = runner.invoke(main, ["resume", "nonexistent-id"])
    assert result.exit_code != 0
    assert "任务不存在" in result.output


def test_resume_wrong_status(runner, aicp_dir, patched_tools):
    """resume 已完成任务应报错。"""
    # 先 scan 一次
    result = runner.invoke(main, [
        "scan", "example.com",
        "--authorized-by", "张三",
        "--authorization-note", "AUTH-001",
        "--scope", "example.com",
        "--scope", "1.2.3.4",
        "--no-report",
    ])
    assert result.exit_code == 0

    # 从输出提取 task_id (任务 XXXXXXXX -> completed)
    import re
    m = re.search(r"任务 ([a-f0-9]+) ->", result.output)
    assert m is not None, result.output
    task_id = m.group(1)

    # resume 已完成任务应报错
    result = runner.invoke(main, ["resume", task_id])
    assert result.exit_code != 0
    assert "不可恢复" in result.output


# ---------------- report ----------------

def test_report_generates_both_formats(runner, aicp_dir, patched_tools):
    """report 命令默认生成 HTML+JSON+Markdown 三种格式 (--format all)。"""
    # 先 scan 一次 (不自动生成报告)
    result = runner.invoke(main, [
        "scan", "example.com",
        "--authorized-by", "张三",
        "--authorization-note", "AUTH-001",
        "--scope", "example.com",
        "--scope", "1.2.3.4",
        "--no-report",
    ])
    assert result.exit_code == 0

    import re
    m = re.search(r"任务 ([a-f0-9]+) ->", result.output)
    task_id = m.group(1)

    # 再调 report (默认 --format all)
    result = runner.invoke(main, ["report", task_id])
    assert result.exit_code == 0, result.output
    assert "报告已生成" in result.output
    report_dir = aicp_dir / ".aicp" / "reports"
    assert len(list(report_dir.glob("*.html"))) == 1
    assert len(list(report_dir.glob("*.json"))) == 1
    assert len(list(report_dir.glob("*.md"))) == 1


def test_report_format_md_only(runner, aicp_dir, patched_tools):
    """report --format md 只生成 Markdown, 不生成 HTML/JSON。"""
    # 先 scan 一次 (不自动生成报告)
    result = runner.invoke(main, [
        "scan", "example.com",
        "--authorized-by", "张三",
        "--authorization-note", "AUTH-001",
        "--scope", "example.com",
        "--scope", "1.2.3.4",
        "--no-report",
    ])
    assert result.exit_code == 0
    import re
    task_id = re.search(r"任务 ([a-f0-9]+) ->", result.output).group(1)

    # 调 report --format md
    result = runner.invoke(main, ["report", task_id, "--format", "md"])
    assert result.exit_code == 0, result.output
    report_dir = aicp_dir / ".aicp" / "reports"
    assert len(list(report_dir.glob("*.md"))) == 1
    # 不应生成 HTML / JSON
    assert not list(report_dir.glob("*.html"))
    assert not list(report_dir.glob("*.json"))

    # 验证 Markdown 内容合法
    md_file = list(report_dir.glob("*.md"))[0]
    content = md_file.read_text(encoding="utf-8")
    assert "# AICP 资产报告" in content
    assert "## 任务信息" in content


def test_report_format_md_with_output(runner, aicp_dir, patched_tools):
    """report --format md -o 指定输出路径。"""
    result = runner.invoke(main, [
        "scan", "example.com",
        "--authorized-by", "张三",
        "--authorization-note", "AUTH-001",
        "--scope", "example.com",
        "--scope", "1.2.3.4",
        "--no-report",
    ])
    import re
    task_id = re.search(r"任务 ([a-f0-9]+) ->", result.output).group(1)

    out_file = aicp_dir / "custom_report.md"
    result = runner.invoke(main, [
        "report", task_id,
        "--format", "md",
        "-o", str(out_file),
    ])
    assert result.exit_code == 0, result.output
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "# AICP 资产报告" in content


def test_report_single_format_with_output(runner, aicp_dir, patched_tools):
    """report --format json -o 指定输出路径。"""
    result = runner.invoke(main, [
        "scan", "example.com",
        "--authorized-by", "张三",
        "--authorization-note", "AUTH-001",
        "--scope", "example.com",
        "--scope", "1.2.3.4",
        "--no-report",
    ])
    import re
    task_id = re.search(r"任务 ([a-f0-9]+) ->", result.output).group(1)

    out_file = aicp_dir / "custom.json"
    result = runner.invoke(main, [
        "report", task_id,
        "--format", "json",
        "-o", str(out_file),
    ])
    assert result.exit_code == 0, result.output
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["task"]["id"] == task_id


def test_report_nonexistent_task(runner, aicp_dir, patched_tools):
    """report 不存在任务应报错。"""
    result = runner.invoke(main, ["report", "nonexistent-id"])
    assert result.exit_code != 0
    assert "任务不存在" in result.output


# ---------------- list ----------------

def test_list_empty(runner, aicp_dir, patched_tools):
    """无任务时 list 显示 (无任务)。"""
    result = runner.invoke(main, ["list"])
    assert result.exit_code == 0
    assert "无任务" in result.output


def test_list_shows_tasks(runner, aicp_dir, patched_tools):
    """scan 后 list 应显示任务。"""
    result = runner.invoke(main, [
        "scan", "example.com",
        "--authorized-by", "张三",
        "--authorization-note", "AUTH-001",
        "--scope", "example.com",
        "--scope", "1.2.3.4",
        "--no-report", "--quiet",
    ])
    assert result.exit_code == 0

    result = runner.invoke(main, ["list"])
    assert result.exit_code == 0, result.output
    assert "example.com" in result.output
    assert "completed" in result.output
    assert "张三" in result.output


def test_list_filter_by_status(runner, aicp_dir, patched_tools):
    """--status 过滤任务。"""
    # 跑一个完成的任务
    runner.invoke(main, [
        "scan", "example.com",
        "--authorized-by", "张三",
        "--authorization-note", "AUTH-001",
        "--scope", "example.com",
        "--scope", "1.2.3.4",
        "--no-report", "--quiet",
    ])

    # 过滤 completed
    result = runner.invoke(main, ["list", "--status", "completed"])
    assert result.exit_code == 0
    assert "example.com" in result.output

    # 过滤 failed (应无)
    result = runner.invoke(main, ["list", "--status", "failed"])
    assert result.exit_code == 0
    assert "无任务" in result.output


def test_list_invalid_status(runner, aicp_dir, patched_tools):
    """--status 传无效值应报错。"""
    result = runner.invoke(main, ["list", "--status", "invalid"])
    assert result.exit_code != 0


# ---------------- show ----------------

def test_show_task_details(runner, aicp_dir, patched_tools):
    """show 命令显示任务详情。"""
    result = runner.invoke(main, [
        "scan", "example.com",
        "--authorized-by", "张三",
        "--authorization-note", "AUTH-001",
        "--scope", "example.com",
        "--scope", "1.2.3.4",
        "--no-report", "--quiet",
    ])
    import re
    task_id = re.search(r"任务 ([a-f0-9]+) ->", result.output).group(1)

    result = runner.invoke(main, ["show", task_id])
    assert result.exit_code == 0, result.output
    assert task_id in result.output
    assert "example.com" in result.output
    assert "张三" in result.output
    assert "AUTH-001" in result.output
    assert "阶段执行" in result.output
    # 4 个阶段都应出现
    assert "subdomain" in result.output
    assert "portscan" in result.output
    assert "fingerprint" in result.output
    assert "correlate" in result.output


def test_show_nonexistent_task(runner, aicp_dir, patched_tools):
    """show 不存在任务应报错。"""
    result = runner.invoke(main, ["show", "nonexistent-id"])
    assert result.exit_code != 0
    assert "任务不存在" in result.output


# ---------------- 自定义 db 路径 ----------------

def test_custom_db_path(runner, aicp_dir, patched_tools):
    """--db 指定自定义数据库路径。"""
    custom_db = aicp_dir / "custom" / "my.db"
    result = runner.invoke(main, [
        "scan", "example.com",
        "--authorized-by", "张三",
        "--authorization-note", "AUTH-001",
        "--scope", "example.com",
        "--scope", "1.2.3.4",
        "--no-report", "--quiet",
        "--db", str(custom_db),
    ])
    assert result.exit_code == 0, result.output
    assert custom_db.exists()

    # 用同一 db list 应能看到
    result = runner.invoke(main, ["list", "--db", str(custom_db)])
    assert "example.com" in result.output


# ---------------- 启动清理 RUNNING 任务 ----------------

def test_cleanup_running_on_startup_clears_running_tasks(tmp_path):
    """启动清理: 把上次崩溃残留的 RUNNING 任务标记为 FAILED。"""
    from aicp.scheduler import Store
    from aicp.models import Task
    from aicp.cli import _cleanup_running_on_startup

    db = tmp_path / "test.db"
    # 准备: 创建一个 RUNNING 任务 (走合法状态路径)
    with Store(db) as store:
        task = Task(targets=["example.com"])
        task.authorized_scope = ["example.com"]
        task.authorized_by = "tester"
        store.save_task(task)
        store.transition_task(task.id, TaskStatus.AUTH_PENDING)
        store.transition_task(task.id, TaskStatus.AUTHORIZED)
        store.transition_task(task.id, TaskStatus.RUNNING)
        task_id = task.id

    # 执行: 调用启动清理
    n = _cleanup_running_on_startup(str(db))

    # 验证: 返回 1, 任务变成 FAILED, error 含 interrupted / 未完成
    assert n == 1
    with Store(db) as store:
        task = store.get_task(task_id)
        assert task.status == TaskStatus.FAILED
        assert "interrupted" in task.error or "未完成" in task.error


def test_cleanup_running_on_startup_no_running_returns_zero(tmp_path):
    """无 RUNNING 任务时启动清理返回 0。"""
    from aicp.scheduler import Store
    from aicp.models import Task
    from aicp.cli import _cleanup_running_on_startup

    db = tmp_path / "test.db"
    with Store(db) as store:
        task = Task(targets=["example.com"])
        store.save_task(task)

    n = _cleanup_running_on_startup(str(db))
    assert n == 0


# ---------------- config (P1-2) ----------------

def test_config_init_creates_file(runner, aicp_dir):
    """`aicp config init` 生成 .aicp/config.toml。"""
    result = runner.invoke(main, ["config", "init"])
    assert result.exit_code == 0, result.output
    assert (aicp_dir / ".aicp" / "config.toml").exists()


def test_config_init_refuses_overwrite_without_force(runner, aicp_dir):
    """配置文件已存在时, 不带 --force 应报错。"""
    from aicp.config import write_default_config
    write_default_config()
    result = runner.invoke(main, ["config", "init"])
    assert result.exit_code != 0
    assert "已存在" in result.output


def test_config_show_prints_merged_values(runner, aicp_dir):
    """`aicp config show` 打印合并后的配置。"""
    from aicp.config import write_default_config
    write_default_config()
    result = runner.invoke(main, ["config", "show"])
    assert result.exit_code == 0, result.output
    assert "安全部" in result.output  # 示例配置的授权人
    assert "example.com" in result.output  # 示例配置的授权范围


def test_scan_reads_auth_from_config(runner, aicp_dir, monkeypatch):
    """P1-2: scan 不传授权参数时, 从 config.toml 读取授权信息。"""
    from aicp.config import write_default_config

    write_default_config()
    monkeypatch.setattr(cli_module, "_default_tools", lambda *a, **k: [FakeSubdomainTool()])

    result = runner.invoke(main, ["scan", "example.com"])
    assert result.exit_code == 0, result.output
    assert "completed" in result.output


def test_scan_cli_overrides_config(runner, aicp_dir, monkeypatch):
    """P1-2: CLI 显式参数优先于 config.toml。"""
    from aicp.config import write_default_config
    from aicp.scheduler import Store

    write_default_config()
    monkeypatch.setattr(cli_module, "_default_tools", lambda *a, **k: [FakeSubdomainTool()])

    result = runner.invoke(main, [
        "scan", "example.com",
        "--authorized-by", "CLI用户",
    ])
    assert result.exit_code == 0, result.output
    with Store(str(aicp_dir / ".aicp" / "aicp.db")) as store:
        task = store.list_tasks()[0]
        assert task.authorized_by == "CLI用户"


# ---------------- cancel (P1-4) ----------------

def test_cancel_command_requests_cancel(runner, aicp_dir):
    """`aicp cancel` 对 RUNNING 任务写入取消请求。"""
    from aicp.models import Task
    from aicp.scheduler import Store

    (aicp_dir / ".aicp").mkdir(parents=True, exist_ok=True)
    db = aicp_dir / ".aicp" / "aicp.db"
    with Store(str(db)) as store:
        t = Task(targets=["example.com"])
        store.save_task(t)
        store.transition_task(t.id, TaskStatus.AUTH_PENDING)
        store.transition_task(t.id, TaskStatus.AUTHORIZED)
        store.transition_task(t.id, TaskStatus.RUNNING)
        task_id = t.id

    result = runner.invoke(main, ["cancel", task_id])
    assert result.exit_code == 0, result.output
    assert "已请求取消" in result.output
    with Store(str(db)) as store:
        assert store.is_cancel_requested(task_id) is True


def test_cancel_non_running_noop(runner, aicp_dir):
    """非 RUNNING 任务 cancel 提示无需取消。"""
    from aicp.models import Task
    from aicp.scheduler import Store

    (aicp_dir / ".aicp").mkdir(parents=True, exist_ok=True)
    db = aicp_dir / ".aicp" / "aicp.db"
    with Store(str(db)) as store:
        t = Task(targets=["example.com"])
        store.save_task(t)
        task_id = t.id  # PENDING

    result = runner.invoke(main, ["cancel", task_id])
    assert result.exit_code == 0
    assert "无需取消" in result.output


def test_config_takes_precedence_over_env(runner, aicp_dir, monkeypatch):
    """审计 5.2 + 复核回归: 无 CLI 时 config 优先于环境变量 (rate_limit)。"""
    from aicp.config import write_default_config

    monkeypatch.setenv("AICP_RATE_LIMIT", "99")
    write_default_config()  # config 里 rate_limit=50

    result = runner.invoke(main, ["config", "show"])
    assert result.exit_code == 0, result.output
    assert "速率限制  : 50" in result.output


def test_banner_marks_auth_source_cli(runner, aicp_dir, monkeypatch):
    """审计 5.4: 授权来自 CLI 时 banner 标注来源。"""
    monkeypatch.setattr(cli_module, "_default_tools", lambda *a, **k: [FakeSubdomainTool()])

    result = runner.invoke(main, [
        "scan", "example.com",
        "--authorized-by", "张三",
        "--authorization-note", "AUTH-001",
        "--scope", "example.com",
    ])
    assert result.exit_code == 0, result.output
    assert "授权来源    : CLI 参数" in result.output


def test_banner_marks_auth_source_config(runner, aicp_dir, monkeypatch):
    """审计 5.4: 授权来自 config.toml 时 banner 标注来源。"""
    from aicp.config import write_default_config

    write_default_config()
    monkeypatch.setattr(cli_module, "_default_tools", lambda *a, **k: [FakeSubdomainTool()])

    result = runner.invoke(main, ["scan", "example.com"])
    assert result.exit_code == 0, result.output
    assert "授权来源    : 配置文件" in result.output


def test_merge_scan_priority_cli_config_env(monkeypatch):
    """审计复核回归: rate_limit 优先级 CLI > config > env, CLI 显式参数不被 env 压过。"""
    from aicp.config import merge_scan

    cfg = {"scan": {"rate_limit": 50}}
    monkeypatch.setenv("AICP_RATE_LIMIT", "999")

    # CLI 显式传 10 + config=50 + env=999: CLI 胜出
    assert merge_scan(10, False, None, cfg)["rate_limit"] == 10
    # CLI 缺省 + config=50 + env=999: config 胜出
    assert merge_scan(None, False, None, cfg)["rate_limit"] == 50
    # CLI/config 都缺省 + env=999: env 兜底
    assert merge_scan(None, False, None, {"scan": {}})["rate_limit"] == 999
    # 全缺省: None
    monkeypatch.delenv("AICP_RATE_LIMIT")
    assert merge_scan(None, False, None, {"scan": {}})["rate_limit"] is None


def test_merge_auth_scope_priority_cli_config_env(monkeypatch):
    """P0 行动项 #6 回归: scope 优先级 CLI > config > env, 显式 CLI --scope 不被 AICP_SCOPE 压过。"""
    from aicp.config import merge_auth

    cfg = {"auth": {"scope": ["config.example.com"]}}
    monkeypatch.setenv("AICP_SCOPE", "env.example.com")

    # CLI 显式 scope + config + env: CLI 胜出
    assert merge_auth(None, None, ("cli.example.com",), cfg)["scope"] == ["cli.example.com"]
    # CLI 缺省 + config + env: config 胜出
    assert merge_auth(None, None, None, cfg)["scope"] == ["config.example.com"]
    # CLI/config 都缺省 + env: env 兜底 (逗号分隔)
    assert merge_auth(None, None, None, {"auth": {}})["scope"] == ["env.example.com"]
    monkeypatch.setenv("AICP_SCOPE", "a.example.com, b.example.com")
    assert merge_auth(None, None, None, {"auth": {}})["scope"] == ["a.example.com", "b.example.com"]
    # 全缺省: []
    monkeypatch.delenv("AICP_SCOPE")
    assert merge_auth(None, None, None, {"auth": {}})["scope"] == []
