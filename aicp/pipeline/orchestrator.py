"""流水线编排器。

职责：
1. 串联各阶段工具 (SUBDOMAIN → PORTSCAN → FINGERPRINT → CORRELATE)；
2. 阶段间资产传递：上一阶段产出的资产作为下一阶段输入；
3. 断点续传：从最近未完成阶段恢复，已完成的阶段不重跑；
4. 失败隔离：单工具失败 -> 阶段 FAILED -> 任务 FAILED，可 resume 重试该阶段；
5. 资产持久化：每阶段产出自动存入 Store。

执行模型：
- 同一阶段注册多个工具时，按注册顺序依次执行；
- 工具的输入资产 = 该阶段所有工具 input_asset_types 的并集，
  从 Store 中已持久化的资产里取 (这样断点续传时能从 DB 恢复输入)；
- 工具产出先存 Store (自动去重)，再传给下一阶段。
"""

from __future__ import annotations

import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional

from ..models import Asset, Task, TaskStatus, StageName, StageStatus
from ..observability import bind_task_id
from ..scheduler import Store
from ..scheduler.store import DEFAULT_LEASE_SECONDS
from ..scheduler.state_machine import StateMachine, MaxRetriesExceededError
from ..tools import Tool, ToolContext, ToolError
from ..auth.verifier import _extract_host


logger = logging.getLogger(__name__)


class OrchestratorError(Exception):
    """编排器错误。"""


class LeaseHeldError(OrchestratorError):
    """任务租约被其他进程/线程持有, 拒绝并发执行 (行动项 #3 / ADR-1)。"""


# 阶段执行顺序 (StageName 枚举顺序刚好就是执行顺序)
_STAGE_ORDER: List[StageName] = [
    StageName.SUBDOMAIN,
    StageName.PORTSCAN,
    StageName.FINGERPRINT,
    StageName.DIRSCAN,
    StageName.VULNERABILITY,
    StageName.CORRELATE,
]


class Orchestrator:
    """流水线编排器。"""

    def __init__(
        self,
        store: Store,
        tools: List[Tool],
        work_dir: str,
        *,
        rate_limit: Optional[int] = None,
        tool_args: Optional[dict] = None,
        owner: Optional[str] = None,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
    ):
        """
        - store: 持久化层
        - tools: 工具列表 (按注册顺序，同阶段工具依次执行)
        - work_dir: 工具工作目录 (临时文件存放)
        - rate_limit: 全局速率限制 (req/s), 透传给各工具
        - tool_args: 按工具名透传额外参数, 如 {"nuclei": ["-t", "/path/templates"]}
        - owner: 租约持有者标识 (默认按 进程 pid + 随机数 生成, 行动项 #3)
        - lease_seconds: 租约时长 (秒); 心跳线程按 lease/3 续约
        """
        self._store = store
        self._tools = tools
        self._work_dir = work_dir
        self._rate_limit = rate_limit
        self._tool_args = tool_args or {}
        self._owner = owner or f"pid-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self._lease_seconds = lease_seconds
        # 按 stage 分组工具，保持注册顺序
        self._tools_by_stage: Dict[StageName, List[Tool]] = {s: [] for s in _STAGE_ORDER}
        for t in tools:
            if t.stage not in self._tools_by_stage:
                raise OrchestratorError(f"未知阶段: {t.stage}")
            self._tools_by_stage[t.stage].append(t)

    def run(self, task: Task) -> Task:
        """启动或恢复任务流水线。

        - task 必须处于 AUTHORIZED / PAUSED / FAILED / RUNNING 状态;
        - 先原子获取任务租约 (行动项 #3): 他方持有有效租约时抛 LeaseHeldError,
          僵死 RUNNING (租约过期) 自动接管;
        - 流水线完成后 task 状态变为 COMPLETED / FAILED / CANCELLED。
        """
        # 从 store 读取最新状态 (传入的 task 对象可能已过期)
        latest = self._store.get_task(task.id)
        if latest is None:
            raise OrchestratorError(f"任务不存在: {task.id}")
        task = latest

        # 允许 RUNNING 作为输入: 线程崩溃/OOM 等场景会让任务卡 RUNNING,
        # 进程仍存活时 resume 必须能恢复 (配合 is_running 守卫防真正并发)
        if task.status not in (
            TaskStatus.AUTHORIZED, TaskStatus.PAUSED, TaskStatus.FAILED, TaskStatus.RUNNING
        ):
            raise OrchestratorError(
                f"任务 {task.id} 状态 {task.status.value} 不可运行，需 AUTHORIZED / PAUSED / FAILED / RUNNING"
            )

        # 任务租约 (行动项 #3 / ADR-1): 原子抢占执行权, 双入口/双进程仅一方成功。
        # 卡 RUNNING 的任务: 租约过期 → 接管 + 重置阶段级 RUNNING 残留;
        # 租约有效 (他方在跑) → 拒绝并发执行。
        was_stale_running = task.status == TaskStatus.RUNNING
        if not self._store.acquire_task_lease(
            task.id, self._owner, self._lease_seconds
        ):
            raise LeaseHeldError(
                f"任务 {task.id} 正在被其他进程/线程执行 (租约有效), 拒绝并发执行"
            )
        task = self._store.get_task(task.id)  # 重新读取 RUNNING 后的最新状态
        if was_stale_running:
            self._store.reset_running_stages(task.id)

        # 绑定 task_id 到当前执行流 (行动项 #7): 此后本线程所有日志自动携带
        task_id_token = bind_task_id(task.id)
        logger.info("task=%s 获取租约 owner=%s 开始执行", task.id, self._owner)

        # 确保工作目录存在
        Path(self._work_dir).mkdir(parents=True, exist_ok=True)

        # 进入 RUNNING: 清除上次的取消标记, 让本次运行成为干净新开始 (审计 3.1)
        # 否则取消后崩溃恢复的 resume 会在首个阶段边界被旧标记再次取消。
        self._store.clear_cancel(task.id)

        # 初始化所有阶段的 Stage 记录 (只首次创建，断点续传不覆盖)
        for stage in _STAGE_ORDER:
            existing = self._store.get_stage(task.id, stage)
            if existing is None:
                from ..models import Stage
                self._store.init_stage(Stage(task_id=task.id, name=stage))

        # 心跳线程 (行动项 #3): 按 lease/3 续约, 防长工具导致租约被误判过期
        stop_heartbeat = threading.Event()
        heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            args=(task.id, stop_heartbeat),
            daemon=True,
            name=f"lease-heartbeat-{task.id[:8]}",
        )
        heartbeat_thread.start()

        try:
            # 依次执行未完成的阶段
            while True:
                next_stage = self._store.next_pending_stage(task.id)
                if next_stage is None:
                    break
                self._run_stage(task, next_stage)
        except _StageFailedError as e:
            # 阶段失败 -> 任务失败
            task = self._store.transition_task(
                task.id, TaskStatus.FAILED, error=str(e)
            )
            return task
        except _CancelledError:
            # 用户请求取消 -> 任务取消 (P1-4)
            task = self._store.transition_task(
                task.id, TaskStatus.CANCELLED, error="用户取消"
            )
            return task
        finally:
            # 停心跳 + 释放租约 (终态清列; 已被接管则 owner 不匹配 no-op)
            stop_heartbeat.set()
            heartbeat_thread.join(timeout=5)
            try:
                self._store.release_lease(task.id, self._owner)
            except Exception:
                logger.exception("释放任务租约失败 task=%s", task.id)
            finally:
                # 解绑 task_id (contextvar restore, 行动项 #7)
                task_id_token.var.reset(task_id_token)

        # 全部阶段完成
        task = self._store.transition_task(task.id, TaskStatus.COMPLETED)
        return task

    def _heartbeat_loop(self, task_id: str, stop: threading.Event) -> None:
        """租约续约心跳 (daemon 线程): 每 lease/3 秒续约一次。

        续约失败 (被接管/终态) 只记 ERROR 不中断流水线 —— 工具子进程无法
        安全中止, 完整冲突处理超出本期范围 (ADR-1 已知边界)。
        每次续约独立开 Store 连接: sqlite3 连接不可跨线程使用。
        """
        interval = max(1, self._lease_seconds // 3)
        while not stop.wait(interval):
            try:
                with Store(self._store.db_path) as store:
                    ok = store.heartbeat_lease(task_id, self._owner, self._lease_seconds)
                if not ok:
                    logger.error(
                        "task=%s 租约续约失败 (可能已被接管), 本次运行结果可能被覆盖",
                        task_id,
                    )
                    return
            except Exception:
                logger.exception("task=%s 租约续约异常", task_id)

    def _run_stage(self, task: Task, stage_record) -> None:
        """执行单个阶段。失败抛 _StageFailedError。"""
        stage_name = stage_record.name

        # 重试次数上限检查: 防止失败任务无限重试
        try:
            StateMachine.check_stage_retry_limit(
                stage_record.attempt, stage_name.value
            )
        except MaxRetriesExceededError as e:
            # 已达上限时阶段已是 FAILED (或由卡死 RUNNING 恢复为 PENDING),
            # FAILED->FAILED / PENDING->FAILED 均非法, 再调 transition_stage
            # 会抛 IllegalTransitionError 崩溃。这里只记审计, 直接抛
            # _StageFailedError 让 run() 把任务标记为 FAILED。
            self._store.append_audit(task.id, "stage_retry_limit_exceeded", str(e))
            raise _StageFailedError(str(e)) from e

        # 取消检查: 阶段边界生效 (P1-4)
        if self._store.is_cancel_requested(task.id):
            raise _CancelledError()

        # CORRELATE 阶段是内置的: 不需要外部工具，直接合并资产并记录摘要
        if stage_name == StageName.CORRELATE:
            self._run_correlate_stage(task)
            return

        tools = self._tools_by_stage.get(stage_name, [])

        # SUBDOMAIN 阶段即使无工具，也要把 task.targets 注入为初始资产
        # (否则下游阶段拿不到输入)
        if stage_name == StageName.SUBDOMAIN and not tools:
            self._store.transition_stage(task.id, stage_name, StageStatus.RUNNING)
            self._build_initial_targets(task)
            self._store.transition_stage(task.id, stage_name, StageStatus.COMPLETED)
            return

        # 没有注册工具的其他阶段直接标记完成
        if not tools:
            self._store.transition_stage(
                task.id, stage_name, StageStatus.RUNNING
            )
            self._store.transition_stage(
                task.id, stage_name, StageStatus.COMPLETED
            )
            return

        # 阶段进入 RUNNING
        self._store.transition_stage(task.id, stage_name, StageStatus.RUNNING)

        try:
            # 收集该阶段所有工具的输入资产类型并集
            input_types = set()
            for t in tools:
                input_types.update(t.input_asset_types)

            # 从 Store 读取已持久化的资产作为输入
            # 特殊处理: SUBDOMAIN 阶段输入用 task.targets 构造初始资产
            if stage_name == StageName.SUBDOMAIN:
                inputs = self._build_initial_targets(task)
            else:
                # type 过滤下推到 SQL, 避免拉取全部资产再在 Python 层过滤
                inputs = self._store.list_assets_by_types(task.id, input_types)

            # 依次执行同阶段的工具 (每个工具独立 ctx, 携带该工具的额外参数)
            for tool in tools:
                # 取消检查: 工具边界生效 (P1-4)
                if self._store.is_cancel_requested(task.id):
                    raise _CancelledError()
                filtered = tool.filter_inputs(inputs, tool.input_asset_types)
                logger.info(
                    "task=%s stage=%s tool=%s inputs=%d",
                    task.id, stage_name.value, type(tool).__name__, len(filtered),
                )
                ctx = ToolContext(
                    task_id=task.id,
                    authorized_scope=task.authorized_scope,
                    work_dir=self._work_dir,
                    rate_limit=self._rate_limit,
                    extra_args=list(
                        self._tool_args.get(tool.name or type(tool).__name__.lower(), [])
                    ),
                )
                result = tool.run(filtered, ctx)
                # 工具原始输出落盘 (行动项 #4/#7): 取证第一现场,
                # 含完整命令行 + stdout/stderr + 范围外告警
                self._persist_raw_output(task.id, tool, result)
                # 持久化产出 (自动去重)
                self._store.save_assets(result.assets)
                # 把产出加入 inputs，供同阶段后续工具使用
                inputs.extend(result.assets)
                self._store.append_audit(
                    task.id,
                    "tool_completed",
                    f"stage={stage_name.value} tool={type(tool).__name__} "
                    f"produced={len(result.assets)} stats={result.stats}",
                )

        except ToolError as e:
            self._store.transition_stage(
                task.id, stage_name, StageStatus.FAILED, error=str(e)
            )
            raise _StageFailedError(
                f"阶段 {stage_name.value} 失败: {e}"
            ) from e
        except Exception as e:
            self._store.transition_stage(
                task.id, stage_name, StageStatus.FAILED, error=f"未捕获异常: {e}"
            )
            raise _StageFailedError(
                f"阶段 {stage_name.value} 异常: {e}"
            ) from e

        self._store.transition_stage(task.id, stage_name, StageStatus.COMPLETED)

    def _persist_raw_output(self, task_id: str, tool: Tool, result) -> None:
        """工具 raw_output 追加落盘 work/{task_id}/logs/{tool}.log (行动项 #4/#7)。

        - 追加模式: resume 重跑同一工具时保留历史轮次, 便于取证;
        - 写盘失败只 warning 不阻断 (取证是尽力而为, 不因磁盘问题中断扫描)。
        """
        if not result.raw_output:
            return
        tool_name = tool.name or type(tool).__name__.lower()
        log_dir = Path(self._work_dir) / task_id / "logs"
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
            with open(log_dir / f"{tool_name}.log", "a", encoding="utf-8") as f:
                f.write(f"\n===== {ts} =====\n{result.raw_output}\n")
        except OSError as e:
            logger.warning(
                "raw_output 落盘失败 task=%s tool=%s: %s", task_id, tool_name, e
            )

    def _run_correlate_stage(self, task: Task) -> None:
        """内置 CORRELATE 阶段: 合并资产，记录摘要到审计日志。

        用户也可以注册自己的 CORRELATE 工具，但通常不需要——
        merge_assets 已经做了关联与去重，报告生成时直接调用。
        """
        self._store.transition_stage(task.id, StageName.CORRELATE, StageStatus.RUNNING)
        try:
            from ..correlate import merge_assets
            assets = self._store.list_assets(task.id)
            graph = merge_assets(assets)
            summary = {
                "domains": len(graph.domains),
                "hosts": len(graph.hosts),
                "ports": sum(len(h.ports) for h in graph.hosts),
                "urls": sum(len(p.urls) for h in graph.hosts for p in h.ports),
                "web_services": sum(
                    1 for h in graph.hosts for p in h.ports for u in p.urls if u.web_service
                ),
            }
            self._store.append_audit(
                task.id,
                "correlate_summary",
                f"合并后资产: domains={summary['domains']} hosts={summary['hosts']} "
                f"ports={summary['ports']} urls={summary['urls']} web_services={summary['web_services']}",
            )
        except Exception as e:
            self._store.transition_stage(
                task.id, StageName.CORRELATE, StageStatus.FAILED, error=str(e)
            )
            raise _StageFailedError(f"阶段 correlate 异常: {e}") from e
        self._store.transition_stage(task.id, StageName.CORRELATE, StageStatus.COMPLETED)

    def _build_initial_targets(self, task: Task) -> List[Asset]:
        """把 task.targets 转为初始资产并持久化。

        - 域名 -> type=domain
        - IP/CIDR -> type=ip (CIDR 保留原值，由工具自行展开)
        工具通过 input_asset_types 自动过滤自己需要的类型。
        """
        import ipaddress

        assets: List[Asset] = []
        for target in task.targets:
            t = target.strip()
            if not t:
                continue
            # 提取 host: URL / host:port / [ipv6]:port 统一处理, 与授权校验一致
            # (修复: 旧逻辑对 http://example.com:80/ 这类 URL 提取失败,
            #  把整个 URL 误当作 domain)
            host = _extract_host(t)
            if not host:
                continue

            # 判断类型
            try:
                ipaddress.ip_address(host)
                asset_type = "ip"
            except ValueError:
                try:
                    ipaddress.ip_network(host, strict=False)
                    asset_type = "ip"
                except ValueError:
                    asset_type = "domain"

            asset = Asset(
                type=asset_type,
                value=host,
                source="user_input",
                task_id=task.id,
                raw={"tool": "user_input"},
            )
            self._store.save_asset(asset)
            assets.append(asset)
        return assets


class _StageFailedError(Exception):
    """阶段执行失败 (内部异常，用于在 run() 中捕获)。"""


class _CancelledError(Exception):
    """任务被用户取消 (内部异常, 阶段边界生效, 用于在 run() 中捕获)。"""
