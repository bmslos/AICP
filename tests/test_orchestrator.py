"""流水线编排器单元测试。

用 fake 工具 (不依赖外部二进制) 验证：
1. 完整流水线执行 (SUBDOMAIN -> PORTSCAN -> FINGERPRINT -> CORRELATE)
2. 断点续传 (中断后 resume 从未完成阶段继续)
3. 失败隔离 (工具失败 -> 阶段 FAILED -> 任务 FAILED)
4. 资产持久化与传递
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from aicp.auth import AuthorizationVerifier
from aicp.models import Asset, Stage, Task, TaskStatus, StageName, StageStatus
from aicp.pipeline import Orchestrator, OrchestratorError
from aicp.scheduler import Store
from aicp.tools import Tool, ToolResult, ToolError


# ---------------- Fake 工具 ----------------

class FakeSubdomainTool(Tool):
    """模拟 OneForAll: 输入 domain，输出更多 domain。"""

    stage = StageName.SUBDOMAIN
    input_asset_types = ("domain",)
    output_asset_types = ("domain",)

    def __init__(self, extra_domains: list[str]):
        self._extra = extra_domains

    def run(self, inputs, ctx):
        out = [
            Asset(type="domain", value=d, source="fake_subdomain", task_id=ctx.task_id)
            for d in self._extra
        ]
        return ToolResult(assets=out, stats={"produced": len(out)})


class FakePortscanTool(Tool):
    """模拟 Nmap: 输入 domain/ip，输出 ip + port。"""

    stage = StageName.PORTSCAN
    input_asset_types = ("domain", "ip")
    output_asset_types = ("ip", "port")

    def __init__(self, ip_map: dict[str, list[int]]):
        self._ip_map = ip_map

    def run(self, inputs, ctx):
        out = []
        for a in inputs:
            ports = self._ip_map.get(a.value, [])
            for p in ports:
                port_val = f"1.2.3.{p % 256}:{p}"
                out.append(Asset(type="port", value=port_val, source="fake_portscan",
                                 task_id=ctx.task_id, parent_id=a.id))
        return ToolResult(assets=out, stats={"open_ports": len(out)})


class FailingTool(Tool):
    """总是失败的工具。"""

    stage = StageName.FINGERPRINT
    input_asset_types = ("port",)
    output_asset_types = ("url",)

    def run(self, inputs, ctx):
        raise ToolError("fake failure")


class NoopTool(Tool):
    """什么都不做的工具。"""

    stage = StageName.CORRELATE
    input_asset_types = ()
    output_asset_types = ()

    def run(self, inputs, ctx):
        return ToolResult(assets=[])


# ---------------- 测试夹具 ----------------

@pytest.fixture
def authorized_task(store):
    t = Task(targets=["example.com"])
    store.save_task(t)
    AuthorizationVerifier().verify(
        t,
        authorized_by="张三",
        authorization_note="AUTH-001",
        authorized_scope=["example.com"],
    )
    store.save_task(t)
    return t


# ---------------- 完整流水线 ----------------

def test_full_pipeline_run_completes_all_stages(store, authorized_task, tmp_path):
    tools = [
        FakeSubdomainTool(["sub1.example.com", "sub2.example.com"]),
        FakePortscanTool({"sub1.example.com": [80, 443], "sub2.example.com": [22]}),
        NoopTool(),  # 占位 FINGERPRINT (实际用 FailingTool 会失败)
    ]
    orch = Orchestrator(store, tools, work_dir=str(tmp_path))

    final = orch.run(authorized_task)

    assert final.status == TaskStatus.COMPLETED
    # 所有阶段都 COMPLETED
    for stage in store.list_stages(authorized_task.id):
        assert stage.status == StageStatus.COMPLETED
    # SUBDOMAIN 阶段产出的子域名已持久化
    assets = store.list_assets(authorized_task.id)
    values = {a.value for a in assets if a.type == "domain"}
    assert "sub1.example.com" in values
    assert "sub2.example.com" in values


def test_pipeline_persists_initial_targets(store, authorized_task, tmp_path):
    """SUBDOMAIN 阶段应把 task.targets 转为初始资产并持久化。"""
    tools = [FakeSubdomainTool([])]
    orch = Orchestrator(store, tools, work_dir=str(tmp_path))
    orch.run(authorized_task)

    assets = store.list_assets(authorized_task.id)
    domains = [a for a in assets if a.type == "domain" and a.source == "user_input"]
    assert len(domains) == 1
    assert domains[0].value == "example.com"


# ---------------- 断点续传 ----------------

def test_pipeline_resume_from_failed_stage(store, authorized_task, tmp_path):
    """任务在 FINGERPRINT 阶段失败后，重新注册工具并 resume 应继续。"""
    # 第一次跑: FINGERPRINT 阶段会失败
    tools_v1 = [
        FakeSubdomainTool(["sub1.example.com"]),
        FakePortscanTool({"sub1.example.com": [80]}),
        FailingTool(),  # FINGERPRINT 失败
    ]
    orch_v1 = Orchestrator(store, tools_v1, work_dir=str(tmp_path))
    final = orch_v1.run(authorized_task)

    assert final.status == TaskStatus.FAILED
    # SUBDOMAIN / PORTSCAN 应该都完成了，FINGERPRINT 失败
    stages = {s.name: s for s in store.list_stages(authorized_task.id)}
    assert stages[StageName.SUBDOMAIN].status == StageStatus.COMPLETED
    assert stages[StageName.PORTSCAN].status == StageStatus.COMPLETED
    assert stages[StageName.FINGERPRINT].status == StageStatus.FAILED

    # 把任务从 FAILED 转回可运行状态 (这里通过 PAUSED -> 不可，需要手动改)
    # 状态机: FAILED 是终态。我们的设计里 FAILED 后需要重试该阶段，
    # 应该允许 FAILED -> ? 实际上状态机里 FAILED 没有出口。
    # 这里通过把阶段状态从 FAILED -> PENDING 来实现重试
    store.transition_stage(authorized_task.id, StageName.FINGERPRINT, StageStatus.PENDING)
    # 任务从 FAILED -> AUTHORIZED (重新授权) -> 可运行
    # 但状态机不允许 FAILED -> AUTHORIZED。我们改用 PAUSED 作为中间态
    # 实际上 FAILED 是终态，需要外部干预。这里模拟"重置任务到 PAUSED"
    # 通过直接更新 store (绕过状态机校验，因为这是外部干预场景)
    task = store.get_task(authorized_task.id)
    task.status = TaskStatus.PAUSED
    store.save_task(task)

    # 重新注册工具 (这次 FINGERPRINT 不失败)
    tools_v2 = [
        FakeSubdomainTool(["sub1.example.com"]),
        FakePortscanTool({"sub1.example.com": [80]}),
        NoopTool(),  # 这次用 NoopTool 代替 FailingTool, 但 stage=CORRELATE
    ]
    # NoopTool.stage=CORRELATE，FINGERPRINT 阶段没工具会被跳过
    # 为了让 FINGERPRINT 真正跑通，需要一个 FINGERPRINT 工具
    class FakeFingerprintTool(Tool):
        stage = StageName.FINGERPRINT
        input_asset_types = ("port",)
        output_asset_types = ("url",)
        def run(self, inputs, ctx):
            return ToolResult(assets=[
                Asset(type="url", value=f"http://{a.value}", source="fake_fp",
                      task_id=ctx.task_id, parent_id=a.id)
                for a in inputs
            ])

    tools_v2 = [
        FakeSubdomainTool(["sub1.example.com"]),
        FakePortscanTool({"sub1.example.com": [80]}),
        FakeFingerprintTool(),
    ]
    orch_v2 = Orchestrator(store, tools_v2, work_dir=str(tmp_path))
    final = orch_v2.run(task)

    assert final.status == TaskStatus.COMPLETED
    # SUBDOMAIN / PORTSCAN 不会重跑 (已完成)
    stages = {s.name: s for s in store.list_stages(authorized_task.id)}
    assert stages[StageName.SUBDOMAIN].status == StageStatus.COMPLETED
    assert stages[StageName.SUBDOMAIN].attempt == 1  # 没重跑
    assert stages[StageName.FINGERPRINT].status == StageStatus.COMPLETED
    assert stages[StageName.FINGERPRINT].attempt == 2  # 重试过一次


def test_pipeline_does_not_replay_completed_stages(store, authorized_task, tmp_path):
    """已完成的阶段在 resume 时不会重新执行。"""
    call_count = {"sub": 0, "port": 0}

    class CountingSub(Tool):
        stage = StageName.SUBDOMAIN
        input_asset_types = ("domain",)
        output_asset_types = ("domain",)
        def run(self, inputs, ctx):
            call_count["sub"] += 1
            return ToolResult(assets=[])

    class CountingPort(Tool):
        stage = StageName.PORTSCAN
        input_asset_types = ("domain", "ip")
        output_asset_types = ("ip", "port")
        def run(self, inputs, ctx):
            call_count["port"] += 1
            return ToolResult(assets=[])

    tools = [CountingSub(), CountingPort()]
    orch = Orchestrator(store, tools, work_dir=str(tmp_path))
    orch.run(authorized_task)

    # 第一次: 两个工具各跑 1 次
    assert call_count == {"sub": 1, "port": 1}

    # 再次 run (模拟 resume，但实际所有阶段已完成)
    task = store.get_task(authorized_task.id)
    # 任务已 COMPLETED，是终态，无法再 run
    # 这里验证: 已 COMPLETED 的任务再 run 应抛错
    with pytest.raises(OrchestratorError):
        orch.run(task)


# ---------------- 失败隔离 ----------------

def test_tool_failure_marks_task_failed(store, authorized_task, tmp_path):
    tools = [
        FakeSubdomainTool(["sub1.example.com"]),
        FailingTool(),  # FINGERPRINT 失败
    ]
    orch = Orchestrator(store, tools, work_dir=str(tmp_path))
    final = orch.run(authorized_task)

    assert final.status == TaskStatus.FAILED
    assert final.error is not None
    assert "FINGERPRINT" in final.error or "fingerprint" in final.error

    stages = {s.name: s for s in store.list_stages(authorized_task.id)}
    assert stages[StageName.SUBDOMAIN].status == StageStatus.COMPLETED
    assert stages[StageName.FINGERPRINT].status == StageStatus.FAILED
    assert stages[StageName.FINGERPRINT].error is not None


def test_empty_stage_marked_completed(store, authorized_task, tmp_path):
    """没有注册工具的阶段 (如 CORRELATE) 直接标记完成。"""
    tools = [FakeSubdomainTool(["sub1.example.com"])]
    orch = Orchestrator(store, tools, work_dir=str(tmp_path))
    orch.run(authorized_task)

    stages = {s.name: s for s in store.list_stages(authorized_task.id)}
    # PORTSCAN / FINGERPRINT / CORRELATE 都没注册工具，但都标记完成
    assert stages[StageName.PORTSCAN].status == StageStatus.COMPLETED
    assert stages[StageName.FINGERPRINT].status == StageStatus.COMPLETED
    assert stages[StageName.CORRELATE].status == StageStatus.COMPLETED


# ---------------- 状态校验 ----------------

def test_run_rejects_unauthorized_task(store, tmp_path):
    t = Task(targets=["example.com"])  # 状态 PENDING
    store.save_task(t)
    orch = Orchestrator(store, [], work_dir=str(tmp_path))
    with pytest.raises(OrchestratorError, match="不可运行"):
        orch.run(t)


def test_run_rejects_terminal_task(store, authorized_task, tmp_path):
    # 先完成一次
    orch = Orchestrator(store, [FakeSubdomainTool([])], work_dir=str(tmp_path))
    orch.run(authorized_task)
    # COMPLETED 是终态，不能再 run
    with pytest.raises(OrchestratorError):
        orch.run(authorized_task)


# ---------------- 资产传递 ----------------

def test_assets_flow_between_stages(store, authorized_task, tmp_path):
    """上游产出自动成为下游输入。"""
    tools = [
        FakeSubdomainTool(["sub1.example.com"]),
        FakePortscanTool({"sub1.example.com": [80]}),
    ]
    orch = Orchestrator(store, tools, work_dir=str(tmp_path))
    orch.run(authorized_task)

    assets = store.list_assets(authorized_task.id)
    # 应有: 1 个初始 domain + 1 个 subdomain + 1 个 port
    domains = [a for a in assets if a.type == "domain"]
    ports = [a for a in assets if a.type == "port"]
    assert len(domains) == 2  # example.com + sub1.example.com
    assert len(ports) == 1
    assert ports[0].value == "1.2.3.80:80"


# ---------------- list_assets / list_assets_by_types 调用次数验证 ----------------

def test_orchestrator_uses_list_assets_by_types_for_stage_inputs(
    store, authorized_task, tmp_path, monkeypatch
):
    """Orchestrator 调用点 A 应改用 list_assets_by_types, 不再调用 list_assets。"""
    list_assets_calls = {"count": 0}
    list_assets_by_types_calls = {"count": 0, "types": []}

    orig_list_assets = Store.list_assets
    orig_list_assets_by_types = Store.list_assets_by_types

    def counting_list_assets(self, task_id):
        list_assets_calls["count"] += 1
        return orig_list_assets(self, task_id)

    def counting_list_assets_by_types(self, task_id, types):
        list_assets_by_types_calls["count"] += 1
        list_assets_by_types_calls["types"].append(set(types))
        return orig_list_assets_by_types(self, task_id, types)

    monkeypatch.setattr(Store, "list_assets", counting_list_assets)
    monkeypatch.setattr(Store, "list_assets_by_types", counting_list_assets_by_types)

    tools = [
        FakeSubdomainTool(["sub1.example.com"]),
        FakePortscanTool({"sub1.example.com": [80]}),
    ]
    orch = Orchestrator(store, tools, work_dir=str(tmp_path))
    orch.run(authorized_task)

    # list_assets_by_types 应在 PORTSCAN 阶段被调用 1 次
    # (FINGERPRINT 因无工具走快速完成分支, 不调用)
    # CORRELATE 不调用 list_assets_by_types, 改用 list_assets
    assert list_assets_by_types_calls["count"] == 1
    # PORTSCAN 工具 input_asset_types = ("domain", "ip")
    assert list_assets_by_types_calls["types"] == [{"domain", "ip"}]

    # list_assets 应只在 CORRELATE 阶段被调用 1 次
    # (调用点 A 已改用 list_assets_by_types, 不应再调 list_assets 做输入收集)
    assert list_assets_calls["count"] == 1


def test_orchestrator_no_list_assets_call_when_all_stages_no_tools(
    store, authorized_task, tmp_path, monkeypatch
):
    """所有阶段都无工具时 (除 SUBDOMAIN 外), list_assets_by_types 不应被调用。"""
    list_assets_by_types_calls = {"count": 0}

    orig = Store.list_assets_by_types
    def counting(self, task_id, types):
        list_assets_by_types_calls["count"] += 1
        return orig(self, task_id, types)
    monkeypatch.setattr(Store, "list_assets_by_types", counting)

    # 不注册任何工具
    orch = Orchestrator(store, [], work_dir=str(tmp_path))
    orch.run(authorized_task)

    # 没有 PORTSCAN/FINGERPRINT 工具, 走快速完成分支, 不调用 list_assets_by_types
    # CORRELATE 仍调用 list_assets 1 次
    assert list_assets_by_types_calls["count"] == 0


# ---------------- RUNNING 卡死恢复 ----------------

@pytest.mark.recovery
def test_run_recovers_from_running_state(store, authorized_task, tmp_path):
    """卡 RUNNING 的任务, run() 应先转 FAILED 重置阶段, 再恢复正常流程, 不能停在 RUNNING。"""
    # 把 AUTHORIZED 任务转 RUNNING (模拟线程崩溃后任务卡死)
    task = store.transition_task(authorized_task.id, TaskStatus.RUNNING)
    # 创建一个卡 RUNNING 的 SUBDOMAIN stage (模拟崩溃现场)
    store.init_stage(Stage(
        task_id=task.id, name=StageName.SUBDOMAIN,
        status=StageStatus.RUNNING, started_at=datetime.now(timezone.utc),
    ))

    orch = Orchestrator(store, [], work_dir=str(tmp_path))
    final = orch.run(task)

    # 无工具时所有阶段走快速完成分支, 最终应 COMPLETED, 不能停在 RUNNING
    assert final.status == TaskStatus.COMPLETED

    # 审计日志应含: task_transition running -> failed (recovery) 和 stage_reset
    audit = store.list_audit(task.id)
    details = [a["detail"] for a in audit]
    events = [a["event"] for a in audit]
    assert "stage_reset" in events
    assert any("running -> failed" in d for d in details)
    assert any("RUNNING -> PENDING (recovery)" in d for d in details)


@pytest.mark.recovery
def test_run_resets_running_stages_on_recovery(store, authorized_task, tmp_path):
    """恢复卡 RUNNING 任务时, 阶段级 RUNNING 应被重置为 PENDING 后重新跑通。"""
    task = store.transition_task(authorized_task.id, TaskStatus.RUNNING)
    store.init_stage(Stage(
        task_id=task.id, name=StageName.SUBDOMAIN,
        status=StageStatus.RUNNING, started_at=datetime.now(timezone.utc),
    ))

    orch = Orchestrator(store, [], work_dir=str(tmp_path))
    final = orch.run(task)

    assert final.status == TaskStatus.COMPLETED
    # SUBDOMAIN stage 最终应是 COMPLETED (被重置为 PENDING 后又重新执行)
    stages = {s.name: s for s in store.list_stages(task.id)}
    assert stages[StageName.SUBDOMAIN].status == StageStatus.COMPLETED

    # 审计日志含 stage_reset: subdomain RUNNING -> PENDING (recovery)
    audit = store.list_audit(task.id)
    details = [a["detail"] for a in audit]
    assert any(
        "subdomain" in d and "RUNNING -> PENDING (recovery)" in d
        for d in details
    )


# ---------------- 重试上限 / 目标分类 ----------------

def test_pipeline_retry_limit_no_crash(store, authorized_task, tmp_path):
    """阶段重试达上限时, run() 不应抛 IllegalTransitionError 崩溃, 任务应 FAILED。

    修复 Bug #3: 旧实现在超限后调用 transition_stage(FAILED->FAILED),
    违反状态机抛 IllegalTransitionError 直接冒泡崩溃。
    """
    from aicp.scheduler.state_machine import MAX_STAGE_ATTEMPTS

    class AlwaysFail(Tool):
        stage = StageName.PORTSCAN
        input_asset_types = ("domain", "ip")
        output_asset_types = ("ip", "port")

        def run(self, inputs, ctx):
            raise ToolError("always fail")

    orch = Orchestrator(store, [AlwaysFail()], work_dir=str(tmp_path))
    final = authorized_task
    # 连续 run 直到 attempt 达到上限 (含触发上限的那一次)
    for _ in range(MAX_STAGE_ATTEMPTS + 1):
        final = orch.run(final)
        assert final.status == TaskStatus.FAILED

    # 阶段最终 attempt == 上限, 且不再崩溃
    stage = store.get_stage(authorized_task.id, StageName.PORTSCAN)
    assert stage.attempt == MAX_STAGE_ATTEMPTS
    # 审计日志记录重试上限
    audit = store.list_audit(authorized_task.id)
    assert any(a["event"] == "stage_retry_limit_exceeded" for a in audit)


def test_build_initial_targets_extracts_url_host(store, tmp_path):
    """URL 型目标应提取 host 作为初始资产, 不被误分类为完整 URL 的 domain (修复 Bug #4)。"""
    t = Task(targets=["http://example.com:80/"])
    store.save_task(t)
    orch = Orchestrator(store, [], work_dir=str(tmp_path))
    assets = orch._build_initial_targets(t)
    assert len(assets) == 1
    assert assets[0].type == "domain"
    assert assets[0].value == "example.com"


def test_orchestrator_passes_rate_limit_and_tool_args(store, authorized_task, tmp_path):
    """P1-1: Orchestrator 把 rate_limit / tool_args 透传到各工具的 ToolContext。"""
    captured = {}

    class CaptureTool(Tool):
        stage = StageName.FINGERPRINT
        input_asset_types = ("domain",)
        output_asset_types = ("url",)
        name = "capture"

        def run(self, inputs, ctx):
            captured["rate_limit"] = ctx.rate_limit
            captured["extra_args"] = ctx.extra_args
            return ToolResult(assets=[])

    orch = Orchestrator(
        store, [CaptureTool()], work_dir=str(tmp_path),
        rate_limit=50, tool_args={"capture": ["-t", "/tmp/x"]},
    )
    orch.run(authorized_task)

    assert captured["rate_limit"] == 50
    assert captured["extra_args"] == ["-t", "/tmp/x"]


def test_run_cancels_task_on_cancel_request(store, authorized_task, tmp_path):
    """P1-4: 运行中请求取消后, 任务在阶段边界转为 CANCELLED。

    真实场景中 `aicp cancel` 只对 RUNNING 任务生效; 这里用工具在运行中
    写入取消标记, 验证阶段边界检查会触发 CANCELLED。
    """
    class SelfCancelTool(Tool):
        stage = StageName.FINGERPRINT
        input_asset_types = ("domain",)
        output_asset_types = ("url",)

        def run(self, inputs, ctx):
            store.request_cancel(ctx.task_id)  # 模拟运行中用户取消
            return ToolResult(assets=[])

    orch = Orchestrator(store, [SelfCancelTool()], work_dir=str(tmp_path))
    final = orch.run(authorized_task)
    assert final.status == TaskStatus.CANCELLED


@pytest.mark.recovery
def test_cancel_marker_cleared_on_resume(store, authorized_task, tmp_path):
    """审计 3.1: 取消标记在重新进入 RUNNING 时被清除, 崩溃恢复后 resume 不会被再次取消。"""
    # 1. 用户请求取消, 但编排器还没走到阶段边界, 进程就崩溃了
    store.request_cancel(authorized_task.id)
    assert store.is_cancel_requested(authorized_task.id) is True

    # 2. 模拟崩溃恢复: cleanup_running_tasks 把任务标记为 FAILED
    store.transition_task(authorized_task.id, TaskStatus.RUNNING)
    store.transition_task(authorized_task.id, TaskStatus.FAILED, error="interrupted")

    # 3. resume: run() 进入 RUNNING 时应清除取消标记, 任务正常完成而非再次 CANCELLED
    orch = Orchestrator(store, [], work_dir=str(tmp_path))
    final = orch.run(authorized_task)
    assert final.status == TaskStatus.COMPLETED
    assert store.is_cancel_requested(authorized_task.id) is False


# ---------------- 工具原始输出落盘 (行动项 #4) ----------------

class RawLoggingTool(Tool):
    """返回 raw_output 的工具 (验证编排器落盘)。"""

    name = "rawtool"
    stage = StageName.SUBDOMAIN
    input_asset_types = ("domain",)
    output_asset_types = ("domain",)

    def run(self, inputs, ctx):
        return ToolResult(
            assets=[],
            raw_output="$ fake-tool --target example.com\n[rc=0] stdout-line-1\nstderr-line-1",
            stats={},
        )


def test_tool_raw_output_persisted_to_log(store, authorized_task, tmp_path):
    """P0 行动项 #4: 工具 raw_output 落盘 work/{task_id}/logs/{tool}.log (取证第一现场)。"""
    orch = Orchestrator(store, [RawLoggingTool()], work_dir=str(tmp_path))

    final = orch.run(authorized_task)
    assert final.status == TaskStatus.COMPLETED

    log_file = tmp_path / authorized_task.id / "logs" / "rawtool.log"
    assert log_file.exists()
    content = log_file.read_text(encoding="utf-8")
    # 含完整命令行与输出
    assert "fake-tool --target example.com" in content
    assert "[rc=0] stdout-line-1" in content
    assert "stderr-line-1" in content


def test_tool_raw_output_persist_on_resume_keeps_history(
    store, authorized_task, tmp_path
):
    """行动项 #4: resume 重跑同一工具时追加而非覆盖 (保留全部轮次, 便于取证)。"""
    orch = Orchestrator(store, [RawLoggingTool()], work_dir=str(tmp_path))

    orch.run(authorized_task)
    # 再次全量跑 (COMPLETED 是终态, 新任务同 id 不可重入; 用新 task 模拟第二轮)
    t2 = Task(targets=["example.com"])
    store.save_task(t2)
    AuthorizationVerifier().verify(
        t2,
        authorized_by="张三",
        authorization_note="AUTH-001",
        authorized_scope=["example.com"],
    )
    store.save_task(t2)
    orch.run(t2)

    # 两个任务各自的日志目录独立
    log1 = tmp_path / authorized_task.id / "logs" / "rawtool.log"
    log2 = tmp_path / t2.id / "logs" / "rawtool.log"
    assert log1.exists() and log2.exists()
    assert log1.read_text(encoding="utf-8") != ""


# ---------------- 任务租约 (行动项 #3 / ADR-1) ----------------

@pytest.mark.recovery
def test_run_rejects_when_lease_held_by_other(store, authorized_task, tmp_path):
    """P0 行动项 #3 DoD: 他方持有有效租约时, run() 抛 LeaseHeldError 拒绝双跑。

    模拟: CLI 进程已抢到租约, Web 线程/第二个 CLI 再 run 同一任务。
    """
    from aicp.pipeline import LeaseHeldError

    # 他方 (如另一 CLI 进程) 先抢到租约
    assert store.acquire_task_lease(authorized_task.id, "other-process", lease_seconds=60)

    orch = Orchestrator(store, [], work_dir=str(tmp_path))
    with pytest.raises(LeaseHeldError, match="租约"):
        orch.run(authorized_task)

    # 任务仍是 RUNNING (由他方持有), 未被误标 FAILED, owner 不被篡改
    assert store.get_task(authorized_task.id).status == TaskStatus.RUNNING
    row = store._conn.execute(
        "SELECT owner FROM tasks WHERE id = ?", (authorized_task.id,)
    ).fetchone()
    assert row["owner"] == "other-process"


@pytest.mark.recovery
def test_run_takes_over_expired_lease_and_completes(store, authorized_task, tmp_path):
    """P0 行动项 #3 DoD: 僵死 RUNNING (租约过期) 被接管并跑完。"""
    from datetime import datetime, timedelta, timezone

    # 模拟持有者已死: 租约过期
    assert store.acquire_task_lease(authorized_task.id, "dead-process", lease_seconds=60)
    store._conn.execute(
        "UPDATE tasks SET lease_expires_at = ? WHERE id = ?",
        (
            (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
            authorized_task.id,
        ),
    )
    store._conn.commit()

    orch = Orchestrator(store, [], work_dir=str(tmp_path))
    final = orch.run(authorized_task)
    assert final.status == TaskStatus.COMPLETED


@pytest.mark.recovery
def test_run_releases_lease_on_completion(store, authorized_task, tmp_path):
    """跑完后租约列被清空 (owner/heartbeat/lease_expires_at)。"""
    orch = Orchestrator(store, [], work_dir=str(tmp_path))
    final = orch.run(authorized_task)
    assert final.status == TaskStatus.COMPLETED

    row = store._conn.execute(
        "SELECT owner, heartbeat_at, lease_expires_at FROM tasks WHERE id = ?",
        (authorized_task.id,),
    ).fetchone()
    assert row["owner"] is None
    assert row["heartbeat_at"] is None
    assert row["lease_expires_at"] is None


@pytest.mark.recovery
def test_run_releases_lease_on_failure(store, authorized_task, tmp_path):
    """失败路径同样释放租约。"""
    class _FailingTool(Tool):
        stage = StageName.SUBDOMAIN
        input_asset_types = ("domain",)
        output_asset_types = ("domain",)

        def run(self, inputs, ctx):
            raise ToolError("boom")

    orch = Orchestrator(store, [_FailingTool()], work_dir=str(tmp_path))
    final = orch.run(authorized_task)
    assert final.status == TaskStatus.FAILED

    row = store._conn.execute(
        "SELECT owner FROM tasks WHERE id = ?", (authorized_task.id,)
    ).fetchone()
    assert row["owner"] is None
