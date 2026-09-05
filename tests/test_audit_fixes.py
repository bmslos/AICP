"""审查修复的回归测试。"""

from __future__ import annotations

from pathlib import Path


from aicp.auth import AuthorizationVerifier
from aicp.models import Asset, Stage, StageName, StageStatus, Task, TaskStatus
from aicp.scheduler import Store
from aicp.tools import ToolContext


# ---------------- 修复 2.1: save_asset 合并指纹 ----------------

def test_save_asset_merges_web_service_technologies(store):
    """同 (task,type,value,source) 的 web_service 重跑时, technologies 取并集。"""
    t = Task(targets=["example.com"])
    store.save_task(t)

    # 第一次: Wappalyzer 发现 Nginx
    a1 = Asset(type="web_service", value="http://example.com:80",
               source="wappalyzer", task_id=t.id, technologies=["Nginx"])
    assert store.save_asset(a1) is True  # 新增

    # 第二次: 同 source 重跑, 发现 Nginx + PHP
    a2 = Asset(type="web_service", value="http://example.com:80",
               source="wappalyzer", task_id=t.id, technologies=["Nginx", "PHP"])
    assert store.save_asset(a2) is False  # 已存在, 合并

    assets = store.list_assets(t.id)
    ws = next(a for a in assets if a.type == "web_service")
    assert set(ws.technologies) == {"Nginx", "PHP"}


def test_save_asset_keeps_first_status_code(store):
    """合并时 status_code 取首次非空。"""
    t = Task(targets=["example.com"])
    store.save_task(t)

    a1 = Asset(type="web_service", value="http://example.com",
               source="httpx", task_id=t.id, status_code=200, title="Old")
    store.save_asset(a1)
    a2 = Asset(type="web_service", value="http://example.com",
               source="httpx", task_id=t.id, status_code=500, title="New")
    store.save_asset(a2)

    assets = store.list_assets(t.id)
    ws = next(a for a in assets if a.type == "web_service")
    assert ws.status_code == 200  # 保留首次
    assert ws.title == "Old"


# ---------------- 修复 1.1: FAILED->RUNNING 清空 finished_at/error ----------------

def test_resume_clears_task_finished_at_and_error(store):
    """任务 FAILED -> RUNNING 时, finished_at 和 error 应被清空。"""
    t = Task(targets=["example.com"])
    AuthorizationVerifier().verify(
        t, authorized_by="x", authorization_note="x",
        authorized_scope=["example.com"],
    )
    store.save_task(t)
    store.transition_task(t.id, TaskStatus.RUNNING)
    store.transition_task(t.id, TaskStatus.FAILED, error="portscan failed")

    t = store.get_task(t.id)
    assert t.finished_at is not None
    assert t.error == "portscan failed"

    # 恢复
    store.transition_task(t.id, TaskStatus.RUNNING)
    t = store.get_task(t.id)
    assert t.status == TaskStatus.RUNNING
    assert t.finished_at is None  # 清空
    assert t.error is None        # 清空
    assert t.started_at is not None  # 保留首次启动时间


# ---------------- 修复 1.2: 阶段 FAILED->RUNNING 清空 finished_at ----------------

def test_resume_clears_stage_finished_at(store):
    """阶段 FAILED -> RUNNING 时, finished_at 应被清空, 避免时间戳倒置。"""
    t = Task(targets=["example.com"])
    AuthorizationVerifier().verify(
        t, authorized_by="x", authorization_note="x",
        authorized_scope=["example.com"],
    )
    store.save_task(t)
    store.init_stage(Stage(task_id=t.id, name=StageName.PORTSCAN))
    store.transition_stage(t.id, StageName.PORTSCAN, StageStatus.RUNNING)
    store.transition_stage(t.id, StageName.PORTSCAN, StageStatus.FAILED, error="mock")

    s = store.get_stage(t.id, StageName.PORTSCAN)
    assert s.finished_at is not None
    assert s.error == "mock"

    # 恢复
    store.transition_stage(t.id, StageName.PORTSCAN, StageStatus.RUNNING)
    s = store.get_stage(t.id, StageName.PORTSCAN)
    assert s.status == StageStatus.RUNNING
    assert s.finished_at is None  # 清空
    assert s.error is None
    assert s.attempt == 2  # 重试计数


# ---------------- 修复 2.2: merger domain 去重 ----------------

def test_merger_deduplicates_domains():
    """同域名不同来源 (user_input + oneforall) 应合并为一个 domain 节点。"""
    from aicp.correlate import merge_assets

    task_id = "test-task-id-0001"
    assets = [
        Asset(type="domain", value="example.com", source="user_input", task_id=task_id),
        Asset(type="domain", value="example.com", source="oneforall", task_id=task_id),
        Asset(type="domain", value="sub.example.com", source="oneforall", task_id=task_id),
    ]
    graph = merge_assets(assets)
    # 应只有 2 个 domain 节点 (example.com 合并 + sub.example.com)
    assert len(graph.domains) == 2
    domain_values = [d.domain for d in graph.domains]
    assert "example.com" in domain_values
    assert "sub.example.com" in domain_values


# ---------------- 修复 8.1: Nmap 范围外 IP 过滤 ----------------

def test_nmap_filters_out_of_scope_ips(tmp_path):
    """Nmap 解析出的 IP 若不在授权范围内, 应被过滤掉。"""
    from aicp.tools.nmap import NmapTool
    from aicp.tools.base import CompletedProcess

    # 构造一个 mock nmap XML, 包含 2 个 IP (1 个在 scope, 1 个不在)
    xml_content = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="1.2.3.4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="9.9.9.9"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    def mock_runner(cmd, work_dir):
        # 模拟 nmap 退出码 0, 并把 XML 写到 -oX 指定的路径
        # (P0-2 起 run() 会先删旧输出文件, 不能依赖预置文件)
        idx = cmd.index("-oX")
        Path(cmd[idx + 1]).write_text(xml_content, encoding="utf-8")
        return CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    tool = NmapTool(runner=mock_runner)
    inputs = [Asset(type="domain", value="example.com", source="user_input",
                    task_id="test")]
    ctx = ToolContext(
        task_id="test",
        authorized_scope=["example.com", "1.2.3.4"],  # 9.9.9.9 不在范围
        work_dir=str(tmp_path),
    )
    # NmapTool 用 f"nmap_{ctx.task_id}.xml" = nmap_test.xml, 由 mock_runner 写入
    result = tool.run(inputs, ctx)

    # 应只保留 1.2.3.4, 过滤掉 9.9.9.9
    ips = [a.value for a in result.assets if a.type == "ip"]
    assert "1.2.3.4" in ips
    assert "9.9.9.9" not in ips
    # port 也应只保留 1.2.3.4:80
    ports = [a.value for a in result.assets if a.type == "port"]
    assert "1.2.3.4:80" in ports
    assert "9.9.9.9:22" not in ports
    # 统计
    assert result.stats["ips_out_of_scope"] == 1


# ---------------- 修复 H1: Web task_id 路径遍历 ----------------

def test_web_rejects_path_traversal_task_id(tmp_path):
    """Web 路由拒绝非 UUID 格式的 task_id, 防止路径遍历。"""
    from aicp.web import create_app

    app = create_app(
        db_path=str(tmp_path / "test.db"),
        work_dir=str(tmp_path / "work"),
        report_dir=str(tmp_path / "reports"),
        tools_factory=lambda: [],
    )
    app.config["TESTING"] = True
    client = app.test_client()

    # 含路径遍历字符的 task_id 应返回 404
    r = client.get("/tasks/..%5C..%5Cetc%5Cpasswd")
    assert r.status_code == 404

    r = client.get("/tasks/../etc/passwd/report")
    assert r.status_code == 404

    r = client.get("/tasks/invalid-id/report.json")
    assert r.status_code == 404

    # 合法 UUID hex 格式应通过校验 (但任务不存在仍 404)
    r = client.get("/tasks/0123456789abcdef0123456789abcdef")
    assert r.status_code == 404  # 任务不存在


# ---------------- 修复 C4: SQLite WAL + busy_timeout ----------------

def test_store_enables_wal_and_busy_timeout(tmp_path):
    """Store 应启用 WAL 模式和 busy_timeout。"""
    db = tmp_path / "test.db"
    with Store(db) as store:
        journal = store._conn.execute("PRAGMA journal_mode").fetchone()[0]
        busy = store._conn.execute("PRAGMA busy_timeout").fetchone()[0]
        assert journal.lower() == "wal"
        assert busy == 30000
