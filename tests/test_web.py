"""Web 前端单元测试。

测试策略:
- 用 Flask test_client 调用各路由
- monkeypatch TaskRunner 的 tools_factory 返回 mock 工具
- 不依赖真实外部工具
"""

from __future__ import annotations

import json
import time
from typing import List

import pytest

from aicp.auth import AuthorizationVerifier
from aicp.models import Asset, StageName, Task, TaskStatus
from aicp.pipeline import Orchestrator
from aicp.scheduler import Store
from aicp.tools import Tool, ToolContext, ToolResult
from aicp.web import create_app


# ---------------- mock 工具 ----------------

class FakeSubdomainTool(Tool):
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
    stage = StageName.PORTSCAN
    input_asset_types = ("domain", "ip")
    output_asset_types = ("ip", "port")

    def run(self, inputs: List[Asset], ctx: ToolContext) -> ToolResult:
        assets: List[Asset] = []
        for a in inputs:
            if a.type == "domain":
                ip = "1.2.3.4"
                assets.append(Asset(type="ip", value=ip, source="fake",
                                    task_id=ctx.task_id))
                assets.append(Asset(type="port", value=f"{ip}:80", source="fake",
                                    task_id=ctx.task_id, raw={"ip": ip, "port": 80}))
        return ToolResult(assets=assets, stats={"produced": len(assets)})


class FakeFingerprintTool(Tool):
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


def _fake_tools_factory():
    return [FakeSubdomainTool(), FakePortscanTool(), FakeFingerprintTool()]


# ---------------- 公共夹具 ----------------

@pytest.fixture
def web_app(tmp_path):
    """构造测试用 Flask app (用 mock 工具)。"""
    db = tmp_path / "test.db"
    work_dir = tmp_path / "work"
    report_dir = tmp_path / "reports"
    work_dir.mkdir()
    report_dir.mkdir()
    app = create_app(
        db_path=str(db),
        work_dir=str(work_dir),
        report_dir=str(report_dir),
        tools_factory=_fake_tools_factory,
    )
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(web_app):
    """模拟前端 JS 行为的客户端: POST 自动附 X-CSRF-Token (行动项 #1)。

    未启用认证时 Web 同样强制 CSRF 校验, 真实前端 JS 会先拉取 /csrf-token
    再提交表单; 本夹具等价模拟该行为。需要验证 CSRF 拦截本身的用例
    直接用 `web_app.test_client()` 裸客户端。
    """
    base = web_app.test_client()

    class _CsrfAutoClient:
        def post(self, *args, **kwargs):
            headers = dict(kwargs.pop("headers", None) or {})
            headers.setdefault(
                "X-CSRF-Token", web_app.config["AICP_CSRF_TOKEN"]
            )
            return base.post(*args, headers=headers, **kwargs)

        def __getattr__(self, name):
            return getattr(base, name)

    return _CsrfAutoClient()


@pytest.fixture
def sample_task(web_app):
    """在 db 里构造一个已授权任务 (不执行)。"""
    db_path = web_app.config["AICP_DB"]
    t = Task(targets=["example.com"])
    with Store(db_path) as store:
        AuthorizationVerifier().verify(
            t, authorized_by="张三", authorization_note="AUTH-001",
            authorized_scope=["example.com", "1.2.3.4"],
        )
        store.save_task(t)
    return t.id


@pytest.fixture
def completed_task(web_app, sample_task):
    """构造一个已执行完成的任务 (用 mock 工具同步跑)。"""
    db_path = web_app.config["AICP_DB"]
    work_dir = web_app.config["AICP_WORK_DIR"]
    with Store(db_path) as store:
        task = store.get_task(sample_task)
        tools = _fake_tools_factory()
        orch = Orchestrator(store, tools, work_dir=work_dir)
        task = orch.run(task)
    return task.id


# ---------------- 首页 / 任务列表 ----------------

def test_index_empty(client):
    """无任务时首页显示提示。"""
    r = client.get("/")
    assert r.status_code == 200
    assert b"\xe6\x9a\x82\xe6\x97\xa0\xe4\xbb\xbb\xe5\x8a\xa1" in r.data  # "暂无任务"


def test_index_shows_tasks(client, completed_task):
    """首页列出已完成的任务。"""
    r = client.get("/")
    assert r.status_code == 200
    data = r.data.decode("utf-8")
    assert "example.com" in data
    assert "completed" in data
    assert "张三" in data


# ---------------- 任务详情 ----------------

def test_task_detail_not_found(client):
    """不存在的任务返回 404。"""
    r = client.get("/tasks/nonexistent")
    assert r.status_code == 404


def test_task_detail_shows_info(client, completed_task):
    """详情页显示任务信息 + 阶段 + 资产。"""
    r = client.get(f"/tasks/{completed_task}")
    assert r.status_code == 200
    data = r.data.decode("utf-8")
    assert completed_task in data
    assert "example.com" in data
    assert "张三" in data
    assert "AUTH-001" in data
    # 4 个阶段
    assert "subdomain" in data
    assert "portscan" in data
    assert "fingerprint" in data
    assert "correlate" in data
    # 资产统计
    assert "Nginx" in data


def test_task_detail_resume_button_for_failed(client, web_app, sample_task):
    """FAILED 任务显示恢复按钮。"""
    db_path = web_app.config["AICP_DB"]
    with Store(db_path) as store:
        # 把任务改为 FAILED
        store.transition_task(sample_task, TaskStatus.RUNNING)
        store.transition_task(sample_task, TaskStatus.FAILED, error="mock")
    r = client.get(f"/tasks/{sample_task}")
    data = r.data.decode("utf-8")
    assert "恢复执行" in data


def test_task_detail_no_resume_for_completed(client, completed_task):
    """COMPLETED 任务不显示恢复按钮。"""
    r = client.get(f"/tasks/{completed_task}")
    data = r.data.decode("utf-8")
    assert "恢复执行" not in data


# ---------------- 创建任务 ----------------

def test_scan_form_get(client):
    """GET /scan 返回表单。"""
    r = client.get("/scan")
    assert r.status_code == 200
    data = r.data.decode("utf-8")
    assert "新建任务" in data
    assert "授权人" in data
    assert "授权范围" in data


def test_scan_submit_creates_task(client, web_app):
    """POST /scan 创建任务并重定向到详情。"""
    r = client.post("/scan", data={
        "targets": "example.com",
        "authorized_by": "测试人",
        "authorization_note": "TEST-001",
        "scope": "example.com",
    }, follow_redirects=False)
    assert r.status_code == 302  # 重定向
    assert "/tasks/" in r.headers["Location"]

    # 任务应在 db 中
    db_path = web_app.config["AICP_DB"]
    with Store(db_path) as store:
        tasks = store.list_tasks()
        assert len(tasks) == 1
        assert tasks[0].authorized_by == "测试人"
        assert tasks[0].status in (TaskStatus.AUTHORIZED, TaskStatus.RUNNING, TaskStatus.COMPLETED)


def test_scan_submit_validation_errors(client):
    """缺字段时返回 400 + 错误提示。"""
    # 缺目标
    r = client.post("/scan", data={
        "authorized_by": "x", "authorization_note": "x", "scope": "x",
    })
    assert r.status_code == 400
    assert "目标不能为空" in r.data.decode("utf-8")

    # 缺授权人
    r = client.post("/scan", data={
        "targets": "x", "authorization_note": "x", "scope": "x",
    })
    assert r.status_code == 400
    assert "授权人不能为空" in r.data.decode("utf-8")


def test_scan_submit_target_out_of_scope(client):
    """目标不在 scope 内返回 400。"""
    r = client.post("/scan", data={
        "targets": "evil.com",
        "authorized_by": "x",
        "authorization_note": "x",
        "scope": "example.com",
    })
    assert r.status_code == 400
    assert "授权校验失败" in r.data.decode("utf-8")


def test_scan_submit_starts_background_thread(client, web_app):
    """提交任务后后台线程应启动并最终完成。"""
    r = client.post("/scan", data={
        "targets": "example.com",
        "authorized_by": "异步测试",
        "authorization_note": "E2E-ASYNC",
        "scope": "example.com",
        "scope_extra": "1.2.3.4",
    }, follow_redirects=False)
    assert r.status_code == 302
    task_id = r.headers["Location"].rsplit("/", 1)[-1]

    # 等待后台线程完成 (mock 工具应该很快)
    runner = web_app.config["AICP_RUNNER"]
    for _ in range(50):  # 最多等 5 秒
        if not runner.is_running(task_id):
            break
        time.sleep(0.1)

    db_path = web_app.config["AICP_DB"]
    with Store(db_path) as store:
        task = store.get_task(task_id)
        assert task is not None
        assert task.status == TaskStatus.COMPLETED
        assert task.authorized_by == "异步测试"


def test_scan_submit_multi_line_targets(client, web_app):
    """多行/逗号分隔的目标都能解析。"""
    r = client.post("/scan", data={
        "targets": "a.com\nb.com, c.com",
        "authorized_by": "x",
        "authorization_note": "x",
        "scope": "a.com\nb.com, c.com",
    }, follow_redirects=False)
    assert r.status_code == 302
    task_id = r.headers["Location"].rsplit("/", 1)[-1]

    db_path = web_app.config["AICP_DB"]
    with Store(db_path) as store:
        task = store.get_task(task_id)
        assert task.targets == ["a.com", "b.com", "c.com"]


# ---------------- resume ----------------

def test_resume_failed_task(client, web_app, sample_task):
    """POST /tasks/<id>/resume 恢复失败任务。"""
    db_path = web_app.config["AICP_DB"]
    with Store(db_path) as store:
        store.transition_task(sample_task, TaskStatus.RUNNING)
        store.transition_task(sample_task, TaskStatus.FAILED, error="mock")

    r = client.post(f"/tasks/{sample_task}/resume", follow_redirects=False)
    assert r.status_code == 302

    # 等后台完成
    runner = web_app.config["AICP_RUNNER"]
    for _ in range(50):
        if not runner.is_running(sample_task):
            break
        time.sleep(0.1)

    with Store(db_path) as store:
        task = store.get_task(sample_task)
        assert task.status == TaskStatus.COMPLETED


def test_resume_completed_task_rejected(client, completed_task):
    """恢复已完成任务返回 400。"""
    r = client.post(f"/tasks/{completed_task}/resume")
    assert r.status_code == 400
    assert "不可恢复" in r.data.decode("utf-8")


def test_resume_not_found(client):
    """恢复不存在的任务返回 404。"""
    r = client.post("/tasks/nonexistent/resume")
    assert r.status_code == 404


@pytest.mark.recovery
def test_web_resume_running_task_when_not_actually_running(client, web_app, sample_task):
    """卡 RUNNING 但后台线程不在跑时, resume 应允许 (返回 302, 不是 400/409)。"""
    db_path = web_app.config["AICP_DB"]
    with Store(db_path) as store:
        # AUTHORIZED -> RUNNING, 模拟线程崩溃后任务卡在 RUNNING
        store.transition_task(sample_task, TaskStatus.RUNNING)

    # runner 上没有该任务的线程, is_running 自然返回 False, 无需 mock
    r = client.post(f"/tasks/{sample_task}/resume", follow_redirects=False)
    assert r.status_code == 302

    # 等后台线程完成 (mock 工具应该很快)
    runner = web_app.config["AICP_RUNNER"]
    for _ in range(50):
        if not runner.is_running(sample_task):
            break
        time.sleep(0.1)

    with Store(db_path) as store:
        task = store.get_task(sample_task)
        assert task.status == TaskStatus.COMPLETED


def test_web_resume_running_task_when_actually_running(client, web_app, sample_task, monkeypatch):
    """RUNNING 任务且后台线程确实在跑时, resume 应返回 409 Conflict。"""
    db_path = web_app.config["AICP_DB"]
    with Store(db_path) as store:
        store.transition_task(sample_task, TaskStatus.RUNNING)

    # mock runner.is_running 返回 True, 模拟线程仍在跑
    runner = web_app.config["AICP_RUNNER"]
    monkeypatch.setattr(runner, "is_running", lambda task_id: True)

    r = client.post(f"/tasks/{sample_task}/resume")
    assert r.status_code == 409
    assert "任务正在运行中" in r.get_json()["error"]


@pytest.mark.recovery
def test_web_resume_rejected_when_lease_held_by_other_process(client, web_app, sample_task):
    """P0 行动项 #3 DoD: 他方进程 (如 CLI) 持有有效租约时 resume 返回 409。

    本进程无该任务的线程 (runner.is_running=False), 但租约有效 ——
    旧实现会放行导致双跑, 现由 Store 级租约拦截。
    """
    db_path = web_app.config["AICP_DB"]
    with Store(db_path) as store:
        # 模拟 CLI 进程抢到租约 (任务 RUNNING + 有效租约)
        assert store.acquire_task_lease(sample_task, "cli-process", lease_seconds=3600)

    r = client.post(f"/tasks/{sample_task}/resume", follow_redirects=False)
    assert r.status_code == 409
    assert "任务正在运行中" in r.get_json()["error"]
    # 任务保持 RUNNING, 未被 Web 侧误标
    with Store(db_path) as store:
        assert store.get_task(sample_task).status == TaskStatus.RUNNING


# ---------------- cancel (P1-4) ----------------

def test_web_cancel_running_task(client, web_app, sample_task):
    """POST /tasks/<id>/cancel 对 RUNNING 任务写入取消请求, 并重定向回详情页。"""
    db_path = web_app.config["AICP_DB"]
    with Store(db_path) as store:
        store.transition_task(sample_task, TaskStatus.RUNNING)

    r = client.post(f"/tasks/{sample_task}/cancel")
    assert r.status_code == 302
    assert f"/tasks/{sample_task}" in r.headers["Location"]

    with Store(db_path) as store:
        assert store.is_cancel_requested(sample_task) is True


def test_web_cancel_non_running_redirects(client, web_app, sample_task):
    """非 RUNNING 任务取消也重定向回详情页 (与 resume 按钮行为一致, 审计 4.1)。"""
    r = client.post(f"/tasks/{sample_task}/cancel")
    assert r.status_code == 302
    assert f"/tasks/{sample_task}" in r.headers["Location"]


def test_web_cancel_not_found(client):
    """取消不存在的任务返回 404。"""
    r = client.post("/tasks/nonexistent/cancel")
    assert r.status_code == 404


# ---------------- 报告 ----------------

def test_view_html_report(client, completed_task):
    """GET /tasks/<id>/report 返回 HTML 报告。"""
    r = client.get(f"/tasks/{completed_task}/report")
    assert r.status_code == 200
    assert r.mimetype == "text/html"
    data = r.data.decode("utf-8")
    assert "<!DOCTYPE html>" in data
    assert "Cloudflare" not in data  # mock 工具产出 Nginx 不是 Cloudflare
    assert "Nginx" in data  # mock 工具的指纹


def test_view_html_report_not_found(client):
    """不存在的任务报告返回 404。"""
    r = client.get("/tasks/nonexistent/report")
    assert r.status_code == 404


def test_download_json_report(client, completed_task):
    """GET /tasks/<id>/report.json 下载 JSON。"""
    r = client.get(f"/tasks/{completed_task}/report.json")
    assert r.status_code == 200
    assert r.mimetype == "application/json"
    data = json.loads(r.data)
    assert data["task"]["id"] == completed_task
    assert data["task"]["authorized_by"] == "张三"


def test_download_markdown_report(client, completed_task):
    """GET /tasks/<id>/report.md 下载 Markdown。"""
    r = client.get(f"/tasks/{completed_task}/report.md")
    assert r.status_code == 200
    assert r.mimetype == "text/markdown"
    # 应作为附件下载
    assert r.headers.get("Content-Disposition", "").startswith("attachment;")
    content = r.data.decode("utf-8")
    assert "# AICP 资产报告" in content
    assert "## 任务信息" in content
    # 授权信息应出现在报告中
    assert "张三" in content
    assert completed_task in content


def test_download_markdown_report_not_found(client):
    """不存在的任务 Markdown 报告返回 404。"""
    r = client.get("/tasks/nonexistent/report.md")
    assert r.status_code == 404


def test_download_markdown_report_path_traversal_rejected(client):
    """task_id 不合法 (非 UUID hex) 时返回 404 (路径遍历防护)。"""
    r = client.get("/tasks/../../etc/passwd/report.md")
    # Flask 会规范化路径, 但 _check_task_id 仍会拒绝非法 task_id
    assert r.status_code == 404


def test_download_markdown_report_caches_file(client, completed_task, web_app):
    """二次访问应复用已生成的 .md 文件, 不重新生成。"""
    # 第一次访问, 现场生成
    r1 = client.get(f"/tasks/{completed_task}/report.md")
    assert r1.status_code == 200
    # 验证文件已落盘
    from pathlib import Path
    report_dir = Path(web_app.config["AICP_REPORT_DIR"])
    md_file = report_dir / f"{completed_task}.md"
    assert md_file.exists()
    first_bytes = md_file.read_bytes()

    # 第二次访问 (文件已存在, 应直接复用, 字节应完全一致)
    r2 = client.get(f"/tasks/{completed_task}/report.md")
    assert r2.status_code == 200
    assert r2.data == first_bytes


# ---------------- API 状态轮询 ----------------

def test_api_task_status(client, completed_task):
    """GET /api/tasks/<id>/status 返回状态 JSON。"""
    r = client.get(f"/api/tasks/{completed_task}/status")
    assert r.status_code == 200
    data = r.get_json()
    assert data["task_id"] == completed_task
    assert data["status"] == "completed"
    assert data["is_running"] is False
    assert len(data["stages"]) == 6


def test_api_task_status_not_found(client):
    r = client.get("/api/tasks/nonexistent/status")
    assert r.status_code == 404


def test_api_task_status_while_running(client, web_app):
    """任务运行中 is_running 应为 True。"""
    r = client.post("/scan", data={
        "targets": "example.com",
        "authorized_by": "x", "authorization_note": "x",
        "scope": "example.com",
    }, follow_redirects=False)
    task_id = r.headers["Location"].rsplit("/", 1)[-1]

    # 立即查询 (可能运行中也可能已完成, 两种都接受)
    r = client.get(f"/api/tasks/{task_id}/status")
    assert r.status_code == 200
    data = r.get_json()
    assert "is_running" in data
    assert "status" in data


# ---------------- 认证 + CSRF ----------------

@pytest.fixture
def auth_web_app(tmp_path):
    """构造启用 auth_token 的 Flask app (用 mock 工具)。"""
    db = tmp_path / "test.db"
    work_dir = tmp_path / "work"
    report_dir = tmp_path / "reports"
    work_dir.mkdir()
    report_dir.mkdir()
    app = create_app(
        db_path=str(db),
        work_dir=str(work_dir),
        report_dir=str(report_dir),
        tools_factory=_fake_tools_factory,
        auth_token="secret123",
    )
    app.config["TESTING"] = True
    return app


@pytest.fixture
def auth_client(auth_web_app):
    return auth_web_app.test_client()


def test_web_no_auth_token_allows_anonymous(client):
    """未启用 auth_token 时, 匿名访问首页返回 200。"""
    r = client.get("/")
    assert r.status_code == 200


# ---------------- 健康探针 (行动项 #7) ----------------

def test_web_health_endpoint_returns_ok(client):
    """P0 行动项 #7 DoD: GET /health 返回 200。"""
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json() == {"status": "ok"}


def test_web_readyz_endpoint_returns_ready(client):
    """P0 行动项 #7 DoD: GET /readyz DB 可查询返回 200。"""
    r = client.get("/readyz")
    assert r.status_code == 200
    assert r.get_json() == {"status": "ready"}


@pytest.mark.recovery
def test_web_readyz_returns_503_when_db_broken(client, monkeypatch):
    """P0 行动项 #7: DB 故障时 /readyz 返回 503 (区分进程死与 DB 故障)。"""
    import sqlite3

    def _broken_store(db_path):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr("aicp.web.app.Store", _broken_store)
    r = client.get("/readyz")
    assert r.status_code == 503
    assert r.get_json()["status"] == "not_ready"


def test_web_health_endpoints_skip_auth(auth_client):
    """行动项 #7: 健康探针免认证 (外部拨测不带凭据)。"""
    r = auth_client.get("/health")
    assert r.status_code == 200
    r = auth_client.get("/readyz")
    assert r.status_code == 200


def test_web_auth_token_rejects_no_credentials(auth_client):
    """启用 auth_token 后, 不带凭据访问返回 401。"""
    r = auth_client.get("/")
    assert r.status_code == 401
    assert r.get_json() == {"error": "未授权"}


def test_web_auth_token_accepts_bearer_header(auth_client):
    """启用 auth_token 后, Authorization: Bearer 通过认证。"""
    r = auth_client.get(
        "/",
        headers={"Authorization": "Bearer secret123"},
    )
    assert r.status_code == 200


def test_web_auth_token_accepts_query_param(auth_client):
    """启用 auth_token 后, ?token= 查询参数通过认证。"""
    r = auth_client.get("/?token=secret123")
    assert r.status_code == 200


def test_web_auth_token_rejects_wrong_bearer(auth_client):
    """错误的 Bearer token 仍返回 401。"""
    r = auth_client.get(
        "/",
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert r.status_code == 401


def test_web_csrf_post_without_token_rejected(auth_client):
    """启用 auth_token 后, POST 不带 X-CSRF-Token 返回 403。"""
    r = auth_client.post(
        "/scan",
        headers={"Authorization": "Bearer secret123"},
        data={
            "targets": "example.com",
            "authorized_by": "测试人",
            "authorization_note": "TEST-001",
            "scope": "example.com",
        },
    )
    assert r.status_code == 403
    assert r.get_json() == {"error": "CSRF 校验失败"}


def test_web_csrf_post_with_token_accepted(auth_client, auth_web_app):
    """POST 带正确 auth + 正确 X-CSRF-Token 返回 302 (任务创建成功)。"""
    csrf_token = auth_web_app.config["AICP_CSRF_TOKEN"]
    r = auth_client.post(
        "/scan",
        headers={
            "Authorization": "Bearer secret123",
            "X-CSRF-Token": csrf_token,
        },
        data={
            "targets": "example.com",
            "authorized_by": "测试人",
            "authorization_note": "TEST-001",
            "scope": "example.com",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "/tasks/" in r.headers["Location"]

    # 任务应已写入 db
    db_path = auth_web_app.config["AICP_DB"]
    with Store(db_path) as store:
        tasks = store.list_tasks()
        assert len(tasks) == 1
        assert tasks[0].authorized_by == "测试人"


def test_web_csrf_post_with_wrong_token_rejected(auth_client):
    """POST 带错误 X-CSRF-Token 返回 403。"""
    r = auth_client.post(
        "/scan",
        headers={
            "Authorization": "Bearer secret123",
            "X-CSRF-Token": "wrong-csrf",
        },
        data={
            "targets": "example.com",
            "authorized_by": "测试人",
            "authorization_note": "TEST-001",
            "scope": "example.com",
        },
    )
    assert r.status_code == 403


def test_web_csrf_endpoint_returns_token(auth_client, auth_web_app):
    """带认证 GET /csrf-token 返回独立的 csrf_token (不等于 auth_token)。"""
    r = auth_client.get(
        "/csrf-token",
        headers={"Authorization": "Bearer secret123"},
    )
    assert r.status_code == 200
    csrf_token = r.get_json()["csrf_token"]
    # CSRF token 应为独立的随机值, 不等于 auth_token
    assert csrf_token is not None
    assert csrf_token != "secret123"
    assert csrf_token == auth_web_app.config["AICP_CSRF_TOKEN"]


def test_web_no_auth_csrf_endpoint_returns_token(client):
    """GET /csrf-token (未启用 auth_token) 返回有效 csrf_token (行动项 #1)。"""
    r = client.get("/csrf-token")
    assert r.status_code == 200
    csrf_token = r.get_json()["csrf_token"]
    assert csrf_token is not None


def test_web_no_auth_csrf_post_without_token_rejected(web_app):
    """P0 行动项 #1: 未启用 auth_token 时, POST 缺 X-CSRF-Token 同样被拒 (403)。

    攻击场景: 本机浏览器中的恶意网页跨站表单直接 POST /scan (无认证模式
    下旧实现完全放行), 以受害者机器为跳板对任意目标发起扫描。
    """
    raw = web_app.test_client()
    r = raw.post("/scan", data={
        "targets": "example.com",
        "authorized_by": "攻击者",
        "authorization_note": "CSRF-ATTACK",
        "scope": "example.com",
    })
    assert r.status_code == 403
    assert r.get_json() == {"error": "CSRF 校验失败"}


def test_web_no_auth_csrf_post_with_wrong_token_rejected(web_app):
    """P0 行动项 #1: 未启用认证时, 错误的 X-CSRF-Token 同样被拒。"""
    raw = web_app.test_client()
    r = raw.post(
        "/scan",
        headers={"X-CSRF-Token": "wrong-csrf"},
        data={
            "targets": "example.com",
            "authorized_by": "x",
            "authorization_note": "x",
            "scope": "example.com",
        },
    )
    assert r.status_code == 403


def test_web_no_auth_csrf_post_with_token_accepted(web_app):
    """P0 行动项 #1: 未启用认证时, 带正确 X-CSRF-Token 的 POST 正常通过。"""
    raw = web_app.test_client()
    csrf_token = raw.get("/csrf-token").get_json()["csrf_token"]
    r = raw.post(
        "/scan",
        headers={"X-CSRF-Token": csrf_token},
        data={
            "targets": "example.com",
            "authorized_by": "测试人",
            "authorization_note": "TEST-001",
            "scope": "example.com",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "/tasks/" in r.headers["Location"]


def test_web_csrf_token_endpoint_requires_auth(auth_client):
    """带认证才能访问 /csrf-token, 未认证返回 401。"""
    r = auth_client.get("/csrf-token")
    assert r.status_code == 401
    assert r.get_json() == {"error": "未授权"}


def test_web_auth_post_with_query_token_still_needs_csrf(auth_client):
    """用 ?token= 通过认证后, POST 仍需 X-CSRF-Token。"""
    r = auth_client.post(
        "/scan?token=secret123",
        data={
            "targets": "example.com",
            "authorized_by": "测试人",
            "authorization_note": "TEST-001",
            "scope": "example.com",
        },
    )
    assert r.status_code == 403


def test_web_auth_browser_flow(auth_client, auth_web_app):
    """模拟浏览器端完整流程 (修复 Bug #2): 前端 JS 用 URL 里的 ?token= 作为
    Authorization, 拉取独立 csrf_token 作为 X-CSRF-Token, POST 才能成功。"""
    # 1. 用户以 ?token=<auth_token> 访问页面 (JS 从此 URL 读取 auth token)
    r = auth_client.get("/?token=secret123")
    assert r.status_code == 200
    data = r.data.decode("utf-8")
    # 页面应内嵌认证/CSRF 前端脚本
    assert "getCsrfToken" in data
    assert "X-CSRF-Token" in data

    # 2. JS 带 Authorization(auth_token) 拉取 /csrf-token, 得到独立的 csrf_token
    r = auth_client.get("/csrf-token", headers={"Authorization": "Bearer secret123"})
    assert r.status_code == 200
    csrf_token = r.get_json()["csrf_token"]
    assert csrf_token is not None and csrf_token != "secret123"

    # 3. JS 提交表单: Authorization 用 auth_token, X-CSRF-Token 用 csrf_token
    r = auth_client.post(
        "/scan",
        headers={
            "Authorization": "Bearer secret123",
            "X-CSRF-Token": csrf_token,
        },
        data={
            "targets": "example.com",
            "authorized_by": "测试人",
            "authorization_note": "TEST-001",
            "scope": "example.com",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302

    # 4. 重定向目标详情页, 带 ?token=<auth_token> 可正常访问
    task_id = r.headers["Location"].rsplit("/", 1)[-1]
    r = auth_client.get(f"/tasks/{task_id}?token=secret123")
    assert r.status_code == 200
