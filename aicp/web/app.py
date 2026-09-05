"""Flask Web 应用。

路由:
  GET  /                   任务列表
  GET  /tasks/<id>         任务详情 (含阶段、资产统计、JS 轮询状态)
  GET  /tasks/<id>/report  内嵌 HTML 报告 (iframe)
  GET  /tasks/<id>/report.json  下载 JSON 报告
  GET  /scan               创建任务表单
  POST /scan               提交任务 (后台线程执行, 重定向到详情)
  POST /tasks/<id>/resume  恢复任务 (后台线程执行)
  GET  /api/tasks/<id>/status  任务状态 JSON (前端轮询用)

设计:
- 复用 Store / Orchestrator / 报告生成器, 不重复实现;
- 模板用 Jinja2 服务端渲染, 不引入前端构建工具;
- 任务执行在后台线程 (TaskRunner), HTTP 请求立即返回;
- 任务详情页用 JS 轮询 /api/tasks/<id>/status, 状态变化时自动刷新。
"""

from __future__ import annotations

import re
import secrets
import tempfile
import os
from pathlib import Path
from typing import Optional

from flask import (
    Flask, abort, g, jsonify, redirect, render_template, request, send_file, url_for,
)

from ..auth import AuthorizationVerifier, AuthorizationError
from ..cli import _default_tools
from ..models import Task, TaskStatus
from ..scheduler import Store
from .runner import TaskRunner


# task_id 安全校验: 必须是 32 位十六进制 (uuid4().hex), 防止路径遍历
_TASK_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def _check_task_id(task_id: str):
    """校验 task_id 格式, 非法则 404。"""
    if not _TASK_ID_RE.match(task_id):
        abort(404)


def create_app(
    db_path: str,
    work_dir: str,
    report_dir: str,
    tools_factory=None,
    auth_token: Optional[str] = None,
) -> Flask:
    """构造 Flask app。

    - db_path: SQLite 路径
    - work_dir: 工具工作目录
    - report_dir: 报告输出目录
    - tools_factory: 无参 callable 返回 Tool 列表 (默认用 CLI 的 _default_tools)
    - auth_token: 可选 API 认证令牌; 设置后所有请求需带 Authorization Bearer
                  或 ?token= 查询参数, 且 POST 请求需带 X-CSRF-Token 头
    """
    template_dir = Path(__file__).parent / "templates"
    static_dir = Path(__file__).parent / "static"
    app = Flask(
        __name__,
        template_folder=str(template_dir),
        static_folder=str(static_dir),
    )

    if tools_factory is None:
        def _factory():
            return _default_tools(work_dir)
        tools_factory = _factory

    runner = TaskRunner(db_path, work_dir, tools_factory)

    # 生成独立的 CSRF token (与 auth_token 分离, 防攻击者用 auth_token 伪造 CSRF)。
    # 未启用认证时也生成 (行动项 #1): 无认证模式下 POST 同样强制 CSRF 校验,
    # 封"本机浏览器恶意网页跨站 POST /scan, 以受害者机器为跳板发起扫描"。
    csrf_token = secrets.token_hex(32)

    # 存到 app.config 供视图函数访问
    app.config["AICP_DB"] = db_path
    app.config["AICP_WORK_DIR"] = work_dir
    app.config["AICP_REPORT_DIR"] = report_dir
    app.config["AICP_RUNNER"] = runner
    app.config["AICP_AUTH_TOKEN"] = auth_token
    app.config["AICP_CSRF_TOKEN"] = csrf_token

    # ---------------- 请求级 Store 连接管理 (避免每请求新建连接) ----------------

    def get_store() -> Store:
        """获取当前请求的 Store 实例 (懒初始化, 请求内复用)。"""
        if "_aicp_store" not in g:
            g._aicp_store = Store(db_path)
        return g._aicp_store

    @app.teardown_appcontext
    def _close_store(exc):
        """请求结束时关闭 Store 连接。"""
        store = g.pop("_aicp_store", None)
        if store is not None:
            store.close()

    # ---------------- 认证 + CSRF 钩子 ----------------

    @app.before_request
    def _check_auth():
        """认证校验 (启用时) + POST 强制 CSRF 校验 (无论是否启用认证)。"""
        # 健康探针免认证 (行动项 #7): 外部拨测不带凭据, 只暴露存活/就绪
        if request.path in ("/health", "/readyz"):
            return None
        if auth_token is not None:
            # 1) 认证校验: Authorization: Bearer <token> 或 ?token=<token>
            token = None
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
            if not token:
                token = request.args.get("token")
            if token != auth_token:
                return jsonify({"error": "未授权"}), 401
        # 2) CSRF 校验: POST 请求需带 X-CSRF-Token 头等于独立的 csrf_token
        #    (行动项 #1: 未启用认证时同样强制, 攻击页受同源策略限制拿不到 token)
        if request.method == "POST":
            req_csrf = request.headers.get("X-CSRF-Token")
            if req_csrf != csrf_token:
                return jsonify({"error": "CSRF 校验失败"}), 403
        return None

    @app.route("/csrf-token", methods=["GET"])
    def get_csrf_token():
        """返回 CSRF token (供前端使用)。

        未启用认证时同样返回有效 csrf_token (行动项 #1): POST 强制 CSRF 后,
        前端需匿名拉取; 攻击页受浏览器同源策略限制无法读取本响应。
        启用认证时此端点需先通过认证 (由 before_request 统一校验)。
        """
        return jsonify({"csrf_token": csrf_token})

    # ---------------- 健康探针 (行动项 #7, 免认证) ----------------

    @app.route("/health")
    def health():
        """进程存活探针: 外部拨测 (uptime-kuma 类) 用, 与 DB 状态解耦。"""
        return jsonify({"status": "ok"})

    @app.route("/readyz")
    def readyz():
        """就绪探针: DB 可查询才 200 (区分"进程死"与"DB 故障"两种失明)。"""
        try:
            store = get_store()
            store._conn.execute("SELECT 1").fetchone()
        except Exception as e:
            return jsonify({"status": "not_ready", "error": str(e)}), 503
        return jsonify({"status": "ready"})

    # ---------------- 路由 ----------------

    @app.route("/")
    def index():
        store = get_store()
        tasks = store.list_tasks()
        return render_template("index.html", tasks=tasks)

    @app.route("/tasks/<task_id>")
    def task_detail(task_id: str):
        _check_task_id(task_id)
        store = get_store()
        task = store.get_task(task_id)
        if task is None:
            abort(404)
        stages = store.list_stages(task_id)
        assets = store.list_assets(task_id)
        audit = store.list_audit(task_id)
        is_running = runner.is_running(task_id)
        return render_template(
            "task_detail.html",
            task=task, stages=stages, assets=assets, audit=audit,
            is_running=is_running,
        )

    @app.route("/tasks/<task_id>/report")
    def view_html_report(task_id: str):
        """内嵌 HTML 报告 (直接返回文件内容, 浏览器渲染)。"""
        _check_task_id(task_id)
        report_file = Path(report_dir) / f"{task_id}.html"
        if not report_file.exists():
            # 现场生成 (原子写入: 先写临时文件再 rename, 避免并发请求损坏报告)
            store = get_store()
            task = store.get_task(task_id)
            if task is None:
                abort(404)
            from ..report.html import write_html_report
            _atomic_report_write(
                lambda p: write_html_report(task, store, p),
                report_file,
            )
        return send_file(str(report_file), mimetype="text/html")

    @app.route("/tasks/<task_id>/report.json")
    def download_json_report(task_id: str):
        _check_task_id(task_id)
        report_file = Path(report_dir) / f"{task_id}.json"
        if not report_file.exists():
            store = get_store()
            task = store.get_task(task_id)
            if task is None:
                abort(404)
            from ..report.json_report import write_json_report
            _atomic_report_write(
                lambda p: write_json_report(task, store, p),
                report_file,
            )
        return send_file(
            str(report_file), mimetype="application/json", as_attachment=True,
            download_name=f"{task_id}.json",
        )

    @app.route("/tasks/<task_id>/report.md")
    def download_markdown_report(task_id: str):
        _check_task_id(task_id)
        report_file = Path(report_dir) / f"{task_id}.md"
        if not report_file.exists():
            store = get_store()
            task = store.get_task(task_id)
            if task is None:
                abort(404)
            from ..report.markdown import write_markdown_report
            _atomic_report_write(
                lambda p: write_markdown_report(task, store, p),
                report_file,
            )
        return send_file(
            str(report_file), mimetype="text/markdown", as_attachment=True,
            download_name=f"{task_id}.md",
        )

    @app.route("/scan", methods=["GET", "POST"])
    def scan():
        if request.method == "GET":
            return render_template("scan_form.html")

        # POST: 创建并启动任务
        targets_raw = request.form.get("targets", "").strip()
        authorized_by = request.form.get("authorized_by", "").strip()
        authorization_note = request.form.get("authorization_note", "").strip()
        scope_raw = request.form.get("scope", "").strip()
        allow_private = request.form.get("allow_private") == "on"

        if not targets_raw:
            return render_template(
                "scan_form.html", error="目标不能为空"
            ), 400
        if not authorized_by:
            return render_template(
                "scan_form.html", error="授权人不能为空"
            ), 400
        if not authorization_note:
            return render_template(
                "scan_form.html", error="授权说明不能为空"
            ), 400
        if not scope_raw:
            return render_template(
                "scan_form.html", error="授权范围不能为空"
            ), 400

        # 解析: targets / scope 用空白或逗号或换行分隔
        targets = _split_multi(targets_raw)
        scope = _split_multi(scope_raw)

        task = Task(targets=targets)
        store = get_store()
        try:
            AuthorizationVerifier().verify(
                task,
                authorized_by=authorized_by,
                authorization_note=authorization_note,
                authorized_scope=scope,
                allow_private=allow_private,
            )
        except AuthorizationError as e:
            return render_template(
                "scan_form.html", error=f"授权校验失败: {e}"
            ), 400
        store.save_task(task)

        # 启动后台执行
        runner.start_scan(task.id)
        return redirect(url_for("task_detail", task_id=task.id))

    @app.route("/tasks/<task_id>/resume", methods=["POST"])
    def resume_task(task_id: str):
        _check_task_id(task_id)
        store = get_store()
        task = store.get_task(task_id)
        if task is None:
            abort(404)
        if task.status not in (
            TaskStatus.AUTHORIZED, TaskStatus.PAUSED, TaskStatus.FAILED, TaskStatus.RUNNING
        ):
            return render_template(
                "task_detail.html",
                task=task, stages=store.list_stages(task_id),
                assets=store.list_assets(task_id),
                audit=store.list_audit(task_id),
                is_running=False,
                error=f"任务状态 {task.status.value} 不可恢复",
            ), 400
        # RUNNING 任务: 本进程线程在跑, 或租约有效 (他方进程在跑, 行动项 #3)
        # 均拒绝 (409); 租约已过期视为僵死, 允许恢复 (acquire_task_lease 接管)
        if task.status == TaskStatus.RUNNING and (
            runner.is_running(task_id) or store.is_lease_valid(task_id)
        ):
            return jsonify({"error": "任务正在运行中, 无法 resume"}), 409
        runner.start_scan(task_id)
        return redirect(url_for("task_detail", task_id=task_id))

    @app.route("/tasks/<task_id>/cancel", methods=["POST"])
    def cancel_task(task_id: str):
        """请求取消正在运行的任务 (阶段边界生效), 完成后回到详情页。"""
        _check_task_id(task_id)
        store = get_store()
        task = store.get_task(task_id)
        if task is None:
            abort(404)
        if task.status == TaskStatus.RUNNING:
            store.request_cancel(task_id)
        # 非 RUNNING 也回到详情页 (与 resume 按钮行为一致, 审计 4.1)
        return redirect(url_for("task_detail", task_id=task_id))

    @app.route("/api/tasks/<task_id>/status")
    def api_task_status(task_id: str):
        """前端轮询用: 返回任务状态 + 阶段状态 + 是否运行中。"""
        _check_task_id(task_id)
        store = get_store()
        task = store.get_task(task_id)
        if task is None:
            return jsonify({"error": "任务不存在"}), 404
        stages = [
            {
                "name": s.name.value,
                "status": s.status.value,
                "error": s.error,
                "attempt": s.attempt,
            }
            for s in store.list_stages(task_id)
        ]
        return jsonify({
            "task_id": task.id,
            "status": task.status.value,
            "error": task.error,
            "is_running": runner.is_running(task_id),
            "stages": stages,
        })

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404, message="任务不存在"), 404

    return app


def _split_multi(text: str) -> list[str]:
    """按换行/逗号/空白分隔, 去空去重。"""
    parts = re.split(r"[\n,\s]+", text)
    seen = []
    for p in parts:
        p = p.strip()
        if p and p not in seen:
            seen.append(p)
    return seen


def _atomic_report_write(writer, target: Path) -> None:
    """原子写入报告文件: 先写临时文件, 再 os.replace 到目标路径。

    避免并发请求同时生成同一报告时产生损坏文件。
    os.replace 在所有平台上都是原子操作。
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        suffix=".tmp", prefix=".report_", dir=str(target.parent)
    )
    os.close(fd)
    try:
        writer(tmp_path)
        os.replace(tmp_path, str(target))
    except BaseException:
        # 清理临时文件
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
