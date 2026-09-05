"""可观测性最小底座测试 (P0 行动项 #7 / ADR-3)。

- JSON 日志格式与 task_id 注入 (contextvars, 线程隔离);
- setup_logging 落盘 RotatingFileHandler 且幂等;
- Orchestrator 运行期间日志自动携带 task_id。
"""

from __future__ import annotations

import json
import logging

from aicp.auth import AuthorizationVerifier
from aicp.models import Task
from aicp.observability import (
    JsonFormatter,
    TaskIdFilter,
    bind_task_id,
    get_task_id,
    setup_logging,
)
from aicp.pipeline import Orchestrator


def _make_record(msg: str = "hello", level: int = logging.INFO) -> logging.LogRecord:
    return logging.LogRecord(
        name="aicp.test", level=level, pathname=__file__, lineno=1,
        msg=msg, args=(), exc_info=None,
    )


# ---------------- JsonFormatter + TaskIdFilter ----------------

def test_json_formatter_output_is_parseable_json():
    rec = _make_record("扫描完成")
    line = JsonFormatter().format(rec)
    entry = json.loads(line)
    assert entry["message"] == "扫描完成"
    assert entry["level"] == "INFO"
    assert entry["logger"] == "aicp.test"
    assert "ts" in entry
    assert "task_id" in entry  # 未绑定 -> "-"


def test_task_id_filter_injects_bound_id():
    token = bind_task_id("task-abc-123")
    try:
        rec = _make_record()
        assert TaskIdFilter().filter(rec) is True
        assert rec.task_id == "task-abc-123"
        line = json.loads(JsonFormatter().format(rec))
        assert line["task_id"] == "task-abc-123"
    finally:
        token.var.reset(token)


def test_task_id_filter_defaults_to_dash():
    assert get_task_id() is None
    rec = _make_record()
    TaskIdFilter().filter(rec)
    assert rec.task_id == "-"


def test_task_id_is_thread_local():
    """contextvar 线程隔离: 主线程绑定不影响子线程。"""
    import threading

    token = bind_task_id("main-task")
    try:
        seen = {}
        ready = threading.Event()

        def worker():
            seen["task_id"] = get_task_id()
            ready.set()

        t = threading.Thread(target=worker)
        t.start()
        ready.wait(5)
        t.join()
        assert seen["task_id"] is None  # 子线程看不到主线程的绑定
        assert get_task_id() == "main-task"
    finally:
        token.var.reset(token)


# ---------------- setup_logging 落盘 ----------------

def test_setup_logging_writes_json_lines_with_task_id(tmp_path):
    log_file = tmp_path / "logs" / "aicp.log"
    setup_logging(log_file=str(log_file))
    # 幂等: 二次调用不重复挂 handler
    setup_logging(log_file=str(log_file))

    token = bind_task_id("task-log-1")
    try:
        logging.getLogger("aicp.demo").info("带任务上下文的日志")
    finally:
        token.var.reset(token)
        logging.getLogger("aicp.demo").info("无任务上下文的日志")

    # flush handlers
    for h in logging.getLogger().handlers:
        h.flush()

    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    assert lines, "日志文件应有内容"
    entries = [json.loads(x) for x in lines]
    with_id = [e for e in entries if e["task_id"] == "task-log-1"]
    without_id = [e for e in entries if e["task_id"] == "-"]
    assert any(e["message"] == "带任务上下文的日志" for e in with_id)
    assert any(e["message"] == "无任务上下文的日志" for e in without_id)


# ---------------- Orchestrator 集成: 运行期日志携带 task_id ----------------

def test_orchestrator_run_logs_carry_task_id(store, tmp_path, monkeypatch):
    """行动项 #7 DoD: 任务执行期间的日志每条含 task_id (JSON 文件日志)。"""
    log_file = tmp_path / "logs" / "aicp.log"
    setup_logging(log_file=str(log_file))

    t = Task(targets=["example.com"])
    store.save_task(t)
    AuthorizationVerifier().verify(
        t, authorized_by="张三", authorization_note="AUTH-001",
        authorized_scope=["example.com"],
    )
    store.save_task(t)

    orch = Orchestrator(store, [], work_dir=str(tmp_path))
    final = orch.run(t)
    assert final.status.value == "completed"

    for h in logging.getLogger().handlers:
        h.flush()
    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    assert lines
    entries = [json.loads(x) for x in lines]
    task_entries = [e for e in entries if e.get("task_id") == t.id]
    # 运行期间 (获取租约/阶段推进) 的日志确实携带了 task_id
    assert task_entries, "应有携带 task_id 的日志行"
    assert any("获取租约" in e["message"] for e in task_entries)
    # 运行结束后 contextvar 已解绑: 后续日志 task_id 为 "-"
    logging.getLogger("aicp.demo").info("运行结束后")
    for h in logging.getLogger().handlers:
        h.flush()
    last = json.loads(log_file.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert last["task_id"] == "-"
