"""可观测性最小底座 (行动项 #7 / ADR-3)。

- JSON 结构化日志: RotatingFileHandler 落盘 (默认 .aicp/logs/aicp.log),
  修复"全部日志走 stderr 重启即丢"的取证盲点 (审查发现 #9);
- contextvars 注入 task_id: 每条日志自动携带当前任务 ID (线程隔离,
  Web 后台任务线程互不串扰);
- Web 侧 /health (进程存活) 与 /readyz (DB 探针) 端点见 web/app.py。

零新重依赖: 标准库 logging/json/contextvars (ADR-3 约束)。
"""

from __future__ import annotations

import contextvars
import json
import logging
import logging.handlers
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# 当前执行流绑定的任务 ID (contextvar: 线程隔离)
_current_task_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "aicp_task_id", default=None
)


def bind_task_id(task_id: Optional[str]) -> contextvars.Token:
    """绑定当前执行流的任务 ID (此后本线程日志自动携带); 返回 token 供 restore。"""
    return _current_task_id.set(task_id)


def get_task_id() -> Optional[str]:
    """读取当前执行流绑定的任务 ID (未绑定为 None)。"""
    return _current_task_id.get()


class TaskIdFilter(logging.Filter):
    """把 contextvar 里的 task_id 注入每条 LogRecord (无则记 '-')。"""

    def filter(self, record: logging.LogRecord) -> bool:
        record.task_id = _current_task_id.get() or "-"
        return True


class JsonFormatter(logging.Formatter):
    """单行 JSON 日志: ts / level / logger / task_id / message (+ exc_info)。"""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "task_id": getattr(record, "task_id", "-"),
            "message": record.getMessage(),
        }
        if record.exc_info:
            entry["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


def setup_logging(log_file: Optional[str] = None, level: int = logging.INFO) -> None:
    """初始化 JSON 文件日志 (RotatingFileHandler, 2MB × 5 备份)。

    - 控制台输出保持不变 (basicConfig, 人类可读);
    - log_file=None 时只设置级别 (不挂文件 handler);
    - 幂等: 重复调用不重复挂 handler。
    """
    root = logging.getLogger()
    if log_file is not None and not getattr(root, "_aicp_json_logging", False):
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=2 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        handler.setFormatter(JsonFormatter())
        handler.addFilter(TaskIdFilter())
        handler._aicp_json_handler = True  # 测试清理识别标记
        root.addHandler(handler)
        root._aicp_json_logging = True
    if root.level == logging.NOTSET or root.level > level:
        root.setLevel(level)
