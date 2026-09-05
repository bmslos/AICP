"""Flask Web 前端 - 任务列表 / 详情 / 报告查看 + 任务创建。"""

from .app import create_app
from .runner import TaskRunner

__all__ = ["create_app", "TaskRunner"]
