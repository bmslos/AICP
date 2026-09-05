"""后台任务执行器。

Web 提交的 scan / resume 在独立线程中调用 Orchestrator.run()，
避免阻塞 HTTP 请求。线程状态记录在模块级 dict 中，供状态查询用。

设计:
- 同一任务同时只允许一个线程运行 (用 task_id 作为 key 防重入);
- 线程内捕获异常写入 task.error (通过 Store), 不向外抛;
- Orchestrator 自身已是幂等 (从 Store 读最新状态), 所以线程安全
  仅需保证 Store 的 sqlite3 连接不被多线程共享 (每个线程开自己的 Store)。
"""

from __future__ import annotations

import logging
import threading
from typing import Dict

from ..models import TaskStatus
from ..pipeline import Orchestrator, LeaseHeldError
from ..scheduler import Store


logger = logging.getLogger(__name__)


class TaskRunner:
    """后台任务执行器 (单例语义, 由 Flask app 持有)。"""

    def __init__(self, db_path: str, work_dir: str, tools_factory):
        """
        - db_path: SQLite 路径 (每个任务线程会新开 Store)
        - work_dir: 工具工作目录
        - tools_factory: 无参 callable, 返回 Tool 列表 (每次执行都重新构造,
          避免工具实例被多线程共享)
        """
        self._db_path = db_path
        self._work_dir = work_dir
        self._tools_factory = tools_factory
        self._threads: Dict[str, threading.Thread] = {}
        self._lock = threading.Lock()

    def is_running(self, task_id: str) -> bool:
        """任务是否正在后台执行。"""
        with self._lock:
            self._cleanup_dead_threads()
            t = self._threads.get(task_id)
            return t is not None and t.is_alive()

    def start_scan(self, task_id: str) -> None:
        """启动后台扫描线程。

        若该任务已有线程在跑, 直接返回 (防重入)。
        """
        with self._lock:
            self._cleanup_dead_threads()
            existing = self._threads.get(task_id)
            if existing is not None and existing.is_alive():
                return
            t = threading.Thread(
                target=self._run, args=(task_id,), daemon=True, name=f"scan-{task_id}"
            )
            self._threads[task_id] = t
        t.start()

    def _cleanup_dead_threads(self) -> None:
        """清理已结束的线程引用, 避免字典无限增长。

        必须在持有 self._lock 的情况下调用。
        """
        dead = [tid for tid, t in self._threads.items() if not t.is_alive()]
        for tid in dead:
            del self._threads[tid]

    def _run(self, task_id: str) -> None:
        """线程入口: 新开 Store + Orchestrator, 跑完即退出。

        异常会被记录到 task.error (通过 Store.transition_task FAILED),
        不向外抛 (后台线程异常无人接, 只能记日志)。
        例外: LeaseHeldError 表示租约被其他执行者持有 (如 CLI 进程在跑
        同一任务), 不动任务状态 —— 他方仍在执行, 标 FAILED 会误伤。
        """
        try:
            with Store(self._db_path) as store:
                task = store.get_task(task_id)
                if task is None:
                    logger.error("后台任务不存在: %s", task_id)
                    return
                tools = self._tools_factory()
                orch = Orchestrator(store, tools, work_dir=self._work_dir)
                orch.run(task)
        except LeaseHeldError:
            logger.warning("后台任务 %s 租约被其他执行者持有, 本次跳过", task_id)
        except Exception as e:
            logger.exception("后台任务 %s 异常", task_id)
            try:
                with Store(self._db_path) as store:
                    task = store.get_task(task_id)
                    if task and task.status not in (
                        TaskStatus.COMPLETED, TaskStatus.CANCELLED
                    ):
                        store.transition_task(
                            task_id, TaskStatus.FAILED, error=f"后台线程异常: {e}"
                        )
            except Exception:
                logger.exception("记录后台任务失败状态时再次异常: %s", task_id)
