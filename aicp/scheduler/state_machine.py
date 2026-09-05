"""任务状态机。

显式声明所有合法的状态迁移，非法迁移抛 IllegalTransitionError。
这样断点续传、并发调度时不会出现状态混乱。
"""

from __future__ import annotations

from ..models.task import TaskStatus, StageStatus


class IllegalTransitionError(Exception):
    """非法状态迁移。"""


class MaxRetriesExceededError(Exception):
    """阶段重试次数超过上限。"""


# 阶段最大重试次数 (防止无限重试循环)
MAX_STAGE_ATTEMPTS = 5


# 任务级合法迁移: {当前状态: {允许到达的下一个状态}}
_TASK_TRANSITIONS: dict[TaskStatus, set[TaskStatus]] = {
    TaskStatus.PENDING: {TaskStatus.AUTH_PENDING, TaskStatus.CANCELLED},
    TaskStatus.AUTH_PENDING: {
        TaskStatus.AUTHORIZED,
        TaskStatus.FAILED,
        TaskStatus.CANCELLED,
    },
    TaskStatus.AUTHORIZED: {TaskStatus.RUNNING, TaskStatus.CANCELLED},
    TaskStatus.RUNNING: {
        TaskStatus.PAUSED,
        TaskStatus.COMPLETED,
        TaskStatus.FAILED,
        TaskStatus.CANCELLED,
    },
    TaskStatus.PAUSED: {TaskStatus.RUNNING, TaskStatus.CANCELLED},
    TaskStatus.COMPLETED: set(),   # 终态
    TaskStatus.FAILED: {TaskStatus.RUNNING},  # 允许断点续传重试
    TaskStatus.CANCELLED: set(),   # 终态
}

# 阶段级合法迁移
_STAGE_TRANSITIONS: dict[StageStatus, set[StageStatus]] = {
    StageStatus.PENDING: {
        StageStatus.RUNNING,
        StageStatus.SKIPPED,
    },
    StageStatus.RUNNING: {
        StageStatus.COMPLETED,
        StageStatus.FAILED,
    },
    StageStatus.COMPLETED: set(),
    StageStatus.FAILED: {StageStatus.PENDING, StageStatus.RUNNING},  # 允许重试
    StageStatus.SKIPPED: set(),
}


class StateMachine:
    """状态机 - 校验状态迁移合法性。"""

    @staticmethod
    def assert_task_transition(current: TaskStatus, target: TaskStatus) -> None:
        allowed = _TASK_TRANSITIONS.get(current, set())
        if target not in allowed:
            raise IllegalTransitionError(
                f"非法任务状态迁移: {current.value} -> {target.value}"
            )

    @staticmethod
    def assert_stage_transition(current: StageStatus, target: StageStatus) -> None:
        allowed = _STAGE_TRANSITIONS.get(current, set())
        if target not in allowed:
            raise IllegalTransitionError(
                f"非法阶段状态迁移: {current.value} -> {target.value}"
            )

    @staticmethod
    def is_terminal_task(status: TaskStatus) -> bool:
        """COMPLETED / CANCELLED 是真正终态；FAILED 可重试故非终态。"""
        return status in {
            TaskStatus.COMPLETED,
            TaskStatus.CANCELLED,
        }

    @staticmethod
    def check_stage_retry_limit(attempt: int, stage_name: str = "") -> None:
        """检查阶段重试次数是否超过上限。

        超过 MAX_STAGE_ATTEMPTS 时抛 MaxRetriesExceededError,
        防止失败任务无限重试。
        """
        if attempt >= MAX_STAGE_ATTEMPTS:
            raise MaxRetriesExceededError(
                f"阶段 {stage_name} 重试次数已达上限 ({MAX_STAGE_ATTEMPTS}), "
                f"不再自动重试。请检查工具配置或目标状态。"
            )
