"""状态机单元测试。"""

import pytest

from aicp.models import TaskStatus, StageStatus
from aicp.scheduler.state_machine import StateMachine, IllegalTransitionError


# ---------------- 任务状态迁移 ----------------

@pytest.mark.parametrize("current,target", [
    (TaskStatus.PENDING, TaskStatus.AUTH_PENDING),
    (TaskStatus.AUTH_PENDING, TaskStatus.AUTHORIZED),
    (TaskStatus.AUTHORIZED, TaskStatus.RUNNING),
    (TaskStatus.RUNNING, TaskStatus.COMPLETED),
    (TaskStatus.RUNNING, TaskStatus.PAUSED),
    (TaskStatus.PAUSED, TaskStatus.RUNNING),
    (TaskStatus.RUNNING, TaskStatus.FAILED),
    (TaskStatus.RUNNING, TaskStatus.CANCELLED),
    (TaskStatus.FAILED, TaskStatus.RUNNING),   # 断点续传重试
])
def test_legal_task_transitions(current, target):
    StateMachine.assert_task_transition(current, target)  # 不抛异常即通过


@pytest.mark.parametrize("current,target", [
    (TaskStatus.PENDING, TaskStatus.RUNNING),       # 必须先授权
    (TaskStatus.AUTH_PENDING, TaskStatus.RUNNING),  # 必须先 AUTHORIZED
    (TaskStatus.COMPLETED, TaskStatus.RUNNING),     # 真终态不可变
    (TaskStatus.CANCELLED, TaskStatus.RUNNING),     # 真终态不可变
    (TaskStatus.AUTHORIZED, TaskStatus.COMPLETED),  # 跳过 RUNNING 非法
])
def test_illegal_task_transitions(current, target):
    with pytest.raises(IllegalTransitionError):
        StateMachine.assert_task_transition(current, target)


# ---------------- 阶段状态迁移 ----------------

@pytest.mark.parametrize("current,target", [
    (StageStatus.PENDING, StageStatus.RUNNING),
    (StageStatus.PENDING, StageStatus.SKIPPED),
    (StageStatus.RUNNING, StageStatus.COMPLETED),
    (StageStatus.RUNNING, StageStatus.FAILED),
    (StageStatus.FAILED, StageStatus.PENDING),     # 允许重试
    (StageStatus.FAILED, StageStatus.RUNNING),     # 直接重试
])
def test_legal_stage_transitions(current, target):
    StateMachine.assert_stage_transition(current, target)


@pytest.mark.parametrize("current,target", [
    (StageStatus.PENDING, StageStatus.COMPLETED),  # 必须先 RUNNING
    (StageStatus.COMPLETED, StageStatus.RUNNING),  # 终态
    (StageStatus.SKIPPED, StageStatus.RUNNING),
])
def test_illegal_stage_transitions(current, target):
    with pytest.raises(IllegalTransitionError):
        StateMachine.assert_stage_transition(current, target)


def test_terminal_task_detection():
    """COMPLETED / CANCELLED 是真终态；FAILED 可重试故非终态。"""
    assert StateMachine.is_terminal_task(TaskStatus.COMPLETED)
    assert StateMachine.is_terminal_task(TaskStatus.CANCELLED)
    assert not StateMachine.is_terminal_task(TaskStatus.FAILED)
    assert not StateMachine.is_terminal_task(TaskStatus.RUNNING)
