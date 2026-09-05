"""调度引擎 - 任务状态机与 SQLite 持久化。"""

from .state_machine import (
    StateMachine, IllegalTransitionError, MaxRetriesExceededError, MAX_STAGE_ATTEMPTS,
)
from .store import Store

__all__ = [
    "StateMachine", "IllegalTransitionError", "MaxRetriesExceededError",
    "MAX_STAGE_ATTEMPTS", "Store",
]
