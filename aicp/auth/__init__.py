"""授权校验 - 合规第一道闸门。"""

from .verifier import (
    AuthorizationError,
    AuthorizationVerifier,
    ConfirmationBanner,
)

__all__ = [
    "AuthorizationError",
    "AuthorizationVerifier",
    "ConfirmationBanner",
]
