"""配置文件支持 (P1-2)。

配置文件默认路径 `.aicp/config.toml` (可用 `aicp config init` 生成)。
取值优先级: **CLI 参数 > 配置文件 > 环境变量 (AICP_*) > 代码默认值**。

授权信息 (authorized_by / authorization_note / scope) 允许写入配置,
但每次 scan 前仍会打印 ConfirmationBanner 二次确认。

Python 3.11+ 用标准库 tomllib; 3.10 需要 tomli (见 pyproject 依赖)。
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

DEFAULT_CONFIG_PATH = ".aicp/config.toml"

# 环境变量前缀 (如 AICP_RATE_LIMIT / AICP_AUTHORIZED_BY)
_ENV_PREFIX = "AICP_"


def load_config(path: Optional[str] = None) -> dict:
    """加载配置文件为 dict; 文件不存在返回空 dict。"""
    cfg_path = Path(path) if path else Path(DEFAULT_CONFIG_PATH)
    if not cfg_path.exists():
        return {}
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            raise RuntimeError(
                "解析 config.toml 需要 Python 3.11+ (内置 tomllib) 或安装 tomli"
            )
    with open(cfg_path, "rb") as f:
        return tomllib.load(f)


def env_override(env_key: str) -> Optional[str]:
    """读取 AICP_* 环境变量 (无则返回 None)。"""
    import os

    return os.environ.get(f"{_ENV_PREFIX}{env_key}")


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def merge_auth(cli_authorized_by, cli_note, cli_scope, cfg: dict) -> dict:
    """合并授权三要素: CLI > config > 环境变量。"""
    auth_cfg = cfg.get("auth", {}) if isinstance(cfg, dict) else {}
    authorized_by = (
        cli_authorized_by
        or auth_cfg.get("authorized_by")
        or env_override("AUTHORIZED_BY")
    )
    authorization_note = (
        cli_note
        or auth_cfg.get("authorization_note")
        or env_override("AUTHORIZATION_NOTE")
    )
    # scope 三级回退: CLI > config > env (对齐 rate_limit, 行动项 #6)
    # env 只在 CLI/config 都缺省时才生效, 避免环境变量压过显式 CLI 参数
    scope = list(cli_scope) if cli_scope else None
    if scope is None:
        scope = auth_cfg.get("scope") or None
    if scope is None:
        env_scope = env_override("SCOPE")
        if env_scope:
            scope = [s.strip() for s in env_scope.split(",") if s.strip()]
    if scope is None:
        scope = []
    return {
        "authorized_by": authorized_by,
        "authorization_note": authorization_note,
        "scope": scope,
    }


def merge_scan(cli_rate_limit, cli_allow_private, cli_work_dir, cfg: dict) -> dict:
    """合并扫描参数: CLI > config > 环境变量 > 默认值 (与 merge_auth 一致, 审计 5.2)。"""
    scan_cfg = cfg.get("scan", {}) if isinstance(cfg, dict) else {}

    rate_limit = cli_rate_limit
    if rate_limit is None:
        rate_limit = scan_cfg.get("rate_limit")
    if rate_limit is None:
        # env 只在 CLI/config 都缺省时才生效, 避免环境变量压过显式 CLI 参数 (审计复核回归)
        env_rl = env_override("RATE_LIMIT")
        if env_rl is not None:
            rate_limit = int(env_rl)

    # allow_private 为"或"语义: 任一来源显式 true 即允许 (安全侧默认 false)
    allow_private = cli_allow_private
    allow_private = allow_private or _as_bool(scan_cfg.get("allow_private", False))
    env_ap = env_override("ALLOW_PRIVATE")
    if env_ap is not None:
        allow_private = allow_private or _as_bool(env_ap)

    work_dir = cli_work_dir or scan_cfg.get("work_dir")
    return {
        "rate_limit": rate_limit,
        "allow_private": allow_private,
        "work_dir": work_dir,
    }


_DEFAULT_CONFIG_TEXT = """\
# AICP 配置文件
# 优先级: CLI 参数 > 本文件 > 环境变量 (AICP_*) > 代码默认值
# 授权信息写入配置后, 每次 scan 仍会打印 ConfirmationBanner 二次确认。
# 如不愿把授权信息落盘, 删除 [auth] 段, 每次用 --authorized-by 等显式传入。

[auth]
authorized_by = "安全部"
authorization_note = "AUTH-2026-001"
scope = ["example.com", "1.2.3.0/24"]

[scan]
rate_limit = 50
allow_private = false
work_dir = ".aicp/work"
report_dir = ".aicp/reports"

[web]
host = "127.0.0.1"
port = 5000
"""


def write_default_config(path: Optional[str] = None, force: bool = False) -> Path:
    """生成默认配置文件 (已存在时不覆盖, 除非 force=True)。"""
    cfg_path = Path(path) if path else Path(DEFAULT_CONFIG_PATH)
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    if force and cfg_path.exists():
        cfg_path.unlink()
    if not cfg_path.exists():
        cfg_path.write_text(_DEFAULT_CONFIG_TEXT, encoding="utf-8")
    return cfg_path
