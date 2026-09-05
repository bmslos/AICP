"""统一资产数据模型。

所有工具的输出最终都归一化为 Asset，便于跨阶段关联与去重。
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, List, Literal


AssetType = Literal[
    "domain", "ip", "port", "url", "web_service",
    "directory", "vulnerability",
]


def _utcnow() -> datetime:
    """统一时区，避免本地时区带来的歧义。"""
    return datetime.now(timezone.utc)


def _gen_id() -> str:
    return uuid.uuid4().hex


@dataclass
class Asset:
    """统一资产 schema。

    字段说明：
    - id: 资产唯一 ID
    - type: 资产类型 (domain / ip / port / url / web_service / directory / vulnerability)
    - value: 资产值 (如 example.com / 1.2.3.4 / 1.2.3.4:80)
    - source: 发现该资产的工具名
    - task_id: 所属任务 ID
    - discovered_at: 发现时间 (UTC)
    - parent_id: 上游资产 ID，用于关联 (如子域名 -> 根域名)
    - technologies: Web 指纹识别出的技术栈
    - status_code: HTTP 状态码
    - title: 网页标题
    - raw: 工具原始输出 (用于审计追溯)
    """

    type: AssetType
    value: str
    source: str
    task_id: str
    id: str = field(default_factory=_gen_id)
    discovered_at: datetime = field(default_factory=_utcnow)
    parent_id: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    status_code: Optional[int] = None
    title: Optional[str] = None
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """转为可序列化的字典 (datetime 转 ISO 字符串)。"""
        d = asdict(self)
        d["discovered_at"] = self.discovered_at.isoformat()
        return d

    @staticmethod
    def dedup_key(type_: AssetType, value: str, task_id: str) -> tuple[str, str, str]:
        """去重键: 同一任务内 (type, value) 视为同一资产。"""
        return (type_, value, task_id)
