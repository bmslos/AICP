"""任务与阶段状态模型。

任务 (Task) 代表一次完整的资产收集流水线运行；
阶段 (Stage) 代表流水线中某个工具的执行 (OneForAll / Nmap / httpx / Wappalyzer)。
任务状态机：
    PENDING → AUTH_PENDING → AUTHORIZED → RUNNING → COMPLETED
                                       ↓
                                  PAUSED / FAILED / CANCELLED
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List


class TaskStatus(str, Enum):
    PENDING = "pending"            # 任务已创建，等待授权登记
    AUTH_PENDING = "auth_pending"  # 已提交授权信息，等待校验
    AUTHORIZED = "authorized"      # 授权通过，可运行
    RUNNING = "running"            # 流水线执行中
    PAUSED = "paused"              # 已暂停 (支持断点续传)
    COMPLETED = "completed"        # 全部阶段成功完成
    FAILED = "failed"              # 终止性失败
    CANCELLED = "cancelled"        # 用户取消


class StageName(str, Enum):
    SUBDOMAIN = "subdomain"      # OneForAll / Subfinder
    PORTSCAN = "portscan"        # Nmap / Masscan
    FINGERPRINT = "fingerprint"  # httpx + Wappalyzer
    DIRSCAN = "dirscan"          # dirsearch / ffuf 目录枚举
    VULNERABILITY = "vulnerability"  # Nuclei 漏洞检测
    CORRELATE = "correlate"      # 数据关联去重 (内置)


class StageStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _gen_id() -> str:
    return uuid.uuid4().hex


@dataclass
class Stage:
    """流水线阶段记录。"""

    task_id: str
    name: StageName
    status: StageStatus = StageStatus.PENDING
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = None
    attempt: int = 0  # 重试次数

    def to_dict(self) -> dict:
        d = asdict(self)
        d["name"] = self.name.value
        d["status"] = self.status.value
        d["started_at"] = self.started_at.isoformat() if self.started_at else None
        d["finished_at"] = self.finished_at.isoformat() if self.finished_at else None
        return d


@dataclass
class Task:
    """一次资产收集任务。

    - targets: 用户输入的目标列表 (域名 / IP / CIDR)
    - authorized_scope: 授权范围 (启动后所有扫描目标必须在此范围内)
    - authorized_by: 授权人
    - authorized_at: 授权时间
    - authorization_note: 授权说明 (如授权书编号)
    """

    targets: List[str]
    created_at: datetime = field(default_factory=_utcnow)
    id: str = field(default_factory=_gen_id)
    status: TaskStatus = TaskStatus.PENDING
    authorized_scope: List[str] = field(default_factory=list)
    authorized_by: Optional[str] = None
    authorized_at: Optional[datetime] = None
    authorization_note: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["created_at"] = self.created_at.isoformat()
        d["authorized_at"] = self.authorized_at.isoformat() if self.authorized_at else None
        d["started_at"] = self.started_at.isoformat() if self.started_at else None
        d["finished_at"] = self.finished_at.isoformat() if self.finished_at else None
        return d
