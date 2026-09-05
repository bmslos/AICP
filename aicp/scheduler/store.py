"""SQLite 持久化层。

存储任务、阶段、资产、审计日志。
所有 datetime 以 ISO 字符串入库，读取时还原为带时区的 datetime。
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, List, Iterable

from ..models.asset import Asset
from ..models.task import Task, TaskStatus, Stage, StageName, StageStatus
from .state_machine import StateMachine


logger = logging.getLogger(__name__)

# 写操作重试配置: 应对 SQLite "database is locked" 瞬时失败
_RETRY_MAX_ATTEMPTS = 5
_RETRY_BASE_DELAY = 0.1  # 秒, 指数退避基数

# 任务租约默认时长 (秒, 行动项 #3 / ADR-1): 与工具级子进程超时对齐 (30 分钟)。
# Orchestrator 心跳线程按 lease/3 续约 (续约间隔 < 检查间隔的 1/3)。
DEFAULT_LEASE_SECONDS = 1800

# 本进程当前持有的活跃租约 owner 集合: atexit 清理时区分"自己的任务"与
# "其他进程还在跑的任务", 修 CLI 与 Web 双入口互杀 (审查发现 #3)。
_active_owners: set[str] = set()


def _retry_commit(conn: sqlite3.Connection) -> None:
    """commit 带重试: 应对并发写导致的瞬时 locked 错误。

    指数退避: 0.1s, 0.2s, 0.4s, 0.8s, 1.6s。超过重试次数后抛出原始异常。
    """
    for attempt in range(_RETRY_MAX_ATTEMPTS):
        try:
            conn.commit()
            return
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower() and attempt < _RETRY_MAX_ATTEMPTS - 1:
                delay = _RETRY_BASE_DELAY * (2 ** attempt)
                logger.debug("commit 失败 (locked), %.1fs 后重试 (%d/%d)",
                             delay, attempt + 1, _RETRY_MAX_ATTEMPTS)
                time.sleep(delay)
            else:
                raise


_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    targets TEXT NOT NULL,            -- JSON 数组
    status TEXT NOT NULL,
    authorized_scope TEXT NOT NULL DEFAULT '[]',  -- JSON 数组
    authorized_by TEXT,
    authorized_at TEXT,
    authorization_note TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS stages (
    task_id TEXT NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    error TEXT,
    attempt INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (task_id, name),
    FOREIGN KEY (task_id) REFERENCES tasks(id)
);

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    parent_id TEXT,
    discovered_at TEXT NOT NULL,
    technologies TEXT NOT NULL DEFAULT '[]',  -- JSON 数组
    status_code INTEGER,
    title TEXT,
    raw TEXT NOT NULL DEFAULT '{}',           -- JSON 对象
    UNIQUE (task_id, type, value, source),    -- 同任务内 (type, value, source) 去重
                                              -- 不同 source 可共存 (web_service 由 correlate 合并)
    FOREIGN KEY (task_id) REFERENCES tasks(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL,
    event TEXT NOT NULL,
    detail TEXT,
    ts TEXT NOT NULL
);

-- 复合索引: 同时覆盖 list_assets (WHERE task_id ORDER BY discovered_at)
-- 和 list_assets_by_types (WHERE task_id AND type IN (...) ORDER BY discovered_at)
-- 替代旧的单列索引 idx_assets_task
CREATE INDEX IF NOT EXISTS idx_assets_task_type_discovered
    ON assets(task_id, type, discovered_at);
CREATE INDEX IF NOT EXISTS idx_audit_task ON audit_log(task_id);
"""


# 数据库 schema 迁移: 每个迁移是 (目标版本号, [SQL 语句列表])
# user_version=0 表示初始 schema; 版本号从 1 开始顺序递增。
# 新迁移追加到列表末尾, 不修改已发布条目 (保证旧库按序升级)。
_MIGRATIONS: list[tuple[int, list[str]]] = [
    # v1: 取消请求标记从 audit_log 事件改为 tasks 列 (P1-4 修复, 审计 3.1)
    # 原实现写 audit_log 事件, append-only 永不消失, 崩溃恢复后 resume
    # 会在阶段边界被旧标记再次取消, 任务永久无法恢复。
    (1, ["ALTER TABLE tasks ADD COLUMN cancel_requested INTEGER NOT NULL DEFAULT 0"]),
    # v2: 任务租约三列 (行动项 #3 / ADR-1)
    # - owner: 当前执行者标识; heartbeat_at: 最近续约时间;
    # - lease_expires_at: 租约到期时间, 过期后他方可接管 (僵死恢复),
    #   未过期则拒绝并发执行 (修双入口误杀/双跑)。
    (2, [
        "ALTER TABLE tasks ADD COLUMN owner TEXT",
        "ALTER TABLE tasks ADD COLUMN heartbeat_at TEXT",
        "ALTER TABLE tasks ADD COLUMN lease_expires_at TEXT",
    ]),
]


def _iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    return dt.isoformat()


def _parse_iso(s: Optional[str]) -> Optional[datetime]:
    if s is None:
        return None
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class Store:
    """SQLite 持久化封装。"""

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        # timeout: 写冲突时等待 30s 而非立即抛 database is locked
        self._conn = sqlite3.connect(self.db_path, timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        # WAL 模式: 读写不互斥 (多读单写); busy_timeout 让并发写排队
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.executescript(_SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """按 _MIGRATIONS 顺序把 schema 升级到最新版本 (PRAGMA user_version 记录)。"""
        current = self._conn.execute("PRAGMA user_version").fetchone()[0]
        for target, statements in _MIGRATIONS:
            if current >= target:
                continue
            for statement in statements:
                self._conn.execute(statement)
            self._conn.execute(f"PRAGMA user_version = {target}")
            logger.info("schema 迁移: user_version %d -> %d", current, target)
            current = target

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---------------- 任务 ----------------

    def save_task(self, task: Task) -> None:
        self._conn.execute(
            """
            INSERT INTO tasks
                (id, targets, status, authorized_scope, authorized_by,
                 authorized_at, authorization_note, created_at,
                 started_at, finished_at, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                targets = excluded.targets,
                status = excluded.status,
                authorized_scope = excluded.authorized_scope,
                authorized_by = excluded.authorized_by,
                authorized_at = excluded.authorized_at,
                authorization_note = excluded.authorization_note,
                started_at = excluded.started_at,
                finished_at = excluded.finished_at,
                error = excluded.error
            """,
            (
                task.id,
                json.dumps(task.targets, ensure_ascii=False),
                task.status.value,
                json.dumps(task.authorized_scope, ensure_ascii=False),
                task.authorized_by,
                _iso(task.authorized_at),
                task.authorization_note,
                _iso(task.created_at),
                _iso(task.started_at),
                _iso(task.finished_at),
                task.error,
            ),
        )
        _retry_commit(self._conn)

    def get_task(self, task_id: str) -> Optional[Task]:
        row = self._conn.execute(
            "SELECT * FROM tasks WHERE id = ?", (task_id,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_task(row)

    def list_tasks(self, *, limit: Optional[int] = None, offset: int = 0) -> List[Task]:
        """列出任务 (按创建时间倒序)。

        - limit: 返回数量上限, None 表示全部
        - offset: 跳过前 N 条 (分页用)
        """
        sql = "SELECT * FROM tasks ORDER BY created_at DESC"
        params: list = []
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            params = [limit, offset]
        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_task(r) for r in rows]

    def count_tasks(self) -> int:
        """任务总数 (分页用)。"""
        row = self._conn.execute("SELECT COUNT(*) as cnt FROM tasks").fetchone()
        return row["cnt"]

    @staticmethod
    def cleanup_running_tasks(db_path: str | Path) -> int:
        """租约感知的 RUNNING 清理 (行动项 #3 / ADR-1, 修双入口互杀)。

        只把以下 RUNNING 任务标记为 FAILED:
        - 租约已过期/无租约的任务 (僵死, 无人执行);
        - owner 属于本进程的任务 (atexit: 本进程即将退出, 自己的必死)。
        其他进程持有的有效租约任务**不动** —— CLI 与 Web 双入口并存时互不误杀。

        返回: 被清理的任务数。
        """
        try:
            with Store(db_path) as store:
                now = datetime.now(timezone.utc)
                rows = store._conn.execute(
                    "SELECT id, owner, lease_expires_at FROM tasks WHERE status = ?",
                    (TaskStatus.RUNNING.value,),
                ).fetchall()
                count = 0
                for row in rows:
                    task_id = row["id"]
                    owner = row["owner"]
                    expires = _parse_iso(row["lease_expires_at"])
                    lease_valid = expires is not None and expires > now
                    ours = owner is not None and owner in _active_owners
                    if lease_valid and not ours:
                        continue  # 他方进程在跑: 不误杀
                    try:
                        store.transition_task(
                            task_id,
                            TaskStatus.FAILED,
                            error="进程退出时未完成 (interrupted)",
                        )
                        count += 1
                    except Exception:
                        # 状态迁移失败 (可能已被其他线程迁移) 跳过
                        pass
                return count
        except Exception:
            # atexit 钩子里的异常无人接, 静默吞掉
            return 0

    # ---------------- 任务租约 (行动项 #3 / ADR-1) ----------------

    def acquire_task_lease(
        self,
        task_id: str,
        owner: str,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
    ) -> bool:
        """原子获取任务执行租约 (BEGIN IMMEDIATE 包裹读-校验-写)。

        - AUTHORIZED / PAUSED / FAILED → RUNNING: 正常获取 (经状态机校验);
        - RUNNING 且租约有效: 返回 False (他方持有, 拒绝并发双跑);
        - RUNNING 且租约过期/无租约: 接管 (僵死恢复, 审计记 lease 过程);
        - 并发下同一任务仅一方成功, 消除旧实现"读-改-写"的 TOCTOU 竞态。
        成功后把 owner 登记到本进程活跃集合 (atexit 清理识别"自己的")。
        """
        now = datetime.now(timezone.utc)
        self._conn.commit()  # 清掉可能挂起的隐式事务, 保证 BEGIN 干净
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT status, started_at, lease_expires_at FROM tasks WHERE id = ?",
                (task_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"任务不存在: {task_id}")
            status = TaskStatus(row["status"])
            audit_events: list[tuple[str, str]] = []
            if status == TaskStatus.RUNNING:
                expires = _parse_iso(row["lease_expires_at"])
                if expires is not None and expires > now:
                    self._conn.rollback()  # 只读未写, 回滚释放写锁
                    return False  # 他方租约有效: 拒绝
                # 僵死接管: 审计上等价旧的 running -> failed (recovery) 两跳
                audit_events.append(
                    ("task_transition", "running -> failed (lease expired, takeover)")
                )
            else:
                StateMachine.assert_task_transition(status, TaskStatus.RUNNING)
            started_at = _parse_iso(row["started_at"]) or now
            expires_at = now + timedelta(seconds=lease_seconds)
            self._conn.execute(
                "UPDATE tasks SET status = ?, started_at = ?, finished_at = NULL, "
                "error = NULL, owner = ?, heartbeat_at = ?, lease_expires_at = ? "
                "WHERE id = ?",
                (
                    TaskStatus.RUNNING.value, _iso(started_at),
                    owner, _iso(now), _iso(expires_at), task_id,
                ),
            )
            if status == TaskStatus.RUNNING:
                audit_events.append(("task_transition", "failed -> running (takeover)"))
            else:
                audit_events.append(("task_transition", f"{status.value} -> running"))
            audit_events.append(
                ("lease_acquired", f"owner={owner} lease={lease_seconds}s")
            )
            for event, detail in audit_events:
                self._conn.execute(
                    "INSERT INTO audit_log (task_id, event, detail, ts) VALUES (?, ?, ?, ?)",
                    (task_id, event, detail, _iso(now)),
                )
            self._conn.commit()
        except BaseException:
            self._conn.rollback()
            raise
        _active_owners.add(owner)
        return True

    def heartbeat_lease(
        self, task_id: str, owner: str, lease_seconds: int = DEFAULT_LEASE_SECONDS
    ) -> bool:
        """租约续约: 延长 lease_expires_at (仅 owner 匹配且 RUNNING 的任务)。

        返回 False 表示续约失败 (已被接管/任务已终态), 调用方视为执行权丢失。
        """
        now = datetime.now(timezone.utc)
        cur = self._conn.execute(
            "UPDATE tasks SET heartbeat_at = ?, lease_expires_at = ? "
            "WHERE id = ? AND owner = ? AND status = ?",
            (
                _iso(now), _iso(now + timedelta(seconds=lease_seconds)),
                task_id, owner, TaskStatus.RUNNING.value,
            ),
        )
        _retry_commit(self._conn)
        return cur.rowcount == 1

    def release_lease(self, task_id: str, owner: str) -> None:
        """终态释放租约: 清 owner/heartbeat/lease 列。

        owner 不匹配时 no-op (租约已被接管, 归新持有者管)。
        """
        self._conn.execute(
            "UPDATE tasks SET owner = NULL, heartbeat_at = NULL, lease_expires_at = NULL "
            "WHERE id = ? AND owner = ?",
            (task_id, owner),
        )
        _retry_commit(self._conn)
        _active_owners.discard(owner)

    def is_lease_valid(self, task_id: str) -> bool:
        """任务是否 RUNNING 且租约未过期 (可能被本进程外的执行者持有)。"""
        row = self._conn.execute(
            "SELECT status, lease_expires_at FROM tasks WHERE id = ?", (task_id,)
        ).fetchone()
        if row is None or row["status"] != TaskStatus.RUNNING.value:
            return False
        expires = _parse_iso(row["lease_expires_at"])
        return expires is not None and expires > datetime.now(timezone.utc)

    def transition_task(
        self,
        task_id: str,
        target: TaskStatus,
        *,
        started_at: Optional[datetime] = None,
        finished_at: Optional[datetime] = None,
        error: Optional[str] = None,
    ) -> Task:
        """校验合法性后迁移任务状态 (BEGIN IMMEDIATE 原子化, 行动项 #3)。

        读-校验-写在同一事务内完成, 消除并发下"两个连接同时读到旧状态、
        各自通过校验、后写覆盖先写"的竞态。只 UPDATE 状态相关列,
        不动 owner/heartbeat/lease 列 (租约由专用方法管理)。
        """
        now = datetime.now(timezone.utc)
        self._conn.commit()  # 清掉可能挂起的隐式事务
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT * FROM tasks WHERE id = ?", (task_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"任务不存在: {task_id}")
            task = self._row_to_task(row)
            StateMachine.assert_task_transition(task.status, target)
            # 进入 RUNNING: 首次记录 started_at; 恢复 (FAILED->RUNNING) 时清空旧的 finished_at/error
            if target == TaskStatus.RUNNING:
                if task.started_at is None:
                    task.started_at = now
                task.finished_at = None
                task.error = None
            # 进入终态或 FAILED: 记录 finished_at
            if StateMachine.is_terminal_task(target) or target == TaskStatus.FAILED:
                task.finished_at = now
            # 显式参数优先
            if started_at is not None:
                task.started_at = started_at
            if finished_at is not None:
                task.finished_at = finished_at
            if error is not None:
                task.error = error
            prev_status = task.status
            task.status = target
            self._conn.execute(
                "UPDATE tasks SET status = ?, started_at = ?, finished_at = ?, error = ? "
                "WHERE id = ?",
                (
                    task.status.value, _iso(task.started_at),
                    _iso(task.finished_at), task.error, task_id,
                ),
            )
            self._conn.execute(
                "INSERT INTO audit_log (task_id, event, detail, ts) VALUES (?, ?, ?, ?)",
                (
                    task_id, "task_transition",
                    f"{prev_status.value} -> {target.value}", _iso(now),
                ),
            )
            self._conn.commit()
        except BaseException:
            self._conn.rollback()
            raise
        return task

    @staticmethod
    def _row_to_task(row: sqlite3.Row) -> Task:
        return Task(
            id=row["id"],
            targets=json.loads(row["targets"]),
            status=TaskStatus(row["status"]),
            authorized_scope=json.loads(row["authorized_scope"]),
            authorized_by=row["authorized_by"],
            authorized_at=_parse_iso(row["authorized_at"]),
            authorization_note=row["authorization_note"],
            created_at=_parse_iso(row["created_at"]) or datetime.now(timezone.utc),
            started_at=_parse_iso(row["started_at"]),
            finished_at=_parse_iso(row["finished_at"]),
            error=row["error"],
        )

    # ---------------- 阶段 ----------------

    def init_stage(self, stage: Stage) -> None:
        self._conn.execute(
            """
            INSERT INTO stages (task_id, name, status, started_at, finished_at, error, attempt)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(task_id, name) DO UPDATE SET
                status = excluded.status,
                started_at = excluded.started_at,
                finished_at = excluded.finished_at,
                error = excluded.error,
                attempt = excluded.attempt
            """,
            (
                stage.task_id,
                stage.name.value,
                stage.status.value,
                _iso(stage.started_at),
                _iso(stage.finished_at),
                stage.error,
                stage.attempt,
            ),
        )
        _retry_commit(self._conn)

    def get_stage(self, task_id: str, name: StageName) -> Optional[Stage]:
        row = self._conn.execute(
            "SELECT * FROM stages WHERE task_id = ? AND name = ?",
            (task_id, name.value),
        ).fetchone()
        if row is None:
            return None
        return Stage(
            task_id=row["task_id"],
            name=StageName(row["name"]),
            status=StageStatus(row["status"]),
            started_at=_parse_iso(row["started_at"]),
            finished_at=_parse_iso(row["finished_at"]),
            error=row["error"],
            attempt=row["attempt"],
        )

    def list_stages(self, task_id: str) -> List[Stage]:
        rows = self._conn.execute(
            "SELECT * FROM stages WHERE task_id = ? ORDER BY rowid",
            (task_id,),
        ).fetchall()
        return [
            Stage(
                task_id=r["task_id"],
                name=StageName(r["name"]),
                status=StageStatus(r["status"]),
                started_at=_parse_iso(r["started_at"]),
                finished_at=_parse_iso(r["finished_at"]),
                error=r["error"],
                attempt=r["attempt"],
            )
            for r in rows
        ]

    def transition_stage(
        self,
        task_id: str,
        name: StageName,
        target: StageStatus,
        *,
        error: Optional[str] = None,
    ) -> Stage:
        """校验合法性后迁移阶段状态，返回更新后的 Stage。"""
        stage = self.get_stage(task_id, name)
        if stage is None:
            raise KeyError(f"阶段不存在: task={task_id} stage={name.value}")
        StateMachine.assert_stage_transition(stage.status, target)
        now = datetime.now(timezone.utc)
        if target == StageStatus.RUNNING:
            stage.started_at = now
            stage.attempt += 1
            stage.finished_at = None  # 恢复时清空旧的失败时间, 避免时间戳倒置
        elif target in (StageStatus.COMPLETED, StageStatus.FAILED):
            stage.finished_at = now
        if error is not None:
            stage.error = error
        elif target == StageStatus.RUNNING:
            stage.error = None
        stage.status = target
        self.init_stage(stage)
        self.append_audit(
            task_id,
            "stage_transition",
            f"{name.value}: -> {target.value}" + (f" error={error}" if error else ""),
        )
        return stage

    def next_pending_stage(self, task_id: str) -> Optional[Stage]:
        """返回第一个未完成的阶段 (用于断点续传)。"""
        for stage in self.list_stages(task_id):
            if stage.status in (StageStatus.PENDING, StageStatus.FAILED):
                return stage
        return None

    def reset_running_stages(self, task_id: str) -> int:
        """把指定任务下所有 RUNNING 的 stage 重置为 PENDING (异常恢复用)。

        RUNNING -> PENDING 不在合法迁移集内 (StateMachine 不允许),
        因此直接 UPDATE 数据库并记审计, 不走 transition_stage。
        清空 error / started_at / finished_at, 让 stage 可以从头重跑。

        返回: 被重置的 stage 数量。
        """
        # 先查出待重置的 stage 名字, UPDATE 后用于逐条记审计
        rows = self._conn.execute(
            "SELECT name FROM stages WHERE task_id = ? AND status = ?",
            (task_id, StageStatus.RUNNING.value),
        ).fetchall()
        names = [r["name"] for r in rows]

        if not names:
            return 0

        self._conn.execute(
            "UPDATE stages SET status = ?, error = NULL, started_at = NULL, "
            "finished_at = NULL WHERE task_id = ? AND status = ?",
            (StageStatus.PENDING.value, task_id, StageStatus.RUNNING.value),
        )
        for name in names:
            self.append_audit(
                task_id,
                "stage_reset",
                f"{name}: RUNNING -> PENDING (recovery)",
            )
        _retry_commit(self._conn)
        return len(names)

    # ---------------- 资产 ----------------

    def save_asset(self, asset: Asset) -> bool:
        """保存资产；同 (task+type+value+source) 已存在时合并指纹 (web_service) 或更新字段。

        - web_service: technologies 取并集，status_code/title 取首次非空
        - 其他类型: 用新值覆盖 (raw/technologies/status_code/title)
        返回 True 表示新增，False 表示已存在 (已合并/更新)。

        并发安全: 用 INSERT OR IGNORE 原子地抢占新增位, 避免 SELECT+INSERT 的 TOCTOU 竞态
        (多线程同时 SELECT 得到 None 后都尝试 INSERT, 第二个会抛 IntegrityError)。
        INSERT OR IGNORE 命中 UNIQUE 约束时不会抛异常, 而是忽略 (rowcount=0);
        随后的 SELECT+UPDATE 在同一连接内, 行已存在, 不会被其他连接的 INSERT 干扰。
        """
        is_new = self._save_asset_no_commit(asset)
        _retry_commit(self._conn)
        return is_new

    def _save_asset_no_commit(self, asset: Asset) -> bool:
        """save_asset 的内部实现, 不执行 commit (供批量操作统一提交)。"""
        # INSERT OR IGNORE 是原子操作: 命中 UNIQUE(task_id,type,value,source) 时忽略而非抛异常
        cur = self._conn.execute(
            """
            INSERT OR IGNORE INTO assets
                (id, task_id, type, value, source, parent_id,
                 discovered_at, technologies, status_code, title, raw)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                asset.id, asset.task_id, asset.type, asset.value, asset.source,
                asset.parent_id, _iso(asset.discovered_at),
                json.dumps(asset.technologies, ensure_ascii=False),
                asset.status_code, asset.title,
                json.dumps(asset.raw, ensure_ascii=False),
            ),
        )
        if cur.rowcount == 1:
            # 新增成功
            return True

        # 已存在: 读取现有值做合并, 再 UPDATE (此时行已被上面的 INSERT OR IGNORE 抢占存在, 无竞态)
        existing = self._conn.execute(
            "SELECT technologies, status_code, title FROM assets "
            "WHERE task_id=? AND type=? AND value=? AND source=?",
            (asset.task_id, asset.type, asset.value, asset.source),
        ).fetchone()

        if asset.type == "web_service":
            # technologies 取并集
            old_techs = json.loads(existing["technologies"] or "[]")
            merged_techs = list(dict.fromkeys(old_techs + list(asset.technologies)))
            # status_code / title 取首次非空
            new_status = existing["status_code"] if existing["status_code"] is not None else asset.status_code
            new_title = existing["title"] if existing["title"] else asset.title
        else:
            merged_techs = asset.technologies
            new_status = asset.status_code
            new_title = asset.title

        self._conn.execute(
            """
            UPDATE assets SET technologies=?, status_code=?, title=?, raw=?
            WHERE task_id=? AND type=? AND value=? AND source=?
            """,
            (
                json.dumps(merged_techs, ensure_ascii=False),
                new_status, new_title,
                json.dumps(asset.raw, ensure_ascii=False),
                asset.task_id, asset.type, asset.value, asset.source,
            ),
        )
        return False

    def save_assets(self, assets: Iterable[Asset]) -> int:
        """批量保存，返回实际新增数量。

        所有 INSERT/UPDATE 在单个事务内完成, 最后统一 commit,
        避免逐条 fsync 带来的性能开销。
        """
        n = 0
        for a in assets:
            if self._save_asset_no_commit(a):
                n += 1
        _retry_commit(self._conn)
        return n

    def list_assets(self, task_id: str, *, limit: Optional[int] = None, offset: int = 0) -> List[Asset]:
        """列出任务下的资产。

        - limit: 返回数量上限, None 表示全部
        - offset: 跳过前 N 条 (分页用)
        """
        sql = "SELECT * FROM assets WHERE task_id = ? ORDER BY discovered_at"
        params: list = [task_id]
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])
        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_asset(r) for r in rows]

    def count_assets(self, task_id: str) -> int:
        """任务下资产总数 (分页用)。"""
        row = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM assets WHERE task_id = ?", (task_id,)
        ).fetchone()
        return row["cnt"]

    def list_assets_by_types(
        self, task_id: str, types: Iterable[str]
    ) -> List[Asset]:
        """按类型过滤返回资产, SQL 层下推 WHERE task_id=? AND type IN (...)。

        用于 Orchestrator _run_stage 的输入收集, 避免拉取全部资产再在 Python 层过滤。
        无 types 时退化为 list_assets。
        """
        types_list = list(types)
        if not types_list:
            return self.list_assets(task_id)
        placeholders = ",".join("?" * len(types_list))
        rows = self._conn.execute(
            f"SELECT * FROM assets WHERE task_id = ? AND type IN ({placeholders}) "
            f"ORDER BY discovered_at",
            (task_id, *types_list),
        ).fetchall()
        return [self._row_to_asset(r) for r in rows]

    @staticmethod
    def _row_to_asset(row: sqlite3.Row) -> Asset:
        return Asset(
            id=row["id"],
            type=row["type"],
            value=row["value"],
            source=row["source"],
            task_id=row["task_id"],
            parent_id=row["parent_id"],
            discovered_at=_parse_iso(row["discovered_at"]) or datetime.now(timezone.utc),
            technologies=json.loads(row["technologies"]),
            status_code=row["status_code"],
            title=row["title"],
            raw=json.loads(row["raw"]),
        )

    # ---------------- 审计 ----------------

    def append_audit(self, task_id: str, event: str, detail: Optional[str] = None) -> None:
        self._conn.execute(
            "INSERT INTO audit_log (task_id, event, detail, ts) VALUES (?, ?, ?, ?)",
            (task_id, event, detail, _iso(datetime.now(timezone.utc))),
        )
        _retry_commit(self._conn)

    def list_audit(self, task_id: str) -> List[dict]:
        rows = self._conn.execute(
            "SELECT * FROM audit_log WHERE task_id = ? ORDER BY id",
            (task_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ---------------- 取消 (P1-4) ----------------

    def request_cancel(self, task_id: str) -> None:
        """写入取消请求标记 (任务取消为阶段边界生效)。

        标记存于 tasks.cancel_requested 列, 而非 audit_log 事件——审计事件
        append-only 永不消失, 崩溃恢复后 resume 会被旧标记再次取消 (审计 3.1)。
        """
        self._conn.execute(
            "UPDATE tasks SET cancel_requested = 1 WHERE id = ?", (task_id,)
        )
        _retry_commit(self._conn)
        self.append_audit(task_id, "task_cancel_requested", "用户请求取消")

    def clear_cancel(self, task_id: str) -> None:
        """清除取消标记 (任务重新进入 RUNNING 时调用, 让 resume 成为干净新开始)。"""
        self._conn.execute(
            "UPDATE tasks SET cancel_requested = 0 WHERE id = ?", (task_id,)
        )
        _retry_commit(self._conn)

    def is_cancel_requested(self, task_id: str) -> bool:
        """是否已请求取消该任务。"""
        row = self._conn.execute(
            "SELECT cancel_requested FROM tasks WHERE id = ?", (task_id,)
        ).fetchone()
        return bool(row and row["cancel_requested"])
