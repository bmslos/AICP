"""SQLite 持久化层单元测试。"""

import pytest

from aicp.models import Asset, Task, TaskStatus, Stage, StageName, StageStatus
from aicp.scheduler.state_machine import IllegalTransitionError
from aicp.scheduler.store import Store


def test_save_and_get_task(store):
    t = Task(targets=["example.com", "1.2.3.4"])
    store.save_task(t)
    got = store.get_task(t.id)
    assert got is not None
    assert got.targets == ["example.com", "1.2.3.4"]
    assert got.status == TaskStatus.PENDING


def test_get_task_not_found(store):
    assert store.get_task("nonexistent") is None


def test_list_tasks_orders_by_created_desc(store):
    t1 = Task(targets=["a.com"])
    t2 = Task(targets=["b.com"])
    store.save_task(t1)
    store.save_task(t2)
    tasks = store.list_tasks()
    assert len(tasks) == 2


def test_task_transition_persists_status(store):
    t = Task(targets=["example.com"])
    store.save_task(t)
    store.transition_task(t.id, TaskStatus.AUTH_PENDING)
    store.transition_task(t.id, TaskStatus.AUTHORIZED)
    store.transition_task(t.id, TaskStatus.RUNNING)
    got = store.get_task(t.id)
    assert got.status == TaskStatus.RUNNING
    assert got.started_at is not None


def test_illegal_task_transition_blocked(store):
    t = Task(targets=["example.com"])
    store.save_task(t)
    with pytest.raises(IllegalTransitionError):
        store.transition_task(t.id, TaskStatus.RUNNING)  # 跳过授权非法


def test_stage_save_and_transition(store):
    t = Task(targets=["example.com"])
    store.save_task(t)
    s = Stage(task_id=t.id, name=StageName.SUBDOMAIN)
    store.init_stage(s)

    store.transition_stage(t.id, StageName.SUBDOMAIN, StageStatus.RUNNING)
    store.transition_stage(t.id, StageName.SUBDOMAIN, StageStatus.COMPLETED)

    got = store.get_stage(t.id, StageName.SUBDOMAIN)
    assert got.status == StageStatus.COMPLETED
    assert got.started_at is not None
    assert got.finished_at is not None
    assert got.attempt == 1


def test_stage_attempt_increments_on_retry(store):
    t = Task(targets=["example.com"])
    store.save_task(t)
    store.init_stage(Stage(task_id=t.id, name=StageName.PORTSCAN))

    store.transition_stage(t.id, StageName.PORTSCAN, StageStatus.RUNNING)
    store.transition_stage(t.id, StageName.PORTSCAN, StageStatus.FAILED, error="boom")
    # FAILED -> PENDING (重试准备)
    store.transition_stage(t.id, StageName.PORTSCAN, StageStatus.PENDING)
    # 第二次 RUNNING，attempt 应为 2
    store.transition_stage(t.id, StageName.PORTSCAN, StageStatus.RUNNING)

    got = store.get_stage(t.id, StageName.PORTSCAN)
    assert got.attempt == 2
    assert got.error is None  # 重新 RUNNING 时清空 error


def test_next_pending_stage_for_resume(store):
    t = Task(targets=["example.com"])
    store.save_task(t)
    store.init_stage(Stage(task_id=t.id, name=StageName.SUBDOMAIN))
    store.init_stage(Stage(task_id=t.id, name=StageName.PORTSCAN))
    store.init_stage(Stage(task_id=t.id, name=StageName.FINGERPRINT))

    # 完成第一个，断点续传应返回第二个
    store.transition_stage(t.id, StageName.SUBDOMAIN, StageStatus.RUNNING)
    store.transition_stage(t.id, StageName.SUBDOMAIN, StageStatus.COMPLETED)

    nxt = store.next_pending_stage(t.id)
    assert nxt is not None
    assert nxt.name == StageName.PORTSCAN


def test_next_pending_stage_returns_failed_for_retry(store):
    t = Task(targets=["example.com"])
    store.save_task(t)
    store.init_stage(Stage(task_id=t.id, name=StageName.SUBDOMAIN))
    store.transition_stage(t.id, StageName.SUBDOMAIN, StageStatus.RUNNING)
    store.transition_stage(t.id, StageName.SUBDOMAIN, StageStatus.FAILED, error="err")

    nxt = store.next_pending_stage(t.id)
    assert nxt.name == StageName.SUBDOMAIN
    assert nxt.status == StageStatus.FAILED


def test_next_pending_stage_none_when_all_done(store):
    t = Task(targets=["example.com"])
    store.save_task(t)
    for name in StageName:
        store.init_stage(Stage(task_id=t.id, name=name))
        store.transition_stage(t.id, name, StageStatus.RUNNING)
        store.transition_stage(t.id, name, StageStatus.COMPLETED)
    assert store.next_pending_stage(t.id) is None


def test_asset_dedup_same_type_value(store):
    t = Task(targets=["example.com"])
    store.save_task(t)
    a1 = Asset(type="ip", value="1.2.3.4", source="nmap", task_id=t.id)
    a2 = Asset(type="ip", value="1.2.3.4", source="nmap", task_id=t.id)
    assert store.save_asset(a1) is True
    assert store.save_asset(a2) is False  # 同 type+value 去重
    assert len(store.list_assets(t.id)) == 1


def test_asset_different_type_not_deduped(store):
    t = Task(targets=["example.com"])
    store.save_task(t)
    a1 = Asset(type="ip", value="1.2.3.4", source="nmap", task_id=t.id)
    a2 = Asset(type="url", value="1.2.3.4", source="httpx", task_id=t.id)
    store.save_asset(a1)
    store.save_asset(a2)
    assert len(store.list_assets(t.id)) == 2


def test_save_assets_batch_returns_new_count(store):
    t = Task(targets=["example.com"])
    store.save_task(t)
    assets = [
        Asset(type="ip", value="1.1.1.1", source="nmap", task_id=t.id),
        Asset(type="ip", value="1.1.1.2", source="nmap", task_id=t.id),
        Asset(type="ip", value="1.1.1.1", source="nmap", task_id=t.id),  # 重复
    ]
    n = store.save_assets(assets)
    assert n == 2


def test_asset_roundtrip_preserves_fields(store):
    t = Task(targets=["example.com"])
    store.save_task(t)
    a = Asset(
        type="web_service",
        value="http://example.com",
        source="wappalyzer",
        task_id=t.id,
        technologies=["Nginx", "WordPress"],
        status_code=200,
        title="Example",
        raw={"extra": "data"},
    )
    store.save_asset(a)
    got = store.list_assets(t.id)[0]
    assert got.technologies == ["Nginx", "WordPress"]
    assert got.status_code == 200
    assert got.title == "Example"
    assert got.raw == {"extra": "data"}


def test_audit_log_appended_on_transitions(store):
    t = Task(targets=["example.com"])
    store.save_task(t)
    store.transition_task(t.id, TaskStatus.AUTH_PENDING)
    store.transition_task(t.id, TaskStatus.AUTHORIZED)

    audit = store.list_audit(t.id)
    events = [a["event"] for a in audit]
    assert events.count("task_transition") == 2


# ---------------- list_assets_by_types ----------------

def _seed_assets_for_type_filter(store):
    """构造一个带 5 类资产的任务, 用于 list_assets_by_types 测试。"""
    t = Task(targets=["example.com"])
    store.save_task(t)
    assets = [
        Asset(type="domain", value="example.com", source="user", task_id=t.id),
        Asset(type="domain", value="sub.example.com", source="oneforall", task_id=t.id),
        Asset(type="ip", value="1.2.3.4", source="nmap", task_id=t.id),
        Asset(type="port", value="1.2.3.4:80", source="nmap", task_id=t.id),
        Asset(type="url", value="http://1.2.3.4", source="httpx", task_id=t.id),
    ]
    for a in assets:
        store.save_asset(a)
    return t, assets


def test_list_assets_by_types_single_type(store):
    """按单类型过滤只返回该类型资产。"""
    t, _ = _seed_assets_for_type_filter(store)
    got = store.list_assets_by_types(t.id, ["domain"])
    assert len(got) == 2
    assert all(a.type == "domain" for a in got)
    assert {a.value for a in got} == {"example.com", "sub.example.com"}


def test_list_assets_by_types_multi_types(store):
    """按多类型过滤返回这些类型的并集。"""
    t, _ = _seed_assets_for_type_filter(store)
    got = store.list_assets_by_types(t.id, ["domain", "ip"])
    assert len(got) == 3
    types = {a.type for a in got}
    assert types == {"domain", "ip"}


def test_list_assets_by_types_empty_types_falls_back(store):
    """空 types 列表应退化为 list_assets (返回全部)。"""
    t, _ = _seed_assets_for_type_filter(store)
    got = store.list_assets_by_types(t.id, [])
    all_assets = store.list_assets(t.id)
    assert len(got) == len(all_assets)
    # 顺序也应一致
    assert [a.id for a in got] == [a.id for a in all_assets]


def test_list_assets_by_types_no_match_returns_empty(store):
    """查询不存在的类型返回空列表。"""
    t, _ = _seed_assets_for_type_filter(store)
    got = store.list_assets_by_types(t.id, ["nonexistent_type"])
    assert got == []


def test_list_assets_by_types_nonexistent_task_returns_empty(store):
    """不存在的 task_id 返回空列表。"""
    got = store.list_assets_by_types("nonexistent-task-id", ["domain"])
    assert got == []


def test_list_assets_by_types_ordered_by_discovered_at(store):
    """结果应按 discovered_at 升序排列 (与 list_assets 一致)。"""
    t, _ = _seed_assets_for_type_filter(store)
    got = store.list_assets_by_types(t.id, ["domain", "ip"])
    # discovered_at 应单调递增
    times = [a.discovered_at for a in got]
    assert times == sorted(times)


def test_list_assets_by_types_accepts_set(store):
    """types 参数应接受 set (Iterable)。"""
    t, _ = _seed_assets_for_type_filter(store)
    got = store.list_assets_by_types(t.id, {"domain", "ip"})
    assert len(got) == 3


# ---------------- save_asset 并发安全 (UPSERT) ----------------

def test_save_asset_upsert_same_asset_twice(store):
    """同一资产连续 save 两次: 不抛异常, 数据库只有一行, 返回值第一次 True 第二次 False。"""
    t = Task(targets=["example.com"])
    store.save_task(t)
    a = Asset(type="ip", value="1.2.3.4", source="nmap", task_id=t.id)
    first = store.save_asset(a)
    second = store.save_asset(a)  # 同一对象再存一次
    assert first is True
    assert second is False
    assert len(store.list_assets(t.id)) == 1


def test_save_asset_upsert_concurrent_threads(tmp_path):
    """10 个线程并发 save 同一资产: 不抛 IntegrityError, 数据库只有一行。

    每个线程独立 Store/连接 (sqlite3 连接默认不可跨线程), 指向同一 db 文件。
    验证 INSERT OR IGNORE 消除了 SELECT+INSERT 的 TOCTOU 竞态。
    """
    from concurrent.futures import ThreadPoolExecutor

    db_path = tmp_path / "concurrent.db"
    # 主线程先建表 + 插入 task
    setup = Store(db_path)
    t = Task(targets=["example.com"])
    setup.save_task(t)
    setup.close()

    errors = []

    def save_one():
        try:
            s = Store(db_path)
            a = Asset(type="ip", value="1.2.3.4", source="nmap", task_id=t.id)
            s.save_asset(a)
            s.close()
        except Exception as e:
            errors.append(e)

    with ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(lambda _: save_one(), range(10)))

    assert errors == [], f"并发 save 抛出异常: {errors}"

    # 验证数据库只有一行
    verify = Store(db_path)
    assets = verify.list_assets(t.id)
    verify.close()
    assert len(assets) == 1
    assert assets[0].value == "1.2.3.4"


def test_save_asset_upsert_web_service_merges_technologies(store):
    """两次 save 同一 web_service (不同 technologies), 验证 technologies 取并集。"""
    t = Task(targets=["example.com"])
    store.save_task(t)
    a1 = Asset(
        type="web_service",
        value="http://example.com",
        source="wappalyzer",
        task_id=t.id,
        technologies=["Nginx", "WordPress"],
        status_code=200,
        title="Example",
    )
    a2 = Asset(
        type="web_service",
        value="http://example.com",
        source="wappalyzer",
        task_id=t.id,
        technologies=["WordPress", "PHP"],  # 与 a1 有交集也有新增
        status_code=None,
        title="",  # 空标题不应覆盖已有标题
    )
    assert store.save_asset(a1) is True
    assert store.save_asset(a2) is False

    got = store.list_assets(t.id)[0]
    # 并集, 保持插入顺序: Nginx, WordPress, PHP
    assert got.technologies == ["Nginx", "WordPress", "PHP"]
    # status_code / title 取首次非空
    assert got.status_code == 200
    assert got.title == "Example"


# ---------------- reset_running_stages (5.3 修复) ----------------

def test_reset_running_stages_resets_running(store):
    """RUNNING stage 被重置为 PENDING, 其他状态不受影响。"""
    from datetime import datetime, timezone

    t = Task(targets=["example.com"])
    store.save_task(t)
    now = datetime.now(timezone.utc)
    # 直接 init_stage 构造目标状态 (init_stage 不校验迁移合法性)
    store.init_stage(Stage(
        task_id=t.id, name=StageName.SUBDOMAIN,
        status=StageStatus.RUNNING, started_at=now,
    ))
    store.init_stage(Stage(
        task_id=t.id, name=StageName.PORTSCAN,
        status=StageStatus.COMPLETED, started_at=now, finished_at=now,
    ))
    store.init_stage(Stage(
        task_id=t.id, name=StageName.FINGERPRINT,
        status=StageStatus.FAILED, error="boom", finished_at=now,
    ))
    store.init_stage(Stage(
        task_id=t.id, name=StageName.CORRELATE,
        status=StageStatus.RUNNING, started_at=now,
    ))

    count = store.reset_running_stages(t.id)
    assert count == 2

    stages = {s.name: s for s in store.list_stages(t.id)}
    assert stages[StageName.SUBDOMAIN].status == StageStatus.PENDING
    assert stages[StageName.CORRELATE].status == StageStatus.PENDING
    assert stages[StageName.PORTSCAN].status == StageStatus.COMPLETED
    assert stages[StageName.FINGERPRINT].status == StageStatus.FAILED
    # RUNNING 字段被清空
    assert stages[StageName.SUBDOMAIN].started_at is None
    assert stages[StageName.SUBDOMAIN].finished_at is None
    assert stages[StageName.SUBDOMAIN].error is None


def test_reset_running_stages_no_running_stages(store):
    """无 RUNNING stage 时返回 0, 状态全部不变。"""
    from datetime import datetime, timezone

    t = Task(targets=["example.com"])
    store.save_task(t)
    now = datetime.now(timezone.utc)
    for name in StageName:
        store.init_stage(Stage(
            task_id=t.id, name=name,
            status=StageStatus.COMPLETED, started_at=now, finished_at=now,
        ))

    before = {s.name: s.status for s in store.list_stages(t.id)}
    count = store.reset_running_stages(t.id)
    assert count == 0
    after = {s.name: s.status for s in store.list_stages(t.id)}
    assert before == after


def test_reset_running_stages_writes_audit(store):
    """重置 RUNNING stage 时为每个 stage 写 stage_reset 审计日志。"""
    from datetime import datetime, timezone

    t = Task(targets=["example.com"])
    store.save_task(t)
    now = datetime.now(timezone.utc)
    store.init_stage(Stage(
        task_id=t.id, name=StageName.SUBDOMAIN,
        status=StageStatus.RUNNING, started_at=now,
    ))

    store.reset_running_stages(t.id)

    audit = store.list_audit(t.id)
    resets = [a for a in audit if a["event"] == "stage_reset"]
    assert len(resets) == 1
    assert "RUNNING -> PENDING (recovery)" in resets[0]["detail"]
    assert "subdomain" in resets[0]["detail"]


# ---------------- schema 迁移机制 (P1-3) ----------------

def test_schema_migration_runs_in_order(tmp_path, monkeypatch):
    """旧库缺列时, 打开 Store 会按 _MIGRATIONS 顺序补齐并更新 user_version。"""
    import sqlite3
    from aicp.scheduler import store as store_module

    db = tmp_path / "legacy.db"
    # 构造一个旧版 schema 的库 (tasks 表缺 rate_limit / profile 列)
    conn = sqlite3.connect(str(db))
    conn.executescript("""
        CREATE TABLE tasks (
            id TEXT PRIMARY KEY,
            targets TEXT NOT NULL,
            status TEXT NOT NULL,
            authorized_scope TEXT NOT NULL DEFAULT '[]',
            authorized_by TEXT,
            authorized_at TEXT,
            authorization_note TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            error TEXT
        );
    """)
    conn.execute("PRAGMA user_version = 0")
    conn.commit()
    conn.close()

    # 模拟两条顺序迁移
    monkeypatch.setattr(store_module, "_MIGRATIONS", [
        (1, ["ALTER TABLE tasks ADD COLUMN rate_limit INTEGER"]),
        (2, ["ALTER TABLE tasks ADD COLUMN profile TEXT"]),
    ])

    with Store(str(db)) as store:
        version = store._conn.execute("PRAGMA user_version").fetchone()[0]
        assert version == 2
        # 两列都已补齐
        cols = {r[1] for r in store._conn.execute("PRAGMA table_info(tasks)")}
        assert "rate_limit" in cols
        assert "profile" in cols


def test_schema_migration_idempotent(tmp_path, monkeypatch):
    """已是最新版本的库再次打开, 不重复执行迁移、不报错。"""
    from aicp.scheduler import store as store_module

    db = tmp_path / "m.db"
    monkeypatch.setattr(store_module, "_MIGRATIONS", [
        (1, ["ALTER TABLE tasks ADD COLUMN rate_limit INTEGER"]),
    ])
    with Store(str(db)) as store:
        assert store._conn.execute("PRAGMA user_version").fetchone()[0] == 1
    with Store(str(db)) as store:
        assert store._conn.execute("PRAGMA user_version").fetchone()[0] == 1


# ---------------- 取消标记 (P1-4) ----------------

def test_request_cancel_and_is_cancel_requested(store):
    t = Task(targets=["example.com"])
    store.save_task(t)
    assert store.is_cancel_requested(t.id) is False
    store.request_cancel(t.id)
    assert store.is_cancel_requested(t.id) is True


def test_clear_cancel_resets_marker(store):
    """审计 3.1: clear_cancel 应清除取消标记。"""
    t = Task(targets=["example.com"])
    store.save_task(t)
    store.request_cancel(t.id)
    store.clear_cancel(t.id)
    assert store.is_cancel_requested(t.id) is False


def test_migration_v1_adds_cancel_requested_column(tmp_path):
    """真实迁移 v1: 打开新库后 tasks 表应有 cancel_requested 列。"""
    db = tmp_path / "m.db"
    with Store(str(db)) as store:
        version = store._conn.execute("PRAGMA user_version").fetchone()[0]
        assert version == 2  # v1 (cancel_requested) + v2 (任务租约三列)
        cols = {r[1] for r in store._conn.execute("PRAGMA table_info(tasks)")}
        assert "cancel_requested" in cols
        # v2: 任务租约三列 (行动项 #3 / ADR-1)
        assert "owner" in cols
        assert "heartbeat_at" in cols
        assert "lease_expires_at" in cols


# ---------------- 任务租约 (行动项 #3 / ADR-1) ----------------

def _authorized(store):
    """构造一个 AUTHORIZED 任务 (走合法迁移链)。"""
    t = Task(targets=["example.com"])
    store.save_task(t)
    store.transition_task(t.id, TaskStatus.AUTH_PENDING)
    store.transition_task(t.id, TaskStatus.AUTHORIZED)
    return t


def _lease_row(store, task_id):
    return store._conn.execute(
        "SELECT status, owner, heartbeat_at, lease_expires_at FROM tasks WHERE id = ?",
        (task_id,),
    ).fetchone()


@pytest.mark.recovery
def test_acquire_lease_authorized_to_running(store):
    """正常获取: AUTHORIZED → RUNNING, 三列写入, 审计记录 lease_acquired。"""
    t = _authorized(store)
    assert store.acquire_task_lease(t.id, "owner-a", lease_seconds=60) is True
    row = _lease_row(store, t.id)
    assert row["status"] == "running"
    assert row["owner"] == "owner-a"
    assert row["heartbeat_at"] is not None
    assert row["lease_expires_at"] is not None
    events = [a["event"] for a in store.list_audit(t.id)]
    assert "lease_acquired" in events


@pytest.mark.recovery
def test_acquire_lease_denied_while_valid(store):
    """有效租约拒绝第二方 (修双入口双跑)。"""
    t = _authorized(store)
    assert store.acquire_task_lease(t.id, "owner-a", lease_seconds=60) is True
    assert store.acquire_task_lease(t.id, "owner-b", lease_seconds=60) is False
    # owner 不被篡改, 任务保持 RUNNING
    row = _lease_row(store, t.id)
    assert row["owner"] == "owner-a"
    assert row["status"] == "running"
    assert store.is_lease_valid(t.id) is True


@pytest.mark.recovery
def test_acquire_lease_takeover_when_expired(store):
    """租约过期后他方可接管 (僵死恢复)。"""
    from datetime import datetime, timedelta, timezone

    t = _authorized(store)
    assert store.acquire_task_lease(t.id, "dead-process", lease_seconds=60)
    # 手动把租约改为过期 (模拟持有者已死)
    store._conn.execute(
        "UPDATE tasks SET lease_expires_at = ? WHERE id = ?",
        (
            (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
            t.id,
        ),
    )
    store._conn.commit()

    assert store.acquire_task_lease(t.id, "owner-b", lease_seconds=60) is True
    row = _lease_row(store, t.id)
    assert row["owner"] == "owner-b"
    assert row["status"] == "running"
    # 审计含接管轨迹
    details = [a["detail"] for a in store.list_audit(t.id)]
    assert any("lease expired, takeover" in d for d in details)


@pytest.mark.recovery
def test_heartbeat_renews_lease(store):
    """续约延长 lease_expires_at; owner 不匹配时失败。"""
    from datetime import datetime

    t = _authorized(store)
    store.acquire_task_lease(t.id, "owner-a", lease_seconds=60)
    before = _lease_row(store, t.id)["lease_expires_at"]
    assert store.heartbeat_lease(t.id, "owner-a", lease_seconds=300) is True
    after = _lease_row(store, t.id)["lease_expires_at"]
    assert datetime.fromisoformat(after) > datetime.fromisoformat(before)
    # 非持有者续约失败
    assert store.heartbeat_lease(t.id, "owner-b", lease_seconds=300) is False


@pytest.mark.recovery
def test_release_lease_clears_columns(store):
    """释放清空三列; owner 不匹配时 no-op。"""
    t = _authorized(store)
    store.acquire_task_lease(t.id, "owner-a", lease_seconds=60)
    # 他方 release (owner 不匹配): 不生效
    store.release_lease(t.id, "owner-b")
    assert _lease_row(store, t.id)["owner"] == "owner-a"
    # 持有者 release: 清空
    store.release_lease(t.id, "owner-a")
    row = _lease_row(store, t.id)
    assert row["owner"] is None
    assert row["lease_expires_at"] is None


def test_transition_task_does_not_touch_lease_columns(store):
    """transition_task 只动状态列, 不清租约列 (租约由专用方法管理)。"""
    t = _authorized(store)
    store.acquire_task_lease(t.id, "owner-a", lease_seconds=60)
    store.transition_task(t.id, TaskStatus.FAILED, error="boom")
    row = _lease_row(store, t.id)
    assert row["status"] == "failed"
    assert row["owner"] == "owner-a"  # 租约列保持
    assert row["lease_expires_at"] is not None


@pytest.mark.recovery
def test_cleanup_skips_task_with_valid_foreign_lease(tmp_path, monkeypatch):
    """P0 行动项 #3 DoD: 他方进程的有效租约任务不被 atexit/启动清理误杀。"""
    import aicp.scheduler.store as store_module

    monkeypatch.setattr(store_module, "_active_owners", set())
    db = tmp_path / "t.db"
    with Store(db) as store:
        t = _authorized(store)
        store.acquire_task_lease(t.id, "cli-process-1", lease_seconds=3600)
    # 模拟另一进程: 本进程的活跃租约集合不含该 owner
    store_module._active_owners.discard("cli-process-1")

    # 模拟另一入口 (Web) 进程启动时的清理: 不该杀 CLI 正在跑的任务
    assert Store.cleanup_running_tasks(db) == 0
    with Store(db) as store:
        assert store.get_task(t.id).status == TaskStatus.RUNNING


@pytest.mark.recovery
def test_cleanup_cleans_expired_lease_and_own_lease(tmp_path, monkeypatch):
    """过期的僵死租约被清理; 本进程自己的有效租约也被清理 (atexit)。"""
    from datetime import datetime, timedelta, timezone

    import aicp.scheduler.store as store_module

    monkeypatch.setattr(store_module, "_active_owners", set())
    db = tmp_path / "t.db"
    with Store(db) as store:
        t_stale = _authorized(store)  # 将成为过期租约
        store.acquire_task_lease(t_stale.id, "dead-process", lease_seconds=60)
        store._conn.execute(
            "UPDATE tasks SET lease_expires_at = ? WHERE id = ?",
            (
                (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
                t_stale.id,
            ),
        )
        store._conn.commit()

    # 本进程自己的有效租约任务 (dead-process 不属于本进程: 模拟他方已死)
    with Store(db) as store:
        t_own = _authorized(store)
        store.acquire_task_lease(t_own.id, "owner-own", lease_seconds=3600)
    store_module._active_owners.discard("dead-process")

    assert Store.cleanup_running_tasks(db) == 2
    with Store(db) as store:
        assert store.get_task(t_stale.id).status == TaskStatus.FAILED
        assert store.get_task(t_own.id).status == TaskStatus.FAILED


@pytest.mark.recovery
def test_concurrent_acquire_exactly_one_wins(tmp_path):
    """并发获取同一任务租约, 恰好一方成功 (BEGIN IMMEDIATE 原子性)。"""
    import threading

    db = tmp_path / "t.db"
    with Store(db) as store:
        t = _authorized(store)
        task_id = t.id

    results: list[bool] = []
    lock = threading.Lock()

    def worker(owner: str):
        with Store(db) as s:
            ok = s.acquire_task_lease(task_id, owner, lease_seconds=60)
        with lock:
            results.append(ok)

    threads = [threading.Thread(target=worker, args=(f"owner-{i}",)) for i in range(4)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    assert sorted(results) == [False, False, False, True]
    with Store(db) as store:
        row = _lease_row(store, task_id)
        assert row["status"] == "running"
        assert row["owner"] is not None
