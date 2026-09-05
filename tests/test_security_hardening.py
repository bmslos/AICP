"""安全加固相关单元测试。

覆盖两个改进:
1. 内网 IP 黑名单 - AuthorizationVerifier 的 allow_private 校验与辅助函数
2. atexit 钩子 - Store.cleanup_running_tasks 与 CLI 的 _register_atexit_cleanup
"""

from __future__ import annotations

import atexit

import pytest
from click.testing import CliRunner

from aicp import cli as cli_module
from aicp.auth import AuthorizationError, AuthorizationVerifier
from aicp.auth.verifier import (
    _cidr_contains_private,
    _extract_host,
    _is_private_or_reserved,
)
from aicp.cli import main
from aicp.models import Task, TaskStatus
from aicp.scheduler import Store


# ================================================================
# 1. 模块级辅助函数: _is_private_or_reserved
# ================================================================

@pytest.mark.parametrize("ip", [
    "10.0.0.1",          # RFC 1918
    "10.255.255.255",
    "172.16.0.1",        # RFC 1918
    "172.31.255.255",
    "192.168.1.1",       # RFC 1918
    "127.0.0.1",         # loopback
    "127.255.255.255",
    "169.254.169.254",   # link-local / 云元数据 (SSRF 高危)
    "169.254.0.1",
    "0.0.0.0",           # "本机" 段
    "0.255.255.255",
    "224.0.0.1",         # 组播
    "239.255.255.255",
    "240.0.0.1",         # 保留 (E 类)
    "255.255.255.255",
    "::1",               # IPv6 loopback
    "fc00::1",           # IPv6 唯一本地
    "fd00::1",
    "fe80::1",           # IPv6 link-local
    "::",                # IPv6 未指定
])
def test_is_private_or_reserved_returns_true(ip):
    """私有/保留 IP 应被识别为 True (默认拒绝)。"""
    assert _is_private_or_reserved(ip) is True


@pytest.mark.parametrize("ip", [
    "1.1.1.1",           # Cloudflare DNS
    "8.8.8.8",           # Google DNS
    "172.32.0.1",        # 紧邻 172.16/12 之外 (公网)
    "192.169.0.1",       # 紧邻 192.168/16 之外 (公网)
    "11.0.0.1",          # 紧邻 10/8 之外
    "2001:4860:4860::8888",  # Google IPv6 DNS
    "2606:4700:4700::1111",  # Cloudflare IPv6
])
def test_is_private_or_reserved_returns_false(ip):
    """公网 IP 应返回 False。"""
    assert _is_private_or_reserved(ip) is False


def test_is_private_or_reserved_non_ip_returns_false():
    """非 IP 字符串 (域名) 应返回 False, 走域名校验路径。"""
    assert _is_private_or_reserved("example.com") is False
    assert _is_private_or_reserved("not-an-ip") is False
    assert _is_private_or_reserved("") is False


# ================================================================
# 1b. IPv4 映射 IPv6 SSRF 绕过防护
# ================================================================

def test_ipv4_mapped_ipv6_cloud_metadata_blocked():
    """::ffff:169.254.169.254 (云元数据 IPv4 映射 IPv6) 应被判为私有。"""
    assert _is_private_or_reserved("::ffff:169.254.169.254") is True


def test_ipv4_mapped_ipv6_loopback_blocked():
    """::ffff:127.0.0.1 (loopback IPv4 映射 IPv6) 应被判为私有。"""
    assert _is_private_or_reserved("::ffff:127.0.0.1") is True


def test_ipv4_mapped_ipv6_public_not_blocked():
    """::ffff:8.8.8.8 (公网 IPv4 映射 IPv6) 不应被误判为私有。"""
    assert _is_private_or_reserved("::ffff:8.8.8.8") is False


def test_ipv4_mapped_ipv6_private_class_blocked():
    """::ffff:10.0.0.1 (RFC 1918 IPv4 映射 IPv6) 应被判为私有。"""
    assert _is_private_or_reserved("::ffff:10.0.0.1") is True


def test_ipv4_mapped_ipv6_in_authorization_verify():
    """AuthorizationVerifier.verify 应拒绝 ::ffff:169.254.169.254 target (防 SSRF)。"""
    v = AuthorizationVerifier()
    t = _make_task(["::ffff:169.254.169.254"])
    with pytest.raises(AuthorizationError, match="私有/保留 IP"):
        v.verify(
            t,
            authorized_by="张三",
            authorization_note="AUTH-001",
            authorized_scope=["::ffff:169.254.0.0/112"],
        )


# ================================================================
# 2. 模块级辅助函数: _cidr_contains_private
# ================================================================

@pytest.mark.parametrize("cidr", [
    "10.0.0.0/24",       # 整段私有
    "10.0.0.0/8",        # 整段私有
    "192.168.0.0/16",
    "172.16.0.0/12",
    "127.0.0.0/8",
    "169.254.0.0/16",    # 含云元数据
    "0.0.0.0/8",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    # 与私有段有交集
    "10.0.0.0/7",        # 包含 10.0.0.0/8 的部分
    "172.0.0.0/8",       # 跨越 172.16/12 边界
])
def test_cidr_contains_private_returns_true(cidr):
    """含私有/保留地址的 CIDR 应返回 True。"""
    assert _cidr_contains_private(cidr) is True


@pytest.mark.parametrize("cidr", [
    "1.0.0.0/24",        # 纯公网
    "8.8.8.0/24",
    "172.32.0.0/11",     # 紧邻 172.16/12 之外
    "192.169.0.0/16",    # 紧邻 192.168/16 之外
    "2001:db8::/32",     # 文档用途 IPv6 (不在黑名单)
])
def test_cidr_contains_private_returns_false(cidr):
    """纯公网 CIDR 应返回 False。"""
    assert _cidr_contains_private(cidr) is False


def test_cidr_contains_private_invalid_returns_false():
    """非法 CIDR 应返回 False (不抛异常)。"""
    assert _cidr_contains_private("not-a-cidr") is False
    assert _cidr_contains_private("999.999.999.999/24") is False


# ================================================================
# 3. 模块级辅助函数: _extract_host
# ================================================================

@pytest.mark.parametrize("target,expected", [
    ("10.0.0.1", "10.0.0.1"),
    ("example.com", "example.com"),
    ("1.2.3.4:80", "1.2.3.4"),
    ("http://10.0.0.1/path", "10.0.0.1"),
    ("https://10.0.0.1:8443/path?q=1", "10.0.0.1"),
    ("http://example.com/", "example.com"),
    ("[::1]:80", "::1"),
    ("http://[::1]:8080/", "::1"),
    ("  10.0.0.1  ", "10.0.0.1"),  # 前后空格
    ("", ""),
])
def test_extract_host(target, expected):
    """URL / host:port / IPv6 等格式都应正确提取 host。"""
    assert _extract_host(target) == expected


# ================================================================
# 4. AuthorizationVerifier.verify 的 allow_private 行为
# ================================================================

def _make_task(targets):
    return Task(targets=list(targets))


def test_verify_rejects_private_ip_target_by_default():
    """默认应拒绝 10.0.0.0/8 等私有 IP target。"""
    v = AuthorizationVerifier()
    t = _make_task(["10.0.0.1"])
    with pytest.raises(AuthorizationError, match="私有/保留 IP"):
        v.verify(
            t,
            authorized_by="张三",
            authorization_note="AUTH-001",
            authorized_scope=["10.0.0.0/24"],
        )


def test_verify_rejects_loopback_target_by_default():
    """默认应拒绝 127.0.0.0/8 loopback。"""
    v = AuthorizationVerifier()
    t = _make_task(["127.0.0.1"])
    with pytest.raises(AuthorizationError, match="私有/保留 IP"):
        v.verify(
            t,
            authorized_by="张三",
            authorization_note="AUTH-001",
            authorized_scope=["127.0.0.0/8"],
        )


def test_verify_rejects_linklocal_target_by_default():
    """默认应拒绝 169.254.169.254 云元数据 IP (防 SSRF)。"""
    v = AuthorizationVerifier()
    t = _make_task(["169.254.169.254"])
    with pytest.raises(AuthorizationError, match="私有/保留 IP"):
        v.verify(
            t,
            authorized_by="张三",
            authorization_note="AUTH-001",
            authorized_scope=["169.254.0.0/16"],
        )


def test_verify_rejects_private_ip_in_url_target():
    """URL 形式的 target 也应提取 host 后校验。"""
    v = AuthorizationVerifier()
    t = _make_task(["http://10.0.0.1/"])
    with pytest.raises(AuthorizationError, match="私有/保留 IP"):
        v.verify(
            t,
            authorized_by="张三",
            authorization_note="AUTH-001",
            authorized_scope=["10.0.0.0/24"],
        )


def test_verify_rejects_ipv6_loopback_target_by_default():
    """默认应拒绝 ::1 IPv6 loopback。"""
    v = AuthorizationVerifier()
    t = _make_task(["::1"])
    with pytest.raises(AuthorizationError, match="私有/保留 IP"):
        v.verify(
            t,
            authorized_by="张三",
            authorization_note="AUTH-001",
            authorized_scope=["::1/128"],
        )


def test_verify_rejects_private_ip_in_scope_by_default():
    """scope 含私有 IP 也应拒绝 (即使 target 不含)。"""
    v = AuthorizationVerifier()
    t = _make_task(["example.com"])
    with pytest.raises(AuthorizationError, match="授权范围含私有/保留 IP"):
        v.verify(
            t,
            authorized_by="张三",
            authorization_note="AUTH-001",
            authorized_scope=["example.com", "10.0.0.1"],
        )


def test_verify_rejects_private_cidr_in_scope_by_default():
    """scope 含私有 CIDR 应拒绝。"""
    v = AuthorizationVerifier()
    t = _make_task(["example.com"])
    with pytest.raises(AuthorizationError, match="含私有/保留网段"):
        v.verify(
            t,
            authorized_by="张三",
            authorization_note="AUTH-001",
            authorized_scope=["example.com", "10.0.0.0/24"],
        )


def test_verify_allows_private_when_allow_private_true():
    """allow_private=True 时私有 IP target 通过校验。"""
    v = AuthorizationVerifier()
    t = _make_task(["10.0.0.1"])
    v.verify(
        t,
        authorized_by="张三",
        authorization_note="内网渗透测试授权书",
        authorized_scope=["10.0.0.0/24"],
        allow_private=True,
    )
    assert t.status == TaskStatus.AUTHORIZED
    assert t.authorized_by == "张三"


def test_verify_allows_private_cidr_in_scope_when_allow_private_true():
    """allow_private=True 时 scope 含私有 CIDR 也能通过。"""
    v = AuthorizationVerifier()
    t = _make_task(["10.0.0.5"])
    v.verify(
        t,
        authorized_by="张三",
        authorization_note="内网授权",
        authorized_scope=["10.0.0.0/24"],
        allow_private=True,
    )
    assert t.status == TaskStatus.AUTHORIZED


def test_verify_public_ip_target_passes_by_default():
    """公网 IP target 默认应通过 (无需 allow_private)。"""
    v = AuthorizationVerifier()
    t = _make_task(["1.2.3.4"])
    v.verify(
        t,
        authorized_by="张三",
        authorization_note="AUTH-001",
        authorized_scope=["1.2.3.4"],
    )
    assert t.status == TaskStatus.AUTHORIZED


def test_verify_domain_target_passes_by_default():
    """域名 target 默认应通过 (无 IP 字面量, 不触发黑名单)。"""
    v = AuthorizationVerifier()
    t = _make_task(["example.com"])
    v.verify(
        t,
        authorized_by="张三",
        authorization_note="AUTH-001",
        authorized_scope=["example.com"],
    )
    assert t.status == TaskStatus.AUTHORIZED


# ================================================================
# 5. CLI 的 --allow-private flag
# ================================================================

@pytest.fixture
def cli_runner():
    return CliRunner()


@pytest.fixture
def aicp_dir(tmp_path, monkeypatch):
    """切换 cwd 到临时目录, 让 .aicp/ 落在 tmp_path 下。"""
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def patched_tools(monkeypatch):
    """替换 _default_tools 为 mock 实现, 不依赖真实工具二进制。"""
    from tests.test_cli import _fake_all_tools
    monkeypatch.setattr(cli_module, "_default_tools", _fake_all_tools)
    return _fake_all_tools


def test_cli_scan_rejects_private_ip_by_default(cli_runner, aicp_dir, patched_tools):
    """scan 命令默认拒绝私有 IP target。"""
    result = cli_runner.invoke(main, [
        "scan", "10.0.0.1",
        "--authorized-by", "张三",
        "--authorization-note", "AUTH-001",
        "--scope", "10.0.0.0/24",
    ])
    assert result.exit_code != 0
    assert "私有/保留 IP" in result.output or "授权校验失败" in result.output


def test_cli_scan_allows_private_with_flag(cli_runner, aicp_dir, patched_tools):
    """scan --allow-private 时私有 IP target 通过授权校验。"""
    result = cli_runner.invoke(main, [
        "scan", "10.0.0.1",
        "--authorized-by", "张三",
        "--authorization-note", "内网授权",
        "--scope", "10.0.0.0/24",
        "--allow-private",
    ])
    # 通过授权校验即视为成功 (后续 mock 工具会跑完)
    assert "私有/保留 IP" not in result.output
    assert "授权校验失败" not in result.output


def test_cli_scan_rejects_metadata_ip_by_default(cli_runner, aicp_dir, patched_tools):
    """scan 默认拒绝 169.254.169.254 云元数据 IP (防 SSRF)。"""
    result = cli_runner.invoke(main, [
        "scan", "169.254.169.254",
        "--authorized-by", "张三",
        "--authorization-note", "AUTH-001",
        "--scope", "169.254.0.0/16",
    ])
    assert result.exit_code != 0
    assert "私有/保留 IP" in result.output or "授权校验失败" in result.output


# ================================================================
# 6. Store.cleanup_running_tasks (atexit 钩子核心)
# ================================================================

@pytest.mark.recovery
def test_cleanup_running_tasks_marks_running_as_failed(tmp_path):
    """RUNNING 状态的任务应被标记为 FAILED。"""
    db = tmp_path / "test.db"
    with Store(db) as store:
        t = Task(targets=["example.com"])
        store.save_task(t)
        # 走合法路径: PENDING -> AUTH_PENDING -> AUTHORIZED -> RUNNING
        store.transition_task(t.id, TaskStatus.AUTH_PENDING)
        store.transition_task(t.id, TaskStatus.AUTHORIZED)
        store.transition_task(t.id, TaskStatus.RUNNING)

    # 关闭 store 后调用静态方法 (模拟进程退出)
    n = Store.cleanup_running_tasks(db)
    assert n == 1

    # 重新打开验证状态
    with Store(db) as store:
        got = store.get_task(t.id)
        assert got.status == TaskStatus.FAILED
        assert got.error == "进程退出时未完成 (interrupted)"
        assert got.finished_at is not None


@pytest.mark.recovery
def test_cleanup_running_tasks_skips_non_running(tmp_path):
    """非 RUNNING 状态的任务应保持不变。"""
    db = tmp_path / "test.db"
    with Store(db) as store:
        t1 = Task(targets=["a.com"])  # 将保持 PENDING
        t2 = Task(targets=["b.com"])  # 将变成 COMPLETED
        store.save_task(t1)
        store.save_task(t2)
        store.transition_task(t2.id, TaskStatus.AUTH_PENDING)
        store.transition_task(t2.id, TaskStatus.AUTHORIZED)
        store.transition_task(t2.id, TaskStatus.RUNNING)
        store.transition_task(t2.id, TaskStatus.COMPLETED)

    n = Store.cleanup_running_tasks(db)
    assert n == 0

    with Store(db) as store:
        assert store.get_task(t1.id).status == TaskStatus.PENDING
        assert store.get_task(t2.id).status == TaskStatus.COMPLETED


@pytest.mark.recovery
def test_cleanup_running_tasks_handles_multiple(tmp_path):
    """多个 RUNNING 任务都应被清理。"""
    db = tmp_path / "test.db"
    with Store(db) as store:
        tasks = []
        for i in range(3):
            t = Task(targets=[f"t{i}.com"])
            store.save_task(t)
            store.transition_task(t.id, TaskStatus.AUTH_PENDING)
            store.transition_task(t.id, TaskStatus.AUTHORIZED)
            store.transition_task(t.id, TaskStatus.RUNNING)
            tasks.append(t)

    n = Store.cleanup_running_tasks(db)
    assert n == 3

    with Store(db) as store:
        for t in tasks:
            assert store.get_task(t.id).status == TaskStatus.FAILED


@pytest.mark.recovery
def test_cleanup_running_tasks_missing_db_returns_zero(tmp_path):
    """不存在的 db_path 应返回 0, 不抛异常 (atexit 钩子里不能抛)。"""
    missing = tmp_path / "nonexistent.db"
    n = Store.cleanup_running_tasks(missing)
    # 注意: Store() 会自动创建空 db, 但里面没有 RUNNING 任务, 返回 0
    assert n == 0


@pytest.mark.recovery
def test_cleanup_running_tasks_idempotent(tmp_path):
    """重复调用应安全: 第二次没有 RUNNING 任务, 返回 0。"""
    db = tmp_path / "test.db"
    with Store(db) as store:
        t = Task(targets=["example.com"])
        store.save_task(t)
        store.transition_task(t.id, TaskStatus.AUTH_PENDING)
        store.transition_task(t.id, TaskStatus.AUTHORIZED)
        store.transition_task(t.id, TaskStatus.RUNNING)

    assert Store.cleanup_running_tasks(db) == 1
    # 第二次: 任务已是 FAILED, 不应再次迁移
    assert Store.cleanup_running_tasks(db) == 0

    with Store(db) as store:
        got = store.get_task(t.id)
        assert got.status == TaskStatus.FAILED


# ================================================================
# 7. CLI 的 _register_atexit_cleanup (幂等性)
# ================================================================

def test_register_atexit_cleanup_is_idempotent(monkeypatch):
    """同一 db_path 多次注册只生效一次。"""
    # 清空全局集合, 隔离测试
    monkeypatch.setattr(cli_module, "_atexit_registered_db", set())
    # 替换 atexit.register 为可计数的 mock
    calls = []
    def fake_register(func, *args, **kwargs):
        calls.append(func)
    monkeypatch.setattr(atexit, "register", fake_register)

    db_path = "/tmp/test_aicp_atexit.db"
    cli_module._register_atexit_cleanup(db_path)
    cli_module._register_atexit_cleanup(db_path)  # 重复
    cli_module._register_atexit_cleanup(db_path)  # 再重复

    assert len(calls) == 1  # 只注册一次


def test_register_atexit_cleanup_distinct_paths(monkeypatch):
    """不同 db_path 应各注册一次。"""
    monkeypatch.setattr(cli_module, "_atexit_registered_db", set())
    calls = []
    def fake_register(func, *args, **kwargs):
        calls.append(func)
    monkeypatch.setattr(atexit, "register", fake_register)

    cli_module._register_atexit_cleanup("/tmp/a.db")
    cli_module._register_atexit_cleanup("/tmp/b.db")
    cli_module._register_atexit_cleanup("/tmp/c.db")

    assert len(calls) == 3


def test_register_atexit_cleanup_invokes_store_cleanup(monkeypatch, tmp_path):
    """注册的钩子被调用时, 应触发 Store.cleanup_running_tasks。"""
    monkeypatch.setattr(cli_module, "_atexit_registered_db", set())

    db = tmp_path / "test.db"
    # 预置一个 RUNNING 任务
    with Store(db) as store:
        t = Task(targets=["example.com"])
        store.save_task(t)
        store.transition_task(t.id, TaskStatus.AUTH_PENDING)
        store.transition_task(t.id, TaskStatus.AUTHORIZED)
        store.transition_task(t.id, TaskStatus.RUNNING)

    # 注册钩子 (用真实 atexit, 但立即手动触发)
    captured_funcs = []
    def capturing_register(func, *args, **kwargs):
        captured_funcs.append(func)
        # 不调用原始 atexit.register, 避免污染测试进程的 atexit 列表
    monkeypatch.setattr(atexit, "register", capturing_register)

    cli_module._register_atexit_cleanup(str(db))

    assert len(captured_funcs) == 1
    # 手动调用注册的钩子 (模拟进程退出)
    captured_funcs[0]()

    # 验证任务已被清理
    with Store(db) as store:
        got = store.get_task(t.id)
        assert got.status == TaskStatus.FAILED
