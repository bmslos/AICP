"""授权校验单元测试。"""

import pytest

from aicp.models import Task, TaskStatus
from aicp.auth import AuthorizationError, AuthorizationVerifier, ConfirmationBanner


def test_verify_success_writes_auth_info():
    v = AuthorizationVerifier()
    t = Task(targets=["example.com", "sub.example.com"])
    v.verify(
        t,
        authorized_by="张三",
        authorization_note="授权书编号 AUTH-2026-001",
        authorized_scope=["example.com"],
    )
    assert t.status == TaskStatus.AUTHORIZED
    assert t.authorized_by == "张三"
    assert t.authorized_scope == ["example.com"]
    assert t.authorized_at is not None


def test_verify_rejects_empty_authorized_by():
    v = AuthorizationVerifier()
    t = Task(targets=["example.com"])
    with pytest.raises(AuthorizationError, match="授权人"):
        v.verify(
            t,
            authorized_by="   ",
            authorization_note="x",
            authorized_scope=["example.com"],
        )


def test_verify_rejects_empty_note():
    v = AuthorizationVerifier()
    t = Task(targets=["example.com"])
    with pytest.raises(AuthorizationError, match="授权说明"):
        v.verify(
            t,
            authorized_by="张三",
            authorization_note="",
            authorized_scope=["example.com"],
        )


def test_verify_rejects_empty_scope():
    v = AuthorizationVerifier()
    t = Task(targets=["example.com"])
    with pytest.raises(AuthorizationError, match="授权范围"):
        v.verify(
            t,
            authorized_by="张三",
            authorization_note="x",
            authorized_scope=[],
        )


def test_verify_rejects_target_out_of_scope():
    v = AuthorizationVerifier()
    t = Task(targets=["example.com", "evil.com"])
    with pytest.raises(AuthorizationError, match="不在授权范围"):
        v.verify(
            t,
            authorized_by="张三",
            authorization_note="x",
            authorized_scope=["example.com"],
        )


# ---------------- 范围匹配 ----------------

def test_subdomain_matches_parent_domain():
    v = AuthorizationVerifier()
    assert v.is_target_in_scope("sub.example.com", ["example.com"], [], [])


def test_sibling_domain_not_matches():
    v = AuthorizationVerifier()
    assert not v.is_target_in_scope("notexample.com", ["example.com"], [], [])


def test_trailing_dot_normalized():
    v = AuthorizationVerifier()
    assert v.is_target_in_scope("example.com.", ["example.com"], [], [])


def test_ip_literal_in_scope():
    v = AuthorizationVerifier()
    assert v.is_target_in_scope("1.2.3.4", [], ["1.2.3.4"], [])


def test_ip_not_in_scope():
    v = AuthorizationVerifier()
    assert not v.is_target_in_scope("1.2.3.5", [], ["1.2.3.4"], [])


def test_ip_in_cidr_scope():
    v = AuthorizationVerifier()
    assert v.is_target_in_scope("10.0.0.5", [], [], ["10.0.0.0/24"])


def test_ip_not_in_cidr_scope():
    v = AuthorizationVerifier()
    assert not v.is_target_in_scope("10.0.1.5", [], [], ["10.0.0.0/24"])


def test_host_port_split_for_ip():
    v = AuthorizationVerifier()
    assert v.is_target_in_scope("1.2.3.4:80", [], ["1.2.3.4"], [])


def test_ipv6_host_port_split():
    v = AuthorizationVerifier()
    assert v.is_target_in_scope("[::1]:80", [], ["::1"], [])


def test_cidr_target_must_be_subnet_of_scope():
    v = AuthorizationVerifier()
    # 10.0.0.0/25 ⊂ 10.0.0.0/24 -> True
    assert v.is_target_in_scope("10.0.0.0/25", [], [], ["10.0.0.0/24"])
    # 10.0.0.0/23 ⊄ 10.0.0.0/24 -> False
    assert not v.is_target_in_scope("10.0.0.0/23", [], [], ["10.0.0.0/24"])


# ---------------- URL 范围匹配 ----------------

def test_url_with_ip_in_scope():
    v = AuthorizationVerifier()
    assert v.is_target_in_scope("http://1.2.3.4:80", [], ["1.2.3.4"], [])


def test_url_with_ip_not_in_scope():
    v = AuthorizationVerifier()
    assert not v.is_target_in_scope("http://9.9.9.9:80", [], ["1.2.3.4"], [])


def test_url_with_domain_in_scope():
    v = AuthorizationVerifier()
    assert v.is_target_in_scope("https://sub.example.com/path", ["example.com"], [], [])


def test_url_with_path_in_scope():
    v = AuthorizationVerifier()
    assert v.is_target_in_scope("http://example.com/a/b?c=1", ["example.com"], [], [])


def test_url_with_ipv6_in_scope():
    v = AuthorizationVerifier()
    assert v.is_target_in_scope("http://[::1]:8080/", [], ["::1"], [])


# ---------------- 运行时资产过滤 ----------------

def test_filter_in_scope_splits_targets():
    v = AuthorizationVerifier()
    targets = ["sub.example.com", "evil.com", "1.2.3.4", "10.0.0.99"]
    in_scope, out_of_scope = v.filter_in_scope(
        targets, authorized_scope=["example.com", "1.2.3.4", "10.0.0.0/24"]
    )
    assert in_scope == ["sub.example.com", "1.2.3.4", "10.0.0.99"]
    assert out_of_scope == ["evil.com"]


# ---------------- 域名 scope DNS 解析 (行动项 #5 / #2) ----------------

def test_filter_in_scope_domain_scope_resolves_ips(monkeypatch):
    """P0 行动项 #5: scope 只含域名时, 域名解析出的 IP 不再被全量清空。"""
    monkeypatch.setattr(
        "aicp.auth.verifier._dns_resolver",
        lambda domain: ["93.184.216.34"] if domain == "example.com" else [],
    )
    v = AuthorizationVerifier()
    in_scope, out_of_scope = v.filter_in_scope(
        ["93.184.216.34", "8.8.8.8"], authorized_scope=["example.com"]
    )
    assert in_scope == ["93.184.216.34"]
    assert out_of_scope == ["8.8.8.8"]


def test_filter_in_scope_domain_scope_dns_failure_falls_back():
    """DNS 解析失败 (返回空) 时回退字面量匹配, 不扩大放行面。"""
    v = AuthorizationVerifier()
    in_scope, out_of_scope = v.filter_in_scope(
        ["93.184.216.34"], authorized_scope=["example.com"]
    )
    assert in_scope == []
    assert out_of_scope == ["93.184.216.34"]


def test_filter_in_scope_resolves_each_domain_once(monkeypatch):
    """懒解析: 多个 IP 失配目标只触发一轮域名解析 (resolved 缓存)。"""
    calls = []

    def fake_resolver(domain):
        calls.append(domain)
        return ["93.184.216.34", "93.184.216.35"]

    monkeypatch.setattr("aicp.auth.verifier._dns_resolver", fake_resolver)
    v = AuthorizationVerifier()
    in_scope, out_of_scope = v.filter_in_scope(
        ["93.184.216.34", "93.184.216.35", "8.8.8.8"],
        authorized_scope=["example.com"],
    )
    assert in_scope == ["93.184.216.34", "93.184.216.35"]
    assert out_of_scope == ["8.8.8.8"]
    # scope 里只有一个域名, 且只解析一轮 (三个 IP 目标共享缓存)
    assert calls == ["example.com"]


def test_verify_rejects_domain_resolving_to_private_ip(monkeypatch):
    """P0 行动项 #2: 域名解析到私有/保留段 (DNS rebinding SSRF) 默认拒绝。"""
    monkeypatch.setattr(
        "aicp.auth.verifier._dns_resolver",
        lambda domain: ["169.254.169.254"],
    )
    t = Task(targets=["rebind.example.com"])
    v = AuthorizationVerifier()
    with pytest.raises(AuthorizationError, match="169.254.169.254"):
        v.verify(
            t,
            authorized_by="张三",
            authorization_note="AUTH-001",
            authorized_scope=["rebind.example.com"],
        )


def test_verify_allows_private_resolution_with_allow_private(monkeypatch):
    """allow_private=True 时放行解析到私有段的域名。"""
    monkeypatch.setattr(
        "aicp.auth.verifier._dns_resolver",
        lambda domain: ["10.0.0.5"],
    )
    t = Task(targets=["internal.example.com"])
    v = AuthorizationVerifier()
    v.verify(
        t,
        authorized_by="张三",
        authorization_note="AUTH-001",
        authorized_scope=["internal.example.com"],
        allow_private=True,
    )
    assert t.status == TaskStatus.AUTHORIZED


def test_verify_allows_domain_resolving_to_public_ip(monkeypatch):
    """域名解析到公网 IP 正常通过授权。"""
    monkeypatch.setattr(
        "aicp.auth.verifier._dns_resolver",
        lambda domain: ["93.184.216.34"],
    )
    t = Task(targets=["example.com"])
    v = AuthorizationVerifier()
    v.verify(
        t,
        authorized_by="张三",
        authorization_note="AUTH-001",
        authorized_scope=["example.com"],
    )
    assert t.status == TaskStatus.AUTHORIZED


# ---------------- 合规 Banner ----------------

def test_banner_renders_required_fields():
    t = Task(targets=["example.com"])
    v = AuthorizationVerifier()
    v.verify(
        t,
        authorized_by="张三",
        authorization_note="AUTH-001",
        authorized_scope=["example.com"],
    )
    banner = ConfirmationBanner(t).render()
    assert "法律与合规警告" in banner
    assert "张三" in banner
    assert "example.com" in banner
    assert "AUTH-001" in banner
    assert "网络安全法" in banner
