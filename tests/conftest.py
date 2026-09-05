"""pytest 公共夹具。"""

import logging
import logging.handlers

import pytest

from aicp.scheduler.store import Store


@pytest.fixture
def store(tmp_path):
    """每个测试用例独立的临时 SQLite。"""
    db = tmp_path / "test.db"
    s = Store(db)
    yield s
    s.close()


@pytest.fixture(autouse=True)
def _stub_dns_resolver(monkeypatch):
    """默认把授权校验器的 DNS 解析 stub 为空 (项目测试约定: 零真实网络依赖)。

    verifier 的域名解析 (行动项 #5 域名 scope 过滤 / #2 DNS rebinding 校验)
    在测试中默认返回空列表; 需要解析行为的用例在自身内再次 monkeypatch
    `aicp.auth.verifier._dns_resolver` 覆盖本 stub (后设置的优先生效)。
    """
    monkeypatch.setattr("aicp.auth.verifier._dns_resolver", lambda domain: [])


@pytest.fixture(autouse=True)
def _reset_aicp_json_logging():
    """每个用例后清理 setup_logging 挂到 root logger 的 JSON 文件 handler。

    防止临时目录的文件句柄跨用例泄漏 (Windows 上锁文件, 且后续用例
    会往已删除的日志文件写)。handler 靠 _aicp_json_handler 标记识别。
    """
    yield
    root = logging.getLogger()
    for h in list(root.handlers):
        if getattr(h, "_aicp_json_handler", False):
            h.close()
            root.removeHandler(h)
    if getattr(root, "_aicp_json_logging", False):
        root._aicp_json_logging = False
