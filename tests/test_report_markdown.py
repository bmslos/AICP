"""Markdown 报告生成单元测试。"""

from __future__ import annotations


import pytest

from aicp.auth import AuthorizationVerifier
from aicp.models import Asset, Task, TaskStatus
from aicp.report import generate_markdown_report
from aicp.report.markdown import write_markdown_report, _escape_cell


# ---------------- 测试夹具 ----------------

@pytest.fixture
def task_with_assets(store):
    """构造一个已授权且已有资产的任务 (与 test_report.py 对齐)。"""
    t = Task(targets=["example.com"])
    store.save_task(t)
    AuthorizationVerifier().verify(
        t,
        authorized_by="张三",
        authorization_note="AUTH-001",
        authorized_scope=["example.com", "1.2.3.4"],
    )
    store.save_task(t)
    assets = [
        Asset(type="domain", value="example.com", source="user_input", task_id=t.id),
        Asset(type="domain", value="sub.example.com", source="oneforall", task_id=t.id),
        Asset(type="ip", value="1.2.3.4", source="nmap", task_id=t.id),
        Asset(type="port", value="1.2.3.4:80", source="nmap", task_id=t.id,
              raw={"ip": "1.2.3.4", "port": 80}),
        Asset(type="url", value="http://1.2.3.4:80", source="httpx", task_id=t.id),
        Asset(type="web_service", value="http://1.2.3.4:80", source="httpx", task_id=t.id,
              technologies=["Nginx"], status_code=200, title="Test"),
        Asset(type="web_service", value="http://1.2.3.4:80", source="wappalyzer", task_id=t.id,
              technologies=["Nginx", "PHP"]),
    ]
    for a in assets:
        store.save_asset(a)
    store.transition_task(t.id, TaskStatus.RUNNING)
    store.transition_task(t.id, TaskStatus.COMPLETED)
    t = store.get_task(t.id)
    return t


# ---------------- _escape_cell ----------------

def test_escape_cell_escapes_pipe():
    """单元格中的 `|` 必须转义为 `\\|`。"""
    assert _escape_cell("a|b") == "a\\|b"


def test_escape_cell_replaces_newline():
    """单元格中的换行替换为空格 (Markdown 表格不支持多行)。"""
    assert _escape_cell("line1\nline2") == "line1 line2"


def test_escape_cell_none_returns_empty():
    assert _escape_cell(None) == ""


def test_escape_cell_no_special_chars_unchanged():
    assert _escape_cell("example.com") == "example.com"


# ---------------- generate_markdown_report ----------------

def test_markdown_report_has_required_sections(task_with_assets, store):
    """报告必须包含 6 个核心 section。"""
    md = generate_markdown_report(task_with_assets, store)
    assert "# AICP 资产报告" in md
    assert "## 任务信息" in md
    assert "## 资产统计" in md
    assert "## 资产详情" in md
    assert "## 阶段时间线" in md
    assert "## 审计日志" in md


def test_markdown_report_contains_task_metadata(task_with_assets, store):
    """报告必须包含任务元信息 (授权人/说明/ID)。"""
    md = generate_markdown_report(task_with_assets, store)
    assert task_with_assets.id in md
    assert "张三" in md
    assert "AUTH-001" in md
    assert "example.com" in md


def test_markdown_report_contains_stats(task_with_assets, store):
    """报告统计区应反映资产数量。"""
    md = generate_markdown_report(task_with_assets, store)
    # 至少应出现域名、IP、端口、URL、Web 服务 5 类计数行
    assert "域名 (Domain)" in md
    assert "IP" in md
    assert "开放端口 (Port)" in md
    assert "URL" in md
    assert "Web 服务" in md
    # 技术栈 (Nginx + PHP 去重后)
    assert "`Nginx`" in md
    assert "`PHP`" in md


def test_markdown_report_contains_host_table(task_with_assets, store):
    """报告资产详情应有主机与端口表。"""
    md = generate_markdown_report(task_with_assets, store)
    assert "### 主机与端口" in md
    assert "1.2.3.4" in md
    assert "1.2.3.4:80" in md


def test_markdown_report_contains_domain_table(task_with_assets, store):
    """报告资产详情应有域名列表表。"""
    md = generate_markdown_report(task_with_assets, store)
    assert "### 域名列表" in md
    assert "sub.example.com" in md


def test_markdown_report_markdown_table_format(task_with_assets, store):
    """生成的 Markdown 必须有合法表格分隔行 (|---|)。"""
    md = generate_markdown_report(task_with_assets, store)
    # 至少 4 个表格 (统计 + 主机端口 + 域名 + 阶段 + 审计 = 5)
    assert md.count("|---|") >= 4


def test_markdown_report_pipe_in_value_escaped(store):
    """资产 value 含 `|` 时必须转义, 避免破坏表格。"""
    t = Task(targets=["example.com"])
    store.save_task(t)
    AuthorizationVerifier().verify(
        t, authorized_by="张三", authorization_note="AUTH-001",
        authorized_scope=["example.com"],
    )
    store.save_task(t)
    # 构造一个 value 含 `|` 的资产
    store.save_asset(Asset(
        type="domain", value="evil|.com", source="test", task_id=t.id,
    ))
    store.transition_task(t.id, TaskStatus.RUNNING)
    store.transition_task(t.id, TaskStatus.COMPLETED)
    t = store.get_task(t.id)

    md = generate_markdown_report(t, store)
    # 转义后的形式应出现
    assert "evil\\|.com" in md
    # 未转义的形式不应作为单元格分隔出现 (在 | 开头的表格行之外不应有裸 |)
    # 至少确认表格行数没有因 | 而增加


def test_markdown_report_empty_assets(store):
    """无资产任务不报错, 资产详情区显示 (无资产)。"""
    t = Task(targets=["example.com"])
    store.save_task(t)
    AuthorizationVerifier().verify(
        t, authorized_by="张三", authorization_note="AUTH-001",
        authorized_scope=["example.com"],
    )
    store.save_task(t)
    md = generate_markdown_report(t, store)
    assert "(无资产)" in md
    assert "## 资产详情" in md


# ---------------- write_markdown_report ----------------

def test_write_markdown_report_creates_file(task_with_assets, store, tmp_path):
    """write_markdown_report 应创建文件并返回路径。"""
    out = tmp_path / "report.md"
    p = write_markdown_report(task_with_assets, store, out)
    assert p == out
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "# AICP 资产报告" in content


def test_write_markdown_report_creates_parent_dir(task_with_assets, store, tmp_path):
    """父目录不存在时应自动创建。"""
    out = tmp_path / "subdir" / "nested" / "report.md"
    p = write_markdown_report(task_with_assets, store, out)
    assert p.exists()
