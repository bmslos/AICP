"""CSV 报告生成单元测试。

覆盖: 扁平化行生成、utf-8-sig BOM (Excel 兼容)、表头列、空字段处理、父目录创建、空任务。
"""

import csv
import io

import pytest

from aicp.auth import AuthorizationVerifier
from aicp.models import Asset, Task
from aicp.report.csv_report import (
    generate_csv_rows,
    write_csv_report,
    _CSV_COLUMNS,
)


@pytest.fixture
def task_with_assets(store):
    """构造一个已授权且已有资产的任务。"""
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
        Asset(type="ip", value="1.2.3.4", source="nmap", task_id=t.id),
        Asset(
            type="web_service", value="http://1.2.3.4:80", source="httpx", task_id=t.id,
            technologies=["Nginx", "PHP"], status_code=200, title="Test",
            parent_id="some-parent",
        ),
    ]
    for a in assets:
        store.save_asset(a)
    return store.get_task(t.id)


# ---------------- generate_csv_rows ----------------

def test_generate_csv_rows_flattens_assets(task_with_assets, store):
    rows = generate_csv_rows(task_with_assets, store)
    assert len(rows) == 3

    # 每个行都是扁平化 dict
    by_value = {r["value"]: r for r in rows}
    ws = by_value["http://1.2.3.4:80"]
    assert ws["task_id"] == task_with_assets.id
    assert ws["type"] == "web_service"
    assert ws["source"] == "httpx"
    assert ws["parent_id"] == "some-parent"
    assert ws["status_code"] == 200
    assert ws["title"] == "Test"
    # technologies 用分号连接
    assert ws["technologies"] == "Nginx;PHP"
    # 时间字段是 ISO 字符串
    assert ws["discovered_at"].endswith("Z") or "+" in ws["discovered_at"]


def test_generate_csv_rows_empty_optional_fields(task_with_assets, store):
    """无 parent_id / status_code / title / technologies 的资产应为空字符串。"""
    rows = generate_csv_rows(task_with_assets, store)
    domain = next(r for r in rows if r["type"] == "domain")
    assert domain["parent_id"] == ""
    assert domain["status_code"] == ""
    assert domain["title"] == ""
    assert domain["technologies"] == ""


def test_generate_csv_rows_orders_by_discovery(task_with_assets, store):
    rows = generate_csv_rows(task_with_assets, store)
    # store.list_assets 按 discovered_at 排序, 此处仅验证顺序与入库一致
    assert rows[0]["type"] == "domain"
    assert rows[1]["type"] == "ip"
    assert rows[2]["type"] == "web_service"


def test_generate_csv_rows_empty_task(store):
    t = Task(targets=["example.com"])
    store.save_task(t)
    rows = generate_csv_rows(store.get_task(t.id), store)
    assert rows == []


# ---------------- write_csv_report ----------------

def test_write_csv_report_writes_utf8_sig_bom(task_with_assets, store, tmp_path):
    out = write_csv_report(task_with_assets, store, tmp_path / "report.csv")
    assert out.exists()
    raw = out.read_bytes()
    # utf-8-sig 编码 => 文件开头带 BOM (Excel 兼容中文的关键)
    assert raw[:3] == b"\xef\xbb\xbf"


def test_write_csv_report_header_and_rows(task_with_assets, store, tmp_path):
    out = write_csv_report(task_with_assets, store, tmp_path / "report.csv")
    # 用 utf-8-sig 解码后可被 csv 直接读取
    text = out.read_text(encoding="utf-8-sig")
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)

    assert rows[0] == _CSV_COLUMNS  # 表头
    assert len(rows) == 4  # 1 表头 + 3 资产
    # 中文数据可正常读写 (BOM 被正确剥离)
    assert any("Nginx;PHP" in r for r in rows)


def test_write_csv_report_creates_parent_dirs(task_with_assets, store, tmp_path):
    out = write_csv_report(task_with_assets, store, tmp_path / "deep" / "nested" / "report.csv")
    assert out.exists()


def test_write_csv_report_empty_task(store, tmp_path):
    t = Task(targets=["example.com"])
    store.save_task(t)
    out = write_csv_report(store.get_task(t.id), store, tmp_path / "empty.csv")
    text = out.read_text(encoding="utf-8-sig")
    rows = list(csv.reader(io.StringIO(text)))
    assert rows == [_CSV_COLUMNS]  # 仅表头


def test_write_csv_report_returns_path(tmp_path):
    """返回值与传入路径一致 (Path 类型)。"""
    from aicp.scheduler.store import Store

    db = tmp_path / "db.sqlite"
    s = Store(db)
    t = Task(targets=["example.com"])
    s.save_task(t)
    try:
        target = tmp_path / "x.csv"
        result = write_csv_report(s.get_task(t.id), s, target)
        assert result == target
    finally:
        s.close()
