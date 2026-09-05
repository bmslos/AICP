"""数据模型单元测试。"""

from aicp.models import Asset, Task, TaskStatus, Stage, StageName, StageStatus


def test_asset_to_dict_serializes_datetime():
    a = Asset(type="domain", value="example.com", source="oneforall", task_id="t1")
    d = a.to_dict()
    assert d["type"] == "domain"
    assert d["value"] == "example.com"
    assert "T" in d["discovered_at"]  # ISO 格式


def test_asset_dedup_key():
    key = Asset.dedup_key("ip", "1.2.3.4", "t1")
    assert key == ("ip", "1.2.3.4", "t1")


def test_task_default_status_is_pending():
    t = Task(targets=["example.com"])
    assert t.status == TaskStatus.PENDING
    assert t.authorized_scope == []


def test_stage_to_dict_serializes_enums():
    s = Stage(task_id="t1", name=StageName.SUBDOMAIN, status=StageStatus.RUNNING)
    d = s.to_dict()
    assert d["name"] == "subdomain"
    assert d["status"] == "running"
    assert d["started_at"] is None


def test_task_to_dict_serializes_status():
    t = Task(targets=["example.com"], status=TaskStatus.AUTHORIZED)
    d = t.to_dict()
    assert d["status"] == "authorized"
    assert d["targets"] == ["example.com"]
