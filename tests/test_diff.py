"""资产差异比较 (P2-1) 单元测试。"""

from aicp.diff import diff_tasks
from aicp.models import Asset, Task


def _seed(store, task_id, domains=(), ports=(), vulns=()):
    t = Task(targets=["example.com"])
    t.id = task_id
    store.save_task(t)
    for d in domains:
        store.save_asset(Asset(
            type="domain", value=d, source="user_input", task_id=task_id,
        ))
    for p in ports:
        store.save_asset(Asset(
            type="port", value=p, source="nmap", task_id=task_id,
        ))
    for value, template, severity in vulns:
        store.save_asset(Asset(
            type="vulnerability", value=value, source="nuclei", task_id=task_id,
            raw={
                "tool": "nuclei", "template_id": template,
                "name": f"vuln-{template}", "severity": severity,
                "matched_at": value.split("|")[0],
            },
        ))


def test_diff_tasks_detects_added_and_removed(store):
    _seed(store, "aaaa",
          domains=["a.com", "gone.com"],
          ports=["1.2.3.4:80"],
          vulns=[("http://1.2.3.4:80|t1", "t1", "high")])
    _seed(store, "bbbb",
          domains=["a.com", "new.com"],
          ports=["1.2.3.4:80", "1.2.3.4:443"],
          vulns=[("http://1.2.3.4:80|t2", "t2", "critical")])

    r = diff_tasks(store, "aaaa", "bbbb")

    assert r["added_domains"] == ["new.com"]
    assert r["removed_domains"] == ["gone.com"]
    assert r["added_ports"] == ["1.2.3.4:443"]
    assert r["removed_ports"] == []
    # 漏洞: t1 修复 (removed), t2 新增 (added)
    assert [a.raw["template_id"] for a in r["added_vulns"]] == ["t2"]
    assert [a.raw["template_id"] for a in r["fixed_vulns"]] == ["t1"]
    # 新增漏洞按 severity 降序
    assert r["added_vulns"][0].raw["severity"] == "critical"


def test_diff_tasks_empty_when_same(store):
    _seed(store, "aaaa", domains=["a.com"], ports=["1.2.3.4:80"])
    _seed(store, "bbbb", domains=["a.com"], ports=["1.2.3.4:80"])

    r = diff_tasks(store, "aaaa", "bbbb")

    assert r["added_domains"] == []
    assert r["removed_domains"] == []
    assert r["added_ports"] == []
    assert r["removed_ports"] == []
    assert r["added_vulns"] == []
    assert r["fixed_vulns"] == []
