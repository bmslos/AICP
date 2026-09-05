"""报告生成单元测试。"""

import json

import pytest

from aicp.auth import AuthorizationVerifier
from aicp.models import Asset, Task, TaskStatus
from aicp.report import generate_json_report, generate_html_report
from aicp.report.json_report import write_json_report
from aicp.report.html import write_html_report


# ---------------- 测试夹具：构造带资产的授权任务 ----------------

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
    # 模拟资产已收集
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
    # 完成任务: AUTHORIZED -> RUNNING -> COMPLETED
    store.transition_task(t.id, TaskStatus.RUNNING)
    store.transition_task(t.id, TaskStatus.COMPLETED)
    # 重新读取最新状态
    t = store.get_task(t.id)
    return t


# ---------------- JSON 报告 ----------------

def test_json_report_has_required_sections(task_with_assets, store):
    report = generate_json_report(task_with_assets, store)
    assert report["version"] == "1.0"
    assert "generated_at" in report
    assert report["task"]["id"] == task_with_assets.id
    assert report["task"]["status"] == "completed"
    assert report["task"]["authorized_by"] == "张三"
    assert "summary" in report
    assert "assets" in report
    assert "stages" in report
    assert "audit_log" in report


def test_json_report_summary_counts(task_with_assets, store):
    report = generate_json_report(task_with_assets, store)
    s = report["summary"]
    assert s["total_domains"] == 2
    assert s["total_ips"] == 1
    assert s["total_ports"] == 1
    assert s["total_urls"] == 1
    assert s["total_web_services"] == 2  # httpx + wappalyzer
    # 唯一技术栈
    assert set(s["unique_technologies"]) == {"Nginx", "PHP"}


def test_json_report_assets_graph_is_merged(task_with_assets, store):
    report = generate_json_report(task_with_assets, store)
    graph = report["assets"]
    # 应有 2 个 domain (用户输入 + oneforall)
    assert len(graph["domains"]) == 2
    # 应有 1 个 host
    assert len(graph["hosts"]) == 1
    host = graph["hosts"][0]
    assert host["ip"] == "1.2.3.4"
    assert len(host["ports"]) == 1
    port = host["ports"][0]
    assert port["port"] == 80
    # url 下挂合并后的 web_service
    assert len(port["urls"]) == 1
    url_node = port["urls"][0]
    ws = url_node["web_service"]
    assert ws is not None
    # 合并后的指纹: Nginx + PHP (去重)
    assert set(ws["technologies"]) == {"Nginx", "PHP"}
    assert ws["status_code"] == 200
    assert ws["title"] == "Test"


def test_write_json_report_to_file(task_with_assets, store, tmp_path):
    out = write_json_report(task_with_assets, store, tmp_path / "report.json")
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["task"]["id"] == task_with_assets.id


# ---------------- HTML 报告 ----------------

def test_html_report_is_valid_html(task_with_assets, store):
    html_str = generate_html_report(task_with_assets, store)
    assert html_str.startswith("<!DOCTYPE html>")
    assert html_str.rstrip().endswith("</body></html>")


def test_html_report_contains_task_info(task_with_assets, store):
    html_str = generate_html_report(task_with_assets, store)
    assert "任务信息" in html_str
    assert "张三" in html_str
    assert "AUTH-001" in html_str
    assert "example.com" in html_str


def test_html_report_contains_assets(task_with_assets, store):
    html_str = generate_html_report(task_with_assets, store)
    assert "资产详情" in html_str
    assert "1.2.3.4" in html_str
    assert "1.2.3.4:80" in html_str
    # 指纹
    assert "Nginx" in html_str
    assert "PHP" in html_str


def test_html_report_escapes_xss(store, tmp_path):
    """资产值含 HTML 注入字符时应被转义。"""
    t = Task(targets=["example.com"])
    store.save_task(t)
    AuthorizationVerifier().verify(
        t,
        authorized_by="x",
        authorization_note="x",
        authorized_scope=["example.com"],
    )
    store.save_task(t)
    store.save_asset(Asset(
        type="domain",
        value="<script>alert(1)</script>",
        source="user_input",
        task_id=t.id,
    ))
    html_str = generate_html_report(t, store)
    # 不应出现未转义的 <script>
    assert "<script>alert(1)</script>" not in html_str
    # 应出现转义后的
    assert "&lt;script&gt;" in html_str


def test_write_html_report_to_file(task_with_assets, store, tmp_path):
    out = write_html_report(task_with_assets, store, tmp_path / "report.html")
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content


def test_html_report_handles_empty_task(store):
    """无资产任务也能生成报告。"""
    t = Task(targets=["example.com"])
    store.save_task(t)
    AuthorizationVerifier().verify(
        t, authorized_by="x", authorization_note="x",
        authorized_scope=["example.com"],
    )
    store.save_task(t)
    html_str = generate_html_report(t, store)
    assert "(无资产)" in html_str or "(无主机资产)" in html_str


# ---------------- CORRELATE 阶段集成测试 ----------------

def test_correlate_stage_runs_builtin(store, tmp_path):
    """编排器自动执行 CORRELATE 阶段，把摘要写入审计日志。"""
    from aicp.pipeline import Orchestrator
    from aicp.models import StageName, StageStatus
    from aicp.tools import Tool, ToolResult

    class FakeSub(Tool):
        stage = StageName.SUBDOMAIN
        input_asset_types = ("domain",)
        output_asset_types = ("domain",)
        def run(self, inputs, ctx):
            return ToolResult(assets=[
                Asset(type="domain", value="sub.example.com",
                      source="fake", task_id=ctx.task_id)
            ])

    t = Task(targets=["example.com"])
    store.save_task(t)
    AuthorizationVerifier().verify(
        t, authorized_by="张三", authorization_note="AUTH-001",
        authorized_scope=["example.com"],
    )
    store.save_task(t)

    orch = Orchestrator(store, [FakeSub()], work_dir=str(tmp_path))
    orch.run(t)

    # CORRELATE 阶段应完成
    stages = {s.name: s for s in store.list_stages(t.id)}
    assert stages[StageName.CORRELATE].status == StageStatus.COMPLETED

    # 审计日志应有 correlate_summary
    audit = store.list_audit(t.id)
    events = [a["event"] for a in audit]
    assert "correlate_summary" in events
    summary_detail = next(a["detail"] for a in audit if a["event"] == "correlate_summary")
    assert "domains=" in summary_detail
    assert "hosts=" in summary_detail


# ---------------- P0-1: 漏洞 / 目录接入报告 ----------------

def test_report_includes_vulnerabilities_and_directories(store):
    """P0-1: 漏洞与目录应出现在 HTML / JSON / Markdown / CSV 四份报告中。"""
    from aicp.report import generate_markdown_report
    from aicp.report.csv_report import generate_csv_rows

    t = Task(targets=["example.com"])
    store.save_task(t)
    AuthorizationVerifier().verify(
        t, authorized_by="张三", authorization_note="AUTH-001",
        authorized_scope=["example.com", "1.2.3.4"],
    )
    store.save_task(t)
    store.save_asset(Asset(
        type="vulnerability",
        value="http://1.2.3.4:80|cves/2021/CVE-2021-44228",
        source="nuclei", task_id=t.id,
        raw={
            "tool": "nuclei", "template_id": "cves/2021/CVE-2021-44228",
            "name": "Log4Shell RCE", "severity": "critical",
            "matched_at": "http://1.2.3.4:80",
        },
    ))
    store.save_asset(Asset(
        type="vulnerability",
        value="http://1.2.3.4:80|http/misconfig/test-headers",
        source="nuclei", task_id=t.id,
        raw={
            "tool": "nuclei", "template_id": "http/misconfig/test-headers",
            "name": "Test Headers", "severity": "medium",
            "matched_at": "http://1.2.3.4:80",
        },
    ))
    store.save_asset(Asset(
        type="directory",
        value="http://1.2.3.4:80/admin",
        source="dirsearch", task_id=t.id,
        status_code=200,
        raw={"tool": "dirsearch", "status_code": 200, "size": 1024, "redirect": ""},
    ))
    store.transition_task(t.id, TaskStatus.RUNNING)
    store.transition_task(t.id, TaskStatus.COMPLETED)
    t = store.get_task(t.id)

    # JSON: summary + 平铺列表 + severity 降序
    report = generate_json_report(t, store)
    assert report["summary"]["total_vulnerabilities"] == 2
    assert report["summary"]["vulns_by_severity"] == {"critical": 1, "medium": 1}
    assert report["summary"]["total_directories"] == 1
    assert len(report["assets"]["vulnerabilities"]) == 2
    assert report["assets"]["vulnerabilities"][0]["severity"] == "critical"
    assert report["assets"]["directories"][0]["url"] == "http://1.2.3.4:80/admin"

    # HTML
    html_str = generate_html_report(t, store)
    assert "漏洞清单" in html_str
    assert "Log4Shell RCE" in html_str
    assert "目录枚举" in html_str
    assert "admin" in html_str

    # Markdown
    md = generate_markdown_report(t, store)
    assert "## 漏洞清单" in md
    assert "Log4Shell RCE" in md
    assert "## 目录枚举" in md

    # CSV: 展开列 + value 为干净的 matched_at
    rows = generate_csv_rows(t, store)
    vulns = [r for r in rows if r["type"] == "vulnerability"]
    assert len(vulns) == 2
    for v in vulns:
        assert v["value"] == "http://1.2.3.4:80"  # 不是 url|template 拼接
        assert v["template_id"] in ("cves/2021/CVE-2021-44228", "http/misconfig/test-headers")
        assert v["severity"] in ("critical", "medium")
    dirs = [r for r in rows if r["type"] == "directory"]
    assert len(dirs) == 1
    assert dirs[0]["size"] == 1024
