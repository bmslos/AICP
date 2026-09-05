"""工具适配器单元测试。

使用 mock runner / mock analyzer，不依赖真实工具二进制。
"""

import json
import logging
from pathlib import Path

import pytest

from aicp.models import Asset
from aicp.tools import ToolContext, CompletedProcess
from aicp.tools.oneforall import OneForAllTool
from aicp.tools.nmap import NmapTool
from aicp.tools.httpx_tool import HttpxTool
from aicp.tools.wappalyzer import WappalyzerTool


# ---------------- 公共夹具 ----------------

@pytest.fixture
def ctx(tmp_path):
    return ToolContext(
        task_id="t1",
        authorized_scope=["example.com", "1.2.3.4", "10.0.0.0/24"],
        work_dir=str(tmp_path),
    )


def make_proc(rc=0, stdout="", stderr=""):
    return CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr=stderr)


# ---------------- OneForAll ----------------

def test_oneforall_parses_csv_and_filters_scope(ctx, tmp_path):
    # 准备 CSV: 3 个子域名，其中 evil.com 超出授权范围
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    csv_content = "subdomain,ip\nexample.com,1.2.3.4\nsub.example.com,1.2.3.5\nevil.com,9.9.9.9\n"
    (results_dir / "example.com.csv").write_text(csv_content, encoding="utf-8")

    calls = []

    def fake_runner(cmd, cwd):
        calls.append(cmd)
        return make_proc(rc=0, stdout="done", stderr="")

    tool = OneForAllTool(runner=fake_runner, results_dir=str(results_dir))
    inputs = [Asset(type="domain", value="example.com", source="user_input", task_id="t1")]
    result = tool.run(inputs, ctx)

    # evil.com 被授权范围过滤
    values = sorted(a.value for a in result.assets)
    assert values == ["example.com", "sub.example.com"]
    assert all(a.source == "oneforall" for a in result.assets)
    assert result.stats["collected_subdomains"] == 2
    # 命令包含 --target example.com
    assert any("--target" in c and "example.com" in c for c in calls)


def test_oneforall_raises_on_nonzero_rc(ctx):
    def fake_runner(cmd, cwd):
        return make_proc(rc=2, stdout="", stderr="boom")

    tool = OneForAllTool(runner=fake_runner, results_dir="./nonexistent")
    inputs = [Asset(type="domain", value="example.com", source="user_input", task_id="t1")]
    from aicp.tools import ToolError
    with pytest.raises(ToolError, match="执行失败"):
        tool.run(inputs, ctx)


def test_oneforall_empty_inputs_returns_empty(ctx):
    tool = OneForAllTool(runner=lambda c, w: make_proc(), results_dir="./x")
    result = tool.run([], ctx)
    assert result.assets == []
    assert result.stats["input_domains"] == 0


# ---------------- OneForAll domain 格式校验 ----------------

def test_oneforall_rejects_path_traversal_domain(ctx, caplog):
    # domain 含 ../ 路径遍历字符, 应在调用 runner 前被拒绝
    def fake_runner(cmd, cwd):
        return make_proc(rc=0, stdout="", stderr="")

    tool = OneForAllTool(runner=fake_runner, results_dir="./results")
    inputs = [Asset(type="domain", value="../etc/passwd", source="user_input", task_id="t1")]
    with caplog.at_level(logging.WARNING, logger="aicp.tools.oneforall"):
        result = tool.run(inputs, ctx)
    assert result.assets == []
    assert "格式非法" in caplog.text


def test_oneforall_accepts_valid_domain(ctx, tmp_path):
    # 合法 domain 应正常跑 OneForAll 并解析 CSV
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    csv_content = "subdomain,ip\nexample.com,1.2.3.4\nsub.example.com,1.2.3.5\n"
    (results_dir / "example.com.csv").write_text(csv_content, encoding="utf-8")

    def fake_runner(cmd, cwd):
        return make_proc(rc=0, stdout="done", stderr="")

    tool = OneForAllTool(runner=fake_runner, results_dir=str(results_dir))
    inputs = [Asset(type="domain", value="example.com", source="user_input", task_id="t1")]
    result = tool.run(inputs, ctx)

    assert len(result.assets) > 0
    values = sorted(a.value for a in result.assets)
    assert "example.com" in values
    assert "sub.example.com" in values


def test_oneforall_rejects_domain_with_slash(ctx, caplog):
    # domain 含斜杠, 应在调用 runner 前被拒绝
    def fake_runner(cmd, cwd):
        return make_proc(rc=0, stdout="", stderr="")

    tool = OneForAllTool(runner=fake_runner, results_dir="./results")
    inputs = [Asset(type="domain", value="a/b", source="user_input", task_id="t1")]
    with caplog.at_level(logging.WARNING, logger="aicp.tools.oneforall"):
        result = tool.run(inputs, ctx)
    assert result.assets == []
    assert "格式非法" in caplog.text


# ---------------- OneForAll._parse_csv 列序健壮性 ----------------

def test_parse_csv_finds_subdomain_column(tmp_path):
    # 表头中 subdomain 在第二列, 首列是 url
    csv_path = tmp_path / "sub.csv"
    csv_path.write_text(
        "url,subdomain,ip,source\n"
        "http://x,sub.example.com,1.2.3.4,httpx\n",
        encoding="utf-8",
    )
    result = OneForAllTool._parse_csv(csv_path)
    assert result == ["sub.example.com"]


def test_parse_csv_case_insensitive_header(tmp_path):
    # 表头大小写混合, 应仍然匹配到 subdomain 列
    csv_path = tmp_path / "sub.csv"
    csv_path.write_text(
        "Url,Subdomain,Ip\n"
        "http://x,sub.example.com,1.2.3.4\n",
        encoding="utf-8",
    )
    result = OneForAllTool._parse_csv(csv_path)
    assert result == ["sub.example.com"]


def test_parse_csv_falls_back_to_first_column(tmp_path, caplog):
    # 表头无 subdomain 列, 回退取第一列 (url)
    csv_path = tmp_path / "sub.csv"
    csv_path.write_text(
        "url,ip,source\n"
        "http://sub.example.com,1.2.3.4,httpx\n",
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING, logger="aicp.tools.oneforall"):
        result = OneForAllTool._parse_csv(csv_path)
    assert result == ["http://sub.example.com"]
    assert any("无 subdomain 列" in rec.message for rec in caplog.records)


def test_parse_csv_empty_file(tmp_path):
    csv_path = tmp_path / "empty.csv"
    csv_path.write_text("", encoding="utf-8")
    assert OneForAllTool._parse_csv(csv_path) == []


def test_parse_csv_missing_file(tmp_path):
    csv_path = tmp_path / "nonexistent.csv"
    assert OneForAllTool._parse_csv(csv_path) == []


# ---------------- Nmap ----------------

NMAP_XML_SAMPLE = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="1.2.3.5" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


def test_nmap_parses_xml_and_links_port_to_ip(ctx):
    def fake_runner(cmd, cwd):
        # 从 cmd 中找到 -oX 后的路径，写入 XML
        idx = cmd.index("-oX")
        Path(cmd[idx + 1]).write_text(NMAP_XML_SAMPLE, encoding="utf-8")
        return make_proc(rc=0, stdout="", stderr="")

    tool = NmapTool(runner=fake_runner)
    inputs = [Asset(type="domain", value="example.com", source="user_input", task_id="t1")]
    result = tool.run(inputs, ctx)

    # 1 个 up 主机 + 2 个开放端口 (down 主机被过滤)
    ip_assets = [a for a in result.assets if a.type == "ip"]
    port_assets = [a for a in result.assets if a.type == "port"]
    assert len(ip_assets) == 1
    assert ip_assets[0].value == "1.2.3.4"
    assert len(port_assets) == 2

    # port 的 parent_id 应指向对应 ip 资产
    port_values = sorted(p.value for p in port_assets)
    assert port_values == ["1.2.3.4:443", "1.2.3.4:80"]
    for p in port_assets:
        assert p.parent_id == ip_assets[0].id

    assert result.stats["hosts_up"] == 1
    assert result.stats["open_ports"] == 2


def test_nmap_filters_out_of_scope_targets(ctx):
    def fake_runner(cmd, cwd):
        return make_proc(rc=0, stdout="", stderr="")

    tool = NmapTool(runner=fake_runner)
    # evil.com 不在授权范围
    inputs = [Asset(type="domain", value="evil.com", source="user_input", task_id="t1")]
    result = tool.run(inputs, ctx)
    assert result.assets == []
    assert result.stats["input_targets"] == 0
    assert result.stats["skipped_out_of_scope"] == 1


def test_nmap_domain_scope_keeps_resolved_assets(tmp_path, monkeypatch):
    """P0 行动项 #5: scope 只含域名时, nmap 解析域名得到的 IP/端口资产不再被清空。

    旧实现 filter_in_scope 对 IP 只做字面量匹配, scope=["example.com"] 时
    所有 IP 恒为 out_of_scope → ip/port 资产全量清空。
    """
    monkeypatch.setattr(
        "aicp.auth.verifier._dns_resolver",
        lambda domain: ["93.184.216.34"] if domain == "example.com" else [],
    )
    xml = NMAP_XML_SAMPLE.replace("1.2.3.4", "93.184.216.34")

    def fake_runner(cmd, cwd):
        idx = cmd.index("-oX")
        Path(cmd[idx + 1]).write_text(xml, encoding="utf-8")
        return make_proc(rc=0, stdout="", stderr="")

    ctx = ToolContext(
        task_id="t1",
        authorized_scope=["example.com"],
        work_dir=str(tmp_path),
    )
    tool = NmapTool(runner=fake_runner)
    inputs = [Asset(type="domain", value="example.com", source="user_input", task_id="t1")]
    result = tool.run(inputs, ctx)

    ip_assets = [a for a in result.assets if a.type == "ip"]
    port_assets = [a for a in result.assets if a.type == "port"]
    assert len(ip_assets) == 1
    assert ip_assets[0].value == "93.184.216.34"
    assert sorted(p.value for p in port_assets) == [
        "93.184.216.34:443", "93.184.216.34:80",
    ]
    assert result.stats["ips_out_of_scope"] == 0


def test_nmap_raises_on_failure(ctx):
    def fake_runner(cmd, cwd):
        return make_proc(rc=3, stdout="", stderr="nmap error")

    tool = NmapTool(runner=fake_runner)
    inputs = [Asset(type="ip", value="1.2.3.4", source="user_input", task_id="t1")]
    from aicp.tools import ToolError
    with pytest.raises(ToolError, match="nmap 执行失败"):
        tool.run(inputs, ctx)


def test_nmap_handles_bare_ipv6_target(tmp_path):
    """裸 IPv6 目标不应被 split(':') 拆错 (修复 Bug #5)。

    旧实现 `t.split(":")[0] if ":" in t and not t.startswith("[")` 会把
    2001:db8::1 拆成 "2001", 导致扫描目标错误。
    """
    ctx = ToolContext(
        task_id="t1",
        authorized_scope=["2001:db8::1"],
        work_dir=str(tmp_path),
    )
    calls = []

    def fake_runner(cmd, cwd):
        calls.append(cmd)
        return make_proc(rc=0, stdout="", stderr="")

    tool = NmapTool(runner=fake_runner)
    inputs = [Asset(type="ip", value="2001:db8::1", source="user_input", task_id="t1")]
    result = tool.run(inputs, ctx)

    # 目标未被拆坏, 完整 IPv6 地址进入扫描命令
    assert result.stats["input_targets"] == 1
    assert "2001:db8::1" in calls[0]


# ---------------- httpx ----------------

def test_httpx_parses_jsonl(ctx):
    sample = [
        {"url": "http://1.2.3.4:80", "status_code": 200, "title": "Test",
         "technologies": ["Nginx"], "host": "1.2.3.4"},
        {"url": "https://example.com", "status_code": 301, "title": "Redirect",
         "technologies": ["Apache"], "host": "example.com"},
    ]

    def fake_runner(cmd, cwd):
        # httpx 会把输出写到 -o 指定的路径
        idx = cmd.index("-o")
        Path(cmd[idx + 1]).write_text("\n".join(json.dumps(x) for x in sample), encoding="utf-8")
        return make_proc(rc=0, stdout="", stderr="")

    tool = HttpxTool(runner=fake_runner)
    inputs = [Asset(type="port", value="1.2.3.4:80", source="nmap", task_id="t1")]
    result = tool.run(inputs, ctx)

    # 2 条 url + 2 条 web_service
    urls = [a for a in result.assets if a.type == "url"]
    wss = [a for a in result.assets if a.type == "web_service"]
    assert len(urls) == 2
    assert len(wss) == 2

    # web_service 字段正确
    ws = next(w for w in wss if w.value == "http://1.2.3.4:80")
    assert ws.status_code == 200
    assert ws.title == "Test"
    assert ws.technologies == ["Nginx"]
    # parent_id 指向 url 资产
    url = next(u for u in urls if u.value == "http://1.2.3.4:80")
    assert ws.parent_id == url.id


def test_httpx_no_targets_returns_empty(ctx):
    tool = HttpxTool(runner=lambda c, w: make_proc())
    result = tool.run([], ctx)
    assert result.assets == []
    assert result.stats["input_targets"] == 0


# ---------------- Wappalyzer ----------------

def test_wappalyzer_enriches_fingerprints(ctx):
    def fake_analyzer(url):
        if url == "http://1.2.3.4:80":
            return {
                "technologies": ["Nginx", "WordPress"],
                "versions": {"Nginx": ["1.18"], "WordPress": ["6.0"]},
                "categories": {"Nginx": ["Web Servers"], "WordPress": ["CMS"]},
            }
        return {"technologies": [], "versions": {}, "categories": {}}

    tool = WappalyzerTool(analyzer=fake_analyzer)
    inputs = [
        Asset(type="url", value="http://1.2.3.4:80", source="httpx", task_id="t1"),
        # 超出范围 url 应被跳过
        Asset(type="url", value="http://evil.com", source="httpx", task_id="t1"),
    ]
    result = tool.run(inputs, ctx)

    assert len(result.assets) == 1
    ws = result.assets[0]
    assert ws.type == "web_service"
    assert ws.value == "http://1.2.3.4:80"
    assert ws.source == "wappalyzer"
    assert set(ws.technologies) == {"Nginx", "WordPress"}
    assert result.stats["analyzed"] == 1
    assert result.stats["skipped_out_of_scope"] == 1


def test_wappalyzer_continues_on_single_url_error(ctx):
    def fake_analyzer(url):
        if ":81" in url:
            raise RuntimeError("connection refused")
        return {"technologies": ["PHP"], "versions": {}, "categories": {}}

    tool = WappalyzerTool(analyzer=fake_analyzer)
    inputs = [
        Asset(type="url", value="http://1.2.3.4:80", source="httpx", task_id="t1"),
        Asset(type="url", value="http://1.2.3.4:81", source="httpx", task_id="t1"),
    ]
    result = tool.run(inputs, ctx)
    # 一个成功一个失败，不中断
    assert len(result.assets) == 1
    assert result.stats["errors"] == 1
    assert "connection refused" in result.raw_output


def test_wappalyzer_concurrent_analyzes_all_urls(ctx):
    """P0-3: 并发路径下所有 in-scope url 都被分析。"""
    def fake_analyzer(url):
        return {"technologies": [url.split(":")[1]], "versions": {}, "categories": {}}

    tool = WappalyzerTool(analyzer=fake_analyzer, max_workers=8)
    inputs = [
        Asset(type="url", value=f"http://1.2.3.4:{p}", source="httpx", task_id="t1")
        for p in (80, 81, 82, 83, 84, 85, 86, 87, 88, 89)
    ]
    result = tool.run(inputs, ctx)

    assert len(result.assets) == 10
    assert result.stats["analyzed"] == 10
    assert result.stats["errors"] == 0
    # 每个 url 都产出一条 web_service
    assert {a.value for a in result.assets} == {
        f"http://1.2.3.4:{p}" for p in (80, 81, 82, 83, 84, 85, 86, 87, 88, 89)
    }


def test_wappalyzer_concurrent_error_isolation(ctx):
    """P0-3: 并发路径下单个 url 失败不中断整批。"""
    def fake_analyzer(url):
        if url.endswith(":89"):
            raise RuntimeError("boom")
        return {"technologies": ["PHP"], "versions": {}, "categories": {}}

    tool = WappalyzerTool(analyzer=fake_analyzer, max_workers=8)
    inputs = [
        Asset(type="url", value=f"http://1.2.3.4:{p}", source="httpx", task_id="t1")
        for p in (80, 89)
    ]
    result = tool.run(inputs, ctx)

    assert len(result.assets) == 1
    assert result.stats["errors"] == 1
    assert "boom" in result.raw_output


def test_wappalyzer_max_workers_one_is_serial(ctx):
    """P0-3: max_workers=1 时串行执行, 结果一致且确定性。"""
    calls = []

    def fake_analyzer(url):
        calls.append(url)
        return {"technologies": ["PHP"], "versions": {}, "categories": {}}

    tool = WappalyzerTool(analyzer=fake_analyzer, max_workers=1)
    inputs = [
        Asset(type="url", value=f"http://1.2.3.4:{p}", source="httpx", task_id="t1")
        for p in (80, 81, 82)
    ]
    result = tool.run(inputs, ctx)

    assert len(result.assets) == 3
    # 串行: 调用顺序与输入顺序一致
    assert calls == ["http://1.2.3.4:80", "http://1.2.3.4:81", "http://1.2.3.4:82"]


def test_wappalyzer_tolerates_non_dict_analyzer_result(ctx):
    """审计 5.1: analyzer 返回非 dict (None) 时不炸整批, 记入 errors。"""
    def fake_analyzer(url):
        return None  # 非法返回类型

    tool = WappalyzerTool(analyzer=fake_analyzer, max_workers=1)
    inputs = [
        Asset(type="url", value="http://1.2.3.4:80", source="httpx", task_id="t1"),
        Asset(type="url", value="http://1.2.3.4:81", source="httpx", task_id="t1"),
    ]
    result = tool.run(inputs, ctx)

    assert result.assets == []
    assert result.stats["errors"] == 2
    assert "返回类型非法" in result.raw_output
