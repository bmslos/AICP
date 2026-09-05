"""Nuclei 漏洞扫描适配器单元测试。

使用 mock runner，不依赖真实 nuclei 二进制。
覆盖: JSONL 解析、字段归一化、无效行容错、授权范围过滤、退出码语义、速率注入。
"""

import json
from pathlib import Path

import pytest

from aicp.models import Asset
from aicp.tools import ToolContext, ToolError, CompletedProcess
from aicp.tools.nuclei import NucleiTool


@pytest.fixture
def ctx(tmp_path):
    return ToolContext(
        task_id="t1",
        authorized_scope=["example.com", "1.2.3.4", "10.0.0.0/24"],
        work_dir=str(tmp_path),
    )


def make_proc(rc=0, stdout="", stderr=""):
    return CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr=stderr)


def write_output(cmd, content, encoding="utf-8"):
    """从 cmd 中取 -o 后的路径并写入内容 (模拟真实工具的产物)。"""
    idx = cmd.index("-o")
    Path(cmd[idx + 1]).write_text(content, encoding=encoding)


def make_vuln(**overrides) -> dict:
    base = {
        "template-id": "cves/2021/CVE-2021-44228",
        "info": {"name": "Log4Shell RCE", "severity": "critical"},
        "type": "http",
        "host": "http://example.com:8080",
        "matched-at": "http://example.com:8080/login",
        "curl-command": "curl 'http://example.com:8080/login'",
    }
    base.update(overrides)
    return base


# ---------------- 运行主流程 ----------------

def test_nuclei_parses_jsonl_and_normalizes_fields(ctx):
    lines = [
        json.dumps(make_vuln()),
        json.dumps(make_vuln(**{
            "template-id": "http/misconfig/test-headers",
            "info": {"name": "Test Headers", "severity": "medium"},
            "matched-at": "http://1.2.3.4:80/admin",
            "type": "dns",
        })),
    ]

    def fake_runner(cmd, cwd):
        write_output(cmd, "\n".join(lines))
        return make_proc(rc=0, stdout="", stderr="")

    tool = NucleiTool(runner=fake_runner)
    inputs = [Asset(type="url", value="http://example.com:8080", source="httpx", task_id="t1")]
    result = tool.run(inputs, ctx)

    assert len(result.assets) == 2
    v1 = result.assets[0]
    assert v1.type == "vulnerability"
    assert v1.source == "nuclei"
    assert v1.task_id == "t1"
    # value 拼入 template_id (去重键区分同 URL 不同模板), 避免漏洞被覆盖丢失
    assert v1.value == "http://example.com:8080/login|cves/2021/CVE-2021-44228"
    assert v1.raw["template_id"] == "cves/2021/CVE-2021-44228"
    assert v1.raw["name"] == "Log4Shell RCE"
    assert v1.raw["severity"] == "critical"
    assert v1.raw["vuln_type"] == "http"
    assert v1.raw["curl_command"] == "curl 'http://example.com:8080/login'"

    # 第二个漏洞: 无 matched-at 时回退 host; severity=medium
    v2 = result.assets[1]
    assert v2.value == "http://1.2.3.4:80/admin|http/misconfig/test-headers"
    assert v2.raw["severity"] == "medium"
    assert v2.raw["vuln_type"] == "dns"

    assert result.stats["input_targets"] == 1
    assert result.stats["vulnerabilities_found"] == 2
    # 命令应包含 -jsonl 与默认 severity 参数
    assert "-jsonl" in result.raw_output
    assert "-severity" in result.raw_output


def test_nuclei_deduplicates_targets(ctx):
    calls = []

    def fake_runner(cmd, cwd):
        calls.append(cmd)
        return make_proc(rc=0, stdout="", stderr="")

    tool = NucleiTool(runner=fake_runner)
    inputs = [
        Asset(type="url", value="http://example.com", source="httpx", task_id="t1"),
        Asset(type="web_service", value="http://example.com", source="httpx", task_id="t1"),
        Asset(type="url", value="http://example.com", source="httpx", task_id="t1"),
    ]
    result = tool.run(inputs, ctx)

    # 3 个输入去重后只剩 1 个目标
    assert result.stats["input_targets"] == 1
    # 输入列表文件只含一个目标
    idx = calls[0].index("-l")
    targets = Path(calls[0][idx + 1]).read_text(encoding="utf-8").splitlines()
    assert targets == ["http://example.com"]


def test_nuclei_injects_rate_limit(ctx):
    calls = []

    def fake_runner(cmd, cwd):
        calls.append(cmd)
        return make_proc(rc=0, stdout="", stderr="")

    ctx.rate_limit = 50
    tool = NucleiTool(runner=fake_runner)
    inputs = [Asset(type="url", value="http://example.com", source="httpx", task_id="t1")]
    tool.run(inputs, ctx)
    assert "-rate-limit" in calls[0]
    assert "50" in calls[0][calls[0].index("-rate-limit") + 1]


def test_nuclei_filters_out_of_scope_targets(ctx):
    def fake_runner(cmd, cwd):
        return make_proc(rc=0, stdout="", stderr="")

    tool = NucleiTool(runner=fake_runner)
    inputs = [Asset(type="url", value="http://evil.com", source="httpx", task_id="t1")]
    result = tool.run(inputs, ctx)
    assert result.assets == []
    assert result.stats["input_targets"] == 0
    assert result.stats["skipped_out_of_scope"] == 1


def test_nuclei_empty_inputs(ctx):
    tool = NucleiTool(runner=lambda c, w: make_proc())
    result = tool.run([], ctx)
    assert result.assets == []
    assert result.stats["input_targets"] == 0


# ---------------- 退出码语义 ----------------

def test_nuclei_rc0_and_rc1_are_success(ctx):
    """rc=0 有发现; rc=1 无发现但扫描完成, 均不应抛错。"""
    for rc in (0, 1):
        def fake_runner(cmd, cwd, _rc=rc):
            return make_proc(rc=_rc, stdout="", stderr="")

        tool = NucleiTool(runner=fake_runner)
        inputs = [Asset(type="url", value="http://example.com", source="httpx", task_id="t1")]
        result = tool.run(inputs, ctx)
        assert result.assets == []
        assert result.stats["vulnerabilities_found"] == 0


def test_nuclei_raises_on_other_rc(ctx):
    def fake_runner(cmd, cwd):
        return make_proc(rc=2, stdout="", stderr="nuclei crashed")

    tool = NucleiTool(runner=fake_runner)
    inputs = [Asset(type="url", value="http://example.com", source="httpx", task_id="t1")]
    with pytest.raises(ToolError, match="nuclei 执行失败 rc=2"):
        tool.run(inputs, ctx)


# ---------------- _parse_jsonl 静态方法 ----------------

def test_parse_jsonl_missing_file_returns_empty(tmp_path):
    assert NucleiTool._parse_jsonl(tmp_path / "nonexistent.jsonl", "t1") == []


def test_parse_jsonl_skips_invalid_lines(tmp_path):
    content = "\n".join([
        json.dumps(make_vuln()),
        "this is not json",
        "{\"broken\": ",
        "",
        json.dumps(make_vuln(**{"matched-at": "http://1.2.3.4:80/x"})),
    ])
    p = tmp_path / "out.jsonl"
    p.write_text(content, encoding="utf-8")

    assets = NucleiTool._parse_jsonl(p, "t1")
    # 2 行有效, 2 行无效跳过
    assert len(assets) == 2


def test_parse_jsonl_handles_missing_fields(tmp_path):
    """info 缺失 / template-id 缺失时用兜底值。"""
    content = json.dumps({"host": "http://example.com", "matched-at": "http://example.com/p"})
    p = tmp_path / "out.jsonl"
    p.write_text(content, encoding="utf-8")

    assets = NucleiTool._parse_jsonl(p, "t1")
    assert len(assets) == 1
    a = assets[0]
    assert a.raw["template_id"] == ""          # 无 template-id
    assert a.raw["name"] == ""                 # info 缺失回退 template_id(空)
    assert a.raw["severity"] == "unknown"
    assert a.value == "http://example.com/p"   # 无 template-id 时 value 不带后缀


def test_nuclei_distinct_templates_not_deduplicated(ctx, tmp_path):
    """同一 URL 上不同模板命中的漏洞, 经 Store 保存后应全部保留 (修复去重覆盖)。"""
    lines = [
        json.dumps(make_vuln()),  # template: cves/2021/CVE-2021-44228
        json.dumps(make_vuln(**{
            "template-id": "http/misconfig/test-headers",
            "info": {"name": "Test Headers", "severity": "medium"},
            "matched-at": "http://example.com:8080/login",
        })),
    ]

    def fake_runner(cmd, cwd):
        write_output(cmd, "\n".join(lines))
        return make_proc(rc=0, stdout="", stderr="")

    tool = NucleiTool(runner=fake_runner)
    inputs = [Asset(type="url", value="http://example.com:8080", source="httpx", task_id="t1")]
    result = tool.run(inputs, ctx)

    # value 因拼入 template_id 而互不相同, 避免被 Store 的 UNIQUE 去重键合并
    values = [a.value for a in result.assets]
    assert len(set(values)) == 2

    from aicp.scheduler import Store
    db = tmp_path / "store.db"
    with Store(db) as store:
        n = store.save_assets(result.assets)
        rows = store.list_assets("t1")
        assert n == 2                       # 两条都是新增
        assert len(rows) == 2               # 不被覆盖丢失
        assert {r.raw["template_id"] for r in rows} == {
            "cves/2021/CVE-2021-44228",
            "http/misconfig/test-headers",
        }


def test_nuclei_cleans_stale_output_before_run(ctx, tmp_path):
    """P0-2: resume 重跑时旧输出文件会被清理, 不解析到旧数据。"""
    # 预置一个残留的旧输出文件 (含一条旧漏洞, 模拟上一轮失败/中断的产物)
    stale_path = tmp_path / "nuclei_output_t1.jsonl"
    stale_path.write_text(json.dumps(make_vuln()), encoding="utf-8")

    # 本轮新结果只有一条新模板的漏洞
    lines = [json.dumps(make_vuln(**{
        "template-id": "http/new-template",
        "matched-at": "http://example.com:8080/new",
    }))]

    def fake_runner(cmd, cwd):
        write_output(cmd, "\n".join(lines))
        return make_proc(rc=0, stdout="", stderr="")

    tool = NucleiTool(runner=fake_runner)
    inputs = [Asset(type="url", value="http://example.com:8080", source="httpx", task_id="t1")]
    result = tool.run(inputs, ctx)

    # 只有新结果, 旧漏洞不被解析
    assert len(result.assets) == 1
    assert result.assets[0].raw["template_id"] == "http/new-template"
