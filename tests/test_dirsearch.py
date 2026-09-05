"""dirsearch 目录枚举适配器单元测试。

使用 mock runner，不依赖真实 dirsearch。
覆盖: JSON 报告解析、404 过滤、无 url 条目跳过、授权范围过滤、退出码语义、速率注入。
"""

import json
from pathlib import Path

import pytest

from aicp.models import Asset
from aicp.tools import ToolContext, ToolError, CompletedProcess
from aicp.tools.dirsearch import DirsearchTool


@pytest.fixture
def ctx(tmp_path):
    return ToolContext(
        task_id="t1",
        authorized_scope=["example.com", "1.2.3.4", "10.0.0.0/24"],
        work_dir=str(tmp_path),
    )


def make_proc(rc=0, stdout="", stderr=""):
    return CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr=stderr)


def write_output(cmd, content):
    """从 cmd 中取 -o 后的路径并写入内容。"""
    idx = cmd.index("-o")
    Path(cmd[idx + 1]).write_text(content, encoding="utf-8")


def make_result(**overrides) -> dict:
    base = {
        "url": "http://example.com/admin",
        "status": 200,
        "size": 1234,
        "redirect": "",
        "content-type": "text/html",
    }
    base.update(overrides)
    return base


# ---------------- 运行主流程 ----------------

def test_dirsearch_parses_json_and_normalizes_fields(ctx):
    payload = {
        "results": [
            make_result(url="http://example.com/admin", status=200, size=1024),
            make_result(url="http://example.com/api/v1", status=301, redirect="http://example.com/api/"),
        ]
    }

    def fake_runner(cmd, cwd):
        write_output(cmd, json.dumps(payload))
        return make_proc(rc=0, stdout="", stderr="")

    tool = DirsearchTool(runner=fake_runner)
    inputs = [Asset(type="url", value="http://example.com", source="httpx", task_id="t1")]
    result = tool.run(inputs, ctx)

    assert len(result.assets) == 2
    d1, d2 = result.assets
    assert d1.type == "directory"
    assert d1.source == "dirsearch"
    assert d1.task_id == "t1"
    assert d1.value == "http://example.com/admin"
    assert d1.status_code == 200
    assert d1.raw["size"] == 1024

    assert d2.value == "http://example.com/api/v1"
    assert d2.status_code == 301
    assert d2.raw["redirect"] == "http://example.com/api/"

    assert result.stats["input_targets"] == 1
    assert result.stats["directories_found"] == 2


def test_dirsearch_filters_404(ctx):
    payload = {
        "results": [
            make_result(url="http://example.com/real", status=200),
            make_result(url="http://example.com/not-found", status=404),
            make_result(url="http://example.com/also-real", status=500),
        ]
    }

    def fake_runner(cmd, cwd):
        write_output(cmd, json.dumps(payload))
        return make_proc(rc=0, stdout="", stderr="")

    tool = DirsearchTool(runner=fake_runner)
    inputs = [Asset(type="url", value="http://example.com", source="httpx", task_id="t1")]
    result = tool.run(inputs, ctx)

    values = sorted(a.value for a in result.assets)
    assert values == ["http://example.com/also-real", "http://example.com/real"]
    assert result.stats["directories_found"] == 2


def test_dirsearch_skips_entries_without_url(ctx):
    payload = {"results": [
        make_result(url="http://example.com/ok", status=200),
        {"status": 200, "size": 1},  # 无 url, 应跳过
    ]}

    def fake_runner(cmd, cwd):
        write_output(cmd, json.dumps(payload))
        return make_proc(rc=0, stdout="", stderr="")

    tool = DirsearchTool(runner=fake_runner)
    inputs = [Asset(type="url", value="http://example.com", source="httpx", task_id="t1")]
    result = tool.run(inputs, ctx)
    assert len(result.assets) == 1
    assert result.assets[0].value == "http://example.com/ok"


def test_dirsearch_injects_rate_limit(ctx):
    calls = []

    def fake_runner(cmd, cwd):
        calls.append(cmd)
        return make_proc(rc=0, stdout="", stderr="")

    ctx.rate_limit = 30
    tool = DirsearchTool(runner=fake_runner)
    inputs = [Asset(type="url", value="http://example.com", source="httpx", task_id="t1")]
    tool.run(inputs, ctx)
    assert "--max-rate" in calls[0]
    assert "30" in calls[0][calls[0].index("--max-rate") + 1]


def test_dirsearch_filters_out_of_scope_targets(ctx):
    def fake_runner(cmd, cwd):
        return make_proc(rc=0, stdout="", stderr="")

    tool = DirsearchTool(runner=fake_runner)
    inputs = [Asset(type="url", value="http://evil.com", source="httpx", task_id="t1")]
    result = tool.run(inputs, ctx)
    assert result.assets == []
    assert result.stats["input_targets"] == 0
    assert result.stats["skipped_out_of_scope"] == 1


def test_dirsearch_empty_inputs(ctx):
    tool = DirsearchTool(runner=lambda c, w: make_proc())
    result = tool.run([], ctx)
    assert result.assets == []
    assert result.stats["input_targets"] == 0


# ---------------- 退出码语义 ----------------

def test_dirsearch_rc0_and_rc1_are_success(ctx):
    """rc=0 成功; rc=1 部分目标失败但整体完成, 均不应抛错。"""
    for rc in (0, 1):
        def fake_runner(cmd, cwd, _rc=rc):
            write_output(cmd, json.dumps({"results": []}))
            return make_proc(rc=_rc, stdout="", stderr="")

        tool = DirsearchTool(runner=fake_runner)
        inputs = [Asset(type="url", value="http://example.com", source="httpx", task_id="t1")]
        result = tool.run(inputs, ctx)
        assert result.assets == []


def test_dirsearch_raises_on_other_rc(ctx):
    def fake_runner(cmd, cwd):
        return make_proc(rc=2, stdout="", stderr="dirsearch error")

    tool = DirsearchTool(runner=fake_runner)
    inputs = [Asset(type="url", value="http://example.com", source="httpx", task_id="t1")]
    with pytest.raises(ToolError, match="dirsearch 执行失败 rc=2"):
        tool.run(inputs, ctx)


# ---------------- _parse_json 静态方法 ----------------

def test_parse_json_missing_file_returns_empty(tmp_path):
    assert DirsearchTool._parse_json(tmp_path / "nonexistent.json", "t1") == []


def test_parse_json_invalid_content_returns_empty(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{invalid json", encoding="utf-8")
    assert DirsearchTool._parse_json(p, "t1") == []


def test_parse_json_empty_results(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text(json.dumps({"results": []}), encoding="utf-8")
    assert DirsearchTool._parse_json(p, "t1") == []
