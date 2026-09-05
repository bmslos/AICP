"""插件系统 (ToolRegistry) 单元测试。

覆盖: 注册/注销/查询、命名规则、类型校验、覆盖警告、实例化、entry_points 发现、
非 Tool 跳过、加载失败容错、全局单例与内置工具注册。
"""

import logging

import pytest

from aicp.models import Asset, StageName
from aicp.tools import Tool, ToolResult
from aicp.tools.registry import ToolRegistry, tool_registry


# ---------------- 测试用 Tool 子类 ----------------

class FakeTool(Tool):
    """无构造参数的简单工具。"""
    stage = StageName.SUBDOMAIN

    def run(self, inputs, ctx):
        return ToolResult(assets=[
            Asset(type="domain", value="fake.example.com", source="fake", task_id=ctx.task_id)
        ])


class RunnerTool(Tool):
    """需要 runner 构造参数的工具。"""
    stage = StageName.PORTSCAN

    def __init__(self, *, runner, tag="default"):
        self.runner = runner
        self.tag = tag

    def run(self, inputs, ctx):
        return ToolResult()


class NotATool:
    pass


# ---------------- 注册 / 查询 ----------------

def test_register_and_get():
    reg = ToolRegistry()
    reg.register(FakeTool)
    assert reg.get("faketool") is FakeTool
    assert reg.get("nonexistent") is None


def test_register_custom_name():
    reg = ToolRegistry()
    reg.register(FakeTool, name="my-fake")
    assert reg.get("my-fake") is FakeTool
    assert reg.get("faketool") is None  # 默认名不再生效


def test_register_rejects_non_tool():
    reg = ToolRegistry()
    with pytest.raises(TypeError, match="Tool 的子类"):
        reg.register(NotATool)
    with pytest.raises(TypeError, match="Tool 的子类"):
        reg.register("not-a-class")


def test_register_overwrite_logs_warning(caplog):
    class ToolA(Tool):
        stage = StageName.SUBDOMAIN
        def run(self, inputs, ctx):
            return ToolResult()

    class ToolB(Tool):
        stage = StageName.SUBDOMAIN
        def run(self, inputs, ctx):
            return ToolResult()

    reg = ToolRegistry()
    reg.register(ToolA, name="dup")
    with caplog.at_level(logging.WARNING, logger="aicp.tools.registry"):
        reg.register(ToolB, name="dup")
    assert reg.get("dup") is ToolB
    assert "将被覆盖" in caplog.text


def test_unregister_removes_and_returns():
    reg = ToolRegistry()
    reg.register(FakeTool)
    assert reg.unregister("faketool") is FakeTool
    assert reg.get("faketool") is None
    assert reg.unregister("faketool") is None  # 不存在返回 None


def test_list_registered_returns_copy():
    reg = ToolRegistry()
    reg.register(FakeTool)
    d = reg.list_registered()
    d["fake"] = NotATool  # 修改副本不影响内部状态
    assert reg.get("fake") is None


# ---------------- 实例化 ----------------

def test_create_tools_passes_runner():
    reg = ToolRegistry()
    reg.register(RunnerTool)

    seen = []
    def fake_runner(cmd, cwd):
        seen.append(cmd)
        return None

    tools = reg.create_tools(runner=fake_runner)
    assert len(tools) == 1
    assert isinstance(tools[0], RunnerTool)
    assert tools[0].runner is fake_runner


def test_create_tools_without_runner_param():
    reg = ToolRegistry()
    reg.register(FakeTool)
    tools = reg.create_tools(runner=lambda c, w: None)
    assert len(tools) == 1
    assert isinstance(tools[0], FakeTool)


def test_create_tools_names_filter():
    reg = ToolRegistry()
    reg.register(FakeTool, name="fake")
    reg.register(RunnerTool, name="runner")
    tools = reg.create_tools(runner=lambda c, w: None, names=["runner"])
    assert len(tools) == 1
    assert isinstance(tools[0], RunnerTool)


def test_create_tools_extra_kwargs():
    reg = ToolRegistry()
    reg.register(RunnerTool, name="runner")
    tools = reg.create_tools(
        runner=lambda c, w: None,
        names=["runner"],
        extra_kwargs={"runner": {"tag": "special"}},
    )
    assert tools[0].tag == "special"


def test_create_tools_missing_name_warns(caplog):
    reg = ToolRegistry()
    reg.register(FakeTool, name="fake")
    with caplog.at_level(logging.WARNING, logger="aicp.tools.registry"):
        tools = reg.create_tools(runner=lambda c, w: None, names=["fake", "ghost"])
    assert len(tools) == 1
    assert "ghost" in caplog.text


def test_create_tools_skips_broken_constructor(caplog):
    class BrokenTool(Tool):
        stage = StageName.SUBDOMAIN
        def __init__(self, *, required_arg):
            self.required_arg = required_arg
        def run(self, inputs, ctx):
            return ToolResult()

    reg = ToolRegistry()
    reg.register(BrokenTool, name="broken")
    with caplog.at_level(logging.WARNING, logger="aicp.tools.registry"):
        tools = reg.create_tools(runner=lambda c, w: None)
    assert tools == []  # 缺少 required_arg, 实例化失败被跳过
    assert "实例化工具" in caplog.text


# ---------------- entry_points 发现 ----------------

class FakeEP:
    """模拟 importlib.metadata.EntryPoint。"""

    def __init__(self, name, loader):
        self.name = name
        self._loader = loader

    def load(self):
        return self._loader()


class FakeSelectableGroups:
    """模拟 Python 3.12+ 的 SelectableGroups (带 .select)。"""

    def __init__(self, groups):
        self._groups = groups  # {group: [FakeEP, ...]}

    def select(self, group=None):
        return self._groups.get(group, [])


def test_discover_entrypoints_via_selectable_groups(monkeypatch):
    reg = ToolRegistry()

    def fake_entry_points():
        return FakeSelectableGroups({
            "aicp.tools": [
                FakeEP("ep_fake", lambda: FakeTool),
                FakeEP("ep_runner", lambda: RunnerTool),
            ],
        })

    monkeypatch.setattr("importlib.metadata.entry_points", fake_entry_points)
    discovered = reg.discover_entrypoints()
    assert discovered == 2
    assert reg.get("ep_fake") is FakeTool
    assert reg.get("ep_runner") is RunnerTool


def test_discover_entrypoints_skips_non_tool(monkeypatch, caplog):
    reg = ToolRegistry()

    def fake_entry_points():
        return FakeSelectableGroups({
            "aicp.tools": [FakeEP("bad", lambda: NotATool)],
        })

    monkeypatch.setattr("importlib.metadata.entry_points", fake_entry_points)
    with caplog.at_level(logging.WARNING, logger="aicp.tools.registry"):
        discovered = reg.discover_entrypoints()
    assert discovered == 0
    assert reg.list_registered() == {}
    assert "不是 Tool 子类" in caplog.text


def test_discover_entrypoints_load_failure_tolerated(monkeypatch, caplog):
    reg = ToolRegistry()

    def boom():
        raise RuntimeError("import error")

    def fake_entry_points():
        return FakeSelectableGroups({
            "aicp.tools": [
                FakeEP("ok", lambda: FakeTool),
                FakeEP("broken", boom),
            ],
        })

    monkeypatch.setattr("importlib.metadata.entry_points", fake_entry_points)
    with caplog.at_level(logging.WARNING, logger="aicp.tools.registry"):
        discovered = reg.discover_entrypoints()
    # 1 个成功 1 个失败, 失败被跳过不中断
    assert discovered == 1
    assert reg.get("ok") is FakeTool
    assert "加载 entry_point 'broken' 失败" in caplog.text


def test_discover_entrypoints_no_results(monkeypatch):
    reg = ToolRegistry()
    monkeypatch.setattr("importlib.metadata.entry_points", lambda: FakeSelectableGroups({}))
    assert reg.discover_entrypoints() == 0


def test_discover_entrypoints_raises_tolerated(monkeypatch, caplog):
    """entry_points() 本身抛异常时应返回 0 而不崩溃。"""
    reg = ToolRegistry()

    def boom():
        raise RuntimeError("metadata broken")

    monkeypatch.setattr("importlib.metadata.entry_points", boom)
    with caplog.at_level(logging.WARNING, logger="aicp.tools.registry"):
        assert reg.discover_entrypoints() == 0
    assert "发现失败" in caplog.text


# ---------------- discover 一站式 ----------------

def test_discover_includes_entrypoints(monkeypatch):
    reg = ToolRegistry()
    reg.register(RunnerTool, name="runner")

    def fake_entry_points():
        return FakeSelectableGroups({
            "aicp.tools": [FakeEP("ep_fake", lambda: FakeTool)],
        })

    monkeypatch.setattr("importlib.metadata.entry_points", fake_entry_points)
    tools = reg.discover(runner=lambda c, w: None)
    types = {type(t) for t in tools}
    assert RunnerTool in types
    assert FakeTool in types


def test_discover_can_skip_entrypoints():
    reg = ToolRegistry()
    reg.register(RunnerTool, name="runner")
    tools = reg.discover(runner=lambda c, w: None, include_entrypoints=False)
    assert len(tools) == 1
    assert isinstance(tools[0], RunnerTool)


# ---------------- 全局单例与内置工具 ----------------

def test_global_singleton_is_tool_registry():
    assert isinstance(tool_registry, ToolRegistry)


def test_global_singleton_has_builtin_tools():
    names = set(tool_registry.list_registered())
    # 5 个核心内置工具 (wappalyzer 因依赖可选, 不强制)
    assert {"oneforall", "nmap", "httpx", "nuclei", "dirsearch"} <= names


def test_builtin_tools_are_tool_subclasses():
    for cls in tool_registry.list_registered().values():
        assert isinstance(cls, type) and issubclass(cls, Tool)
