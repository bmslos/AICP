"""插件系统 - Tool 注册与发现机制。

允许第三方通过 entry_points 或显式注册方式扩展工具，无需修改核心代码。

使用方式:
1. Entry Point 自动发现 (推荐):
   在第三方包的 setup.cfg / pyproject.toml 中声明:
   [project.entry-points."aicp.tools"]
   my_tool = "my_package.module:MyToolClass"

2. 显式注册:
   from aicp.tools.registry import tool_registry
   tool_registry.register(MyToolClass)

3. 获取所有已注册工具:
   from aicp.tools.registry import tool_registry
   tools = tool_registry.discover(runner=my_runner)
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Type

from .base import Tool, ProcessRunner

logger = logging.getLogger(__name__)


class ToolRegistry:
    """工具注册表 - 管理所有可用的 Tool 类。

    支持:
    - 显式注册 (register)
    - entry_points 自动发现 (discover_entrypoints)
    - 按名称/阶段查询
    - 实例化 (传入 runner 等构造参数)
    """

    def __init__(self):
        # name -> Tool 子类
        self._registry: Dict[str, Type[Tool]] = {}

    def register(self, tool_cls: Type[Tool], name: Optional[str] = None) -> None:
        """注册一个 Tool 类。

        - tool_cls: Tool 的子类
        - name: 注册名称 (默认用类名的小写形式)
        """
        if not (isinstance(tool_cls, type) and issubclass(tool_cls, Tool)):
            raise TypeError(f"tool_cls 必须是 Tool 的子类, 得到: {tool_cls}")
        reg_name = name or tool_cls.name or tool_cls.__name__.lower()
        if reg_name in self._registry:
            logger.warning("工具 '%s' 已注册, 将被覆盖: %s -> %s",
                           reg_name, self._registry[reg_name], tool_cls)
        self._registry[reg_name] = tool_cls
        logger.debug("注册工具: %s -> %s", reg_name, tool_cls)

    def unregister(self, name: str) -> Optional[Type[Tool]]:
        """注销一个已注册的工具，返回被移除的类 (不存在则返回 None)。"""
        return self._registry.pop(name, None)

    def get(self, name: str) -> Optional[Type[Tool]]:
        """按名称获取 Tool 类。"""
        return self._registry.get(name)

    def list_registered(self) -> Dict[str, Type[Tool]]:
        """返回所有已注册工具的 {name: cls} 字典。"""
        return dict(self._registry)

    def discover_entrypoints(self, group: str = "aicp.tools") -> int:
        """通过 importlib.metadata entry_points 自动发现并注册第三方工具。

        返回新发现的工具数量。
        """
        try:
            from importlib.metadata import entry_points
        except ImportError:
            # Python < 3.9 fallback
            try:
                import importlib_metadata
                entry_points = importlib_metadata.entry_points
            except ImportError:
                logger.warning("importlib.metadata 不可用, 跳过 entry_points 发现")
                return 0

        discovered = 0
        try:
            # Python 3.12+ / 3.9+ 兼容
            eps = entry_points()
            if hasattr(eps, "select"):
                # Python 3.12+ 返回 SelectableGroups
                group_eps = eps.select(group=group)
            elif isinstance(eps, dict):
                # Python 3.9-3.11 返回 dict
                group_eps = eps.get(group, [])
            else:
                group_eps = [ep for ep in eps if ep.group == group]
        except Exception as e:
            logger.warning("entry_points 发现失败: %s", e)
            return 0

        for ep in group_eps:
            try:
                tool_cls = ep.load()
                if isinstance(tool_cls, type) and issubclass(tool_cls, Tool):
                    self.register(tool_cls, name=ep.name)
                    discovered += 1
                    logger.info("从 entry_points 发现工具: %s -> %s", ep.name, tool_cls)
                else:
                    logger.warning("entry_point '%s' 不是 Tool 子类, 已跳过", ep.name)
            except Exception as e:
                logger.warning("加载 entry_point '%s' 失败: %s", ep.name, e)

        return discovered

    def create_tools(
        self,
        runner: ProcessRunner,
        names: Optional[List[str]] = None,
        extra_kwargs: Optional[Dict[str, dict]] = None,
    ) -> List[Tool]:
        """实例化工具列表。

        - runner: 进程执行器 (传给需要 runner 的工具)
        - names: 只实例化指定名称的工具 (None = 全部)
        - extra_kwargs: 按工具名传递额外构造参数 {"nmap": {"nmap_cmd": [...]}}
        """
        extra_kwargs = extra_kwargs or {}
        tools: List[Tool] = []

        targets = self._registry
        if names:
            targets = {n: cls for n, cls in self._registry.items() if n in names}
            missing = set(names) - set(targets.keys())
            if missing:
                logger.warning("以下工具未注册: %s", ",".join(sorted(missing)))

        for name, cls in targets.items():
            kwargs = dict(extra_kwargs.get(name, {}))
            try:
                # 检查构造函数是否接受 runner 参数
                import inspect
                sig = inspect.signature(cls.__init__)
                if "runner" in sig.parameters:
                    tool = cls(runner=runner, **kwargs)
                else:
                    tool = cls(**kwargs)
                tools.append(tool)
            except Exception as e:
                logger.warning("实例化工具 '%s' 失败: %s", name, e)

        return tools

    def discover(
        self,
        runner: ProcessRunner,
        names: Optional[List[str]] = None,
        include_entrypoints: bool = True,
    ) -> List[Tool]:
        """一站式: 发现 entry_points + 实例化工具。"""
        if include_entrypoints:
            self.discover_entrypoints()
        return self.create_tools(runner=runner, names=names)


# 全局单例注册表
tool_registry = ToolRegistry()


def _register_builtin_tools() -> None:
    """注册内置工具到全局注册表。"""
    from .oneforall import OneForAllTool
    from .nmap import NmapTool
    from .httpx_tool import HttpxTool
    from .nuclei import NucleiTool
    from .dirsearch import DirsearchTool

    tool_registry.register(OneForAllTool, name="oneforall")
    tool_registry.register(NmapTool, name="nmap")
    tool_registry.register(HttpxTool, name="httpx")
    tool_registry.register(NucleiTool, name="nuclei")
    tool_registry.register(DirsearchTool, name="dirsearch")

    # Wappalyzer 特殊处理: 需要 analyzer 而非 runner
    try:
        from .wappalyzer import WappalyzerTool
        tool_registry.register(WappalyzerTool, name="wappalyzer")
    except ImportError:
        logger.debug("Wappalyzer 依赖不可用, 跳过注册")


# 模块导入时自动注册内置工具
_register_builtin_tools()
