"""工具适配层统一接口。

所有外部工具 (OneForAll/Nmap/httpx/Wappalyzer) 都实现 Tool 接口，
编排器只面向 Tool 接口编程，不感知具体工具。

输入: 上游阶段产出的 Asset 列表 + 任务上下文
输出: 本阶段产出的 Asset 列表 (已归一化)
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import List, Optional, Callable

from ..models import Asset, StageName


class ToolError(Exception):
    """工具执行失败。"""


@dataclass
class ToolContext:
    """工具运行上下文。"""

    task_id: str
    authorized_scope: List[str]                  # 授权范围，工具内部过滤用
    work_dir: str                                # 工作目录 (存放临时文件)
    rate_limit: Optional[int] = None             # 全局速率 (req/s)，None 表示不限
    extra_args: List[str] = field(default_factory=list)  # 透传给工具的额外参数


@dataclass
class ToolResult:
    """工具执行结果。"""

    assets: List[Asset] = field(default_factory=list)
    raw_output: str = ""                         # 原始输出 (用于审计)
    stats: dict = field(default_factory=dict)    # 统计信息


class Tool(abc.ABC):
    """工具适配层统一接口。"""

    #: 工具名 (registry 注册名 / --tool-args 匹配键, 由子类声明)
    name: str = ""

    #: 该工具对应的阶段
    stage: StageName

    #: 该工具产出的资产类型 (用于上游过滤输入)
    input_asset_types: tuple[str, ...] = ()

    #: 该工具产出的资产类型
    output_asset_types: tuple[str, ...] = ()

    @abc.abstractmethod
    def run(self, inputs: List[Asset], ctx: ToolContext) -> ToolResult:
        """执行工具，返回归一化后的资产列表。

        - inputs: 上游阶段产出的资产 (已按 input_asset_types 过滤)
        - ctx: 运行上下文
        - 抛 ToolError 表示执行失败
        """
        raise NotImplementedError

    @staticmethod
    def filter_inputs(
        inputs: List[Asset], types: tuple[str, ...]
    ) -> List[Asset]:
        """从上游资产中筛选出指定类型的资产。"""
        if not types:
            return list(inputs)
        return [a for a in inputs if a.type in types]


# 进程执行器 - 抽象出来便于测试时 mock
ProcessRunner = Callable[[List[str], str], "CompletedProcess"]


@dataclass
class CompletedProcess:
    """子进程执行结果 (subprocess.CompletedProcess 的简化版，便于 mock)。"""

    args: List[str]
    returncode: int
    stdout: str
    stderr: str
