"""工具适配层 - 每个外部工具封装为统一的 Tool 接口。"""

from .base import Tool, ToolResult, ToolError, ToolContext, ProcessRunner, CompletedProcess
from .registry import ToolRegistry, tool_registry

__all__ = [
    "Tool", "ToolResult", "ToolError", "ToolContext", "ProcessRunner", "CompletedProcess",
    "ToolRegistry", "tool_registry",
]
