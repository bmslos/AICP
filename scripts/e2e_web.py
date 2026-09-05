"""端到端启动 Web 前端 (用真实 Wappalyzer + StubUrlInjector)。

环境现状:
- python-Wappalyzer 已安装
- nmap / httpx (Go) / OneForAll 未安装

用法:
    python scripts/e2e_web.py --port 5000
    # 浏览器打开 http://127.0.0.1:5000/

验证点:
- 首页能正常加载
- 新建任务表单能提交
- 任务在后台异步执行
- 详情页 JS 轮询能看到状态变化
- 报告查看能显示真实指纹 (Cloudflare 等)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional, Sequence

# 让脚本能 import aicp
sys.path.insert(0, str(Path(__file__).parent.parent))

import aicp.cli as cli_module
from aicp.models import Asset, StageName
from aicp.tools import Tool, ToolContext, ToolResult
from aicp.tools.wappalyzer import WappalyzerTool, default_analyzer_factory
from aicp.web import create_app


class StubUrlInjector(Tool):
    """stub: 把 domain/ip/port 资产转成 url 资产 (替代 httpx)。"""
    stage = StageName.FINGERPRINT
    input_asset_types = ("domain", "ip", "port")
    output_asset_types = ("url",)

    def run(self, inputs: List[Asset], ctx: ToolContext) -> ToolResult:
        urls: List[Asset] = []
        for a in inputs:
            if a.type == "domain":
                url = f"http://{a.value}:80"
            elif a.type == "ip":
                url = f"http://{a.value}:80"
            elif a.type == "port":
                url = f"http://{a.value}"
            else:
                continue
            urls.append(Asset(
                type="url", value=url, source="stub_httpx",
                task_id=ctx.task_id, parent_id=a.id,
            ))
        return ToolResult(assets=urls, stats={"produced": len(urls)})


def _stub_tools_factory():
    """每次调用都重新构造 (TaskRunner 要求无参 callable)。"""
    analyzer = default_analyzer_factory()
    return [StubUrlInjector(), WappalyzerTool(analyzer=analyzer)]


# 替换 CLI 默认工具工厂 (web 命令会用到)
cli_module._default_tools = lambda work_dir, names=None: _stub_tools_factory()


if __name__ == "__main__":
    import click

    @click.command()
    @click.option("--host", default="127.0.0.1")
    @click.option("--port", default=5000, type=int)
    @click.option("--db", default=None)
    @click.option("--work-dir", default=None)
    @click.option("--report-dir", default=None)
    @click.option("--debug", is_flag=True, default=False)
    def main(host, port, db, work_dir, report_dir, debug):
        from aicp.cli import DEFAULT_DB, DEFAULT_WORK_DIR, DEFAULT_REPORT_DIR, _ensure_task_dir, _resolve_paths

        paths = _resolve_paths(db, work_dir, report_dir)
        _ensure_task_dir(paths)

        app = create_app(
            db_path=paths["db"],
            work_dir=paths["work_dir"],
            report_dir=paths["report_dir"],
            tools_factory=_stub_tools_factory,
        )
        click.echo(f"AICP Web (e2e) 启动: http://{host}:{port}/")
        app.run(host=host, port=port, debug=debug)

    main()
