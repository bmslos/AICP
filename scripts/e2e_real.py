"""端到端真实工具联调脚本。

环境现状:
- python-Wappalyzer 已安装 (0.3.1)，API 已适配
- nmap / httpx (projectdiscovery Go 版) / OneForAll 未安装

联调策略:
- 用真实 Wappalyzer 做指纹识别
- StubUrlInjector 替代 httpx: 把 domain/ip 资产转成 url 资产
    (因为 Wappalyzer 输入是 url，没 httpx 就没 url 资产)
- 走 aicp CLI scan 命令，验证整条链路: CLI -> 编排器 -> 工具适配 -> Store -> 报告

目标: example.com (IANA 保留示例域名，访问合法合规)

用法:
    python scripts/e2e_real.py scan example.com \
        --authorized-by "联调测试" --authorization-note "E2E-DEMO" \
        --scope example.com

预期:
- 任务状态 completed
- 报告里 web_service.technologies 至少识别出 1 项 (如 Cloudflare)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional, Sequence

# 让脚本能 import aicp (不依赖 pip install -e .)
sys.path.insert(0, str(Path(__file__).parent.parent))

import aicp.cli as cli_module
from aicp.models import Asset, StageName
from aicp.tools import Tool, ToolContext, ToolResult
from aicp.tools.wappalyzer import WappalyzerTool, default_analyzer_factory


class StubUrlInjector(Tool):
    """stub: 把 domain/ip/port 资产转成 url 资产 (替代 httpx 的 url 产出)。

    不发起真实 HTTP 请求，只做资产形式转换。
    默认补 80 端口 (与 httpx 行为一致)。
    """

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
                # port.value 形如 "1.2.3.4:80"
                url = f"http://{a.value}"
            else:
                continue
            urls.append(Asset(
                type="url", value=url, source="stub_httpx",
                task_id=ctx.task_id, parent_id=a.id,
            ))
        return ToolResult(assets=urls, stats={"produced": len(urls)})


def _stub_tools(work_dir: str, names: Optional[Sequence[str]] = None) -> List[Tool]:
    """stub 工具链: StubUrlInjector + 真实 Wappalyzer。

    SUBDOMAIN / PORTSCAN 阶段无工具，编排器会标记为 COMPLETED (空跑)。
    """
    analyzer = default_analyzer_factory()
    return [StubUrlInjector(), WappalyzerTool(analyzer=analyzer)]


# 替换 CLI 的默认工具工厂
cli_module._default_tools = _stub_tools


if __name__ == "__main__":
    cli_module.main()
