"""httpx 适配器 - Web 探测与基础指纹。

调用 projectdiscovery/httpx (Go 单二进制) 对上游 port 资产做 HTTP 探测，
输出 JSONL (-jsonl -o out.jsonl)，归一化为：
- type=url          (http://1.2.3.4:80)
- type=web_service  (含 status_code / title / technologies 基础信息)

httpx 自带轻量指纹 (tech detect)，详细指纹交给 Wappalyzer 阶段补充。

设计要点：
- 输入只取 type=port 资产，构建 url 列表喂给 httpx；
- 通过 -rate-limit 注入速率；
- 解析 JSONL 后做授权范围过滤 (ip 必须在 scope 内)。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from ..auth import AuthorizationVerifier
from ..models import Asset, StageName
from .base import Tool, ToolContext, ToolResult, ToolError, ProcessRunner


class HttpxTool(Tool):
    """httpx Web 探测适配器。"""

    name = "httpx"
    stage = StageName.FINGERPRINT
    input_asset_types = ("port", "ip", "domain")
    output_asset_types = ("url", "web_service")

    def __init__(
        self,
        *,
        runner: ProcessRunner,
        httpx_cmd: Optional[List[str]] = None,
        default_args: Optional[List[str]] = None,
    ):
        self._runner = runner
        self._cmd = httpx_cmd or ["httpx"]
        # 默认: 探测 + 标题 + 技术栈 + 静默 + JSONL 输出
        self._default_args = default_args or ["-title", "-tech-detect", "-silent", "-jsonl"]
        self._verifier = AuthorizationVerifier()

    def run(self, inputs: List[Asset], ctx: ToolContext) -> ToolResult:
        # 上游 port 资产 + domain 直接喂给 httpx
        targets: List[str] = []
        for a in inputs:
            if a.type == "port":
                targets.append(a.value)  # 形如 1.2.3.4:80
            elif a.type in ("ip", "domain"):
                targets.append(a.value)
        # 授权范围过滤
        targets, skipped = self._verifier.filter_in_scope(targets, ctx.authorized_scope)
        if not targets:
            return ToolResult(stats={"input_targets": 0, "skipped_out_of_scope": len(skipped)})

        # 写入输入文件 (httpx 通过 -list 读)
        work_path = Path(ctx.work_dir)
        work_path.mkdir(parents=True, exist_ok=True)
        list_path = work_path / f"httpx_input_{ctx.task_id}.txt"
        list_path.write_text("\n".join(targets), encoding="utf-8")

        out_path = work_path / f"httpx_output_{ctx.task_id}.jsonl"
        # 清掉上一轮残留: resume 重跑时 httpx -o 是追加模式, 避免解析到旧数据 (P0-2)
        out_path.unlink(missing_ok=True)
        cmd = list(self._cmd) + list(self._default_args)
        cmd += ["-list", str(list_path), "-o", str(out_path)]
        if ctx.rate_limit:
            cmd += ["-rate-limit", str(ctx.rate_limit)]
        cmd.extend(ctx.extra_args)

        proc = self._runner(cmd, ctx.work_dir)
        raw = f"$ {' '.join(cmd)}\n[rc={proc.returncode}]\n{proc.stdout}\n{proc.stderr}"

        # httpx 退出码 0 = 全部成功；非 0 不一定致命，按解析结果判断
        if proc.returncode not in (0, 1):
            raise ToolError(f"httpx 执行失败 rc={proc.returncode}: {proc.stderr[:200]}")

        assets = self._parse_jsonl(out_path, ctx.task_id)
        url_count = sum(1 for a in assets if a.type == "url")
        return ToolResult(
            assets=assets,
            raw_output=raw,
            stats={
                "input_targets": len(targets),
                "skipped_out_of_scope": len(skipped),
                "live_urls": url_count,
            },
        )

    @staticmethod
    def _parse_jsonl(jsonl_path: Path, task_id: str) -> List[Asset]:
        """解析 httpx JSONL 输出，每行产出 (url, web_service) 两个资产。"""
        if not jsonl_path.exists():
            return []
        assets: List[Asset] = []
        with open(jsonl_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                url = obj.get("url")
                if not url:
                    continue
                techs = obj.get("technologies") or []
                status = obj.get("status_code")
                title = obj.get("title")
                host = obj.get("host") or url

                url_asset = Asset(
                    type="url",
                    value=url,
                    source="httpx",
                    task_id=task_id,
                    raw={"tool": "httpx", "host": host},
                )
                ws_asset = Asset(
                    type="web_service",
                    value=url,
                    source="httpx",
                    task_id=task_id,
                    parent_id=url_asset.id,
                    technologies=list(techs),
                    status_code=status,
                    title=title,
                    raw={"tool": "httpx", "raw": obj},
                )
                assets.append(url_asset)
                assets.append(ws_asset)
        return assets
