"""dirsearch 适配器 - 目录/路径枚举。

调用 dirsearch (Python 工具) 对上游 url / web_service 资产进行目录枚举，
输出 JSON 报告 (--format=json -o out.json)，归一化为：
- type=directory  (发现的目录/路径，含 status_code / size / redirect)

设计要点：
- 输入取 type=url 和 type=web_service 资产，逐个目标扫描；
- 通过 --max-rate 注入速率；
- 默认使用常见扩展名 (php,asp,aspx,jsp,html,js)；
- 解析 JSON 输出后做授权范围过滤。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from ..auth import AuthorizationVerifier
from ..models import Asset, StageName
from .base import Tool, ToolContext, ToolResult, ToolError, ProcessRunner


class DirsearchTool(Tool):
    """dirsearch 目录枚举适配器。"""

    name = "dirsearch"
    stage = StageName.DIRSCAN
    input_asset_types = ("url", "web_service")
    output_asset_types = ("directory",)

    def __init__(
        self,
        *,
        runner: ProcessRunner,
        dirsearch_cmd: Optional[List[str]] = None,
        default_args: Optional[List[str]] = None,
    ):
        self._runner = runner
        self._cmd = dirsearch_cmd or ["dirsearch"]
        # 默认: 常见扩展名 + 递归深度 1 + 静默
        self._default_args = default_args or [
            "-e", "php,asp,aspx,jsp,html,js,json",
            "--recursion-depth", "1",
            "--quiet",
        ]
        self._verifier = AuthorizationVerifier()

    def run(self, inputs: List[Asset], ctx: ToolContext) -> ToolResult:
        # 收集目标 URL
        targets: List[str] = []
        for a in inputs:
            if a.type in ("url", "web_service"):
                targets.append(a.value)
        # 去重
        targets = list(dict.fromkeys(targets))
        # 授权范围过滤
        targets, skipped = self._verifier.filter_in_scope(targets, ctx.authorized_scope)
        if not targets:
            return ToolResult(stats={"input_targets": 0, "skipped_out_of_scope": len(skipped)})

        work_path = Path(ctx.work_dir)
        work_path.mkdir(parents=True, exist_ok=True)

        # dirsearch 每次只能扫描一个目标 (或用 -l 文件)，这里用 -l 批量
        list_path = work_path / f"dirsearch_input_{ctx.task_id}.txt"
        list_path.write_text("\n".join(targets), encoding="utf-8")

        out_path = work_path / f"dirsearch_output_{ctx.task_id}.json"
        # 清掉上一轮残留: resume 重跑时不留下旧结果 (P0-2)
        out_path.unlink(missing_ok=True)
        cmd = list(self._cmd) + list(self._default_args)
        cmd += ["-l", str(list_path), "--format", "json", "-o", str(out_path)]
        if ctx.rate_limit:
            cmd += ["--max-rate", str(ctx.rate_limit)]
        cmd.extend(ctx.extra_args)

        proc = self._runner(cmd, ctx.work_dir)
        raw = f"$ {' '.join(cmd)}\n[rc={proc.returncode}]\n{proc.stdout}\n{proc.stderr}"

        # dirsearch 退出码 0 = 成功; 非 0 不一定致命 (部分目标可能失败)
        if proc.returncode not in (0, 1):
            raise ToolError(f"dirsearch 执行失败 rc={proc.returncode}: {proc.stderr[:200]}")

        all_assets = self._parse_json(out_path, ctx.task_id)

        return ToolResult(
            assets=all_assets,
            raw_output=raw,
            stats={
                "input_targets": len(targets),
                "skipped_out_of_scope": len(skipped),
                "directories_found": len(all_assets),
            },
        )

    @staticmethod
    def _parse_json(json_path: Path, task_id: str) -> List[Asset]:
        """解析 dirsearch JSON 输出。

        dirsearch JSON 格式:
        {
            "results": [
                {"url": "...", "status": 200, "size": 1234, "redirect": "...", ...},
                ...
            ]
        }
        """
        if not json_path.exists():
            return []
        try:
            data = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            return []

        results = data.get("results", [])
        assets: List[Asset] = []
        for item in results:
            url = item.get("url", "")
            if not url:
                continue
            status_code = item.get("status")
            size = item.get("size")
            redirect = item.get("redirect", "")

            # 过滤 404 (dirsearch 有时也会输出)
            if status_code == 404:
                continue

            asset = Asset(
                type="directory",
                value=url,
                source="dirsearch",
                task_id=task_id,
                status_code=status_code,
                raw={
                    "tool": "dirsearch",
                    "status_code": status_code,
                    "size": size,
                    "redirect": redirect,
                },
            )
            assets.append(asset)
        return assets
