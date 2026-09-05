"""Nuclei 适配器 - 基于模板的漏洞检测。

调用 projectdiscovery/nuclei (Go 单二进制) 对上游 url / web_service 资产
进行漏洞扫描，输出 JSONL (-jsonl -o out.jsonl)，归一化为：
- type=vulnerability  (含 template_id / severity / name / matched_at)

设计要点：
- 输入取 type=url 和 type=web_service 资产，构建目标 URL 列表；
- 通过 -rate-limit 注入速率；
- 默认使用 nuclei 内置模板 (可通过 extra_args 指定 -t 自定义模板目录)；
- 解析 JSONL 后做授权范围过滤。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from ..auth import AuthorizationVerifier
from ..models import Asset, StageName
from .base import Tool, ToolContext, ToolResult, ToolError, ProcessRunner


class NucleiTool(Tool):
    """Nuclei 漏洞扫描适配器。"""

    name = "nuclei"
    stage = StageName.VULNERABILITY
    input_asset_types = ("url", "web_service")
    output_asset_types = ("vulnerability",)

    def __init__(
        self,
        *,
        runner: ProcessRunner,
        nuclei_cmd: Optional[List[str]] = None,
        default_args: Optional[List[str]] = None,
    ):
        self._runner = runner
        self._cmd = nuclei_cmd or ["nuclei"]
        # 默认: JSONL 输出 + 静默 + 排除信息级模板 (减少噪音)
        self._default_args = default_args or [
            "-jsonl", "-silent", "-severity", "low,medium,high,critical",
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

        # 写入输入文件 (nuclei 通过 -l 读取目标列表)
        work_path = Path(ctx.work_dir)
        work_path.mkdir(parents=True, exist_ok=True)
        list_path = work_path / f"nuclei_input_{ctx.task_id}.txt"
        list_path.write_text("\n".join(targets), encoding="utf-8")

        out_path = work_path / f"nuclei_output_{ctx.task_id}.jsonl"
        # 清掉上一轮残留: resume 重跑时 nuclei -o 是追加模式, 避免解析到旧数据 (P0-2)
        out_path.unlink(missing_ok=True)
        cmd = list(self._cmd) + list(self._default_args)
        cmd += ["-l", str(list_path), "-o", str(out_path)]
        if ctx.rate_limit:
            cmd += ["-rate-limit", str(ctx.rate_limit)]
        cmd.extend(ctx.extra_args)

        proc = self._runner(cmd, ctx.work_dir)
        raw = f"$ {' '.join(cmd)}\n[rc={proc.returncode}]\n{proc.stdout}\n{proc.stderr}"

        # nuclei 退出码 0 = 有发现; 1 = 无发现但扫描完成; 其它视为失败
        if proc.returncode not in (0, 1):
            raise ToolError(f"nuclei 执行失败 rc={proc.returncode}: {proc.stderr[:200]}")

        assets = self._parse_jsonl(out_path, ctx.task_id)
        return ToolResult(
            assets=assets,
            raw_output=raw,
            stats={
                "input_targets": len(targets),
                "skipped_out_of_scope": len(skipped),
                "vulnerabilities_found": len(assets),
            },
        )

    @staticmethod
    def _parse_jsonl(jsonl_path: Path, task_id: str) -> List[Asset]:
        """解析 nuclei JSONL 输出，每行产出一个 vulnerability 资产。"""
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

                # nuclei JSONL 格式:
                # {"template-id": "...", "info": {"name": "...", "severity": "..."},
                #  "type": "http", "host": "...", "matched-at": "...", ...}
                template_id = obj.get("template-id") or obj.get("template", "")
                info = obj.get("info") or {}
                name = info.get("name") or template_id
                severity = info.get("severity") or "unknown"
                matched_at = obj.get("matched-at") or obj.get("host", "")
                vuln_type = obj.get("type", "http")
                curl_cmd = obj.get("curl-command", "")

                # value 拼入 template_id: Store 去重键为 (task, type, value, source),
                # 若只用 matched_at (URL), 同一 URL 上不同模板命中的漏洞会被后者覆盖丢失。
                # 拼入模板 ID 后, 每个 (URL, 模板) 组合唯一, 漏洞不丢失。
                value = f"{matched_at}|{template_id}" if template_id else matched_at
                asset = Asset(
                    type="vulnerability",
                    value=value,
                    source="nuclei",
                    task_id=task_id,
                    raw={
                        "tool": "nuclei",
                        "template_id": template_id,
                        "name": name,
                        "severity": severity,
                        "vuln_type": vuln_type,
                        "matched_at": matched_at,
                        "curl_command": curl_cmd,
                    },
                )
                assets.append(asset)
        return assets
