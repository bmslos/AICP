"""OneForAll 适配器 - 子域名收集。

调用 OneForAll (https://github.com/shmilylty/OneForAll) 收集子域名。
OneForAll 默认输出 CSV 到 results/{domain}.csv，本适配器读取 CSV 后归一化为
type=domain 的 Asset 列表。

设计要点：
- 进程执行器可注入 (ProcessRunner)，便于测试 mock；
- 子域名产出会做授权范围过滤 (只保留在 authorized_scope 内的子域名)；
- 失败抛 ToolError，由编排器决定是否重试。
"""

from __future__ import annotations

import csv
import logging
import re
from pathlib import Path
from typing import List, Optional

from ..auth import AuthorizationVerifier
from ..models import Asset, StageName
from .base import Tool, ToolContext, ToolResult, ToolError, ProcessRunner

logger = logging.getLogger(__name__)


class OneForAllTool(Tool):
    """OneForAll 子域名收集适配器。"""

    # domain 格式校验: 只允许字母数字下划线、点、连字符, 防止路径遍历
    _DOMAIN_RE = re.compile(r"^[\w\.\-]+$")

    name = "oneforall"
    stage = StageName.SUBDOMAIN
    input_asset_types = ("domain",)
    output_asset_types = ("domain",)

    def __init__(
        self,
        *,
        runner: ProcessRunner,
        oneforall_cmd: Optional[List[str]] = None,
        results_dir: Optional[str] = None,
    ):
        """
        - runner: 进程执行器 (生产环境用 subprocess 包装，测试用 mock)
        - oneforall_cmd: 启动 OneForAll 的命令，默认 ["python", "oneforall.py"]
        - results_dir: OneForAll 输出目录，默认 "./results"
        """
        self._runner = runner
        self._cmd = oneforall_cmd or ["python", "oneforall.py"]
        self._results_dir = results_dir or "./results"
        self._verifier = AuthorizationVerifier()

    def run(self, inputs: List[Asset], ctx: ToolContext) -> ToolResult:
        domains = self.filter_inputs(inputs, self.input_asset_types)
        if not domains:
            return ToolResult(stats={"input_domains": 0})

        all_assets: List[Asset] = []
        raw_logs: List[str] = []
        errors: List[str] = []
        for d in domains:
            try:
                assets, raw = self._collect_one(d.value, ctx)
                all_assets.extend(assets)
                raw_logs.append(raw)
            except ToolError as e:
                errors.append(f"{d.value}: {e}")
                logger.warning("OneForAll 域名 %s 收集失败, 继续执行其他域名: %s", d.value, e)

        # 所有域名都失败时才抛异常
        if errors and not all_assets:
            raise ToolError(
                f"OneForAll 所有域名均执行失败 ({len(errors)}/{len(domains)}): "
                + "; ".join(errors[:5])
            )

        if errors:
            raw_logs.append(f"[警告] {len(errors)} 个域名失败: " + "; ".join(errors[:10]))

        return ToolResult(
            assets=all_assets,
            raw_output="\n---\n".join(raw_logs),
            stats={
                "input_domains": len(domains),
                "collected_subdomains": len(all_assets),
                "failed_domains": len(errors),
            },
        )

    def _collect_one(self, domain: str, ctx: ToolContext) -> tuple[list[Asset], str]:
        """对单个根域名跑 OneForAll，返回 (资产列表, 原始日志)。"""
        # domain 格式校验: 防止 ../ 等路径遍历攻击
        if not self._DOMAIN_RE.match(domain):
            logger.warning("OneForAll domain 格式非法, 跳过: %s", domain)
            return [], ""

        cmd = list(self._cmd) + ["--target", domain, "--alive", "false"]
        cmd.extend(ctx.extra_args)

        proc = self._runner(cmd, ctx.work_dir)
        raw = f"$ {' '.join(cmd)}\n[rc={proc.returncode}]\n{proc.stdout}\n{proc.stderr}"

        # OneForAll 退出码非 0 视为失败 (但子域名收集允许部分失败)
        if proc.returncode != 0:
            raise ToolError(f"OneForAll 执行失败: {domain} (rc={proc.returncode})")

        # 解析 CSV 结果: results_dir 若为相对路径, 相对 work_dir 解析
        # (subprocess 在 work_dir 下执行, OneForAll 把 CSV 写到 {work_dir}/results/)
        results_dir = Path(self._results_dir)
        if not results_dir.is_absolute():
            results_dir = Path(ctx.work_dir) / results_dir
        csv_path = results_dir / f"{domain}.csv"
        subdomains = self._parse_csv(csv_path)

        # 授权范围过滤 + 归一化
        in_scope, out_of_scope = self._verifier.filter_in_scope(
            subdomains, ctx.authorized_scope
        )
        assets = [
            Asset(
                type="domain",
                value=sub,
                source="oneforall",
                task_id=ctx.task_id,
                parent_id=None,  # 上游 domain 资产 id 在编排器侧关联
                raw={"tool": "oneforall", "root": domain},
            )
            for sub in in_scope
        ]
        if out_of_scope:
            raw += f"\n[warn] {len(out_of_scope)} 个子域名超出授权范围，已跳过: {out_of_scope[:5]}"
        return assets, raw

    @staticmethod
    def _parse_csv(csv_path: Path) -> List[str]:
        """从 OneForAll 的 CSV 输出中提取子域名列表。

        按表头列名匹配 subdomain 列(大小写不敏感);
        若表头无此列, 回退到第一列并记录警告。
        """
        if not csv_path.exists():
            return []
        subdomains: List[str] = []
        with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.reader(f)
            try:
                header = next(reader)
            except StopIteration:
                return []
            if not header:
                return []

            # 按表头列名匹配 subdomain (大小写不敏感)
            lower_header = [h.strip().lower() for h in header]
            try:
                subdomain_idx = lower_header.index("subdomain")
            except ValueError:
                # 回退到第一列, 记录警告
                logger.warning(
                    "OneForAll CSV 表头无 subdomain 列, 回退取第一列: %s", header
                )
                subdomain_idx = 0

            for row in reader:
                if row and len(row) > subdomain_idx and row[subdomain_idx].strip():
                    subdomains.append(row[subdomain_idx].strip())
        return subdomains

# 生产环境进程执行器统一使用 aicp.cli._default_process_runner
# (包含 30 分钟超时处理), 不再在此处重复定义。
