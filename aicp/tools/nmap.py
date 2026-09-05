"""Nmap 适配器 - 端口扫描。

调用 nmap 进行存活探测 + 端口扫描，输出 XML (-oX)，本适配器解析 XML 后归一化为：
- type=ip       (扫描到的主机 IP)
- type=port     (开放端口，value 形如 "1.2.3.4:80"，parent_id 指向 ip 资产)

设计要点：
- 默认端口集 -sT -T4 --top-ports 1000，可通过 extra_args 覆盖；
- 速率限制通过 --max-rate 注入；
- 解析失败或进程异常抛 ToolError。
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional

from ..auth import AuthorizationVerifier
from ..auth.verifier import _extract_host
from ..models import Asset, StageName
from .base import Tool, ToolContext, ToolResult, ToolError, ProcessRunner


class NmapTool(Tool):
    """Nmap 端口扫描适配器。"""

    name = "nmap"
    stage = StageName.PORTSCAN
    input_asset_types = ("domain", "ip")
    output_asset_types = ("ip", "port")

    def __init__(
        self,
        *,
        runner: ProcessRunner,
        nmap_cmd: Optional[List[str]] = None,
        default_args: Optional[List[str]] = None,
    ):
        self._runner = runner
        self._cmd = nmap_cmd or ["nmap"]
        # 默认参数: TCP 同步扫描 + top1000 端口 + 不 ping
        self._default_args = default_args or ["-sT", "-T4", "--top-ports", "1000", "-Pn"]
        self._verifier = AuthorizationVerifier()

    def run(self, inputs: List[Asset], ctx: ToolContext) -> ToolResult:
        # 把上游 domain / ip 全部作为扫描目标
        targets = [a.value for a in inputs if a.type in self.input_asset_types]
        # 拆出 host 部分 (URL / host:port / [ipv6] 统一处理, 与授权校验一致;
        # 旧逻辑对裸 IPv6 2001:db8::1 用 split(":")[0] 会拆出错误段)
        targets = [h for h in (_extract_host(t) for t in targets) if h]
        # 去重
        targets = list(dict.fromkeys(targets))
        # 授权范围过滤
        targets, skipped = self._verifier.filter_in_scope(targets, ctx.authorized_scope)
        if not targets:
            return ToolResult(stats={"input_targets": 0, "skipped_out_of_scope": len(skipped)})

        xml_path = Path(ctx.work_dir) / f"nmap_{ctx.task_id}.xml"
        # 清掉上一轮残留: resume 重跑时不留下旧结果 (P0-2)
        xml_path.unlink(missing_ok=True)
        cmd = list(self._cmd) + list(self._default_args)
        if ctx.rate_limit:
            cmd += ["--max-rate", str(ctx.rate_limit)]
        cmd += ["-oX", str(xml_path)]
        cmd.extend(ctx.extra_args)
        # -- 分隔: 防止 target 以 - 开头被 nmap 当选项解析 (P3)
        cmd += ["--"] + targets

        proc = self._runner(cmd, ctx.work_dir)
        raw = f"$ {' '.join(cmd)}\n[rc={proc.returncode}]\n{proc.stdout}\n{proc.stderr}"

        # nmap 退出码 0 = 成功；1 = 无开放端口但扫描完成；其它视为失败
        if proc.returncode not in (0, 1):
            raise ToolError(f"nmap 执行失败 rc={proc.returncode}: {proc.stderr[:200]}")

        ip_assets, port_assets = self._parse_xml(xml_path, ctx.task_id)

        # 合规关卡: nmap 解析出的 IP 是域名实际解析的 IP, 必须在授权范围内
        # (防止子域名解析到范围外 IP 被误扫)
        ip_values = [a.value for a in ip_assets]
        in_scope_ips, out_of_scope_ips = self._verifier.filter_in_scope(
            ip_values, ctx.authorized_scope
        )
        in_scope_set = set(in_scope_ips)
        filtered_ip = [a for a in ip_assets if a.value in in_scope_set]
        filtered_port = [p for p in port_assets
                         if p.value.rsplit(":", 1)[0] in in_scope_set]
        if out_of_scope_ips:
            # 记录到 raw_output 便于审计
            raw += f"\n[警告] 跳过范围外 IP: {','.join(out_of_scope_ips)}"

        # 关联: port.parent_id -> 对应 ip 的 id
        ip_by_value = {a.value: a.id for a in filtered_ip}
        for p in filtered_port:
            host = p.value.rsplit(":", 1)[0]
            p.parent_id = ip_by_value.get(host)

        all_assets = filtered_ip + filtered_port
        return ToolResult(
            assets=all_assets,
            raw_output=raw,
            stats={
                "input_targets": len(targets),
                "skipped_out_of_scope": len(skipped),
                "hosts_up": len(filtered_ip),
                "open_ports": len(filtered_port),
                "ips_out_of_scope": len(out_of_scope_ips),
            },
        )

    @staticmethod
    def _parse_xml(xml_path: Path, task_id: str) -> tuple[list[Asset], list[Asset]]:
        """解析 nmap XML 输出，返回 (ip 资产列表, port 资产列表)。"""
        if not xml_path.exists():
            return [], []
        tree = ET.parse(xml_path)
        root = tree.getroot()

        ip_assets: List[Asset] = []
        port_assets: List[Asset] = []
        for host in root.findall("host"):
            addr_elem = host.find("address")
            if addr_elem is None:
                continue
            ip = addr_elem.get("addr")
            if not ip:
                continue
            # 状态过滤: 只要 up 的主机
            state_elem = host.find("status")
            if state_elem is not None and state_elem.get("state") != "up":
                continue

            ip_asset = Asset(
                type="ip",
                value=ip,
                source="nmap",
                task_id=task_id,
                raw={"tool": "nmap"},
            )
            ip_assets.append(ip_asset)

            ports_elem = host.find("ports")
            if ports_elem is None:
                continue
            for port_elem in ports_elem.findall("port"):
                if port_elem.get("protocol") != "tcp":
                    continue
                port_num = port_elem.get("portid")
                if not port_num:
                    continue
                state = port_elem.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service_elem = port_elem.find("service")
                service_name = service_elem.get("name") if service_elem is not None else None

                port_asset = Asset(
                    type="port",
                    value=f"{ip}:{port_num}",
                    source="nmap",
                    task_id=task_id,
                    raw={
                        "tool": "nmap",
                        "ip": ip,
                        "port": int(port_num),
                        "protocol": "tcp",
                        "service": service_name,
                    },
                )
                port_assets.append(port_asset)
        return ip_assets, port_assets
