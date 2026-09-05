"""授权校验机制。

启动扫描前必须通过 AuthorizationVerifier.verify()，确保：
1. 授权信息完整 (授权人 + 授权说明 + 授权范围)
2. 所有用户输入目标都在授权范围内
3. 所有用户输入目标不在私有/保留 IP 段 (除非 allow_private=True)
4. 运行时发现的资产 (如子域名) 超出范围时自动跳过并记录

授权范围支持：
- 域名: example.com (匹配其所有子域名 sub.example.com)
- IP: 1.2.3.4
- CIDR: 10.0.0.0/24

私有/保留 IP 黑名单 (默认拒绝, 防止 SSRF 与内网探测):
- RFC 1918 私有段: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- loopback: 127.0.0.0/8, ::1/128
- link-local: 169.254.0.0/16 (含云元数据服务 169.254.169.254), fe80::/10
- IPv6 私有: fc00::/7 (唯一本地地址)
- 保留段: 0.0.0.0/8, 224.0.0.0/4 (组播), 240.0.0.0/4 (保留), ::/128
- IPv4 映射 IPv6 地址 (::ffff:x.x.x.x) 在匹配前归一化为 IPv4, 防 SSRF 绕过
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, List
from urllib.parse import urlparse

from ..models.task import Task, TaskStatus


class AuthorizationError(Exception):
    """授权校验失败。"""


# 私有/保留 IP 段黑名单 (IPv4 + IPv6)
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),           # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),        # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),       # RFC 1918
    ipaddress.ip_network("127.0.0.0/8"),          # loopback
    ipaddress.ip_network("169.254.0.0/16"),       # link-local (含云元数据)
    ipaddress.ip_network("0.0.0.0/8"),            # "本机" 段
    ipaddress.ip_network("224.0.0.0/4"),          # 组播
    ipaddress.ip_network("240.0.0.0/4"),          # 保留 (E 类)
    ipaddress.ip_network("::1/128"),              # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),             # IPv6 唯一本地地址
    ipaddress.ip_network("fe80::/10"),            # IPv6 link-local
    ipaddress.ip_network("::/128"),               # IPv6 未指定
]


def _is_private_or_reserved(ip_str: str) -> bool:
    """判断 IP 字符串是否属于私有/保留段。

    返回 True 表示该 IP 在黑名单中 (默认拒绝扫描)。
    无法解析为 IP 的字符串返回 False (走域名校验路径)。

    IPv4 映射 IPv6 地址 (::ffff:x.x.x.x) 在匹配前归一化为 IPv4,
    防止攻击者用 IPv6 形式绕过 IPv4 黑名单 (SSRF)。
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    # IPv4 映射 IPv6 地址 (::ffff:x.x.x.x) 归一化为 IPv4, 防 SSRF 绕过
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return any(ip in net for net in _PRIVATE_NETWORKS)


def _cidr_contains_private(cidr_str: str) -> bool:
    """判断 CIDR 是否包含任何私有/保留 IP。

    用于校验 scope 中的 CIDR (如 10.0.0.0/24 整段私有)。

    IPv4 映射 IPv6 网段 (::ffff:0:0/96 等) 在匹配前归一化为 IPv4。
    """
    try:
        net = ipaddress.ip_network(cidr_str, strict=False)
    except ValueError:
        return False
    # IPv4 映射 IPv6 网段归一化 (前 96 位为 0:0:0:0:0:ffff, 后 32 位为 IPv4)
    if isinstance(net, ipaddress.IPv6Network) and net.network_address.ipv4_mapped is not None:
        try:
            net = ipaddress.ip_network(
                f"{net.network_address.ipv4_mapped}/{net.prefixlen - 96}",
                strict=False,
            )
        except ValueError:
            pass
    # 网段本身是私有的 / 与黑名单网段有交集
    for private in _PRIVATE_NETWORKS:
        if net.overlaps(private):
            return True
    return False


def _default_dns_resolver(domain: str) -> List[str]:
    """默认 DNS 解析 (socket.getaddrinfo)。解析失败返回空列表, 不抛异常。"""
    import socket

    try:
        infos = socket.getaddrinfo(domain, None)
    except OSError:
        return []
    ips: List[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


# 模块级可替换 (测试 monkeypatch; 生产为真实 getaddrinfo)
_dns_resolver = _default_dns_resolver


def resolve_domain_ips(domains: List[str]) -> List[str]:
    """解析域名列表为去重 IP 列表 (单个域名解析失败跳过, 不影响其他)。

    行动项 #5 (域名 scope 下过滤 IP 资产) 与 #2 (域名 target 防DNS rebinding SSRF)
    共用本入口, 保证两处解析口径一致。
    """
    out: List[str] = []
    for d in domains:
        for ip in _dns_resolver(d):
            if ip not in out:
                out.append(ip)
    return out


@dataclass
class ConfirmationBanner:
    """启动前的合规警告与确认。"""

    task: Task
    #: 授权信息来源 (CLI 参数 / 配置文件 / 环境变量), 审计 5.4 建议标注
    auth_source: str = "CLI 参数"

    def render(self) -> str:
        scope = ", ".join(self.task.authorized_scope) or "(空)"
        lines = [
            "=" * 70,
            "法律与合规警告",
            "=" * 70,
            "本工具仅可用于已获书面授权的目标。未经授权对第三方系统进行",
            "扫描/探测可能违反《网络安全法》《刑法》第二百八十五条等规定。",
            "",
            f"  任务 ID     : {self.task.id}",
            f"  授权人      : {self.task.authorized_by or '(未填写)'}",
            f"  授权范围    : {scope}",
            f"  授权说明    : {self.task.authorization_note or '(未填写)'}",
            f"  授权时间    : {self.task.authorized_at or '(未填写)'}",
            f"  授权来源    : {self.auth_source}",
            "=" * 70,
        ]
        return "\n".join(lines)


class AuthorizationVerifier:
    """授权校验器。"""

    @staticmethod
    def _is_ip_literal(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_cidr(value: str) -> bool:
        try:
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            return False

    @staticmethod
    def _domain_in_scope(domain: str, scope_domains: List[str]) -> bool:
        """域名匹配: example.com 匹配 sub.example.com，但不匹配 notexample.com。"""
        d = domain.lower().rstrip(".")
        for s in scope_domains:
            s = s.lower().rstrip(".")
            if d == s or d.endswith("." + s):
                return True
        return False

    @staticmethod
    def _ip_in_scope(ip_str: str, scope_ips: List[str], scope_cidrs: List[str]) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        for s in scope_ips:
            try:
                if ip == ipaddress.ip_address(s):
                    return True
            except ValueError:
                continue
        for c in scope_cidrs:
            try:
                if ip in ipaddress.ip_network(c, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _classify_scope(self, authorized_scope: List[str]) -> tuple[list[str], list[str], list[str]]:
        """将授权范围拆分为 (域名, IP, CIDR) 三类。"""
        domains, ips, cidrs = [], [], []
        for item in authorized_scope:
            item = item.strip()
            if not item:
                continue
            if self._is_cidr(item) and "/" in item:
                cidrs.append(item)
            elif self._is_ip_literal(item):
                ips.append(item)
            else:
                domains.append(item)
        return domains, ips, cidrs

    def verify(
        self,
        task: Task,
        *,
        authorized_by: str,
        authorization_note: str,
        authorized_scope: List[str],
        authorized_at: Optional[datetime] = None,
        allow_private: bool = False,
    ) -> Task:
        """校验并写入授权信息，返回更新后的 Task。

        - authorized_by: 授权人 (非空)
        - authorization_note: 授权说明，如授权书编号 (非空)
        - authorized_scope: 授权范围列表 (非空)
        - allow_private: 是否允许扫描私有/保留 IP 段 (默认 False,
          拒绝 10.0.0.0/8 / 127.0.0.0/8 / 169.254.0.0/16 等, 防 SSRF)
        """
        if not authorized_by or not authorized_by.strip():
            raise AuthorizationError("授权人不能为空")
        if not authorization_note or not authorization_note.strip():
            raise AuthorizationError("授权说明不能为空 (如授权书编号)")
        if not authorized_scope:
            raise AuthorizationError("授权范围不能为空")

        scope = [s.strip() for s in authorized_scope if s.strip()]
        if not scope:
            raise AuthorizationError("授权范围不能为空")

        # 校验所有用户输入目标都在授权范围内
        domains, ips, cidrs = self._classify_scope(scope)
        for target in task.targets:
            if not self.is_target_in_scope(target, domains, ips, cidrs):
                raise AuthorizationError(
                    f"目标 {target!r} 不在授权范围内，已拒绝"
                )

        # 私有/保留 IP 黑名单校验 (防 SSRF 与内网探测)
        if not allow_private:
            self._reject_private_targets(task.targets, scope)
            # 域名 target 的 DNS 解析结果套用私有段黑名单
            # (行动项 #2: 防攻击者 DNS 把授权域名指向内网/云元数据, DNS rebinding SSRF)
            self._reject_private_resolved_targets(task.targets)

        task.authorized_by = authorized_by.strip()
        task.authorization_note = authorization_note.strip()
        task.authorized_scope = scope
        task.authorized_at = authorized_at or datetime.now(timezone.utc)
        task.status = TaskStatus.AUTHORIZED
        return task

    @staticmethod
    def _reject_private_targets(targets: List[str], scope: List[str]) -> None:
        """校验 targets 和 scope 中是否含私有/保留 IP, 含则抛 AuthorizationError。

        - 对 target: 提取 host (URL/host:port 都提取), 检查是否私有 IP
        - 对 scope: 同时检查 IP 字面量和 CIDR 网段
        """
        # 检查 targets
        for t in targets:
            host = _extract_host(t)
            if host and _is_private_or_reserved(host):
                raise AuthorizationError(
                    f"目标 {t!r} 解析到私有/保留 IP {host!r}, 默认拒绝。"
                    f"如确需扫描内网, 请显式传 allow_private=True / --allow-private"
                )
        # 检查 scope (IP 字面量 + CIDR)
        for s in scope:
            s = s.strip()
            if not s:
                continue
            if _is_private_or_reserved(s):
                raise AuthorizationError(
                    f"授权范围含私有/保留 IP {s!r}, 默认拒绝。"
                    f"如确需扫描内网, 请显式传 allow_private=True / --allow-private"
                )
            if "/" in s and _cidr_contains_private(s):
                raise AuthorizationError(
                    f"授权范围 CIDR {s!r} 含私有/保留网段, 默认拒绝。"
                    f"如确需扫描内网, 请显式传 allow_private=True / --allow-private"
                )

    @staticmethod
    def _reject_private_resolved_targets(targets: List[str]) -> None:
        """域名 target 的 DNS 解析结果套用私有/保留段黑名单 (行动项 #2)。

        授权校验阶段把域名解析为 IP, 任一解析结果落入私有/保留段
        (如攻击者控制的 DNS 把授权域名指向 169.254.169.254 云元数据)
        即拒绝, 封 DNS rebinding SSRF。DNS 解析失败不阻断 (无证据不扩大拒绝)。
        """
        checked: set[str] = set()
        for t in targets:
            host = _extract_host(t)
            if not host or host in checked:
                continue
            if AuthorizationVerifier._is_ip_literal(host) or AuthorizationVerifier._is_cidr(host):
                continue  # IP/CIDR 字面量由 _reject_private_targets 覆盖
            checked.add(host)
            for ip in resolve_domain_ips([host]):
                if _is_private_or_reserved(ip):
                    raise AuthorizationError(
                        f"目标 {t!r} 的域名解析到私有/保留 IP {ip!r}, 默认拒绝"
                        f" (防 DNS rebinding SSRF)。如确需扫描内网, "
                        f"请显式传 allow_private=True / --allow-private"
                    )


    def is_target_in_scope(
        self,
        target: str,
        scope_domains: List[str],
        scope_ips: List[str],
        scope_cidrs: List[str],
    ) -> bool:
        """判断单个目标是否在授权范围内。

        支持: 域名 (含子域名) / IP / CIDR / URL / host:port / [ipv6]:port。
        URL (http://1.2.3.4:80/path) 会先用 urlparse 提取 host。
        """
        t = target.strip()
        if not t:
            return False

        # URL / host:port / IPv6 统一提取 host (复用 _extract_host, 避免重复逻辑)
        host = _extract_host(t)
        if not host:
            return False

        if self._is_ip_literal(host):
            return self._ip_in_scope(host, scope_ips, scope_cidrs)
        if self._is_cidr(host):
            # 目标本身就是 CIDR，必须被授权范围中的 CIDR 包含
            try:
                net = ipaddress.ip_network(host, strict=False)
            except ValueError:
                return False
            for c in scope_cidrs:
                try:
                    if net.subnet_of(ipaddress.ip_network(c, strict=False)):
                        return True
                except ValueError:
                    continue
            return False
        return self._domain_in_scope(host, scope_domains)

    def filter_in_scope(
        self, targets: List[str], authorized_scope: List[str]
    ) -> tuple[list[str], list[str]]:
        """将一组目标分为 (在范围内, 超出范围) 两组，用于运行时资产过滤。

        域名 scope 的 IP 兼容 (行动项 #5): scope 含域名时, 该域名当前解析出的 IP
        同样视为在范围内 —— 否则 nmap 等工具解析域名得到的 IP/端口资产会被全量
        清空 (`aicp scan example.com --scope example.com` 产出恒为空)。
        仅在出现"IP 字面量未命中且 scope 含域名"时才解析 DNS (域名目标为主的
        常见路径不触发), 每次调用至多解析一轮; 解析失败回退字面量匹配。
        """
        domains, ips, cidrs = self._classify_scope(authorized_scope)
        in_scope, out_of_scope = [], []
        resolved: Optional[List[str]] = None  # None=未解析过; 解析后缓存 (含空结果)
        for t in targets:
            if self.is_target_in_scope(t, domains, ips, cidrs):
                in_scope.append(t)
                continue
            # IP 字面量未命中 + scope 含域名 → 懒解析域名并入 ips 后重试
            host = _extract_host(t)
            if host and self._is_ip_literal(host) and domains and resolved is None:
                resolved = resolve_domain_ips(domains)
                ips = ips + [ip for ip in resolved if ip not in ips]
            if self.is_target_in_scope(t, domains, ips, cidrs):
                in_scope.append(t)
            else:
                out_of_scope.append(t)
        return in_scope, out_of_scope


def _extract_host(target: str) -> str:
    """从 target 提取 host (URL/host:port/IPv6 都处理)。与 is_target_in_scope 一致。"""
    t = target.strip()
    if not t:
        return ""
    if "://" in t:
        parsed = urlparse(t)
        return parsed.hostname or ""
    if t.count(":") == 1 and not t.startswith("["):
        return t.split(":")[0]
    if t.startswith("["):
        return t.split("]")[0].strip("[]")
    return t
