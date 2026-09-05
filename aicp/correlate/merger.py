"""数据关联与去重。

输入: 任务的全部 Asset 列表 (来自多个工具)
输出: AssetGraph - 以根资产 (domain/ip) 为根的资产树

关联规则:
- domain  -> ip        (通过 DNS 解析记录关联，但 OneForAll 输出已含 IP 时直接关联)
- ip      -> port      (通过 port.parent_id)
- port    -> url       (通过 url 中的 host:port 匹配)
- url     -> web_service (通过 web_service.parent_id)

合并规则 (指纹):
- 同一 url 的多个 web_service 资产 (httpx + Wappalyzer) 合并 technologies 取并集
- 优先保留 Wappalyzer 的指纹 (更详细)，httpx 作为补充
- status_code / title 取首次非空值

去重规则:
- 同 (type, value) 的资产视为同一资产 (Store 已保证唯一)
- 合并阶段对 web_service 按 value 去重，technologies 取并集
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

from ..models import Asset


@dataclass
class WebServiceNode:
    """合并后的 Web 服务节点。"""

    url: str
    technologies: List[str] = field(default_factory=list)
    status_code: Optional[int] = None
    title: Optional[str] = None
    sources: List[str] = field(default_factory=list)
    raw_history: List[dict] = field(default_factory=list)


@dataclass
class UrlNode:
    """URL 节点，下挂合并后的 web_service。"""

    url: str
    web_service: Optional[WebServiceNode] = None


@dataclass
class PortNode:
    """端口节点，下挂 url 列表。"""

    value: str          # 形如 "1.2.3.4:80"
    ip: str             # 形如 "1.2.3.4"
    port: int
    urls: List[UrlNode] = field(default_factory=list)


@dataclass
class HostNode:
    """主机节点 (IP)，下挂端口列表。

    一个 IP 可能对应多个 domain (通过反向 DNS 或扫描时关联)，这里只记录端口。
    domain 关联在 AssetGraph.domains_by_ip 中维护。
    """

    ip: str
    ports: List[PortNode] = field(default_factory=list)


@dataclass
class DomainNode:
    """域名节点，记录其解析到的 IP 列表。"""

    domain: str
    resolved_ips: List[str] = field(default_factory=list)
    source: str = "user_input"


@dataclass
class AssetGraph:
    """资产关联图 - 最终的标准化资产视图。"""

    domains: List[DomainNode] = field(default_factory=list)
    hosts: List[HostNode] = field(default_factory=list)
    # 反向索引: domain -> 关联到的 ip 列表 (与 DomainNode.resolved_ips 一致)
    domains_by_ip: Dict[str, List[str]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """转为可序列化的字典 (用于报告生成)。"""
        return {
            "domains": [
                {
                    "domain": d.domain,
                    "resolved_ips": d.resolved_ips,
                    "source": d.source,
                }
                for d in self.domains
            ],
            "hosts": [
                {
                    "ip": h.ip,
                    "ports": [
                        {
                            "value": p.value,
                            "port": p.port,
                            "urls": [
                                {
                                    "url": u.url,
                                    "web_service": {
                                        "technologies": u.web_service.technologies,
                                        "status_code": u.web_service.status_code,
                                        "title": u.web_service.title,
                                        "sources": u.web_service.sources,
                                    } if u.web_service else None,
                                }
                                for u in p.urls
                            ],
                        }
                        for p in h.ports
                    ],
                }
                for h in self.hosts
            ],
        }


def merge_assets(assets: List[Asset]) -> AssetGraph:
    """把扁平 Asset 列表合并为 AssetGraph。

    步骤:
    1. 按 type 分组；
    2. port 按 parent_id 关联到 ip；
    3. url 按 host:port 关联到 port；
    4. web_service 按 url 合并 (technologies 取并集)；
    5. domain -> ip 关联: 通过 nmap 的 port.raw.ip 或 oneforall 的 raw 字段。
    """
    # 1. 按 type 分组
    by_type: Dict[str, List[Asset]] = {}
    for a in assets:
        by_type.setdefault(a.type, []).append(a)

    domains = by_type.get("domain", [])
    ips = by_type.get("ip", [])
    ports = by_type.get("port", [])
    urls = by_type.get("url", [])
    web_services = by_type.get("web_service", [])

    # 2. 合并 web_services (按 url 聚合，technologies 取并集)
    merged_ws: Dict[str, WebServiceNode] = {}
    # 辅助 set: 加速 technologies 去重 (避免 list 的 O(n) in 检查)
    ws_tech_sets: Dict[str, set] = {}
    for ws in web_services:
        node = merged_ws.get(ws.value)
        if node is None:
            node = WebServiceNode(
                url=ws.value,
                technologies=list(ws.technologies),
                status_code=ws.status_code,
                title=ws.title,
                sources=[ws.source],
                raw_history=[ws.raw],
            )
            merged_ws[ws.value] = node
            ws_tech_sets[ws.value] = set(ws.technologies)
        else:
            # 合并: technologies 取并集 (set 辅助 O(1) 去重)
            tech_set = ws_tech_sets[ws.value]
            for t in ws.technologies:
                if t not in tech_set:
                    tech_set.add(t)
                    node.technologies.append(t)
            # status_code / title 取首次非空
            if node.status_code is None and ws.status_code is not None:
                node.status_code = ws.status_code
            if node.title is None and ws.title is not None:
                node.title = ws.title
            if ws.source not in node.sources:
                node.sources.append(ws.source)
            node.raw_history.append(ws.raw)

    # 3. 构建 url 节点，挂载合并后的 web_service
    url_nodes: Dict[str, UrlNode] = {}
    for u in urls:
        url_nodes[u.value] = UrlNode(
            url=u.value,
            web_service=merged_ws.get(u.value),
        )

    # 4. 构建 port 节点，关联 url (通过 host:port 匹配)
    port_nodes: Dict[str, PortNode] = {}
    for p in ports:
        ip = _extract_ip_from_port(p)
        port_num = _extract_port_num(p)
        node = PortNode(
            value=p.value,
            ip=ip,
            port=port_num,
            urls=[],
        )
        port_nodes[p.value] = node

    # 把 url 关联到 port (url 的 host:port 应等于 port.value)
    matched_url_values = set()
    for url_value, url_node in url_nodes.items():
        host_port = _extract_host_port_from_url(url_value)
        if host_port and host_port in port_nodes:
            port_nodes[host_port].urls.append(url_node)
            matched_url_values.add(url_value)

    # 未关联到 port 的 url: 创建虚拟 port 节点 (场景: 没跑 nmap 但有 httpx url)
    for url_value, url_node in url_nodes.items():
        if url_value in matched_url_values:
            continue
        host_port = _extract_host_port_from_url(url_value)
        if not host_port:
            continue
        ip, port_num = _split_host_port(host_port)
        if ip is None:
            continue
        port_nodes[host_port] = PortNode(
            value=host_port, ip=ip, port=port_num, urls=[url_node]
        )

    # 5. 构建 host 节点，关联 ports
    host_nodes: Dict[str, HostNode] = {}
    for port_node in port_nodes.values():
        host = host_nodes.get(port_node.ip)
        if host is None:
            host = HostNode(ip=port_node.ip)
            host_nodes[port_node.ip] = host
        host.ports.append(port_node)

    # 没 port 的 ip 也要保留 (nmap 扫到但无开放端口)
    for ip_asset in ips:
        if ip_asset.value not in host_nodes:
            host_nodes[ip_asset.value] = HostNode(ip=ip_asset.value)

    # 6. 构建 domain 节点 (按 value 去重, sources 取并集), 关联 ip
    # 关联来源: oneforall 的 raw.ip / nmap 的 raw.ip / 子域名父级关系
    domain_node_map: dict[str, DomainNode] = {}
    domains_by_ip: Dict[str, List[str]] = {}
    for d in domains:
        resolved = _extract_resolved_ips(d)
        if d.value in domain_node_map:
            # 同域名不同来源 (如 user_input + oneforall): 合并 sources 与 resolved_ips
            node = domain_node_map[d.value]
            for ip in resolved:
                if ip not in node.resolved_ips:
                    node.resolved_ips.append(ip)
        else:
            domain_node_map[d.value] = DomainNode(
                domain=d.value,
                resolved_ips=list(resolved),
                source=d.source,
            )
        for ip in resolved:
            if d.value not in domains_by_ip.setdefault(ip, []):
                domains_by_ip[ip].append(d.value)
    domain_nodes = list(domain_node_map.values())

    # 排序: domain 字典序、host 按 ip 排序
    domain_nodes.sort(key=lambda x: x.domain)
    hosts_sorted = sorted(host_nodes.values(), key=lambda h: _ip_sort_key(h.ip))

    return AssetGraph(
        domains=domain_nodes,
        hosts=hosts_sorted,
        domains_by_ip=domains_by_ip,
    )


# ---------------- 内部工具函数 ----------------

def _extract_ip_from_port(port: Asset) -> str:
    """从 port 资产提取 IP (value 形如 '1.2.3.4:80')。"""
    if ":" in port.value:
        return port.value.rsplit(":", 1)[0]
    # 从 raw 中取
    return port.raw.get("ip", port.value)


def _extract_port_num(port: Asset) -> int:
    """从 port 资产提取端口号。"""
    if ":" in port.value:
        try:
            return int(port.value.rsplit(":", 1)[1])
        except ValueError:
            pass
    return port.raw.get("port", 0)


def _extract_host_port_from_url(url: str) -> Optional[str]:
    """从 URL 提取 host:port (用于关联到 port 资产)。

    'http://1.2.3.4:80/path' -> '1.2.3.4:80'
    'https://example.com' -> 'example.com:443' (补默认端口)
    'http://example.com' -> 'example.com:80'
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    host = parsed.hostname
    if not host:
        return None
    port = parsed.port
    if port is None:
        # 补默认端口
        port = 443 if parsed.scheme == "https" else 80
    # IPv6 主机用 [] 包裹
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _split_host_port(host_port: str) -> tuple[Optional[str], int]:
    """把 host:port 拆成 (ip, port_num)。

    '1.2.3.4:80' -> ('1.2.3.4', 80)
    '[::1]:80'   -> ('::1', 80)
    'example.com:80' -> ('example.com', 80)
    """
    try:
        if host_port.startswith("["):
            # IPv6: [::1]:80
            bracket_end = host_port.index("]")
            ip = host_port[1:bracket_end]
            port_str = host_port.rsplit(":", 1)[1]
            return ip, int(port_str)
        # 普通 host:port
        ip, port_str = host_port.rsplit(":", 1)
        return ip, int(port_str)
    except (ValueError, IndexError):
        return None, 0


def _extract_resolved_ips(domain: Asset) -> List[str]:
    """从 domain 资产提取解析到的 IP 列表。

    不同工具输出位置不同:
    - OneForAll CSV: 通常没有 IP 字段 (本适配器未采集)
    - 用户输入: 没有 IP
    - nmap 扫描结果中 domain -> ip 的关联通过 port.raw.ip 间接得到
    这里只返回 raw.ip 字段 (如果有)，更精确的关联在 AssetGraph 层做。
    """
    raw = domain.raw or {}
    if isinstance(raw, dict):
        ip = raw.get("ip")
        if ip:
            return [ip] if isinstance(ip, str) else list(ip)
    return []


def _ip_sort_key(ip: str) -> tuple:
    """IP 排序键 (按 IPv4 数值排序，非 IP 字符串排序)。"""
    try:
        import ipaddress
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)
