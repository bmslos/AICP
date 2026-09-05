"""数据关联与去重单元测试。"""

from aicp.correlate import merge_assets
from aicp.models import Asset


def _make_assets():
    """构造一组跨工具的测试资产。"""
    return [
        # 用户输入的根域名
        Asset(type="domain", value="example.com", source="user_input", task_id="t1"),
        # OneForAll 收集的子域名
        Asset(type="domain", value="sub.example.com", source="oneforall", task_id="t1"),
        # Nmap 扫到 2 个 IP，每个有端口
        Asset(type="ip", value="1.2.3.4", source="nmap", task_id="t1"),
        Asset(type="port", value="1.2.3.4:80", source="nmap", task_id="t1",
              raw={"ip": "1.2.3.4", "port": 80, "protocol": "tcp", "service": "http"}),
        Asset(type="port", value="1.2.3.4:443", source="nmap", task_id="t1",
              raw={"ip": "1.2.3.4", "port": 443, "protocol": "tcp", "service": "https"}),
        Asset(type="ip", value="1.2.3.5", source="nmap", task_id="t1"),
        Asset(type="port", value="1.2.3.5:22", source="nmap", task_id="t1",
              raw={"ip": "1.2.3.5", "port": 22, "protocol": "tcp", "service": "ssh"}),
        # httpx 探测出 url
        Asset(type="url", value="http://1.2.3.4:80", source="httpx", task_id="t1"),
        Asset(type="url", value="https://1.2.3.4:443", source="httpx", task_id="t1"),
        # httpx 的 web_service 指纹
        Asset(type="web_service", value="http://1.2.3.4:80", source="httpx", task_id="t1",
              technologies=["Nginx"], status_code=200, title="Test"),
        Asset(type="web_service", value="https://1.2.3.4:443", source="httpx", task_id="t1",
              technologies=["Apache"], status_code=301, title="Redirect"),
        # Wappalyzer 增强指纹 (与 httpx 同 url 合并)
        Asset(type="web_service", value="http://1.2.3.4:80", source="wappalyzer", task_id="t1",
              technologies=["Nginx", "WordPress", "PHP"]),
        Asset(type="web_service", value="https://1.2.3.4:443", source="wappalyzer", task_id="t1",
              technologies=["Apache", "OpenSSL"]),
    ]


def test_merge_groups_hosts_by_ip():
    graph = merge_assets(_make_assets())
    host_ips = sorted(h.ip for h in graph.hosts)
    assert host_ips == ["1.2.3.4", "1.2.3.5"]


def test_merge_links_ports_to_host():
    graph = merge_assets(_make_assets())
    host = next(h for h in graph.hosts if h.ip == "1.2.3.4")
    port_values = sorted(p.value for p in host.ports)
    assert port_values == ["1.2.3.4:443", "1.2.3.4:80"]
    # 端口号解析正确
    ports = sorted(p.port for p in host.ports)
    assert ports == [80, 443]


def test_merge_links_urls_to_port_by_host_port():
    graph = merge_assets(_make_assets())
    host = next(h for h in graph.hosts if h.ip == "1.2.3.4")
    port80 = next(p for p in host.ports if p.port == 80)
    # http://1.2.3.4:80 -> 关联到 1.2.3.4:80
    assert any(u.url == "http://1.2.3.4:80" for u in port80.urls)


def test_merge_merges_web_services_with_union_of_techs():
    graph = merge_assets(_make_assets())
    host = next(h for h in graph.hosts if h.ip == "1.2.3.4")
    port80 = next(p for p in host.ports if p.port == 80)
    url_node = next(u for u in port80.urls if u.url == "http://1.2.3.4:80")

    ws = url_node.web_service
    assert ws is not None
    # httpx: [Nginx] + Wappalyzer: [Nginx, WordPress, PHP] -> 去重并集
    assert set(ws.technologies) == {"Nginx", "WordPress", "PHP"}
    # sources 记录两个工具
    assert set(ws.sources) == {"httpx", "wappalyzer"}
    # status_code / title 取首次非空 (httpx 先入)
    assert ws.status_code == 200
    assert ws.title == "Test"


def test_merge_preserves_host_without_ports():
    """扫到 IP 但没开放端口的也要保留。"""
    assets = [Asset(type="ip", value="1.2.3.4", source="nmap", task_id="t1")]
    graph = merge_assets(assets)
    assert len(graph.hosts) == 1
    assert graph.hosts[0].ip == "1.2.3.4"
    assert graph.hosts[0].ports == []


def test_merge_empty_assets_returns_empty_graph():
    graph = merge_assets([])
    assert graph.hosts == []
    assert graph.domains == []


def test_merge_sorts_hosts_by_ip_numerically():
    """IP 按数值排序，不是字符串排序。"""
    assets = [
        Asset(type="ip", value="10.0.0.99", source="nmap", task_id="t1"),
        Asset(type="ip", value="10.0.0.2", source="nmap", task_id="t1"),
        Asset(type="ip", value="10.0.0.10", source="nmap", task_id="t1"),
    ]
    graph = merge_assets(assets)
    ips = [h.ip for h in graph.hosts]
    assert ips == ["10.0.0.2", "10.0.0.10", "10.0.0.99"]


def test_to_dict_is_serializable():
    import json
    graph = merge_assets(_make_assets())
    d = graph.to_dict()
    # 应可 JSON 序列化
    json.dumps(d, ensure_ascii=False)
    assert "domains" in d
    assert "hosts" in d


def test_url_with_default_port_matches_port():
    """URL 没有显式端口时应补默认端口匹配。"""
    assets = [
        Asset(type="port", value="example.com:80", source="nmap", task_id="t1",
              raw={"ip": "example.com", "port": 80}),
        Asset(type="url", value="http://example.com/", source="httpx", task_id="t1"),
    ]
    graph = merge_assets(assets)
    # 找到 port=80 的端口节点 (host 视为字符串)
    found = False
    for h in graph.hosts:
        for p in h.ports:
            for u in p.urls:
                if u.url == "http://example.com/":
                    found = True
    assert found, "默认端口 80 应匹配到 port 资产 example.com:80"
