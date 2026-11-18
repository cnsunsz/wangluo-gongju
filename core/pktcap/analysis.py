"""传统规则生成的报文分析与整次抓包离线诊断。不调用任何在线模型。"""
from __future__ import annotations

import base64
import ipaddress
import re
from typing import Any, Iterable, Optional


TCP_FLAGS = (
    ("NS", 0x100), ("CWR", 0x80), ("ECE", 0x40), ("URG", 0x20),
    ("ACK", 0x10), ("PSH", 0x08), ("RST", 0x04), ("SYN", 0x02), ("FIN", 0x01),
)

ICMP4 = {
    0: "回显应答（Echo Reply）",
    3: "目的不可达（Destination Unreachable）",
    8: "回显请求（Echo Request）",
    11: "超时（Time Exceeded）",
}
ICMP4_UNREACH = {
    0: "网络不可达", 1: "主机不可达", 2: "协议不可达", 3: "端口不可达",
    4: "需要分片但设置了 DF",
    9: "网络被管理员禁止", 10: "主机被管理员禁止", 13: "通信被管理员禁止",
}
ICMP6 = {
    1: "目的不可达", 2: "报文过大", 3: "超时", 4: "参数问题",
    128: "回显请求", 129: "回显应答",
    133: "路由器请求", 134: "路由器通告",
    135: "邻居请求", 136: "邻居通告",
}
ICMP6_UNREACH = {
    0: "无路由", 1: "通信被管理员禁止", 2: "超出源地址范围",
    3: "地址不可达", 4: "端口不可达",
}


UDP_SERVICES = {
    53: "DNS",
    67: "DHCP 服务端",
    68: "DHCP 客户端",
    69: "TFTP",
    123: "NTP",
    137: "NetBIOS 名称服务",
    138: "NetBIOS 数据报",
    161: "SNMP",
    162: "SNMP Trap",
    443: "HTTPS / QUIC",
    500: "IKE / IPsec",
    514: "syslog",
    520: "RIP",
    853: "DNS over TLS 或 QUIC",
    1701: "L2TP",
    1812: "RADIUS 认证",
    1813: "RADIUS 计费",
    4500: "IPsec NAT-T",
    4789: "VXLAN",
    5353: "mDNS",
    5355: "LLMNR",
    5683: "CoAP",
    6081: "Geneve",
    8472: "VXLAN（备选端口）",
}
TCP_SERVICES = {
    20: "FTP 数据", 21: "FTP 控制", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP 提交",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "Microsoft SQL Server", 2049: "NFS",
    3306: "MySQL", 3389: "远程桌面（RDP）", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP 备选", 8443: "HTTPS 备选",
}
_NON_TCP = {"UDP", "ARP", "ICMP", "ICMPV6", "IPV6-ICMP", "VXLAN", "GRE", "GENEVE"}


# 移动云文档写明：这些端口存在安全隐患，平台会拦截；即使安全组放通，访问也可能失败。
ECLOUD_BLOCKED_PORTS = {
    135: "Windows RPC 端点映射",
    137: "NetBIOS 名称服务",
    138: "NetBIOS 数据报",
    139: "NetBIOS 会话服务 / SMB",
    445: "SMB 文件共享",
    4444: "常见高危监听端口",
}

# 国内主流云（含移动云）常见出站封禁，通常需向云商申请解封。
CLOUD_OUTBOUND_SMTP = {25: "SMTP 邮件发送"}

# 运营商或云环境常见高危端口。仅在出现失败迹象时提示，不把正常通信当成封堵。
CARRIER_HIGH_RISK_TCP = {
    42: "WINS / 名称服务",
    444: "简易网络管理 / 常见后门端口",
    593: "RPC over HTTP",
    1025: "Windows 动态 RPC",
    1068: "常见扫描目标端口",
    1433: "Microsoft SQL Server",
    1434: "SQL Server 浏览器",
    3127: "常见后门端口",
    3128: "HTTP 代理",
    3129: "常见后门端口",
    3130: "常见后门端口",
    5554: "蠕虫相关端口",
    5800: "VNC HTTP",
    5900: "VNC",
    8998: "常见扫描目标端口",
    9995: "常见扫描目标端口",
    9996: "常见扫描目标端口",
}
CARRIER_HIGH_RISK_UDP = {
    1026: "Windows Messenger / 动态端口",
    1027: "Windows 动态端口",
    1028: "Windows 动态端口",
    1068: "常见扫描目标端口",
    1433: "SQL Server",
    1434: "SQL Server 浏览器",
    5554: "蠕虫相关端口",
    9995: "常见扫描目标端口",
    9996: "常见扫描目标端口",
}

ICMP_ADMIN_CODES_V4 = {9, 10, 13}  # 网络/主机/通信被管理禁止
ICMP_ADMIN_CODES_V6 = {1}  # Destination Unreachable, administratively prohibited

# 静默丢弃需要足够的等待或可见的 SYN 重传间隔，避免把短窗口里的单个 SYN 说成已经确认被封。
_SYN_CONFIRM_WAIT_S = 1.0
_SYN_RETRANS_GAP_S = 0.5


def _classify_blocked_port(port, proto="TCP"):
    """返回 (类别, 角色说明) 或 None。类别：ecloud / smtp25 / carrier。"""
    if port is None:
        return None
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    proto = (proto or "TCP").upper()
    if port in ECLOUD_BLOCKED_PORTS:
        return ("ecloud", ECLOUD_BLOCKED_PORTS[port])
    if proto == "TCP" and port in CLOUD_OUTBOUND_SMTP:
        return ("smtp25", CLOUD_OUTBOUND_SMTP[port])
    if proto == "TCP" and port in CARRIER_HIGH_RISK_TCP:
        return ("carrier", CARRIER_HIGH_RISK_TCP[port])
    if proto in ("UDP", "VXLAN") and port in CARRIER_HIGH_RISK_UDP:
        return ("carrier", CARRIER_HIGH_RISK_UDP[port])
    return None


def _dest_ports_of(view):
    """本包可能被对端拦截的目的端口（含内层隧道和 ICMP 原始报文）。"""
    ports = []
    dport = _as_port(view.get("dport"))
    proto = (view.get("protocol") or view.get("l4") or "TCP").upper()
    # 外层 VXLAN/GRE 的 4789 不是业务拦截目标
    if dport is not None and proto not in ("VXLAN", "GRE", "GENEVE"):
        ports.append((dport, "TCP" if _packet_is_tcp(view) else (proto if proto in ("UDP", "TCP") else "TCP")))
    inner_dport = _as_port(view.get("inner_dport"))
    if inner_dport is not None:
        inner_proto = (view.get("inner_protocol") or view.get("inner_l4") or "TCP").upper()
        l4 = "TCP" if inner_proto in ("TCP", "HTTP", "TLS", "SSL") else ("UDP" if inner_proto in ("UDP", "VXLAN") else "TCP")
        ports.append((inner_dport, l4))
    orig_dport = _as_port(view.get("icmp_orig_dport"))
    orig_proto = (view.get("icmp_orig_protocol") or "TCP").upper()
    if orig_dport is None and view.get("layers"):
        orig_layer = _find_layer(view.get("layers"), "original datagram")
        if orig_layer:
            orig_dport = _as_port(_child_val(orig_layer, "destination port"))
            summary = (orig_layer.get("summary") or "").upper()
            if "UDP" in summary:
                orig_proto = "UDP"
            elif "TCP" in summary or "HTTP" in summary or "TLS" in summary:
                orig_proto = "TCP"
    if orig_dport is not None:
        l4 = "TCP" if orig_proto in ("TCP", "HTTP", "TLS", "SSL") else ("UDP" if orig_proto in ("UDP", "VXLAN") else "TCP")
        ports.append((orig_dport, l4))
    return ports


def _port_block_texts(view, hs=None, outcome=None):
    """生成端口封堵相关结论条目，返回 (level, title, detail, evidence) 列表。"""
    out = []
    outcome = outcome or {}
    kind_fail = outcome.get("kind") or ""
    flags = int(view.get("tcp_flags") or 0)
    ev = (view.get("info") or "").strip() or None
    if not ev and view.get("icmp_orig_info"):
        ev = str(view.get("icmp_orig_info")).strip()
    seen = set()
    retrans = int(outcome.get("retrans") or 0)
    icmp = outcome.get("icmp") or {}

    def _orig_bits():
        bits = []
        if icmp.get("orig_src") and icmp.get("orig_dst"):
            port_s = f":{icmp.get('orig_dport')}" if icmp.get("orig_dport") is not None else ""
            bits.append(f"ICMP 指向的原始报文是 {icmp.get('orig_src')} → {icmp.get('orig_dst')}{port_s}")
        elif icmp.get("orig_dport") is not None:
            bits.append(f"ICMP 指向的原始目的端口是 {icmp.get('orig_dport')}")
        if icmp.get("no") is not None:
            bits.append(f"见第 {icmp.get('no')} 号报文")
        return "，".join(bits)

    for port, proto in _dest_ports_of(view):
        kind = _classify_blocked_port(port, proto)
        if not kind or (port, proto) in seen:
            continue
        seen.add((port, proto))
        cat, role = kind
        if kind_fail == "ok":
            out.append(("info", f"目的端口 {port} 已见应答",
                        f"本流使用 {role}（{proto} {port}），已经观察到对端应答或数据。"
                        "虽然此端口可能出现在云平台的限制名单中，当前抓包并不支持本次连接被静默封堵的判断。", ev))
            continue
        if cat == "ecloud":
            if kind_fail == "rst":
                title = f"目的端口 {port} 属于移动云会拦截的高危端口，但本流是被 RST 拒绝"
                detail = (
                    f"本报文访问的是 {role}（{proto} {port}）。移动云文档写明该端口存在安全隐患，平台会拦截，"
                    "即使安全组已经放通，访问也可能失败。"
                    "抓包里这条流在握手阶段收到了 RST，这通常表示对端或路径上的设备主动拒绝连接，"
                    "常见原因是目的端口未在监听，或防火墙以复位方式拒绝。"
                    "这与完全没有应答的静默丢弃不同，不能仅凭 RST 断定就是云平台在静默拦截。"
                    "本工具也不能仅凭端口断定环境一定是移动云，但该端口与移动云及国内云常见拦截名单相符。"
                )
                out.append(("warn", title, detail, ev))
            elif kind_fail == "icmp_admin":
                title = f"目的端口 {port} 符合移动云高危端口拦截特征"
                detail = (
                    f"本报文访问的是 {role}（{proto} {port}）。移动云文档写明该端口存在安全隐患，平台会拦截，"
                    "即使安全组已经放通，访问也可能失败。"
                    "抓包里出现了针对该目的的 ICMP 管理策略禁止，这更像安全组、防火墙或云平台按策略拦截，"
                    "而不是对端主机不存在，也不是简单的端口未监听。"
                    + ((" " + _orig_bits() + "。") if _orig_bits() else "")
                    + "本工具不能仅凭这一点断定环境一定是移动云，但特征与移动云及国内云常见拦截名单相符。"
                )
                out.append(("warn", title, detail, ev))
            elif kind_fail == "silent":
                title = f"目的端口 {port} 符合移动云高危端口拦截特征"
                detail = (
                    f"本报文访问的是 {role}（{proto} {port}）。移动云文档写明该端口存在安全隐患，平台会拦截，"
                    "即使安全组已经放通，访问也可能失败。"
                    "抓包里这条流只见到 SYN"
                    + ("，并且出现了 SYN 重传" if retrans else "")
                    + "，没有对应的 SYN-ACK，也没有看到 RST。"
                    "这与平台侧拦截、运营商封堵或安全组/ACL 静默丢弃的表现一致。"
                    "本工具不能仅凭抓包断定这一定是移动云环境，但特征与移动云及国内云常见拦截名单相符。"
                )
                out.append(("warn", title, detail, ev))
            elif kind_fail in ("icmp_host", "icmp_net"):
                title = f"目的端口 {port} 属于移动云会拦截的高危端口，但当前更像主机或网络不可达"
                detail = (
                    f"本报文访问的是 {role}（{proto} {port}）。该端口在移动云文档的高危拦截名单中。"
                    f"不过抓包里对应的 ICMP 含义是{_icmp_kind_phrase(kind_fail[5:])}，"
                    "更说明对端主机或网络不可达，而不能直接写成端口被云平台拦截。"
                    + ((" " + _orig_bits() + "。") if _orig_bits() else "")
                )
                out.append(("warn", title, detail, ev))
            elif kind_fail == "icmp_port":
                title = f"目的端口 {port} 返回了端口不可达"
                detail = (
                    f"本报文访问的是 {role}（{proto} {port}）。抓包里出现了 ICMP 端口不可达，"
                    "这通常表示对端主机可达，但该端口没有进程在听，与完全静默丢弃不同。"
                    "该端口仍属于移动云会拦截的高危端口名单，需要结合环境判断，但不能把端口不可达直接写成平台静默拦截。"
                    + ((" " + _orig_bits() + "。") if _orig_bits() else "")
                )
                out.append(("warn", title, detail, ev))
            elif kind_fail == "short_window":
                title = f"目的端口 {port} 属于移动云会拦截的高危端口"
                detail = (
                    f"本报文访问的是 {role}（{proto} {port}）。移动云会拦截 135、137–139、445、4444 这些端口；"
                    "即使安全组放通，云主机之间或与外部互访也可能不通。"
                    "当前这条流只见到 SYN，抓包窗口还较短，尚未见到应答，还不能确认是被拦截、对端未响应，还是应答尚未到达或未被抓到。"
                    "需要更长的抓包才能确认。"
                )
                out.append(("warn", title, detail, ev))
            else:
                title = f"目的端口 {port} 属于移动云会拦截的高危端口"
                detail = (
                    f"本报文访问的是 {role}（{proto} {port}）。移动云会拦截 135、137–139、445、4444 这些端口；"
                    "即使安全组放通，云主机之间或与外部互访也可能不通。"
                    "若同时看到握手失败或 ICMP 管理禁止，更应优先怀疑平台拦截，而不是应用自身故障。"
                )
                out.append(("warn", title, detail, ev))
        elif cat == "smtp25":
            title = "TCP 25 是国内云常见出站封禁端口"
            detail = (
                "本报文使用 SMTP 的 25 端口发信。国内主流云（含移动云）通常默认拦截云主机出站 TCP 25，"
                "需要向云商申请解封，或改用 465 / 587 提交端口。"
            )
            if kind_fail == "silent":
                detail += "当前这条流只见到 SYN" + (" 且出现了重传" if retrans else "") + "，没有完成握手，也没有 RST，与出站被静默丢弃的表现一致。"
            elif kind_fail == "icmp_admin":
                detail += "抓包里还出现了针对该目的的 ICMP 管理禁止，与出站策略拦截相符。"
            elif kind_fail == "rst":
                detail += "当前这条流在握手阶段被 RST 拒绝，这通常表示对端未监听或主动拒绝，与完全没有应答的出站封禁不完全相同。"
            elif kind_fail == "short_window":
                detail += "当前这条流只见到 SYN，抓包窗口还较短，尚未见到应答，还不能确认这次是否被封禁，需要更长的抓包才能确认。"
            out.append(("warn", title, detail, ev))
        elif cat == "carrier" and kind_fail in ("silent", "icmp_admin"):
            title = f"目的端口 {port} 属于运营商或云环境常见高危拦截端口"
            detail = (
                f"本报文访问的是 {role}（{proto} {port}）。部分运营商和云平台会拦截或限速这类高危端口。"
                "抓包里这条流没有完成握手，并且没有看到对端的正常应答"
                + ("，同时出现了 ICMP 管理禁止。" if kind_fail == "icmp_admin" else "，表现更像中间设备静默丢弃。")
                + "除了检查对端服务是否在听，也应核对云安全组、主机防火墙和运营商策略。"
            )
            out.append(("warn", title, detail, ev))
    return out


def _icmp_admin_prohibited(app):
    icmp = (app or {}).get("icmp") or {}
    typ = icmp.get("type")
    code = icmp.get("code")
    if typ is None or code is None:
        return False
    if icmp.get("v6"):
        return typ == 1 and code in ICMP_ADMIN_CODES_V6
    return typ == 3 and code in ICMP_ADMIN_CODES_V4


def _ip_like(a, b) -> bool:
    """地址只作精确比较，避免 .2 与 .20 或不同 IPv6 文本形式误关联。"""
    try:
        return ipaddress.ip_address(str(a or "")) == ipaddress.ip_address(str(b or ""))
    except ValueError:
        return bool(a and b) and str(a) == str(b)


def _icmp_error_kind(icmp: dict | None) -> str | None:
    """把 ICMP / ICMPv6 差错分成可向用户说明的类别。"""
    icmp = icmp or {}
    typ, code = icmp.get("type"), icmp.get("code")
    if typ is None:
        return None
    v6 = bool(icmp.get("v6"))
    if v6:
        if typ == 1:
            if code == 1:
                return "admin"
            if code == 4:
                return "port"
            if code == 3:
                return "host"
            if code in (0, 2):
                return "net"
            return "unreach"
        if typ == 2:
            return "needfrag"
        if typ == 3:
            return "time_exceeded"
        return None
    if typ == 3:
        if code in ICMP_ADMIN_CODES_V4:
            return "admin"
        if code == 3:
            return "port"
        if code == 1:
            return "host"
        if code == 0:
            return "net"
        if code == 2:
            return "proto"
        if code == 4:
            return "needfrag"
        return "unreach"
    if typ == 11:
        return "time_exceeded"
    return None


def _icmp_kind_phrase(kind: str | None) -> str:
    return {
        "admin": "通信被管理策略禁止",
        "port": "目的端口不可达",
        "host": "主机不可达",
        "net": "网络不可达",
        "proto": "协议不可达",
        "needfrag": "需要分片或报文过大",
        "time_exceeded": "报文传输超时",
        "unreach": "目的不可达",
    }.get(kind or "", "目的不可达")


def _collect_icmp_events(views: list[dict] | None) -> list[dict]:
    events: list[dict] = []
    for v in views or []:
        app = _extract_app(v)
        icmp = app.get("icmp") or {}
        kind = _icmp_error_kind(icmp)
        if not kind:
            continue
        events.append({
            "no": v.get("no"),
            "kind": kind,
            "type": icmp.get("type"),
            "code": icmp.get("code"),
            "v6": bool(icmp.get("v6")),
            "orig_src": icmp.get("orig_src") or v.get("icmp_orig_src") or "",
            "orig_dst": icmp.get("orig_dst") or v.get("icmp_orig_dst") or "",
            "orig_sport": _as_port(icmp.get("orig_sport") if icmp.get("orig_sport") is not None else v.get("icmp_orig_sport")),
            "orig_dport": _as_port(icmp.get("orig_dport") if icmp.get("orig_dport") is not None else v.get("icmp_orig_dport")),
            "orig_proto": (icmp.get("orig_proto") or v.get("icmp_orig_protocol") or "").upper(),
            "orig_info": icmp.get("orig_info") or v.get("icmp_orig_info") or "",
            "info": v.get("info") or "",
        })
    return events


def _match_icmp_event(events: list[dict] | None, src, dst, dport, proto: str = "TCP", sport=None):
    """仅用已解出的原始地址、协议和端口配对，不从文本子串猜测。"""
    want_port = _as_port(dport)
    if not src or not dst or want_port is None:
        return None
    for e in events or []:
        if not _ip_like(src, e.get("orig_src")) or not _ip_like(dst, e.get("orig_dst")):
            continue
        if _as_port(e.get("orig_dport")) != want_port:
            continue
        if sport is not None and _as_port(e.get("orig_sport")) != _as_port(sport):
            continue
        ep = (e.get("orig_proto") or "").upper()
        ep = "TCP" if ep in ("HTTP", "TLS", "SSL") else ep
        if ep == (proto or "TCP").upper():
            return e
    return None


def _as_inner_tcp_view(view: dict) -> dict | None:
    """当外层是 VXLAN 等已恢复成 underlay 的封装时，构造内层 TCP 视图。"""
    proto = (view.get("inner_protocol") or view.get("inner_l4") or "").upper()
    if proto not in ("TCP", "HTTP", "TLS", "SSL"):
        return None
    if not (view.get("inner_src") or view.get("inner_dst")):
        return None
    outer = (view.get("protocol") or "").upper()
    # 6in4/GRE 等本身已保留内层 TCP 字段，不必再造一份，以免重复统计
    if _packet_is_tcp(view) and outer not in ("VXLAN", "GENEVE"):
        return None
    return {
        "no": view.get("no"),
        "ts": view.get("ts"),
        "protocol": proto,
        "l4": "TCP",
        "ip_src": view.get("inner_src"),
        "ip_dst": view.get("inner_dst"),
        "src": view.get("inner_src"),
        "dst": view.get("inner_dst"),
        "sport": view.get("inner_sport"),
        "dport": view.get("inner_dport"),
        "tcp_flags": int(view.get("inner_tcp_flags") or 0),
        "tcp_seq": view.get("inner_tcp_seq"),
        "tcp_ack": view.get("inner_tcp_ack"),
        "tcp_window": view.get("inner_tcp_window"),
        "payload_len": int(view.get("inner_payload_len") or 0),
        "stream_key": view.get("inner_stream_key"),
        "inner_dport": view.get("inner_dport"),
        "info": view.get("inner_info") or "",
    }


def _syn_packets(pkts: list[dict] | None) -> list[dict]:
    out = []
    for p in pkts or []:
        if not _packet_is_tcp(p):
            continue
        flags = int(p.get("tcp_flags") or 0)
        if _has(flags, "SYN") and not _has(flags, "ACK"):
            out.append(p)
    return out


def _syn_retrans_info(syns: list[dict]) -> tuple[int, float]:
    if len(syns) < 2:
        return 0, 0.0
    ordered = sorted(syns, key=lambda p: (p.get("ts") or 0, p.get("no") or 0))
    times = [float(p.get("ts")) for p in ordered if p.get("ts") is not None]
    gap = (max(times) - min(times)) if len(times) >= 2 else 0.0
    return len(ordered) - 1, gap


def _wait_after_last_syn(syns: list[dict], capture_end_ts) -> float:
    if not syns or capture_end_ts is None:
        return 0.0
    last = max((float(p.get("ts")) for p in syns if p.get("ts") is not None), default=None)
    if last is None:
        return 0.0
    return max(0.0, float(capture_end_ts) - last)


def _flow_outcome(pkts: list[dict] | None, *, capture_end_ts=None, icmp_events=None) -> dict:
    """根据握手、RST、ICMP 和等待时间判断这条 TCP 流为什么失败（或还不能下结论）。"""
    pkts = list(pkts or [])
    hs = _handshake_state(pkts)
    syns = _syn_packets(pkts)
    retrans, retrans_gap = _syn_retrans_info(syns)
    wait_s = _wait_after_last_syn(syns, capture_end_ts)
    dest_ip = src_ip = ""
    dport = None
    if syns:
        syn = syns[0]
        dest_ip = syn.get("ip_dst") or syn.get("dst") or ""
        src_ip = syn.get("ip_src") or syn.get("src") or ""
        dport = _as_port(syn.get("dport")) or _as_port(syn.get("inner_dport"))
    icmp_hit = _match_icmp_event(icmp_events, src_ip, dest_ip, dport, "TCP", sport=syns[0].get("sport")) if syns else None
    base = {
        "hs": hs,
        "syns": syns,
        "retrans": retrans,
        "retrans_gap": retrans_gap,
        "wait_s": wait_s,
        "src": src_ip,
        "dst": dest_ip,
        "dport": dport,
        "icmp": icmp_hit,
        "confirmed": False,
        "kind": "unknown",
    }
    if hs.get("complete") or hs.get("synack") or hs.get("data"):
        base["kind"] = "ok"
        return base
    if icmp_hit and icmp_hit.get("kind"):
        base["kind"] = "icmp_" + icmp_hit["kind"]
        base["confirmed"] = True
        return base
    if hs.get("syn") and hs.get("rst") and not hs.get("synack"):
        base["kind"] = "rst"
        base["confirmed"] = True
        return base
    if hs.get("syn") and not hs.get("synack"):
        enough = (retrans >= 1 and retrans_gap >= _SYN_RETRANS_GAP_S) or (wait_s >= _SYN_CONFIRM_WAIT_S)
        if enough:
            base["kind"] = "silent"
            base["confirmed"] = True
        else:
            base["kind"] = "short_window"
            base["confirmed"] = False
        return base
    if hs.get("syn") and hs.get("synack") and not hs.get("ack") and not hs.get("data"):
        base["kind"] = "half"
        return base
    return base


def _outcome_for_view(view, *, peers=None, inner_stream=None, capture_end_ts=None, icmp_events=None) -> dict:
    inner_v = _as_inner_tcp_view(view)
    if inner_v:
        inner_peers = [_as_inner_tcp_view(p) or p for p in (inner_stream or [inner_v])]
        return _flow_outcome(inner_peers, capture_end_ts=capture_end_ts, icmp_events=icmp_events)
    if _packet_is_tcp(view):
        return _flow_outcome(peers or [view], capture_end_ts=capture_end_ts, icmp_events=icmp_events)
    app = _extract_app(view)
    icmp = app.get("icmp") or {}
    kind = _icmp_error_kind(icmp)
    if kind:
        return {
            "kind": "icmp_" + kind,
            "confirmed": True,
            "hs": {},
            "syns": [],
            "retrans": 0,
            "retrans_gap": 0.0,
            "wait_s": 0.0,
            "src": icmp.get("orig_src") or "",
            "dst": icmp.get("orig_dst") or "",
            "dport": _as_port(icmp.get("orig_dport")),
            "icmp": {
                "no": view.get("no"),
                "kind": kind,
                "type": icmp.get("type"),
                "code": icmp.get("code"),
                "orig_src": icmp.get("orig_src") or "",
                "orig_dst": icmp.get("orig_dst") or "",
                "orig_dport": _as_port(icmp.get("orig_dport")),
                "orig_sport": _as_port(icmp.get("orig_sport")),
                "orig_proto": icmp.get("orig_proto") or "",
                "orig_info": icmp.get("orig_info") or "",
                "info": view.get("info") or "",
            },
        }
    return {"kind": "unknown", "confirmed": False, "hs": {}, "syns": [], "retrans": 0, "retrans_gap": 0.0, "wait_s": 0.0, "icmp": None}


def _tunnel_packet_items(view, ev):
    """隧道/封装相关的单包结论。"""
    items = []
    proto = (view.get("protocol") or "").upper()
    vni = view.get("vni")
    tunnel = (view.get("tunnel") or "").strip()
    inner_proto = (view.get("inner_protocol") or "").strip()
    inner_src = (view.get("inner_src") or "").strip()
    inner_dst = (view.get("inner_dst") or "").strip()
    inner_info = (view.get("inner_info") or "").strip()
    inner_ver = view.get("inner_ip_version")
    outer_src = (view.get("outer_src") or view.get("ip_src") or view.get("src") or "").strip()
    outer_dst = (view.get("outer_dst") or view.get("ip_dst") or view.get("dst") or "").strip()

    if proto == "VXLAN" or vni is not None:
        vni_s = f"VNI {vni}" if vni is not None else "VNI 未能读出"
        inner_bits = []
        if inner_proto:
            inner_bits.append(inner_proto)
        if inner_src and inner_dst:
            inner_bits.append(f"{inner_src} → {inner_dst}")
        if inner_info:
            inner_bits.append(inner_info)
        inner_txt = "，".join(inner_bits) if inner_bits else "内层帧已解析，但未识别出网络层地址"
        ver_txt = f"IPv{inner_ver}" if inner_ver else "内层报文"
        title = f"这是 VXLAN 隧道报文，{vni_s}"
        detail = (
            f"外层是 VTEP {outer_src} 与 {outer_dst} 之间的 UDP 封装；{vni_s} 标识租户或网段。"
            f"内层是 {ver_txt}：{inner_txt}。"
            "分析时请同时看外层underlay和内层业务，不要只把外层 IPv4 当成最终通信双方。"
        )
        items.append(("info", title, detail, ev or inner_info or None))
    elif tunnel or proto == "GRE":
        tname = tunnel or proto
        inner_bits = []
        if inner_proto:
            inner_bits.append(inner_proto)
        if inner_src and inner_dst:
            inner_bits.append(f"{inner_src} → {inner_dst}")
        if inner_info:
            inner_bits.append(inner_info)
        inner_txt = "，".join(inner_bits) if inner_bits else "内层载荷已解析"
        ver_txt = f"IPv{inner_ver}" if inner_ver else "内层报文"
        title = f"这是 {tname} 隧道封装"
        detail = (
            f"外层是 {outer_src} → {outer_dst} 的隧道头，内层是 {ver_txt}：{inner_txt}。"
            "列表和结论里应能看到内层地址，而不是只显示外层 IPv4。"
        )
        items.append(("info", title, detail, ev or inner_info or None))
    return items


def _packet_is_tcp(view: dict) -> bool:
    """只有真正的 TCP（含 HTTP/TLS 等承载）才按 TCP 标志和序号分析。"""
    l4 = (view.get("l4") or "").upper()
    proto = (view.get("protocol") or "").upper()
    if l4 in _NON_TCP or proto in _NON_TCP:
        return False
    return l4 == "TCP" or proto in ("TCP", "HTTP", "TLS", "SSL")


def _as_port(value) -> int | None:
    try:
        if value is None or value == "":
            return None
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return int(value)
        s = str(value).strip()
        if not s:
            return None
        if s.isdigit() or (s[0] in "+-" and s[1:].isdigit()):
            return int(s)
        m = re.match(r"(\d+)", s)
        if m:
            return int(m.group(1))
        return None
    except (TypeError, ValueError):
        return None




def _service_name(port, proto: str = "UDP") -> str:
    port = _as_port(port)
    if port is None:
        return ""
    primary = TCP_SERVICES if (proto or "").upper() in ("TCP", "HTTP", "TLS", "SSL") else UDP_SERVICES
    return primary.get(port) or ""


def _port_context(view: dict, proto: str) -> str:
    sport, dport = _as_port(view.get("sport")), _as_port(view.get("dport"))
    parts: list[str] = []
    ds, ss = _service_name(dport, proto), _service_name(sport, proto)
    if ds and dport is not None:
        parts.append(f"目的端口 {dport} 是 {ds} 的常用端口")
    elif dport is not None:
        parts.append(f"目的端口 {dport} 不是本工具内置的常见服务端口，不能仅凭端口号断定应用协议")
    if ss and sport is not None and ss != ds:
        parts.append(f"源端口 {sport} 是 {ss} 的常用端口")
    elif sport is not None and not ss:
        parts.append(f"源端口 {sport} 是临时端口，一般由发送端自动分配")
    if not parts:
        return ""
    text = "；".join(parts) + "。"
    if ds == "VXLAN" or ss == "VXLAN":
        text += "VXLAN 用于在 IP 网络上封装二层以太网帧，把虚拟网络标识（VNI）和内层帧放在 UDP 载荷里。"
    return text


_SENSITIVE_HDR = re.compile(
    r"(?im)^((?:set-)?cookie|authorization|proxy-authorization|x-api-key)\s*:\s*.+$"
)
_COOKIE_IN_INFO = re.compile(r"(?i)(cookie|authorization|set-cookie)=([^;\s]+)")


def _flag_names(bits: int) -> list[str]:
    bits = int(bits or 0)
    return [name for name, mask in TCP_FLAGS if bits & mask]


def _has(bits: int, name: str) -> bool:
    for n, mask in TCP_FLAGS:
        if n == name:
            return bool(int(bits or 0) & mask)
    return False


def _endpoint(view: dict, which: str = "src") -> str:
    ip = view.get("ip_src") if which == "src" else view.get("ip_dst")
    ip = ip or view.get(which) or "—"
    port = view.get("sport") if which == "src" else view.get("dport")
    if port is not None and port != "":
        return f"{ip}:{port}"
    return str(ip)


def _walk(nodes: Iterable[dict] | None):
    for n in nodes or []:
        yield n
        yield from _walk(n.get("children") or [])


def _find_layer(layers: list | None, *names: str) -> Optional[dict]:
    want = tuple(x.lower() for x in names)
    for n in layers or []:
        name = (n.get("name") or "").lower()
        if any(w in name for w in want):
            return n
    return None


def _child_val(layer: dict | None, *names: str) -> str:
    if not layer:
        return ""
    want = tuple(x.lower() for x in names)
    for n in _walk(layer.get("children") or []):
        name = (n.get("name") or "").lower()
        if any(name == w or w in name for w in want):
            val = n.get("value")
            if val:
                return str(val)
    return ""


def _inet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _verify_ipv4(raw: bytes, off: int, ihl: int) -> Optional[bool]:
    if ihl < 20 or off < 0 or off + ihl > len(raw):
        return None
    return _inet_checksum(raw[off:off + ihl]) == 0


def _verify_l4_ipv4(raw: bytes, ip_off: int, ihl: int, proto: int,
                    l4_off: int, l4_end: int) -> Optional[bool]:
    if l4_off < 0 or l4_end > len(raw) or l4_end <= l4_off:
        return None
    if ip_off + 20 > len(raw):
        return None
    src = raw[ip_off + 12:ip_off + 16]
    dst = raw[ip_off + 16:ip_off + 20]
    length = l4_end - l4_off
    # 截断报文的校验和通常对不上，不做判断
    total = int.from_bytes(raw[ip_off + 2:ip_off + 4], "big")
    if total and ip_off + total > len(raw):
        return None
    pseudo = src + dst + bytes([0, proto]) + length.to_bytes(2, "big") + raw[l4_off:l4_end]
    return _inet_checksum(pseudo) == 0


def _verify_l4_ipv6(raw: bytes, ip_off: int, proto: int,
                    l4_off: int, l4_end: int) -> Optional[bool]:
    if l4_off < 0 or l4_end > len(raw) or l4_end <= l4_off:
        return None
    if ip_off + 40 > len(raw):
        return None
    src = raw[ip_off + 8:ip_off + 24]
    dst = raw[ip_off + 24:ip_off + 40]
    length = l4_end - l4_off
    plen = int.from_bytes(raw[ip_off + 4:ip_off + 6], "big")
    if plen and ip_off + 40 + plen > len(raw):
        return None  # 截断
    pseudo = src + dst + length.to_bytes(4, "big") + bytes([0, 0, 0, proto]) + raw[l4_off:l4_end]
    return _inet_checksum(pseudo) == 0


def _decode_raw(raw: Any) -> bytes:
    if raw is None:
        return b""
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    if isinstance(raw, str):
        try:
            return base64.b64decode(raw)
        except Exception:
            return b""
    return b""


def _seq_lt(a: int, b: int) -> bool:
    return ((a - b) & 0xFFFFFFFF) > 0x80000000


def _extract_app(view: dict) -> dict:
    """从字段树与摘要中收集应用层事实，解不到就省略。"""
    app: dict[str, Any] = {}
    layers = view.get("layers") or []
    proto = (view.get("protocol") or "").upper()
    info = view.get("info") or ""

    http = _find_layer(layers, "hypertext transfer protocol")
    if http or proto == "HTTP":
        method = _child_val(http, "method")
        uri = _child_val(http, "request uri")
        host = _child_val(http, "host")
        status = _child_val(http, "status code")
        start = _child_val(http, "request/status line") or info
        if not method and start and not start.upper().startswith("HTTP/"):
            parts = start.split(" ", 2)
            if parts:
                method = parts[0]
            if len(parts) >= 2:
                uri = uri or parts[1]
        if not host:
            m = re.search(r"Host:\s*(\S+)", info, re.I)
            if m:
                host = m.group(1)
        if not status and start.upper().startswith("HTTP/"):
            parts = start.split(" ", 2)
            if len(parts) >= 2:
                status = " ".join(parts[1:])
        app["http"] = {
            "method": method, "path": uri, "host": host,
            "status": status, "start": start[:200],
        }

    dns = _find_layer(layers, "domain name system")
    if dns or proto == "DNS":
        resp = _child_val(dns, "response")
        is_resp = bool(resp and "response" in resp.lower() and "query" not in resp.lower().split("is a")[0][-12:])
        if info.lower().find("response") >= 0:
            is_resp = True
        if info.lower().find("standard query") >= 0 and "response" not in info.lower():
            is_resp = False
        qname = _child_val(dns, "name") or ""
        qtype = _child_val(dns, "type")
        rcode = _child_val(dns, "reply code")
        answers = []
        if dns:
            for n in _walk(dns.get("children") or []):
                name = (n.get("name") or "")
                if name in ("Answers", "Answer"):
                    for ch in n.get("children") or []:
                        sm = ch.get("summary") or ch.get("value") or ch.get("name")
                        if sm:
                            answers.append(str(sm))
                elif name.startswith("A ") or name in ("A", "AAAA", "CNAME", "MX", "NS", "PTR", "TXT", "SOA"):
                    val = n.get("value") or n.get("summary")
                    if val:
                        answers.append(f"{name} {val}")
        if not qname:
            m = re.search(r"\b(?:A|AAAA|CNAME|MX|NS|PTR|TXT|SOA|SRV|ANY|TYPE\d+)\s+(\S+)", info)
            if m:
                qtype = qtype or m.group(0).split()[0]
                qname = m.group(1)
        tid = _child_val(dns, "transaction id")
        app["dns"] = {
            "response": is_resp, "qname": qname.rstrip("."), "qtype": qtype,
            "rcode": rcode, "answers": answers[:8], "tid": tid,
        }

    tls = _find_layer(layers, "transport layer security", "tls")
    if tls or proto in ("TLS", "SSL"):
        rec = _child_val(tls, "content type")
        ver = _child_val(tls, "version") or _child_val(tls, "legacy version")
        hs = _child_val(tls, "handshake type")
        sni = _child_val(tls, "host name") or _child_val(tls, "server_name")
        if not sni:
            m = re.search(r"SNI:\s*([^)\s]+)", info)
            if m:
                sni = m.group(1)
        alert_level = _child_val(tls, "alert level")
        alert_desc = _child_val(tls, "alert description")
        is_alert = bool(alert_level) or "alert" in ((rec or "") + " " + (info or "") + " " + (hs or "")).lower()
        app["tls"] = {
            "record": rec, "version": ver, "handshake": hs, "sni": sni,
            "alert": is_alert, "alert_level": alert_level, "alert_desc": alert_desc,
        }

    icmp = _find_layer(layers, "internet control message", "icmpv6")
    if icmp or proto in ("ICMP", "ICMPV6"):
        typ_s = _child_val(icmp, "type")
        code_s = _child_val(icmp, "code")
        typ = None
        if typ_s:
            m = re.match(r"(\d+)", typ_s)
            if m:
                typ = int(m.group(1))
        code = None
        if code_s and re.match(r"\d+", code_s):
            code = int(code_s.split()[0])
        v6 = proto == "ICMPv6" or (icmp and "v6" in (icmp.get("name") or "").lower())
        orig_src = (view.get("icmp_orig_src") or "").strip()
        orig_dst = (view.get("icmp_orig_dst") or "").strip()
        orig_proto = (view.get("icmp_orig_protocol") or "").strip()
        orig_sport = _as_port(view.get("icmp_orig_sport"))
        orig_dport = _as_port(view.get("icmp_orig_dport"))
        orig_info = (view.get("icmp_orig_info") or "").strip()
        if not orig_dst or orig_dport is None:
            orig_layer = _find_layer(layers, "original datagram")
            if orig_layer:
                orig_info = orig_info or (orig_layer.get("summary") or "")
                orig_src = orig_src or _child_val(orig_layer, "source address")
                orig_dst = orig_dst or _child_val(orig_layer, "destination address")
                orig_sport = orig_sport if orig_sport is not None else _as_port(_child_val(orig_layer, "source port"))
                orig_dport = orig_dport if orig_dport is not None else _as_port(_child_val(orig_layer, "destination port"))
                if not orig_proto:
                    sm = (orig_layer.get("summary") or "").upper()
                    if "UDP" in sm:
                        orig_proto = "UDP"
                    elif "TCP" in sm or "HTTP" in sm or "TLS" in sm:
                        orig_proto = "TCP"
        app["icmp"] = {
            "type": typ, "code": code, "name": typ_s or info,
            "v6": v6,
            "orig_src": orig_src, "orig_dst": orig_dst, "orig_proto": orig_proto,
            "orig_sport": orig_sport, "orig_dport": orig_dport, "orig_info": orig_info,
        }

    arp = _find_layer(layers, "address resolution protocol")
    if arp or proto == "ARP":
        op = _child_val(arp, "opcode") or _child_val(arp, "operation") or info
        spa = _child_val(arp, "sender ip") or view.get("src") or ""
        tpa = _child_val(arp, "target ip") or view.get("dst") or ""
        sha = _child_val(arp, "sender mac")
        app["arp"] = {"op": op, "spa": spa, "tpa": tpa, "sha": sha}

    return app


def _iter_layers(nodes):
    for n in nodes or []:
        yield n
        yield from _iter_layers(n.get("children") or [])


def _checksum_hints(view: dict, raw: bytes) -> list[dict]:
    """按层次配对校验：内层 TCP/UDP 必须用紧邻的内层 IP，而不是外层隧道头。"""
    hints = []
    if not raw:
        return hints
    caplen = int(view.get("caplen") or len(raw))
    wire = int(view.get("length") or caplen)
    truncated = caplen < wire
    layers = list(_iter_layers(view.get("layers") or []))
    ip_headers = []
    for n in layers:
        name = (n.get("name") or "").lower()
        off = int(n.get("offset") or 0)
        if "internet protocol version 4" in name:
            ihl = int(n.get("length") or 20)
            ok = _verify_ipv4(raw, off, ihl)
            if ok is False:
                hints.append({"level": "error", "text": "IPv4 首部校验和异常。"})
            ip_headers.append(("v4", off, ihl, n))
        elif "internet protocol version 6" in name:
            ip_headers.append(("v6", off, 40, n))

    def _enclosing_ip(l4_off: int):
        best = None
        for item in ip_headers:
            if item[1] <= l4_off:
                best = item
        return best

    def _ip_payload_end(item) -> Optional[int]:
        ver, off, _ln, _n = item
        if ver == "v4":
            if off + 4 > len(raw):
                return None
            total = int.from_bytes(raw[off + 2:off + 4], "big")
            end = off + total
            if total and end > len(raw):
                return None
            return min(end, len(raw)) if total else None
        plen = int.from_bytes(raw[off + 4:off + 6], "big") if off + 6 <= len(raw) else 0
        end = off + 40 + plen
        if plen and end > len(raw):
            return None
        return min(end, len(raw)) if plen else None

    if not truncated:
        for n in layers:
            name = (n.get("name") or "").lower()
            if "transmission control protocol" in name:
                proto, label = 6, "TCP"
            elif "user datagram protocol" in name:
                proto, label = 17, "UDP"
            else:
                continue
            l4_off = int(n.get("offset") or 0)
            enc = _enclosing_ip(l4_off)
            if not enc:
                continue
            l4_end = _ip_payload_end(enc)
            if l4_end is None or l4_end <= l4_off:
                continue
            if proto == 17 and l4_off + 8 <= len(raw):
                csum = int.from_bytes(raw[l4_off + 6:l4_off + 8], "big")
                if csum == 0 and enc[0] == "v4":
                    continue  # IPv4 中 UDP 校验和为 0 表示未计算
            if enc[0] == "v4":
                ok = _verify_l4_ipv4(raw, enc[1], enc[2], proto, l4_off, l4_end)
            else:
                ok = _verify_l4_ipv6(raw, enc[1], proto, l4_off, l4_end)
            if ok is False:
                hints.append({"level": "error", "text": f"{label} 校验和异常。"})
    return hints


def _stream_peers(view: dict, stream: list[dict] | None) -> list[dict]:
    if not stream:
        return []
    key = view.get("stream_key")
    if not key:
        return []
    return [p for p in stream if p.get("stream_key") == key]


def _handshake_state(peers: list[dict]) -> dict:
    """根据同一条流里已见到的标志判断握手/关闭进展。"""
    syn = synack = ack3 = fin = rst = data = False
    syn_no = synack_no = ack_no = fin_no = rst_no = None
    ordered = sorted(peers, key=lambda p: (p.get("ts") or 0, p.get("no") or 0))
    for p in ordered:
        flags = int(p.get("tcp_flags") or 0)
        if not _packet_is_tcp(p):
            continue
        syn_b = _has(flags, "SYN")
        ack_b = _has(flags, "ACK")
        fin_b = _has(flags, "FIN")
        rst_b = _has(flags, "RST")
        plen = int(p.get("payload_len") or 0)
        if syn_b and not ack_b:
            syn = True
            syn_no = syn_no or p.get("no")
        elif syn_b and ack_b:
            synack = True
            synack_no = synack_no or p.get("no")
        elif ack_b and not syn_b and not fin_b and not rst_b:
            if syn and synack and not ack3:
                ack3 = True
                ack_no = p.get("no")
            elif not syn and not synack:
                # 抓包起点已在数据阶段
                ack3 = True
                ack_no = ack_no or p.get("no")
        if plen > 0 and not syn_b:
            data = True
            if syn and synack:
                ack3 = True
        if fin_b:
            fin = True
            fin_no = fin_no or p.get("no")
        if rst_b:
            rst = True
            rst_no = rst_no or p.get("no")
    complete = bool((syn and synack and ack3) or (data and synack) or (data and not syn and not synack))
    # 只有 SYN 没有应答 → 未完成；SYN+SYN-ACK 无第三步 → 可能未完成
    if syn and not synack and not data:
        complete = False
    if syn and synack and not ack3 and not data:
        complete = False
    return {
        "syn": syn, "synack": synack, "ack": ack3, "fin": fin, "rst": rst,
        "data": data, "complete": complete,
        "syn_no": syn_no, "synack_no": synack_no, "ack_no": ack_no,
        "fin_no": fin_no, "rst_no": rst_no,
    }


def _this_packet_role(view: dict, hs: dict, peers: list[dict]) -> str:
    flags = int(view.get("tcp_flags") or 0)
    syn, ack, fin, rst, psh = (_has(flags, n) for n in ("SYN", "ACK", "FIN", "RST", "PSH"))
    plen = int(view.get("payload_len") or 0)
    no = view.get("no")
    if rst:
        return "这条报文用 RST 中止连接。"
    if syn and not ack:
        return "这是 TCP 三次握手的第一拍（SYN），用于发起连接。"
    if syn and ack:
        return "这是 TCP 三次握手的第二拍（SYN-ACK），对端同意建立连接。"
    if fin:
        if hs.get("fin_no") == no or not any(
            _has(int(p.get("tcp_flags") or 0), "FIN") and (p.get("no") or 0) < (no or 0)
            for p in peers
        ):
            return "这条报文置位 FIN" + (" 和 ACK" if ack else "") + "，表示正在关闭连接。"
        return "这条报文置位 FIN" + (" 和 ACK" if ack else "") + "，属于连接关闭过程中的回应。"
    if ack and not syn and plen == 0 and not psh and not fin and not rst:
        if hs.get("syn") and hs.get("synack") and hs.get("ack_no") == no:
            return "这是 TCP 三次握手的第三拍（ACK），连接随后可以传输数据。"
        return "这是一条无载荷的纯 ACK，用于确认对端已收到的数据或控制报文。"
    if plen > 0:
        if psh:
            return "这条报文携带有效载荷（PSH），把数据交给应用层。"
        return "这条报文携带有效载荷。"
    if ack:
        return "这是一条 TCP 确认报文。"
    return "这是一条 TCP 报文。"


def _detect_retrans_or_ooo(view: dict, peers: list[dict]) -> list[dict]:
    hints = []
    flags = int(view.get("tcp_flags") or 0)
    if _has(flags, "SYN") or _has(flags, "RST"):
        # SYN 重传另算
        pass
    seq = view.get("tcp_seq")
    if seq is None:
        return hints
    plen = int(view.get("payload_len") or 0)
    no = view.get("no") or 0
    same_dir = []
    src, dst = view.get("ip_src") or view.get("src"), view.get("ip_dst") or view.get("dst")
    sport, dport = view.get("sport"), view.get("dport")
    for p in peers:
        if (p.get("no") or 0) >= no:
            continue
        if (p.get("ip_src") or p.get("src")) != src:
            continue
        if (p.get("sport") != sport) or (p.get("dport") != dport):
            continue
        if p.get("tcp_seq") is None:
            continue
        same_dir.append(p)
    if not same_dir:
        return hints
    if plen > 0 or _has(flags, "SYN") or _has(flags, "FIN"):
        for p in same_dir:
            if int(p.get("tcp_seq") or -1) == int(seq) and int(p.get("payload_len") or 0) == plen:
                hints.append({
                    "level": "warn",
                    "text": f"可能是重传：与第 {p.get('no')} 号报文序列号相同（Seq={seq}）。",
                })
                break
    # 乱序：本包 seq 小于同向已见到的最大“已发送”seq（排除纯 ACK）
    prev_seqs = [
        int(p["tcp_seq"]) for p in same_dir
        if p.get("tcp_seq") is not None and (
            int(p.get("payload_len") or 0) > 0 or _has(int(p.get("tcp_flags") or 0), "SYN")
        )
    ]
    if prev_seqs and plen > 0:
        max_seq = prev_seqs[-1]
        # 用最后一拍的 seq 作为参考不够稳，用同向最大 seq
        max_seq = max(prev_seqs)
        if _seq_lt(int(seq), max_seq) and int(seq) != max_seq:
            # 若等于已出现过的 seq 已在重传里说明
            if all(int(p.get("tcp_seq") or -1) != int(seq) for p in same_dir):
                hints.append({
                    "level": "warn",
                    "text": f"序列号可能乱序：本包 Seq={seq}，同向先前已出现过更大的 Seq={max_seq}。",
                })
    return hints


def _endpoint_phrase(view: dict) -> str:
    proto = view.get("protocol") or "未知协议"
    src, dst = _endpoint(view, "src"), _endpoint(view, "dst")
    return f"{proto} 报文，从 {src} 到 {dst}"



def _conclusion(level: str, title: str, detail: str, evidence: str = "") -> dict:
    return {
        "level": level or "info",
        "title": re.sub(r"\s+", " ", (title or "")).strip(),
        "detail": re.sub(r"\s+", " ", (detail or "")).strip(),
        "evidence": re.sub(r"\s+", " ", (evidence or "")).strip(),
    }


def _hint_conclusion(hint: dict) -> dict | None:
    text = (hint.get("text") or "").strip()
    if not text:
        return None
    level = hint.get("level") or "info"
    if level == "note":
        level = "info"
    low = text.lower()
    if "校验和" in text:
        title = "校验和异常"
        level = "error"
    elif "截断" in text:
        title = "报文被截断"
    elif "零窗口" in text:
        title = "零窗口"
    elif "重传" in text:
        title = "可能重传"
    elif "乱序" in text:
        title = "可能乱序"
    elif "标志组合异常" in text:
        title = "标志组合异常"
    elif "nxdomain" in low:
        title = "域名不存在"
    elif "dns 应答异常" in low or "dns 应答异常" in text:
        title = "DNS 应答异常"
    elif text.startswith("HTTP ") and ("服务器出错" in text or "未被成功处理" in text):
        title = "HTTP 状态异常"
    elif "纯 ack" in low or "纯 ACK" in text:
        title = "纯 ACK"
    elif "fin" in low and "载荷" in text:
        title = "FIN 无载荷"
    else:
        title = "注意事项"
    return _conclusion(level, title, text)


def _build_packet_conclusions(
    view: dict,
    *,
    proto: str,
    summary: str,
    points: list[str],
    hints: list[dict],
    app: dict,
    hs: dict,
    peers: list[dict],
    flag_names: list[str],
    plen: int,
    is_tcp: bool,
    recognized: list[str],
    window,
    ttl,
    outcome: dict | None = None,
    inner_stream: list[dict] | None = None,
    capture_end_ts=None,
) -> list[dict]:
    """把本包事实整理成若干条带标题的分析结论，保证非空。"""
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(level: str, title: str, detail: str, evidence: str = "") -> None:
        item = _conclusion(level, title, detail, evidence)
        if not item["title"] or not item["detail"]:
            return
        key = (item["title"], item["detail"])
        if key in seen:
            return
        seen.add(key)
        out.append(item)

    src, dst = _endpoint(view, "src"), _endpoint(view, "dst")
    ev_end = f"{src} → {dst}"
    ev_flags = ("TCP 标志：" + "、".join(flag_names)) if flag_names else ""
    flags = int(view.get("tcp_flags") or 0)
    ev_seq = ""
    if view.get("tcp_seq") is not None:
        ev_seq = f"Seq={view.get('tcp_seq')}"
        if _has(flags, "ACK"):
            ev_seq += f" Ack={view.get('tcp_ack')}"

    layers_s = " / ".join(recognized) if recognized else proto
    port_txt = _port_context(view, "TCP" if is_tcp or proto in ("TCP", "HTTP", "TLS", "SSL") else proto)

    if proto == "ARP" or app.get("arp"):
        arp = app.get("arp") or {}
        op = (arp.get("op") or view.get("info") or "")
        spa = arp.get("spa") or view.get("src") or ""
        tpa = arp.get("tpa") or view.get("dst") or ""
        sha = arp.get("sha") or ""
        ev = ev_end + (f"；{op}" if op else "")
        if "who has" in op.lower() or "request" in op.lower() or "请求" in op:
            add("info", "ARP 请求", f"这是一条 ARP 请求报文，由 {spa} 发出，询问 {tpa} 当前对应的 MAC 地址。ARP 工作在数据链路层，本身没有 TCP 标志或传输层序号。", ev)
            add("info", "局域网地址解析", "ARP 请求通常以广播发送到局域网内所有主机，用来把 IPv4 地址解析成对应的硬件（MAC）地址，以便后续封装以太网帧。")
        elif "is at" in op.lower() or "reply" in op.lower() or "应答" in op or "响应" in op:
            add("info", "ARP 应答", f"这是一条 ARP 应答报文：{spa} 宣称其 MAC 地址为 {sha or '（见字段）'}，用来回答对 {tpa} 的地址查询。该报文没有 TCP 标志或序号。", ev)
            add("info", "地址绑定", "ARP 应答把 IP 与 MAC 的对应关系告诉请求方，收到后通常会写入本机 ARP 缓存，供后续向该 IP 发送以太网帧时使用。")
        else:
            add("info", "ARP 报文", summary or f"这是一条 ARP 报文，从 {src} 到 {dst}。ARP 用于在局域网解析 IPv4 与 MAC 的对应关系，没有 TCP 标志。", ev)

    elif proto in ("ICMP", "ICMPV6") or app.get("icmp"):
        icmp = app.get("icmp") or {}
        typ = icmp.get("type")
        code = icmp.get("code")
        v6 = proto == "ICMPv6" or icmp.get("v6")
        kind = "ICMPv6" if v6 else "ICMP"
        ev = ev_end + (f"；类型 {typ}，代码 {code}" if typ is not None else "")
        orig_bits = []
        if icmp.get("orig_src") and icmp.get("orig_dst"):
            op = f"{icmp.get('orig_src')}"
            if icmp.get("orig_sport") is not None:
                op += f":{icmp.get('orig_sport')}"
            od = f"{icmp.get('orig_dst')}"
            if icmp.get("orig_dport") is not None:
                od += f":{icmp.get('orig_dport')}"
            orig_bits.append(f"被反映的原始报文是 {op} → {od}")
            if icmp.get("orig_proto"):
                orig_bits[-1] += f"（{icmp.get('orig_proto')}）"
        elif icmp.get("orig_dport") is not None:
            orig_bits.append(f"被反映的原始目的端口是 {icmp.get('orig_dport')}")
        orig_txt = (" " + "，".join(orig_bits) + "。") if orig_bits else ""
        err_kind = _icmp_error_kind(icmp)
        if typ == 3 and not v6:
            extra = ICMP4_UNREACH.get(code, f"代码 {code}")
            add("warn", "目的不可达", f"这是一条 ICMP 目的不可达报文，从 {src} 到 {dst}，含义是{extra}。{orig_txt}".strip(), ev)
        elif typ == 1 and v6:
            extra = ICMP6_UNREACH.get(code, f"代码 {code}")
            add("warn", "目的不可达", f"这是一条 ICMPv6 目的不可达报文，从 {src} 到 {dst}，含义是{extra}。{orig_txt}".strip(), ev)
        elif typ == 2 and v6:
            add("warn", "报文过大", f"这是一条 ICMPv6 报文过大（Packet Too Big）报文，从 {src} 到 {dst}，通常表示路径 MTU 不足。{orig_txt}".strip(), ev)
        if err_kind == "admin" or _icmp_admin_prohibited(app):
            port_note = ""
            odport = _as_port(icmp.get("orig_dport"))
            if odport in ECLOUD_BLOCKED_PORTS:
                port_note = (
                    f"原始报文的目的端口 {odport}（{ECLOUD_BLOCKED_PORTS[odport]}）属于移动云文档中的高危拦截端口，"
                    "与移动云及国内云常见的平台拦截高度吻合；本工具不能仅凭这一点断定环境一定是移动云，但特征相符。"
                )
            elif odport in CLOUD_OUTBOUND_SMTP:
                port_note = "原始报文的目的端口是 TCP 25，与国内云常见的出站 SMTP 封禁相符。"
            else:
                port_note = (
                    "若被禁的原始报文目的端口属于 135、137–139、445、4444，则与移动云文档中的高危端口拦截高度吻合；"
                    "本工具不能仅凭这一点断定环境一定是移动云，但特征相符。"
                )
            add(
                "warn",
                "通信被管理策略禁止",
                "这条 ICMP 的类型和代码表示通信被管理策略禁止"
                "（IPv4 目的不可达代码 9/10/13，或 ICMPv6 目的不可达代码 1）。"
                "这常见于云安全组、主机防火墙、运营商或云平台的端口拦截，而不是对端主机不存在。"
                + orig_txt + port_note,
                ev,
            )
        elif typ in (8, 128):
            add("info", f"{kind} 回显请求", f"这是一条 {kind} 回显请求（ping），从 {src} 到 {dst}，用于探测对端是否可达。", ev)
        elif typ in (0, 129):
            add("info", f"{kind} 回显应答", f"这是一条 {kind} 回显应答，从 {src} 到 {dst}，是对先前 ping 请求的回复。", ev)
        elif not (typ == 3 and not v6) and not (typ == 1 and v6) and not (typ == 2 and v6) and err_kind not in ("admin", "needfrag"):
            table = ICMP6 if v6 else ICMP4
            name = table.get(typ, icmp.get("name") or kind)
            add("info", f"{kind} 报文", summary or f"这是一条 {kind} 报文（{name}），从 {src} 到 {dst}。", ev)
        if ttl is not None:
            add("info", "生存时间", f"这是该报文网络层的生存时间（TTL / Hop Limit），当前值为 {ttl}，表示它在转发路径上还可以经过的跳数上限。")

    elif proto == "DNS" or app.get("dns"):
        dns = app.get("dns") or {}
        qn = dns.get("qname") or "（域名未解出）"
        qt = dns.get("qtype") or "记录"
        ev = ev_end + f"；{qt} {qn}"
        if dns.get("response"):
            answers = "；".join(dns.get("answers") or [])
            rcode = dns.get("rcode") or ""
            detail = f"这是一条 DNS 应答，从 {src} 到 {dst}，回答 {qt} {qn}"
            if answers:
                detail += f"：{answers}"
            detail += "。"
            add("info", "DNS 应答", detail, ev)
            if rcode and rcode.lower() not in ("no error", "0", "noerror"):
                low = rcode.lower()
                if "nxdomain" in low:
                    add("warn", "域名不存在", f"这条 DNS 应答的响应码为 {rcode}，表示查询的名称 {qn} 在该服务器看来不存在（NXDOMAIN）。", rcode)
                elif "server failure" in low or "servfail" in low or low.strip() in ("2", "failure"):
                    add("warn", "DNS 服务器失败", f"这条 DNS 应答的响应码为 {rcode}（SERVFAIL），表示服务器在解析 {qt} {qn} 时失败，常见于上游故障、配置错误或被干扰，并不能说明域名一定不存在。", rcode)
                elif "refus" in low:
                    add("warn", "DNS 查询被拒绝", f"这条 DNS 应答的响应码为 {rcode}，表示服务器拒绝回答对 {qt} {qn} 的查询。", rcode)
                else:
                    add("warn", "DNS 响应码", f"这条 DNS 应答的响应码为 {rcode}，表示查询 {qt} {qn} 没有得到正常的成功结果，需要结合具体响应码判断域名是否不存在、是否被拒绝或服务器失败。", rcode)
            elif answers:
                add("info", "解析结果", f"应答中已解出的资源记录为：{answers}。这些记录是服务器对 {qt} {qn} 的回答，可供请求方继续访问对应主机。", ev)
            else:
                add("info", "应答记录", f"这是对 {qt} {qn} 的 DNS 应答，但其中未见已解出的资源记录，或记录类型尚未解析，因此不能断定具体解析结果。")
        else:
            add("info", "DNS 查询", f"这是一条 DNS 查询，从 {src} 发送到 {dst}，询问 {qt} 记录 {qn}，用于把域名解析成地址或其他资源记录。", ev)
            add("info", "查询内容", f"查询类型为 {qt}，查询名称为 {qn}。若该查询走 UDP，则没有 TCP 标志或序号；具体传输层请结合报文详情中的层次查看。")

    elif proto == "HTTP" or app.get("http"):
        http = app.get("http") or {}
        host = http.get("host") or ""
        method = http.get("method") or ""
        path = http.get("path") or ""
        status = http.get("status") or ""
        if method:
            detail = f"这是一条 HTTP 请求，从 {src} 到 {dst}：{method} {path or '/'}"
            if host:
                detail += f"（Host: {host}）"
            detail += "。"
            add("info", "HTTP 请求", detail, ev_end + f"；{method} {path or '/'}")
            if host:
                add("info", "目标主机", f"请求头中的 Host 为 {host}，表示客户端要访问的网站或虚拟主机名；实际 TCP 连接的目的地址是 {dst}。", f"Host: {host}")
        elif status:
            level = "info"
            try:
                code = int(str(status).split()[0])
                if code >= 400:
                    level = "warn"
            except (TypeError, ValueError):
                pass
            title = "HTTP 响应"
            extra = ""
            try:
                code = int(str(status).split()[0])
                if code >= 500:
                    title = "HTTP 服务器出错"
                    extra = "这是 5xx 状态，表示服务器在处理该请求时出错。"
                elif code >= 400:
                    title = "HTTP 客户端请求未被成功处理"
                    extra = "这是 4xx 状态，表示服务器认为该请求不能被成功处理。"
            except (TypeError, ValueError):
                pass
            add(level, title, f"这是一条 HTTP 响应，从 {src} 到 {dst}，状态 {status}。{extra}", ev_end + f"；{status}")
        else:
            add("info", "HTTP 报文", summary or f"这是一条 HTTP 报文，从 {src} 到 {dst}。", ev_end)
        if is_tcp and flag_names:
            add("info", "TCP 承载", f"这条 HTTP 报文承载在 TCP 上，从 {src} 发送到 {dst}，TCP 标志为 {'、'.join(flag_names)}，本包载荷 {plen} 字节" + (f"，{ev_seq}" if ev_seq else "") + "。", ev_flags)

    elif proto in ("TLS", "SSL") or app.get("tls"):
        tls = app.get("tls") or {}
        sni = tls.get("sni") or ""
        hs_name = tls.get("handshake") or ""
        rec = tls.get("record") or ""
        blob = (hs_name + " " + (view.get("info") or "")).lower()
        if sni or "client hello" in blob:
            detail = f"这是一条 TLS ClientHello，从 {src} 到 {dst}"
            if sni:
                detail += f"，SNI 为 {sni}"
            else:
                detail += "，未能解出 SNI"
            detail += "。本工具不解密 TLS 内容。"
            ev = ev_end + (("；SNI=" + sni) if sni else "；ClientHello")
            add("info", "TLS ClientHello", detail, ev)
            if sni:
                add("info", "访问主机名", f"客户端在 TLS 握手的 ClientHello 中声明要访问的主机名（SNI）是 {sni}。这只说明准备连接的目标名称，并不等于已经完成握手或已能看到加密后的应用内容。", f"SNI={sni}")
            add("info", "不解密内容", "本工具只能看到握手阶段的明文字段（例如 SNI、记录类型），不会解密随后的 TLS 应用数据，因此不能从本包还原出网页或接口的具体内容。")
        elif "server hello" in blob:
            add("info", "TLS ServerHello", f"这是一条 TLS ServerHello，从 {src} 发送到 {dst}，是服务端对 ClientHello 的回应。本工具不解密 TLS 内容，只能看到握手明文中的有限字段。", ev_end)
            if tls.get("version"):
                add("info", "TLS 版本字段", f"记录层或遗留版本字段显示为 {tls.get('version')}。该字段有时只是兼容用的遗留值，不一定等于最终协商出的 TLS 版本。")
        elif "application data" in ((rec or "") + (view.get("info") or "")).lower() and not tls.get("alert"):
            add("info", "TLS 应用数据", f"这是一条 TLS 应用数据，从 {src} 到 {dst}。内容已加密，本工具不解密。", ev_end)
        elif tls.get("alert") or "alert" in ((rec or "") + " " + (view.get("info") or "")).lower():
            level_s = tls.get("alert_level") or ""
            desc_s = tls.get("alert_desc") or ""
            extra = ""
            if level_s or desc_s:
                extra = f"告警为 {((level_s + '：') if level_s else '')}{desc_s or '（描述未解出）'}。"
            add(
                "warn",
                "TLS Alert",
                f"这是一条 TLS Alert，从 {src} 到 {dst}。{extra}"
                "Alert 表示本方向发出了告警，可能中止握手或关闭连接。本工具不解密 TLS 内容，只能看到记录层和已解出的告警字段。",
                ev_end + (("；" + extra) if extra else "；Alert"),
            )
        else:
            extra = hs_name or rec or view.get("info") or "握手或记录未完全解出"
            add("info", "TLS 报文", f"这是一条 TLS 报文，从 {src} 到 {dst}（{extra}）。本工具不解密 TLS 内容。", ev_end)

    elif is_tcp or proto == "TCP":
        role = _this_packet_role(view, hs, peers)
        ev = "；".join(x for x in (ev_end, ev_flags, ev_seq) if x)
        base = f"这是一条 TCP 报文，从 {src} 发送到 {dst}"
        flag_s = ("，标志为 " + "、".join(flag_names)) if flag_names else ""
        seq_s = ("，" + ev_seq) if ev_seq else ""
        if _has(flags, "RST"):
            add("warn", "RST 中止连接", f"{base}{flag_s}{seq_s}。{role}RST 会立刻中止这条连接，对端通常不再继续发送数据。", ev)
        elif _has(flags, "SYN") and not _has(flags, "ACK"):
            add("info", "三次握手第 1 拍", f"{base}{flag_s}{seq_s}。{role}这是客户端（或发起方）在请求建立 TCP 连接，此时还没有进入数据传输阶段。", ev)
        elif _has(flags, "SYN") and _has(flags, "ACK"):
            add("info", "三次握手第 2 拍", f"{base}{flag_s}{seq_s}。{role}对端已经同意建立连接，并回带了对发起方 SYN 的确认，等待第三拍 ACK 后即可传输数据。", ev)
        elif _has(flags, "FIN"):
            add("info", "连接正在关闭", f"{base}{flag_s}{seq_s}，本包载荷 {plen} 字节。{role}FIN 表示这一方向准备结束发送；连接要等另一方向也关闭（或被 RST）后才完全终止。", ev)
        elif (
            _has(flags, "ACK")
            and not _has(flags, "SYN")
            and plen == 0
            and not _has(flags, "PSH")
            and not _has(flags, "FIN")
            and not _has(flags, "RST")
        ):
            if hs.get("syn") and hs.get("synack") and hs.get("ack_no") == view.get("no"):
                add("info", "三次握手第 3 拍", f"{base}{flag_s}{seq_s}。{role}三次握手至此完成，随后这条连接就可以传输应用数据。", ev)
            else:
                add("info", "纯 ACK", f"{base}{flag_s}{seq_s}。{role}本包没有应用载荷，主要用于确认对端已经收到的数据或控制报文，并通告当前接收窗口。", ev)
        elif plen > 0:
            detail = f"{base}，携带 {plen} 字节有效载荷{flag_s}{seq_s}。"
            if _has(flags, "PSH"):
                detail += "置位了 PSH，表示希望把这些数据尽快交给对端应用层，而不是继续在缓冲里等待。"
            else:
                detail += "这些字节是该方向上的应用数据或上层协议数据。"
            if port_txt:
                detail += port_txt
            add("info", "携带有效载荷", detail, ev)
        else:
            add("info", "TCP 报文", f"{base}{flag_s}{seq_s}。{role or (summary or '')}".strip(), ev)
        if ev_flags:
            add("info", "TCP 标志", f"这条报文的 TCP 标志为 {'、'.join(flag_names)}" + (f"，{ev_seq}" if ev_seq else "") + "。这些标志用来表示连接控制（如 SYN、ACK、FIN、RST）或数据推送（PSH），需要结合上面的本包结论一起看。", ev_seq or ev_flags)
        if window is not None:
            add("info", "通告窗口", f"这条报文通告的 TCP 接收窗口为 {window} 字节，用来告诉对端自己当前还能接收多少数据。" + ("窗口为 0 时，对端通常应暂停发送新数据，直到窗口再次打开。" if window == 0 else ""))
        if port_txt and plen == 0:
            add("info", "端口含义", port_txt, ev_end)
        if peers and hs:
            if hs.get("complete"):
                add("info", "流状态", f"在同一条 TCP 流（{src} 与对端 {dst} 之间）里，已经能看到完整的三次握手，或抓包窗口内已经出现数据传输。")
            elif (outcome or {}).get("kind") == "rst" and hs.get("syn") and not hs.get("synack"):
                add("warn", "流状态", f"同一条 TCP 流在发出 SYN 后收到了 RST，连接在握手阶段被拒绝。这通常表示目的端口未在监听，或路径上的设备以复位方式拒绝，与完全没有应答的静默丢弃不同。")
            elif (outcome or {}).get("kind") == "silent":
                add("warn", "流状态", f"同一条 TCP 流目前只见到 SYN，没有看到对端的 SYN-ACK，也没有看到 RST。"
                    + ("已经出现 SYN 重传，" if (outcome or {}).get("retrans") else "")
                    + "更像对端未应答或中间设备静默丢弃；还需要结合目的端口和 ICMP 差错进一步判断。")
            elif (outcome or {}).get("kind") == "short_window" or (hs.get("syn") and not hs.get("synack")):
                add("info", "流状态", f"同一条 TCP 流目前只见到 SYN，还没有看到对端的 SYN-ACK。抓包窗口还较短，尚未见到应答，还不能确认是被拦截、对端未响应，还是应答尚未到达或未被抓到。需要更长的抓包才能确认。")
            elif hs.get("syn") and hs.get("synack") and not hs.get("ack"):
                add("info", "流状态", f"同一条 TCP 流已有 SYN 与 SYN-ACK，但尚未看到发起方的第三拍 ACK，握手可能仍未完成，或第三拍没有出现在当前抓包范围里。")

    elif proto == "VXLAN" or view.get("vni") is not None:
        detail = (
            f"这是一条 VXLAN 报文，外层从 {src} 发送到 {dst}，载荷 {plen} 字节。"
            "外层是 VTEP 之间的 UDP 封装，内层才是租户的以太网和 IP 通信；不要把外层 IPv4 地址当成最终通信双方。"
        )
        if ttl is not None:
            detail += f" 外层 IP TTL / Hop Limit 为 {ttl}。"
        add("info", "VXLAN 外层封装", detail, ev_end)

    elif proto == "GRE" or (view.get("tunnel") or "").strip():
        tname = (view.get("tunnel") or proto or "隧道").strip()
        detail = (
            f"这是一条 {tname} 隧道报文，外层从 {src} 发送到 {dst}，载荷 {plen} 字节。"
            "内层地址和协议见下面的隧道结论。"
        )
        if ttl is not None:
            detail += f" 外层 IP TTL / Hop Limit 为 {ttl}。"
        add("info", f"{tname} 隧道", detail, ev_end)

    elif proto == "UDP":
        sport, dport = _as_port(view.get("sport")), _as_port(view.get("dport"))
        detail = (
            f"这是一条 UDP 报文，从 {src} 发送到 {dst}，载荷 {plen} 字节。"
            "UDP 是无连接传输，没有握手过程，也没有 TCP 那样的标志位或确认号，因此不能用 TCP 的标志或序号规则来分析这条报文。"
        )
        if ttl is not None:
            detail += f" IP TTL / Hop Limit 为 {ttl}。"
        add("info", "UDP 报文", detail, ev_end)
        if port_txt:
            title = "VXLAN 端口" if "VXLAN" in port_txt else "端口含义"
            add("info", title, port_txt, ev_end)
        known_app = {53, 5353, 67, 68, 123, 161, 162, 443, 853, 4789, 8472, 6081}
        if view.get("vni") is not None or (view.get("protocol") or "").upper() == "VXLAN":
            pass  # VXLAN 内层与 VNI 由后面的隧道结论给出
        elif sport not in known_app and dport not in known_app:
            add(
                "info",
                "上层未解析",
                f"已识别到 {layers_s}。目的端口 {dport if dport is not None else '未知'} 不是本工具当前会继续向上解析的常见应用协议端口，因此不再假装已经分析出应用层内容。",
                ev_end,
            )
        else:
            add(
                "info",
                "已识别到的层次",
                f"已识别到 {layers_s}。该端口对应的应用协议若未被单独解出，请结合报文详情中的字段查看；未解出的部分不会编造结论。",
                ev_end,
            )

    else:
        if recognized:
            add(
                "info",
                "已识别到的层次",
                f"这是一条 {proto} 报文，从 {src} 到 {dst}。已识别到 {' / '.join(recognized)}。其余部分未能解析，不编造结论。",
                ev_end,
            )
        else:
            add(
                "info",
                "未能完全解析",
                summary or f"这是一条 {proto} 报文，从 {src} 到 {dst}，未能解析出更高层协议。",
                ev_end,
            )

    for level, title, detail, evx in _tunnel_packet_items(view, ev_end):
        add(level, title, detail, evx)
    inner_v = _as_inner_tcp_view(view)
    if inner_v:
        i_src = _endpoint(inner_v, "src")
        i_dst = _endpoint(inner_v, "dst")
        i_flags = _flag_names(int(inner_v.get("tcp_flags") or 0))
        inner_out = outcome if (outcome and not _packet_is_tcp(view)) else _flow_outcome(
            inner_stream or [inner_v], capture_end_ts=capture_end_ts
        )
        detail = f"内层是 TCP，由 {i_src} 发往 {i_dst}"
        if i_flags:
            detail += f"，本包内层置位了 {'、'.join(i_flags)}"
        detail += "。"
        ik = inner_out.get("kind")
        if ik == "ok":
            detail += "同一条内层流已经能看到对端应答或数据，内层连接并非只停在发起请求上。"
        elif ik == "rst":
            detail += "同一条内层流在发起后收到了 RST，更像内层目的端口未监听或被拒绝，而不是外层隧道本身中断。"
        elif ik == "silent":
            detail += "同一条内层流只见到 SYN，没有看到对端应答或 RST，更像内层请求被静默丢弃或对端未响应。"
        elif ik == "short_window":
            detail += "同一条内层流目前只见到 SYN，抓包窗口还较短，尚未见到内层应答，还不能对内层连接是否失败下结论。"
        add("info", "内层 TCP", detail, ev_end)
    for level, title, detail, evx in _port_block_texts(view, hs, outcome=outcome):
        add(level, title, detail, evx)

    # 把告警类 hints 升为结论（避免与已有标题或正文重复）
    existing_titles = {c["title"] for c in out}
    existing_details = {c["detail"] for c in out}
    for h in hints:
        item = _hint_conclusion(h)
        if not item:
            continue
        # 纯 ACK / FIN 无载荷已在主结论中说明时不再重复
        if item["title"] in ("纯 ACK", "FIN 无载荷") and item["title"] in existing_titles:
            continue
        # 非 TCP 报文不得套用 TCP 标志结论
        if item["title"] == "标志组合异常" and not is_tcp:
            continue
        if item["detail"] in existing_details:
            continue
        if any(item["detail"] in (c["detail"] or "") or (c["detail"] or "") in item["detail"] for c in out):
            continue
        key = (item["title"], item["detail"])
        if key in seen:
            continue
        seen.add(key)
        out.append(item)

    if not out:
        if recognized:
            add(
                "info",
                "已识别到的层次",
                f"已识别到 {' / '.join(recognized)}。其余部分未能解析，不编造更高层结论。",
                (view.get("info") or ev_end),
            )
        else:
            add(
                "info",
                "未能完全解析",
                summary or f"这是第 {view.get('no') or '?'} 号报文（{proto}），从 {src} 到 {dst}。",
            )

    # 保留全部本包结论，由界面完整展示，不再截成短列表
    return out


def analyze_packet(view: dict, *, raw: Any = None, stream: list[dict] | None = None,
                   inner_stream: list[dict] | None = None, capture_end_ts=None,
                   capture_views: list[dict] | None = None) -> dict:
    """为单条报文生成中文说明。返回 summary / points / hints / conclusions，保证 summary 与 conclusions 非空。"""
    view = view or {}
    raw_b = _decode_raw(raw)
    app = _extract_app(view)
    proto = (view.get("protocol") or "DATA").upper()
    points: list[str] = []
    hints: list[dict] = []
    layers = view.get("layers") or []
    recognized = [n.get("name") for n in layers if n.get("name")]
    last_layer = recognized[-1] if recognized else ""

    ttl = view.get("ttl")
    if ttl is None:
        ttl_s = _child_val(_find_layer(layers, "internet protocol version"), "time to live", "hop limit")
        if ttl_s and re.match(r"\d+", ttl_s):
            ttl = int(ttl_s.split()[0])
    window = view.get("tcp_window")
    if window is None:
        win_s = _child_val(_find_layer(layers, "transmission control protocol"), "window")
        if win_s and re.match(r"\d+", str(win_s)):
            window = int(str(win_s).split()[0])

    peers = _stream_peers(view, stream)
    hs = _handshake_state(peers or [view])
    if capture_end_ts is None:
        times = [p.get("ts") for p in (stream or peers or [view]) if p.get("ts") is not None]
        if capture_views:
            times.extend(v.get("ts") for v in capture_views if v.get("ts") is not None)
        if times:
            capture_end_ts = max(times)
    icmp_events = _collect_icmp_events(capture_views) if capture_views else []
    outcome = _outcome_for_view(
        view, peers=peers or [view], inner_stream=inner_stream,
        capture_end_ts=capture_end_ts, icmp_events=icmp_events,
    )
    # 若本包是普通 TCP，以内层以外的握手为准
    if _packet_is_tcp(view) and not _as_inner_tcp_view(view):
        outcome = _flow_outcome(peers or [view], capture_end_ts=capture_end_ts, icmp_events=icmp_events)
    flags = int(view.get("tcp_flags") or 0)
    flag_names = _flag_names(flags)
    plen = int(view.get("payload_len") or 0)
    is_tcp = _packet_is_tcp(view)

    summary = ""
    if proto == "ARP" or app.get("arp"):
        arp = app.get("arp") or {}
        op = (arp.get("op") or view.get("info") or "")
        if "who has" in op.lower() or "request" in op.lower() or "请求" in op:
            summary = (
                f"这是一条 ARP 请求：{_endpoint_phrase(view)}。"
                f"{arp.get('spa') or view.get('src') or ''} 询问 {arp.get('tpa') or view.get('dst') or ''} 的 MAC 地址。"
            )
            points.append("ARP 请求通常以广播发送，用于在局域网解析 IPv4 地址对应的硬件地址。")
        elif "is at" in op.lower() or "reply" in op.lower() or "应答" in op or "响应" in op:
            summary = (
                f"这是一条 ARP 应答：{arp.get('spa') or view.get('src')} "
                f"宣称其 MAC 为 {arp.get('sha') or '（见字段）'}，回答对 {arp.get('tpa') or view.get('dst')} 的查询。"
            )
            points.append("ARP 应答把 IP 与 MAC 的对应关系告诉请求方。")
        else:
            summary = f"这是一条 ARP 报文，从 {view.get('src')} 到 {view.get('dst')}。{view.get('info') or ''}".strip()
            points.append(f"操作：{op or '未能进一步识别 ARP 操作码'}。")

    elif proto in ("ICMP", "ICMPV6") or app.get("icmp"):
        icmp = app.get("icmp") or {}
        typ = icmp.get("type")
        code = icmp.get("code")
        v6 = proto == "ICMPv6" or icmp.get("v6")
        table = ICMP6 if v6 else ICMP4
        name = table.get(typ, icmp.get("name") or "ICMP")
        if typ == 3 and not v6:
            extra = ICMP4_UNREACH.get(code, f"代码 {code}")
            summary = f"这是一条 ICMP 目的不可达报文，从 {_endpoint(view,'src')} 到 {_endpoint(view,'dst')}，含义是{extra}。"
            points.append(f"类型 3（Destination Unreachable），代码 {code}：{extra}。")
        elif typ == 1 and v6:
            summary = f"这是一条 ICMPv6 目的不可达报文，从 {_endpoint(view,'src')} 到 {_endpoint(view,'dst')}。"
            points.append(f"ICMPv6 类型 1，代码 {code}。")
        elif typ in (8, 128):
            summary = f"这是一条 {'ICMPv6' if v6 else 'ICMP'} 回显请求（ping），从 {_endpoint(view,'src')} 到 {_endpoint(view,'dst')}。"
            points.append("用于探测对端是否可达。")
        elif typ in (0, 129):
            summary = f"这是一条 {'ICMPv6' if v6 else 'ICMP'} 回显应答，从 {_endpoint(view,'src')} 到 {_endpoint(view,'dst')}。"
            points.append("这是对先前 ping 请求的回复。")
        else:
            summary = f"这是一条 {'ICMPv6' if v6 else 'ICMP'} 报文（{name}），从 {_endpoint(view,'src')} 到 {_endpoint(view,'dst')}。"
            points.append(f"类型 {typ}，代码 {code}。")
        if ttl is not None:
            points.append(f"TTL / Hop Limit 为 {ttl}。")

    elif proto == "DNS" or app.get("dns"):
        dns = app.get("dns") or {}
        qn = dns.get("qname") or "（域名未解出）"
        qt = dns.get("qtype") or "记录"
        if dns.get("response"):
            answers = "；".join(dns.get("answers") or [])
            rcode = dns.get("rcode") or ""
            summary = f"这是一条 DNS 应答，从 {_endpoint(view,'src')} 到 {_endpoint(view,'dst')}，回答 {qt} {qn}"
            if answers:
                summary += f"：{answers}"
            summary += "。"
            if rcode and rcode.lower() not in ("no error", "0", "noerror"):
                points.append(f"响应码为 {rcode}。")
                if "nxdomain" in rcode.lower():
                    hints.append({"level": "warn", "text": f"域名 {qn} 返回 NXDOMAIN（不存在）。"})
                elif "refused" in rcode.lower() or "fail" in rcode.lower():
                    hints.append({"level": "warn", "text": f"DNS 应答异常：{rcode}。"})
            elif answers:
                points.append(f"应答记录：{answers}。")
            else:
                points.append("应答中未见已解出的资源记录，或记录类型未解析。")
        else:
            summary = f"这是一条 DNS 查询，从 {_endpoint(view,'src')} 到 {_endpoint(view,'dst')}，询问 {qt} {qn}。"
            points.append(f"查询类型 {qt}，名称 {qn}。")

    elif proto == "HTTP" or app.get("http"):
        http = app.get("http") or {}
        host = http.get("host") or ""
        method = http.get("method") or ""
        path = http.get("path") or ""
        status = http.get("status") or ""
        if method:
            summary = f"这是一条 HTTP 请求，从 {_endpoint(view,'src')} 到 {_endpoint(view,'dst')}：{method} {path or '/'}"
            if host:
                summary += f"（Host: {host}）"
            summary += "。"
            points.append(f"方法 {method}，路径 {path or '/'}。")
            if host:
                points.append(f"目标主机 {host}。")
        elif status:
            summary = f"这是一条 HTTP 响应，从 {_endpoint(view,'src')} 到 {_endpoint(view,'dst')}，状态 {status}。"
            points.append(f"状态行：{status}。")
            try:
                code = int(str(status).split()[0])
                if code >= 500:
                    hints.append({"level": "warn", "text": f"HTTP {code} 表示服务器出错。"})
                elif code >= 400:
                    hints.append({"level": "warn", "text": f"HTTP {code} 表示客户端请求未被成功处理。"})
            except (TypeError, ValueError):
                pass
        else:
            summary = f"这是一条 HTTP 报文，从 {_endpoint(view,'src')} 到 {_endpoint(view,'dst')}。{view.get('info') or ''}".strip()
        if is_tcp and flag_names:
            points.append("承载在 TCP 上，标志为 " + "、".join(flag_names) + f"，载荷 {plen} 字节。")

    elif proto in ("TLS", "SSL") or app.get("tls"):
        tls = app.get("tls") or {}
        sni = tls.get("sni") or ""
        hs = tls.get("handshake") or ""
        rec = tls.get("record") or ""
        if sni or (hs and "client hello" in (hs.lower() + " " + (view.get("info") or "").lower())):
            summary = f"这是一条 TLS ClientHello，从 {_endpoint(view,'src')} 到 {_endpoint(view,'dst')}"
            if sni:
                summary += f"，SNI 为 {sni}"
            else:
                summary += "，未能解出 SNI"
            summary += "。本工具不解密 TLS 内容。"
            if sni:
                points.append(f"客户端在握手中声明要访问的主机名（SNI）是 {sni}。")
            points.append("只能看到握手明文字段；加密后的应用数据不会被解密。")
        elif "server hello" in (hs.lower() + " " + (view.get("info") or "").lower()):
            summary = f"这是一条 TLS ServerHello，从 {_endpoint(view,'src')} 到 {_endpoint(view,'dst')}。本工具不解密 TLS 内容。"
            if tls.get("version"):
                points.append(f"记录或遗留版本字段为 {tls.get('version')}。")
        elif "application data" in ((rec or "") + (view.get("info") or "")).lower():
            summary = f"这是一条 TLS 应用数据，从 {_endpoint(view,'src')} 到 {_endpoint(view,'dst')}。内容已加密，本工具不解密。"
            points.append("已识别到 TLS 记录层，载荷为加密的 Application Data。")
        else:
            extra = hs or rec or view.get("info") or "握手或记录未完全解出"
            summary = f"这是一条 TLS 报文，从 {_endpoint(view,'src')} 到 {_endpoint(view,'dst')}（{extra}）。本工具不解密 TLS 内容。"
            points.append("已识别到 TLS，其余字段若未列出即未能解析。")

    elif is_tcp or proto == "TCP":
        summary = f"这是一条 {_endpoint_phrase(view)}。"
        role = _this_packet_role(view, hs, peers)
        summary = summary[:-1] + "，" + role
        if flag_names:
            points.append("TCP 标志：" + "、".join(flag_names) + "。")
        if view.get("tcp_seq") is not None:
            line = f"序列号 Seq={view.get('tcp_seq')}"
            if _has(flags, "ACK"):
                line += f"，确认号 Ack={view.get('tcp_ack')}"
            points.append(line + "。")
        if window is not None:
            points.append(f"通告窗口为 {window}。")
            if window == 0 and _has(flags, "ACK") and not _has(flags, "RST"):
                hints.append({"level": "warn", "text": "零窗口：对端暂时通告接收窗口为 0，可能无法继续接收数据。"})
        if ttl is not None:
            points.append(f"IP TTL / Hop Limit 为 {ttl}。")
        points.append(f"本包载荷 {plen} 字节。")
        if plen == 0 and _has(flags, "ACK") and not _has(flags, "SYN") and not _has(flags, "FIN") and not _has(flags, "RST") and not _has(flags, "PSH"):
            hints.append({"level": "note", "text": "纯 ACK，没有载荷。"})
        if plen == 0 and _has(flags, "FIN"):
            hints.append({"level": "note", "text": "这是载荷为 0 的 FIN，只表示关闭方向，不再携带应用数据。"})
        odd = []
        if _has(flags, "SYN") and _has(flags, "FIN"):
            odd.append("同时置位 SYN 与 FIN")
        if _has(flags, "SYN") and _has(flags, "RST"):
            odd.append("同时置位 SYN 与 RST")
        if _has(flags, "FIN") and _has(flags, "RST"):
            odd.append("同时置位 FIN 与 RST")
        if not flag_names:
            odd.append("未置位任何常见标志")
        if odd:
            hints.append({"level": "warn", "text": "标志组合异常：" + "；".join(odd) + "。"})
        hints.extend(_detect_retrans_or_ooo(view, peers))
        if peers and hs:
            if hs.get("complete"):
                points.append("同一条流里已能看到完整或已在传输数据的握手过程。")
            elif hs.get("syn") and not hs.get("synack"):
                points.append("同一条流目前只见到 SYN，还没有看到 SYN-ACK。")
            elif hs.get("syn") and hs.get("synack") and not hs.get("ack"):
                points.append("同一条流已有 SYN 与 SYN-ACK，尚未看到第三拍 ACK。")

    elif proto == "VXLAN" or view.get("vni") is not None:
        vni = view.get("vni")
        inner = (view.get("inner_info") or "").strip()
        inner_addr = ""
        if view.get("inner_src") and view.get("inner_dst"):
            inner_addr = f"{view.get('inner_src')} → {view.get('inner_dst')}"
        bits = [f"这是一条 VXLAN 报文，外层从 {_endpoint(view,'src')} 到 {_endpoint(view,'dst')}"]
        if vni is not None:
            bits.append(f"VNI {vni}")
        if inner_addr:
            bits.append("内层 " + inner_addr)
        if inner and inner not in inner_addr:
            bits.append(inner)
        summary = "，".join(bits) + "。"
    elif proto == "GRE" or (view.get("tunnel") or "").strip():
        tname = (view.get("tunnel") or proto or "隧道").strip()
        inner_addr = ""
        if view.get("inner_src") and view.get("inner_dst"):
            inner_addr = f"{view.get('inner_src')} → {view.get('inner_dst')}"
        summary = f"这是一条 {tname} 隧道报文，外层从 {_endpoint(view,'src')} 到 {_endpoint(view,'dst')}"
        if inner_addr:
            summary += f"，内层 {inner_addr}"
        summary += "。"
    elif proto == "UDP":
        summary = f"这是一条 UDP 报文，从 {_endpoint(view,'src')} 到 {_endpoint(view,'dst')}，载荷 {plen} 字节。"
        points.append("已识别到 UDP。若端口不是常见协议，载荷未再往上解析。")
        sport, dport = view.get("sport"), view.get("dport")
        if sport not in (53, 5353) and dport not in (53, 5353, 67, 68, 123, 161, 162, 443, 853):
            points.append("其余上层协议未能解析，不假装已分析出应用内容。")
        if ttl is not None:
            points.append(f"IP TTL / Hop Limit 为 {ttl}。")

    else:
        if last_layer:
            summary = f"这是一条 { _endpoint_phrase(view) }。已识别到 { ' / '.join(recognized) }。"
        else:
            summary = f"这是一条 { _endpoint_phrase(view) }，未能解析出更高层协议。"
        points.append("已识别到的层次：" + ("、".join(recognized) if recognized else "无") + "。")
        if view.get("info"):
            points.append("摘要：" + str(view.get("info"))[:240])
        points.append("其余部分未能解析，不编造结论。")

    # 截断
    caplen = int(view.get("caplen") or 0)
    wire = int(view.get("length") or 0)
    if caplen and wire and caplen < wire:
        hints.append({"level": "warn", "text": f"报文被截断：捕获 {caplen} 字节，线上长度为 {wire} 字节，部分字段可能不完整。"})
        points.append("捕获长度小于线上长度，分析仅依据已捕获字节。")

    hints.extend(_checksum_hints(view, raw_b))

    # 去重 hints
    seen = set()
    uniq = []
    for h in hints:
        t = h.get("text") or ""
        if t in seen:
            continue
        seen.add(t)
        uniq.append(h)
    hints = uniq

    if not summary:
        summary = f"这是第 {view.get('no') or '?'} 号报文（{proto}），从 {_endpoint(view,'src')} 到 {_endpoint(view,'dst')}。"
    summary = re.sub(r"\s+", " ", summary).strip()
    if not summary.endswith("。") and not summary.endswith("."):
        summary += "。"

    conclusions = _build_packet_conclusions(
        view,
        proto=proto,
        summary=summary,
        points=points,
        hints=hints,
        app=app,
        hs=hs,
        peers=peers,
        flag_names=flag_names,
        plen=plen,
        is_tcp=is_tcp,
        recognized=recognized,
        window=window,
        ttl=ttl,
        outcome=outcome,
        inner_stream=inner_stream,
        capture_end_ts=capture_end_ts,
    )
    return {
        "summary": summary,
        "points": [re.sub(r"\s+", " ", p).strip() for p in points if p],
        "hints": hints,
        "conclusions": conclusions,
        "protocol": proto,
    }


def _stream_label(view: dict) -> str:
    proto = view.get("l4") or view.get("protocol") or "TCP"
    a = _endpoint(view, "src")
    b = _endpoint(view, "dst")
    # 规范化顺序仅用于显示第一条
    return f"{proto} {a} ↔ {b}"



def _working_tcp_ports_to(tcp_streams, dest_ip: str) -> list[int]:
    """通往同一目的、握手已成功的 TCP 端口，用来和被拦截端口对照。"""
    ports: list[int] = []
    dest_ip = dest_ip or ""
    for _key, pkts in tcp_streams:
        hs = _handshake_state(pkts)
        if not (hs.get("complete") or hs.get("synack") or hs.get("data")):
            continue
        for p in pkts:
            if not _packet_is_tcp(p):
                continue
            flags = int(p.get("tcp_flags") or 0)
            if _has(flags, "SYN") and not _has(flags, "ACK"):
                dip = p.get("ip_dst") or p.get("dst") or ""
                if dest_ip and dest_ip not in str(dip) and str(dip) not in dest_ip:
                    continue
                dport = _as_port(p.get("dport")) or _as_port(p.get("inner_dport"))
                if dport is not None and dport not in ports:
                    ports.append(dport)
    return ports


def _group_inner_tcp_streams(views: list[dict]) -> list:
    streams: dict[Any, list[dict]] = {}
    for v in views:
        inner = _as_inner_tcp_view(v)
        if not inner:
            continue
        key = inner.get("stream_key") or (
            "INNER-TCP", inner.get("ip_src"), inner.get("sport"), inner.get("ip_dst"), inner.get("dport")
        )
        streams.setdefault(key, []).append(inner)
    return list(streams.items())


def _diagnose_tunnels_and_port_blocks(views: list[dict], tcp_streams: list, conclusions: list[dict],
                                      *, capture_end_ts=None, icmp_events=None,
                                      inner_streams: list | None = None) -> set:
    """整次抓包：VXLAN/隧道概况，以及移动云风格的端口拦截识别。返回已被关联说明过的 ICMP 报文序号。"""
    explained_icmp: set = set()
    vxlan_pkts = [v for v in views if (v.get("protocol") or "").upper() == "VXLAN" or v.get("vni") is not None]
    if vxlan_pkts:
        vnis = sorted({v.get("vni") for v in vxlan_pkts if v.get("vni") is not None})
        inner_vers = sorted({v.get("inner_ip_version") for v in vxlan_pkts if v.get("inner_ip_version")})
        ev_parts = []
        for v in vxlan_pkts[:6]:
            bits = [f"第 {v.get('no')} 号"]
            if v.get("vni") is not None:
                bits.append(f"VNI {v.get('vni')}")
            if v.get("inner_src") and v.get("inner_dst"):
                bits.append(f"内层 {v.get('inner_src')} → {v.get('inner_dst')}")
            ev_parts.append(" ".join(bits))
        ver_txt = "、".join(f"IPv{x}" for x in inner_vers) if inner_vers else "内层以太网/IP"
        vni_txt = "、".join(str(x) for x in vnis) if vnis else "未能读出"
        conclusions.append({
            "level": "info",
            "title": "发现 VXLAN 隧道流量",
            "detail": (
                f"本次抓包中有 {len(vxlan_pkts)} 条 VXLAN 报文，见到的 VNI 有 {vni_txt}。"
                f"内层出现了 {ver_txt}。"
                "分析时请同时看外层 VTEP（underlay）和内层租户通信，不要只把外层 IPv4 当成最终通信双方。"
            ),
            "evidence": "；".join(ev_parts),
        })

    tunnel_pkts = [
        v for v in views
        if (v.get("tunnel") or "").strip() or (v.get("protocol") or "").upper() == "GRE"
    ]
    tunnel_pkts = [v for v in tunnel_pkts if (v.get("protocol") or "").upper() != "VXLAN" and v.get("vni") is None]
    if tunnel_pkts:
        kinds = sorted({(v.get("tunnel") or v.get("protocol") or "隧道").strip() for v in tunnel_pkts})
        ev_parts = []
        for v in tunnel_pkts[:6]:
            bits = [f"第 {v.get('no')} 号 {(v.get('tunnel') or v.get('protocol') or '').strip()}"]
            if v.get("inner_src") and v.get("inner_dst"):
                bits.append(f"{v.get('inner_src')} → {v.get('inner_dst')}")
            ev_parts.append(" ".join(bits))
        conclusions.append({
            "level": "info",
            "title": "发现 IP 隧道封装",
            "detail": (
                f"本次抓包中有 {len(tunnel_pkts)} 条隧道报文（{'、'.join(kinds)}）。"
                "内层地址应能在列表和结论中看到，而不是只显示外层 IPv4。"
            ),
            "evidence": "；".join(ev_parts),
        })

    inner_streams = list(inner_streams or [])
    if inner_streams:
        ev_in = []
        silent_n = short_n = rst_n = ok_n = 0
        for _key, pkts in inner_streams:
            outc = _flow_outcome(pkts, capture_end_ts=capture_end_ts, icmp_events=icmp_events)
            label = f"内层 TCP {outc.get('src') or pkts[0].get('ip_src')} → {outc.get('dst') or pkts[0].get('ip_dst')}:{outc.get('dport')}"
            k = outc.get("kind")
            if k == "ok":
                ok_n += 1
            elif k == "silent":
                silent_n += 1
                ev_in.append(label + " 只见到 SYN，未见内层应答")
            elif k == "rst":
                rst_n += 1
                ev_in.append(label + " 在握手阶段被 RST")
            elif k == "short_window":
                short_n += 1
                ev_in.append(label + " 窗口较短，尚未见到内层应答")
            elif k and k.startswith("icmp_"):
                ev_in.append(label + " " + _icmp_kind_phrase(k[5:]))
        if ev_in or silent_n or rst_n or short_n:
            detail = f"在 VXLAN 等隧道内层观察到 {len(inner_streams)} 条 TCP 流。"
            if ok_n:
                detail += f" 其中 {ok_n} 条内层已经有应答或数据。"
            if silent_n:
                detail += f" 有 {silent_n} 条内层只见到 SYN、没有应答，更像内层请求被丢弃或对端未响应。"
            if rst_n:
                detail += f" 有 {rst_n} 条内层在握手阶段被 RST。"
            if short_n:
                detail += f" 有 {short_n} 条内层因抓包窗口较短，还不能确认是否失败。"
            conclusions.append({
                "level": "warn" if (silent_n or rst_n) else "info",
                "title": "隧道内层 TCP",
                "detail": detail,
                "evidence": "；".join(ev_in[:8]),
            })

    intercept_hits: list[str] = []
    rst_hits: list[str] = []
    other_fail_hits: list[str] = []
    smtp_hits: list[str] = []
    carrier_hits: list[str] = []
    ecloud_ports: set[int] = set()
    ecloud_dests: set[str] = set()
    smtp_pending: list[str] = []

    def _record(outc: dict, proto: str, extra: str = "") -> None:
        nonlocal intercept_hits, rst_hits, other_fail_hits, smtp_hits, carrier_hits
        k = outc.get("kind") or ""
        dport = _as_port(outc.get("dport"))
        src, dst = outc.get("src") or "", outc.get("dst") or ""
        syns = outc.get("syns") or []
        nos = "、".join(str(p.get("no")) for p in syns[:6]) if syns else ""
        icmp = outc.get("icmp") or {}
        if icmp.get("no") is not None:
            explained_icmp.add(icmp["no"])
        why_map = {
            "rst": "在握手阶段被 RST 拒绝，更像端口未监听或被主动拒绝，而不是静默丢弃",
            "silent": "只见到 SYN"
                      + (" 且有重传" if outc.get("retrans") else "")
                      + "，没有 SYN-ACK 也没有 RST，更像中间设备或云平台静默丢弃",
            "icmp_admin": "收到 ICMP 管理策略禁止"
                          + (f"（第 {icmp.get('no')} 号，原始目的 {icmp.get('orig_dst')}:{icmp.get('orig_dport')}）" if icmp.get("no") is not None else ""),
            "icmp_host": "收到 ICMP 主机不可达，更像对端主机不可达，而不能直接写成端口拦截",
            "icmp_net": "收到 ICMP 网络不可达，更像路径或对端网络不可达",
            "icmp_port": "收到 ICMP 端口不可达，通常表示对端可达但该端口未监听",
            "short_window": "只见到 SYN，抓包窗口较短，尚未见到应答，还不能确认",
        }
        ev = f"{src} → {dst}:{dport}，{why_map.get(k, k)}"
        if nos:
            ev += f"，相关报文第 {nos} 号"
        ev += extra
        kind = _classify_blocked_port(dport, proto)
        if k == "short_window":
            if kind and kind[0] == "smtp25":
                smtp_pending.append(ev)
            return
        if not kind:
            return
        cat = kind[0]
        ev_role = ev + f"（{kind[1]}）"
        if cat == "ecloud":
            ecloud_ports.add(dport)
            ecloud_dests.add(str(dst))
            if k in ("silent", "icmp_admin"):
                intercept_hits.append(ev_role)
            elif k == "rst" or k == "icmp_port":
                rst_hits.append(ev_role)
            elif k in ("icmp_host", "icmp_net"):
                other_fail_hits.append(ev_role)
        elif cat == "smtp25":
            if k in ("silent", "icmp_admin"):
                smtp_hits.append(ev)
            elif k in ("rst", "icmp_port", "icmp_host", "icmp_net"):
                smtp_hits.append(ev)
        elif cat == "carrier" and k in ("silent", "icmp_admin"):
            carrier_hits.append(ev_role)

    for _key, pkts in list(tcp_streams) + list(inner_streams):
        extra = "（隧道内层）" if any(pkts is stream[1] for stream in inner_streams) else ""
        outc = _flow_outcome(pkts, capture_end_ts=capture_end_ts, icmp_events=icmp_events)
        if outc.get("syns"):
            _record(outc, "TCP", extra)

    # ICMP 管理禁止即使没有成对的 SYN，也按原始目的端口记录
    for evn in icmp_events or []:
        if evn.get("no") in explained_icmp:
            continue
        if evn.get("kind") != "admin":
            continue
        dport = _as_port(evn.get("orig_dport"))
        kind = _classify_blocked_port(dport, evn.get("orig_proto") or "TCP")
        ev = (
            f"第 {evn.get('no')} 号 ICMP 管理禁止，原始报文 "
            f"{evn.get('orig_src') or '?'} → {evn.get('orig_dst') or '?'}"
            + (f":{dport}" if dport is not None else "")
        )
        if kind and kind[0] in ("ecloud", "smtp25"):
            explained_icmp.add(evn.get("no"))
        if kind and kind[0] == "ecloud":
            intercept_hits.append(ev + f"（{kind[1]}）")
            ecloud_ports.add(dport)
            if evn.get("orig_dst"):
                ecloud_dests.add(str(evn.get("orig_dst")))
        elif kind and kind[0] == "smtp25":
            smtp_hits.append(ev)
        # 无名单端口的管理禁止留给后面的 ICMP 结论，但带上原目的

    # UDP 打到移动云拦截端口
    for v in views:
        proto = (v.get("protocol") or v.get("l4") or "").upper()
        if proto not in ("UDP",):
            continue
        dport = _as_port(v.get("dport"))
        kind = _classify_blocked_port(dport, "UDP")
        if not kind or kind[0] != "ecloud":
            continue
        src = v.get("ip_src") or v.get("src") or ""
        dst = v.get("ip_dst") or v.get("dst") or ""
        sport = _as_port(v.get("sport"))
        has_reply = False
        last_ts = v.get("ts")
        for o in views:
            if o is v:
                continue
            if (o.get("protocol") or o.get("l4") or "").upper() != "UDP":
                continue
            if (o.get("ip_src") or o.get("src")) == dst and (o.get("ip_dst") or o.get("dst")) == src:
                if _as_port(o.get("sport")) == dport and _as_port(o.get("dport")) == sport:
                    has_reply = True
                    break
        if has_reply:
            continue
        wait_s = 0.0
        if capture_end_ts is not None and v.get("ts") is not None:
            wait_s = max(0.0, float(capture_end_ts) - float(v.get("ts")))
        ev = f"第 {v.get('no')} 号 UDP {src} → {dst}:{dport}（{kind[1]}），未见对向回应"
        icmp_hit = _match_icmp_event(icmp_events, src, dst, dport, "UDP")
        if icmp_hit:
            ev += f"，并有第 {icmp_hit.get('no')} 号 ICMP {_icmp_kind_phrase(icmp_hit.get('kind'))}"
            explained_icmp.add(icmp_hit.get("no"))
            if icmp_hit.get("kind") == "admin":
                intercept_hits.append(ev)
            elif icmp_hit.get("kind") == "port":
                rst_hits.append(ev)
            else:
                other_fail_hits.append(ev)
            ecloud_ports.add(dport)
            ecloud_dests.add(str(dst))
        # UDP 本身不承诺回应；仅凭无回包（含广播）不能推断被封。

    all_streams = list(tcp_streams) + list(inner_streams)
    contrast = ""
    if ecloud_dests:
        worked = []
        for dest in sorted(ecloud_dests):
            ports = _working_tcp_ports_to(all_streams, dest)
            if ports:
                worked.append(f"到 {dest} 的端口 {', '.join(str(p) for p in ports)} 握手是成功的")
        if worked:
            contrast = "对照来看，" + "；".join(worked) + "，更说明问题集中在被拦截或被拒绝的高危端口，而不是整条路径不通。"

    if intercept_hits:
        port_s = "、".join(str(p) for p in sorted(ecloud_ports)) if ecloud_ports else "高危端口"
        extra_rst = ""
        if rst_hits:
            extra_rst = "另外还有访问这些端口时在握手阶段被 RST 或报端口不可达的情况，那一类更像端口未监听或被主动拒绝，与静默丢弃要分开看。"
        conclusions.append({
            "level": "warn",
            "title": "疑似移动云或同类云平台的高危端口拦截",
            "detail": (
                f"抓包中有访问 {port_s} 的通信失败：只见到请求（如 TCP SYN）没有正常回应，或收到 ICMP 管理禁止。"
                "135、137–139、445、4444 正是移动云文档写明会拦截的高危端口，即使安全组已经放通，访问也可能失败。"
                "本工具不能仅凭抓包证明一定运行在移动云上，但现象与移动云及国内云常见的平台拦截一致。"
                "建议改用其他端口，或向云商确认是否属于平台侧封禁。"
                + extra_rst + contrast
            ),
            "evidence": "；".join((intercept_hits + rst_hits + other_fail_hits)[:8]),
        })
    elif rst_hits:
        port_s = "、".join(str(p) for p in sorted(ecloud_ports)) if ecloud_ports else "高危端口"
        conclusions.append({
            "level": "warn",
            "title": "高危端口在握手阶段被 RST 或报端口不可达",
            "detail": (
                f"抓包中有访问 {port_s} 的连接在握手阶段被 RST，或收到 ICMP 端口不可达。"
                "这通常表示对端主机可达，但该端口未在监听，或防火墙以复位方式拒绝，与完全没有应答的静默丢弃不同。"
                "这些端口仍在移动云文档的高危拦截名单中，需要结合环境判断，但不能仅凭 RST 断定就是平台静默拦截。"
                + contrast
            ),
            "evidence": "；".join(rst_hits[:8]),
        })
    elif other_fail_hits:
        port_s = "、".join(str(p) for p in sorted(ecloud_ports)) if ecloud_ports else "高危端口"
        conclusions.append({
            "level": "warn",
            "title": "高危端口访问失败，但更像主机或网络不可达",
            "detail": (
                f"抓包中有访问 {port_s} 的通信收到了 ICMP 主机或网络不可达。"
                "这些端口虽在移动云高危名单中，当前证据更支持对端或路径不可达，而不能直接写成端口被云平台拦截。"
            ),
            "evidence": "；".join(other_fail_hits[:8]),
        })

    if smtp_hits:
        smtp_policy = any("没有 SYN-ACK" in h or "管理" in h for h in smtp_hits)
        conclusions.append({
            "level": "warn",
            "title": "疑似国内云出站封禁 TCP 25" if smtp_policy else "TCP 25 访问被拒绝或目的不可达",
            "detail": (
                "抓包中有发往 TCP 25（SMTP）的连接未能完成握手。"
                "国内主流云（含移动云）通常默认拦截云主机出站 25 端口，需要向云商申请解封，或改用 465 / 587 提交邮件。"
                "若失败表现是完全没有应答或 ICMP 管理禁止，与出站封禁更相符；若是 RST 或端口不可达，则更像对端未监听。"
            ),
            "evidence": "；".join(smtp_hits[:8]),
        })
    if carrier_hits:
        conclusions.append({
            "level": "warn",
            "title": "高危端口访问失败，可能被运营商或云平台拦截",
            "detail": (
                "抓包中有通往常见高危端口的连接握手失败，并且没有看到对端的正常应答，更像中间设备静默丢弃或策略拦截。"
                "部分运营商和云平台会拦截或限速这类端口；请同时检查对端服务是否在听、安全组和主机防火墙。"
            ),
            "evidence": "；".join(carrier_hits[:8]),
        })

    admin_left = [e for e in (icmp_events or []) if e.get("kind") == "admin" and e.get("no") not in explained_icmp]
    if intercept_hits or admin_left:
        # 已关联的管理禁止并入上面的拦截结论；若还有未关联的，或需要一条总述
        admin_hits = []
        for e in (icmp_events or []):
            if e.get("kind") != "admin":
                continue
            ev = f"第 {e.get('no')} 号 管理禁止（类型 {e.get('type')} 代码 {e.get('code')}）"
            if e.get("orig_dst") or e.get("orig_dport") is not None:
                ev += f"，原始目的 {e.get('orig_dst') or '?'}"
                if e.get("orig_dport") is not None:
                    ev += f":{e.get('orig_dport')}"
            admin_hits.append(ev)
        if admin_hits and admin_left:
            conclusions.append({
                "level": "warn",
                "title": "ICMP 显示通信被管理策略禁止",
                "detail": (
                    "抓包中出现了 ICMP 管理禁止（IPv4 目的不可达代码 9/10/13，或 ICMPv6 目的不可达代码 1）。"
                    "这通常表示安全组、防火墙、运营商或云平台主动拒绝，而不是对端主机不存在。"
                    "若被禁的原报文目的端口属于 135、137–139、445、4444，则与移动云高危端口拦截高度吻合。"
                ),
                "evidence": "；".join(admin_hits[:8]),
            })
        elif admin_hits and intercept_hits:
            # 已经在拦截结论里关联过，不再单独重复一条无关结论
            pass

    return explained_icmp


def diagnose_capture(views: list[dict], *, filtered: bool = False) -> dict:
    """针对一次抓包（或当前可见集合）给出若干带依据的离线结论。"""
    conclusions: list[dict] = []
    if not views:
        return {
            "overview": "当前没有可分析的报文。",
            "conclusions": [{
                "level": "info",
                "title": "暂无报文",
                "detail": "打开 pcap 或开始抓包后，将在这里给出握手、重置、协议与会话等方面的结论。",
                "evidence": "",
            }],
            "count": 0,
            "filtered": filtered,
        }

    views = list(views)
    total = len(views)
    proto_counts: dict[str, int] = {}
    bytes_total = 0
    for v in views:
        p = (v.get("protocol") or "DATA")
        proto_counts[p] = proto_counts.get(p, 0) + 1
        bytes_total += int(v.get("length") or 0)
    proto_s = "、".join(f"{k} {n} 个" for k, n in sorted(proto_counts.items(), key=lambda x: (-x[1], x[0])))
    scope = "当前显示过滤后的集合" if filtered else "本次打开或抓到的报文"
    conclusions.append({
        "level": "info",
        "title": "流量概况",
        "detail": f"{scope}共 {total} 个报文、约 {bytes_total} 字节。按协议：{proto_s}。",
        "evidence": f"统计 {total} 个报文",
    })

    # 会话分组
    streams: dict[Any, list[dict]] = {}
    orphan = []
    for v in views:
        key = v.get("stream_key")
        if key:
            streams.setdefault(key, []).append(v)
        else:
            orphan.append(v)

    tcp_streams = []
    for key, pkts in streams.items():
        proto = (key[0] if isinstance(key, (list, tuple)) and key else "") or (
            pkts[0].get("l4") or pkts[0].get("protocol") or ""
        )
        if str(proto).upper() in ("TCP", "HTTP", "TLS", "SSL") or any(
            _packet_is_tcp(p) for p in pkts
        ):
            tcp_streams.append((key, pkts))

    ts_all = [float(v.get("ts")) for v in views if v.get("ts") is not None]
    capture_end_ts = max(ts_all) if ts_all else None
    icmp_events = _collect_icmp_events(views)
    inner_streams = _group_inner_tcp_streams(views)

    complete = incomplete_syn = half = closing = reset = 0
    ev_complete = []
    ev_incomp = []
    ev_half = []
    ev_close = []
    ev_rst = []
    ev_rst_hs = []
    ev_retrans = []
    ev_zero = []
    ev_zero_persist = []
    ev_csum = []
    incomplete_short = 0
    incomplete_silent = 0
    ev_incomp_short = []
    ev_incomp_silent = []

    for key, pkts in tcp_streams:
        hs = _handshake_state(pkts)
        outc = _flow_outcome(pkts, capture_end_ts=capture_end_ts, icmp_events=icmp_events)
        label = _stream_label(pkts[0])
        nos = ",".join(str(p.get("no")) for p in pkts[:8])
        if len(pkts) > 8:
            nos += "…"
        if hs["rst"]:
            reset += 1
            if hs["syn"] and not hs["synack"] and not hs["complete"] and not hs["data"]:
                ev_rst_hs.append(f"{label}（第 {hs['rst_no']} 号在握手阶段出现 RST，更像端口未监听或被拒绝）")
                ev_rst.append(ev_rst_hs[-1])
            else:
                ev_rst.append(f"{label}（第 {hs['rst_no']} 号出现 RST，连接被中止）")
        if hs["fin"]:
            closing += 1
            ev_close.append(f"{label}（第 {hs['fin_no']} 号出现 FIN）")
        if hs["complete"] or (hs["data"] and not hs["syn"]):
            complete += 1
            ev_complete.append(f"{label}（{len(pkts)} 个包，序号 {nos}）")
        elif hs["syn"] and hs["synack"] and not hs["ack"] and not hs["data"]:
            half += 1
            ev_half.append(f"{label}（见到 SYN 与 SYN-ACK，未见第三拍，序号 {nos}）")
        elif hs["syn"] and not hs["synack"]:
            incomplete_syn += 1
            if outc.get("kind") == "silent":
                incomplete_silent += 1
                ev_incomp_silent.append(f"{label}（只见到 SYN，已有重传或等待足够时间仍无应答，序号 {nos}）")
                ev_incomp.append(ev_incomp_silent[-1])
            elif outc.get("kind") == "rst":
                ev_incomp.append(f"{label}（SYN 后被 RST，序号 {nos}）")
            elif outc.get("kind") and str(outc.get("kind")).startswith("icmp_"):
                ev_incomp.append(f"{label}（{_icmp_kind_phrase(outc['kind'][5:])}，序号 {nos}）")
            else:
                incomplete_short += 1
                ev_incomp_short.append(f"{label}（仅有 SYN，窗口较短，序号 {nos}）")
                ev_incomp.append(ev_incomp_short[-1])
        else:
            # 只有 ACK/数据片段、没有看到开头，当作已在传输
            if any(int(p.get("payload_len") or 0) > 0 or _has(int(p.get("tcp_flags") or 0), "ACK") for p in pkts):
                complete += 1
                ev_complete.append(f"{label}（抓包窗口内未见完整握手，但已有确认或数据，序号 {nos}）")

        # 重传 / 零窗口（只在本集合内判断）
        seen_seq: dict[tuple, int] = {}
        last_win_by_dir: dict[tuple, tuple] = {}
        zero_pkts = []
        for p in sorted(pkts, key=lambda x: (x.get("ts") or 0, x.get("no") or 0)):
            flags = int(p.get("tcp_flags") or 0)
            win = p.get("tcp_window")
            dir_ep = (p.get("ip_src") or p.get("src"), p.get("sport"))
            if win is not None and _has(flags, "ACK") and not _has(flags, "RST"):
                last_win_by_dir[dir_ep] = (win, p.get("no"))
                if win == 0:
                    ev_zero.append(f"{label} 第 {p.get('no')} 号通告窗口为 0")
                    zero_pkts.append(p)
            plen = int(p.get("payload_len") or 0)
            seq = p.get("tcp_seq")
            if seq is None:
                continue
            if plen > 0 or _has(flags, "SYN") or _has(flags, "FIN"):
                prev = seen_seq.get((p.get("ip_src") or p.get("src"), p.get("sport"), int(seq), plen))
                if prev is not None:
                    ev_retrans.append(f"{label} 第 {p.get('no')} 号与第 {prev} 号 Seq={seq} 相同，可能为重传")
                else:
                    seen_seq[(p.get("ip_src") or p.get("src"), p.get("sport"), int(seq), plen)] = p.get("no")
        for dir_ep, (win, no) in last_win_by_dir.items():
            if win == 0:
                ev_zero_persist.append(f"{label} 来自 {dir_ep[0]}:{dir_ep[1]} 的最后一次窗口通告仍为 0（第 {no} 号）")

    if tcp_streams:
        detail = f"共观察到 {len(tcp_streams)} 条 TCP 会话。"
        if complete:
            detail += f" 其中 {complete} 条已完成三次握手，或抓包窗口内已在传输数据。"
        if incomplete_syn:
            detail += f" 有 {incomplete_syn} 条只看到 SYN、未见 SYN-ACK"
            bits = []
            if incomplete_silent:
                bits.append(f"{incomplete_silent} 条已出现 SYN 重传或已等待足够时间仍无应答，更像对端未响应或中间设备静默丢弃")
            if incomplete_short:
                bits.append(f"{incomplete_short} 条因抓包窗口较短，尚不能确认是被拦截还是应答尚未到达")
            if bits:
                detail += "：" + "；".join(bits)
            else:
                detail += "，握手可能未完成或应答未被抓到"
            detail += "。"
        if half:
            detail += f" 有 {half} 条看到 SYN 与 SYN-ACK，但还没有第三拍 ACK。"
        if not complete and not incomplete_syn and not half:
            detail += " 窗口内的 TCP 流不足以判断握手是否完成。"
        evidence = "；".join((ev_complete[:4] + ev_incomp[:4] + ev_half[:4])[:6])
        conclusions.append({
            "level": "warn" if (incomplete_syn or half) and not complete else "info",
            "title": "TCP 握手",
            "detail": detail,
            "evidence": evidence,
        })
    else:
        conclusions.append({
            "level": "info",
            "title": "TCP 握手",
            "detail": "当前集合中没有识别到 TCP 会话，无法判断三次握手。",
            "evidence": "",
        })

    if closing:
        conclusions.append({
            "level": "info",
            "title": "连接关闭",
            "detail": f"有 {closing} 条 TCP 会话出现 FIN，连接正在或已经进入关闭过程。",
            "evidence": "；".join(ev_close[:6]),
        })
    if reset:
        detail = f"有 {reset} 条 TCP 会话出现 RST。"
        if ev_rst_hs:
            detail += f" 其中 {len(ev_rst_hs)} 条发生在握手阶段，通常表示目的端口未在监听，或路径上的设备以复位方式拒绝；这与完全没有应答的静默丢弃不同。"
            if len(ev_rst_hs) < reset:
                detail += " 其余 RST 出现在已经有应答或数据之后，表示已建立的连接被中止。"
        else:
            detail += " 这些复位出现在已经有应答或数据的会话里，表示连接被中止。"
        conclusions.append({
            "level": "warn",
            "title": "连接被重置",
            "detail": detail,
            "evidence": "；".join(ev_rst[:6]),
        })
    if ev_retrans:
        conclusions.append({
            "level": "warn",
            "title": "可能的重传",
            "detail": f"在同一会话、同一方向上发现 {len(ev_retrans)} 处序列号重复，可能是重传（也可能是抓包起点不完整）。",
            "evidence": "；".join(ev_retrans[:6]),
        })
    if ev_zero:
        detail = f"发现 {len(ev_zero)} 个通告窗口为 0 的 TCP 报文，接收方可能暂缓收数据。"
        if ev_zero_persist:
            detail += f" 其中 {len(ev_zero_persist)} 个方向在抓包窗口结束时仍然通告零窗口，属于持续零窗口，对端应暂停发送新数据，直到窗口再次打开。"
        conclusions.append({
            "level": "warn",
            "title": "持续零窗口" if ev_zero_persist else "零窗口",
            "detail": detail,
            "evidence": "；".join((ev_zero_persist or ev_zero)[:6]),
        })

    # 应用层事实
    http_reqs = []
    http_st = []
    http_bad = []
    dns_queries = []  # dicts
    dns_resps = []
    dns_bad = []
    sni = []
    tls_alerts = []
    for v in views:
        app = _extract_app(v)
        if app.get("http"):
            h = app["http"]
            if h.get("method"):
                http_reqs.append(
                    f"第 {v.get('no')} 号 {h.get('method')} {h.get('path') or '/'} Host={h.get('host') or '?'}"
                )
            if h.get("status"):
                item = f"第 {v.get('no')} 号 {h.get('status')}"
                http_st.append(item)
                try:
                    code = int(str(h.get("status")).split()[0])
                    if code >= 400:
                        http_bad.append(item)
                except (TypeError, ValueError):
                    pass
        if app.get("dns"):
            d = app["dns"]
            qn = d.get("qname") or ""
            rec = {
                "no": v.get("no"), "ts": v.get("ts"), "qname": qn, "qtype": d.get("qtype"),
                "tid": d.get("tid") or "",
                "src": v.get("ip_src") or v.get("src"),
                "dst": v.get("ip_dst") or v.get("dst"),
                "sport": v.get("sport"), "dport": v.get("dport"),
                "response": bool(d.get("response")), "rcode": d.get("rcode") or "",
            }
            if rec["response"]:
                dns_resps.append(rec)
                rcode = rec["rcode"]
                if rcode and rcode.lower() not in ("no error", "0", "noerror", ""):
                    dns_bad.append(f"第 {v.get('no')} 号 {qn} {rcode}")
            elif qn:
                dns_queries.append(rec)
        tls = app.get("tls") or {}
        if tls.get("sni"):
            sni.append(tls.get("sni"))
        if tls.get("alert"):
            bits = [f"第 {v.get('no')} 号"]
            if tls.get("alert_level") or tls.get("alert_desc"):
                bits.append(((tls.get("alert_level") or "") + ("：" if tls.get("alert_level") and tls.get("alert_desc") else "") + (tls.get("alert_desc") or "")).strip("："))
            tls_alerts.append(" ".join(bits))

    if http_reqs or http_st:
        detail = ""
        if http_reqs:
            detail += f"见到 {len(http_reqs)} 条 HTTP 请求。"
        if http_st:
            detail += f" 见到 {len(http_st)} 条 HTTP 响应。"
        if http_bad:
            detail += f" 其中 {len(http_bad)} 条是 4xx 或 5xx，表示请求未被成功处理或服务器出错。"
        conclusions.append({
            "level": "warn" if http_bad else "info",
            "title": "HTTP",
            "detail": detail.strip(),
            "evidence": "；".join((http_reqs + http_st)[:8]),
        })

    dns_qnames = [d["qname"] for d in dns_queries]
    dns_timeout = []
    dns_pending = []
    for q in dns_queries:
        matched = False
        for r in dns_resps:
            if q.get("qname") and r.get("qname") and q["qname"] != r["qname"]:
                continue
            if q.get("tid") and r.get("tid") and q["tid"] != r["tid"]:
                continue
            # 查询与应答应地址对调、端口对调
            if q.get("src") and r.get("dst") and not _ip_like(q["src"], r["dst"]):
                continue
            if q.get("dst") and r.get("src") and not _ip_like(q["dst"], r["src"]):
                continue
            if q.get("sport") is not None and r.get("dport") is not None and _as_port(q["sport"]) != _as_port(r["dport"]):
                continue
            matched = True
            break
        if matched:
            continue
        wait_s = 0.0
        if capture_end_ts is not None and q.get("ts") is not None:
            wait_s = max(0.0, float(capture_end_ts) - float(q["ts"]))
        item = f"第 {q.get('no')} 号 {q.get('qname')}"
        if wait_s >= _SYN_CONFIRM_WAIT_S:
            dns_timeout.append(item)
        else:
            dns_pending.append(item)
    if dns_qnames or dns_bad or dns_timeout:
        uniq = list(dict.fromkeys(dns_qnames))
        detail = f"见到对 {len(uniq)} 个不同名称的 DNS 查询" if uniq else "见到 DNS 报文"
        extras = []
        if dns_bad:
            extras.append(f"{len(dns_bad)} 条应答含错误码")
        if dns_timeout:
            extras.append(f"{len(dns_timeout)} 条查询在抓包窗口内未见应答，更像 DNS 超时")
        if dns_pending and not dns_timeout:
            extras.append(f"{len(dns_pending)} 条查询尚未见到应答，但抓包窗口较短，还不能确认已经超时")
        if extras:
            detail += "，其中 " + "；".join(extras)
        detail += "。"
        ev = "查询：" + "、".join(uniq[:8]) if uniq else ""
        if dns_bad:
            ev += ("；" if ev else "") + "异常：" + "；".join(dns_bad[:4])
        if dns_timeout:
            ev += ("；" if ev else "") + "未见应答：" + "；".join(dns_timeout[:4])
        conclusions.append({
            "level": "warn" if (dns_bad or dns_timeout) else "info",
            "title": "DNS",
            "detail": detail,
            "evidence": ev,
        })

    if sni:
        uniq = list(dict.fromkeys(sni))
        conclusions.append({
            "level": "info",
            "title": "TLS SNI",
            "detail": f"在 ClientHello 中解出 {len(uniq)} 个服务器名称（不解密 TLS 内容）。",
            "evidence": "、".join(uniq[:10]),
        })
    if tls_alerts:
        conclusions.append({
            "level": "warn",
            "title": "TLS Alert",
            "detail": f"发现 {len(tls_alerts)} 条 TLS Alert。Alert 表示该方向发出了告警，可能中止握手或关闭连接；本工具不解密 TLS 内容，只能看到记录层和已解出的告警字段。",
            "evidence": "；".join(tls_alerts[:6]),
        })

    explained_icmp = _diagnose_tunnels_and_port_blocks(
        views, tcp_streams, conclusions,
        capture_end_ts=capture_end_ts, icmp_events=icmp_events, inner_streams=inner_streams,
    ) or set()

    icmp_by_kind: dict[str, list[str]] = {}
    for evn in icmp_events:
        kind = evn.get("kind") or "unreach"
        ev = f"第 {evn.get('no')} 号 {_icmp_kind_phrase(kind)}"
        if evn.get("orig_dst") or evn.get("orig_dport") is not None:
            ev += f"，原始目的 {evn.get('orig_dst') or '?'}"
            if evn.get("orig_dport") is not None:
                ev += f":{evn.get('orig_dport')}"
        icmp_by_kind.setdefault(kind, []).append(ev)
    needfrag = icmp_by_kind.get("needfrag") or []
    if needfrag:
        conclusions.append({
            "level": "warn",
            "title": "路径需要分片或报文过大",
            "detail": (
                f"发现 {len(needfrag)} 条 ICMP 需要分片（IPv4 目的不可达代码 4，设置了 DF）或 ICMPv6 报文过大。"
                "这表示当前报文超过了路径允许的 MTU，需要减小报文或调整分片策略；不能仅凭这条差错确认已经发生分片重组丢失。"
            ),
            "evidence": "；".join(needfrag[:6]),
        })
    other_unreach = []
    for kind, items in icmp_by_kind.items():
        if kind in ("admin", "needfrag"):
            continue
        other_unreach.extend(items)
    # 尚未在拦截结论中说明的不可达（不含已单独写过的管理禁止总述）
    visible_unreach = [x for x in other_unreach]
    if visible_unreach:
        conclusions.append({
            "level": "warn",
            "title": "ICMP 目的不可达",
            "detail": (
                f"发现 {len(visible_unreach)} 条目的不可达或差错报文。"
                "已按代码区分主机不可达、网络不可达、端口不可达等；端口不可达通常表示对端可达但该端口未监听，"
                "主机或网络不可达则更像对端或路径不通，而不是单纯的端口拦截。"
            ),
            "evidence": "；".join(visible_unreach[:6]),
        })

    # 校验和：仅对提供了 _csum 标记或现场计算过的？ diagnose 不一定有 raw。
    # 若 view 里已有 analysis hints 则收集；否则跳过（session 层会传入带 raw 的分析）。
    for v in views:
        for h in (v.get("_checksum_hints") or []):
            ev_csum.append(f"第 {v.get('no')} 号 {h}")
    if ev_csum:
        conclusions.append({
            "level": "error",
            "title": "校验和异常",
            "detail": f"有 {len(ev_csum)} 个报文的 IP 或传输层校验和与计算结果不一致（截断报文已排除）。",
            "evidence": "；".join(ev_csum[:6]),
        })

    overview = conclusions[0]["detail"] if conclusions else ""
    return {
        "overview": overview,
        "conclusions": conclusions,
        "count": total,
        "filtered": filtered,
        "tcp_sessions": len(tcp_streams),
    }


def sanitize_text(text: str, limit: int = 400) -> str:
    if not text:
        return ""
    text = _SENSITIVE_HDR.sub(r"\1: ***", text)
    text = _COOKIE_IN_INFO.sub(r"\1=***", text)
    text = re.sub(r"(?i)(cookie|set-cookie|authorization)\s*[:=]\s*\S+", r"\1=***", text)
    if len(text) > limit:
        return text[:limit] + "…（已截断）"
    return text


def build_ai_brief(diagnosis: dict, *, selected: dict | None = None,
                   selected_analysis: dict | None = None,
                   stats: dict | None = None,
                   conversations: list | None = None,
                   more_packets: list | None = None) -> str:
    """给大模型的结构化摘要：只有元数据与规则结论，不含完整原始包。"""
    lines = [
        "以下是本机抓包工具生成的脱敏摘要，不是完整原始报文。",
        "不要假设未出现的字段；HTTP Cookie / Authorization 等已去除或截断。",
        "TLS 仅提供已解出的握手字段（如 SNI），内容未解密。",
        "",
    ]
    if diagnosis:
        scope = "（当前显示过滤后的集合）" if diagnosis.get("filtered") else ""
        lines.append(f"【离线诊断】{scope}共 {diagnosis.get('count', 0)} 个报文。")
        for c in diagnosis.get("conclusions") or []:
            ev = c.get("evidence") or ""
            lines.append(f"- {c.get('title')}: {c.get('detail')}" + (f" 依据：{sanitize_text(ev, 240)}" if ev else ""))
        lines.append("")
    if stats:
        protos = stats.get("protocols") or []
        if protos:
            lines.append("【协议统计】" + "，".join(
                f"{p.get('protocol')} {p.get('count')} 个/{p.get('bytes')} 字节" for p in protos[:16]
            ))
            lines.append("")
    if conversations:
        lines.append("【主要会话】（最多 12 条）")
        for c in conversations[:12]:
            lines.append(
                f"- {c.get('protocol')} {c.get('endpoint_a')} ↔ {c.get('endpoint_b')}："
                f"{c.get('packets')} 个包，{c.get('bytes')} 字节"
            )
        lines.append("")
    if selected:
        lines.append(
            f"【当前选中报文】第 {selected.get('no')} 号 {selected.get('protocol')} "
            f"{selected.get('src')} → {selected.get('dst')}  长度 {selected.get('length')}  "
            f"Info: {sanitize_text(selected.get('info') or '', 200)}"
        )
        if selected_analysis:
            lines.append("规则解读：" + (selected_analysis.get("summary") or ""))
            for c in selected_analysis.get("conclusions") or []:
                ev = f"（依据：{c.get('evidence')}）" if c.get("evidence") else ""
                lines.append(
                    f"  结论[{c.get('level') or 'info'}] {c.get('title')}：{sanitize_text(c.get('detail') or '', 200)}{ev}"
                )
            for p in selected_analysis.get("points") or []:
                lines.append("  - " + sanitize_text(p, 200))
            for h in selected_analysis.get("hints") or []:
                lines.append(f"  ! {h.get('level')}: {h.get('text')}")
        lines.append("")
    if more_packets:
        lines.append("【部分报文摘要】（已截断，最多 40 条）")
        for p in more_packets[:40]:
            lines.append(
                f"#{p.get('no')} {p.get('protocol')} {p.get('src')} → {p.get('dst')} "
                f"{sanitize_text(p.get('info') or '', 120)}"
            )
        if len(more_packets) > 40:
            lines.append(f"…另有 {len(more_packets) - 40} 条未列出")
        lines.append("")
    text = "\n".join(lines).strip()
    if len(text) > 14000:
        text = text[:14000] + "\n…（摘要过长，已截断）"
    return text
