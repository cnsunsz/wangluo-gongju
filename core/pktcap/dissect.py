"""报文逐层解析：摘要行 + 带偏移的字段树。独立实现，不依赖 scapy / Wireshark。"""
from __future__ import annotations

import ipaddress
import re
import struct
from typing import Any

# pcap 链路类型
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 12
DLT_RAW_ALT = 14
DLT_LINUX_SLL = 113
DLT_IEEE802_11 = 105
DLT_LINUX_SLL2 = 276
DLT_IPV4 = 228
DLT_IPV6 = 229

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
ETH_VLAN = 0x8100
ETH_IPV6 = 0x86DD
ETH_QINQ = 0x88A8
ETH_VLAN_OLD = 0x9100

IP_ICMP = 1
IP_TCP = 6
IP_UDP = 17
IP_ICMPV6 = 58

ETH_TYPES = {
    ETH_IPV4: "IPv4",
    ETH_ARP: "ARP",
    ETH_VLAN: "802.1Q VLAN",
    ETH_IPV6: "IPv6",
    ETH_QINQ: "802.1ad QinQ",
    ETH_VLAN_OLD: "VLAN",
    0x0805: "X.25",
    0x8035: "RARP",
    0x8847: "MPLS",
    0x8863: "PPPoE Discovery",
    0x8864: "PPPoE Session",
    0x88CC: "LLDP",
}

IP_PROTOS = {
    0: "HOPOPT", 1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP",
    41: "IPv6", 43: "IPv6-Route", 44: "IPv6-Frag", 47: "GRE",
    50: "ESP", 51: "AH", 58: "ICMPv6", 59: "IPv6-NoNxt", 60: "IPv6-Opts",
    89: "OSPF", 132: "SCTP",
}

PORT_NAMES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    110: "pop3", 123: "ntp", 143: "imap", 161: "snmp", 162: "snmptrap",
    443: "https", 445: "smb", 465: "smtps", 587: "submission",
    853: "dot", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    1883: "mqtt", 3306: "mysql", 3389: "rdp", 5060: "sip", 5353: "mdns",
    5432: "postgres", 5672: "amqp", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 27017: "mongodb",
}

TCP_FLAGS = (
    ("NS", 0x100), ("CWR", 0x80), ("ECE", 0x40), ("URG", 0x20),
    ("ACK", 0x10), ("PSH", 0x08), ("RST", 0x04), ("SYN", 0x02), ("FIN", 0x01),
)

DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 43: "DS", 46: "RRSIG",
    47: "NSEC", 48: "DNSKEY", 257: "CAA", 255: "ANY",
}

TLS_RECORD = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "Application Data", 24: "Heartbeat"}
TLS_HS = {
    0: "HelloRequest", 1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket",
    8: "EncryptedExtensions", 11: "Certificate", 12: "ServerKeyExchange",
    13: "CertificateRequest", 14: "ServerHelloDone", 15: "CertificateVerify",
    16: "ClientKeyExchange", 20: "Finished",
}
TLS_VER = {0x0200: "SSL 2.0", 0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}


def node(name: str, value: Any = None, offset: int = 0, length: int = 0,
         children: list | None = None, summary: str | None = None) -> dict:
    d: dict[str, Any] = {"name": name, "offset": int(offset), "length": int(length)}
    if value is not None:
        d["value"] = value if isinstance(value, str) else str(value)
    if summary:
        d["summary"] = summary
    if children:
        d["children"] = children
    return d


def _ok(data: bytes, off: int, n: int) -> bool:
    return off >= 0 and n >= 0 and off + n <= len(data)


def u8(data: bytes, off: int) -> int:
    return data[off]


def u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 2], "big")


def u24(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 3], "big")


def u32(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 4], "big")


def mac_str(data: bytes, off: int = 0) -> str:
    return ":".join(f"{b:02x}" for b in data[off:off + 6])


def ipv4_str(data: bytes, off: int) -> str:
    return ".".join(str(b) for b in data[off:off + 4])


def ipv6_str(data: bytes, off: int) -> str:
    try:
        return str(ipaddress.IPv6Address(data[off:off + 16]))
    except Exception:
        return data[off:off + 16].hex()


def port_label(port: int) -> str:
    name = PORT_NAMES.get(port)
    return f"{port} ({name})" if name else str(port)


def _tcp_flag_names(bits: int) -> list[str]:
    return [name for name, mask in TCP_FLAGS if bits & mask]


def _dscp_name(dscp: int) -> str:
    known = {
        0: "CS0 / BE", 8: "CS1", 10: "AF11", 12: "AF12", 14: "AF13",
        16: "CS2", 18: "AF21", 20: "AF22", 22: "AF23", 24: "CS3",
        26: "AF31", 28: "AF32", 30: "AF33", 32: "CS4", 34: "AF41",
        36: "AF42", 38: "AF43", 40: "CS5", 46: "EF", 48: "CS6", 56: "CS7",
    }
    return known.get(dscp, str(dscp))


def _fmt_ts(ts: float) -> str:
    from datetime import datetime
    try:
        sec = int(ts)
        frac = ts - sec
        base = datetime.fromtimestamp(sec).strftime("%Y-%m-%d %H:%M:%S")
        return f"{base}.{int(frac * 1_000_000):06d}"
    except Exception:
        return f"{ts:.6f}"


class _Ctx:
    """解析过程中收集摘要与会话信息。"""

    def __init__(self) -> None:
        self.src = ""
        self.dst = ""
        self.protocol = "DATA"
        self.info = ""
        self.sport: int | None = None
        self.dport: int | None = None
        self.ip_src = ""
        self.ip_dst = ""
        self.l4 = ""
        self.tcp_flags = 0
        self.tcp_seq: int | None = None
        self.tcp_ack: int | None = None
        self.payload_off: int | None = None
        self.payload_len = 0
        self.stream_key: tuple | None = None


def dissect(raw: bytes, *, ts: float = 0.0, number: int = 1,
            orig_len: int | None = None, linktype: int = DLT_EN10MB,
            iface: str = "") -> dict:
    """解析一帧，返回摘要 + 层次树。raw 为捕获到的链路层及更高层字节。"""
    caplen = len(raw)
    wire = caplen if orig_len is None else int(orig_len)
    ctx = _Ctx()
    layers: list[dict] = []

    frame_children = [
        node("Arrival Time", _fmt_ts(ts), 0, 0),
        node("Frame Number", str(number), 0, 0),
        node("Frame Length", f"{wire} bytes ({wire * 8} bits)", 0, 0),
        node("Capture Length", f"{caplen} bytes ({caplen * 8} bits)", 0, caplen),
        node("Encapsulation", _dlt_name(linktype), 0, 0),
    ]
    if iface:
        frame_children.append(node("Interface", iface, 0, 0))
    layers.append(node("Frame", summary=f"{wire} bytes on wire, {caplen} bytes captured",
                       offset=0, length=caplen, children=frame_children))

    try:
        _dissect_link(raw, 0, linktype, layers, ctx)
    except Exception as e:
        layers.append(node("Malformed", f"解析中断：{type(e).__name__}: {e}", 0, caplen))
        if not ctx.info:
            ctx.info = "畸形或截断的报文"

    if not ctx.src:
        ctx.src = "—"
    if not ctx.dst:
        ctx.dst = "—"
    if not ctx.info:
        ctx.info = ctx.protocol

    return {
        "no": number,
        "ts": float(ts),
        "length": wire,
        "caplen": caplen,
        "src": ctx.src,
        "dst": ctx.dst,
        "protocol": ctx.protocol,
        "info": ctx.info,
        "layers": layers,
        "sport": ctx.sport,
        "dport": ctx.dport,
        "ip_src": ctx.ip_src,
        "ip_dst": ctx.ip_dst,
        "l4": ctx.l4,
        "tcp_flags": ctx.tcp_flags,
        "tcp_seq": ctx.tcp_seq,
        "tcp_ack": ctx.tcp_ack,
        "payload_off": ctx.payload_off,
        "payload_len": ctx.payload_len,
        "stream_key": ctx.stream_key,
    }


def _dlt_name(linktype: int) -> str:
    return {
        DLT_NULL: "BSD loopback",
        DLT_EN10MB: "Ethernet",
        DLT_RAW: "Raw IP",
        DLT_RAW_ALT: "Raw IP",
        DLT_LINUX_SLL: "Linux cooked capture",
        DLT_LINUX_SLL2: "Linux cooked capture v2",
        DLT_IEEE802_11: "IEEE 802.11",
        DLT_IPV4: "Raw IPv4",
        DLT_IPV6: "Raw IPv6",
    }.get(linktype, f"DLT {linktype}")


def _dissect_link(data: bytes, off: int, linktype: int, layers: list, ctx: _Ctx) -> None:
    if linktype in (DLT_EN10MB,):
        _eth(data, off, layers, ctx)
        return
    if linktype in (DLT_RAW, DLT_RAW_ALT, DLT_IPV4, DLT_IPV6):
        _ip_or_ver(data, off, layers, ctx)
        return
    if linktype == DLT_NULL:
        if not _ok(data, off, 4):
            layers.append(node("BSD loopback", "截断", off, max(0, len(data) - off)))
            return
        family = int.from_bytes(data[off:off + 4], "little")
        fam = {2: "AF_INET", 24: "AF_INET6", 28: "AF_INET6", 30: "AF_INET6"}.get(family, f"AF {family}")
        layers.append(node("BSD loopback", summary=fam, offset=off, length=4, children=[
            node("Address Family", f"{fam} ({family})", off, 4),
        ]))
        if family in (24, 28, 30):
            _ipv6(data, off + 4, layers, ctx)
        else:
            _ipv4(data, off + 4, layers, ctx)
        return
    if linktype == DLT_LINUX_SLL:
        _sll(data, off, layers, ctx)
        return
    if linktype == DLT_LINUX_SLL2:
        _sll2(data, off, layers, ctx)
        return
    ctx.protocol = _dlt_name(linktype)
    ctx.info = f"未解析的链路层（{_dlt_name(linktype)}），仅显示原始字节"
    layers.append(node("Link", f"未解出：{_dlt_name(linktype)}", off, max(0, len(data) - off)))


def _sll(data: bytes, off: int, layers: list, ctx: _Ctx) -> None:
    if not _ok(data, off, 16):
        layers.append(node("Linux cooked", "截断", off, max(0, len(data) - off)))
        return
    pkttype = u16(data, off)
    etype = u16(data, off + 14)
    hatype = u16(data, off + 2)
    halen = u16(data, off + 4)
    addr = data[off + 6:off + 14]
    mac = mac_str(addr, 0) if halen == 6 else addr[:halen].hex()
    typ = {0: "Unicast to us", 1: "Broadcast", 2: "Multicast", 3: "Sent by us", 4: "Sent to other"}.get(pkttype, str(pkttype))
    layers.append(node("Linux cooked capture", summary=f"{typ}, protocol 0x{etype:04x}",
                       offset=off, length=16, children=[
        node("Packet type", typ, off, 2),
        node("Link-layer address type", str(hatype), off + 2, 2),
        node("Link-layer address length", str(halen), off + 4, 2),
        node("Source", mac, off + 6, 8),
        node("Protocol", f"0x{etype:04x} ({ETH_TYPES.get(etype, '未知')})", off + 14, 2),
    ]))
    ctx.src = mac
    _ethertype(data, off + 16, etype, layers, ctx)


def _sll2(data: bytes, off: int, layers: list, ctx: _Ctx) -> None:
    if not _ok(data, off, 20):
        layers.append(node("Linux cooked v2", "截断", off, max(0, len(data) - off)))
        return
    etype = u16(data, off)
    _ethertype(data, off + 20, etype, layers, ctx)


def _eth(data: bytes, off: int, layers: list, ctx: _Ctx) -> None:
    if not _ok(data, off, 14):
        layers.append(node("Ethernet", "截断", off, max(0, len(data) - off)))
        return
    dst = mac_str(data, off)
    src = mac_str(data, off + 6)
    etype = u16(data, off + 12)
    ctx.src = src
    ctx.dst = dst
    children = [
        node("Destination", _mac_desc(dst), off, 6),
        node("Source", _mac_desc(src), off + 6, 6),
        node("Type", f"0x{etype:04x} ({ETH_TYPES.get(etype, '未知')})", off + 12, 2),
    ]
    hdr_len = 14
    cur_off = off + 14
    # VLAN tags
    while etype in (ETH_VLAN, ETH_QINQ, ETH_VLAN_OLD) and _ok(data, cur_off, 4):
        tci = u16(data, cur_off)
        vid = tci & 0x0FFF
        pcp = (tci >> 13) & 0x7
        dei = (tci >> 12) & 0x1
        inner = u16(data, cur_off + 2)
        children.append(node("VLAN", f"ID {vid}, PCP {pcp}, DEI {dei}, Type 0x{inner:04x}",
                             cur_off, 4, children=[
            node("Priority (PCP)", str(pcp), cur_off, 2),
            node("DEI", str(dei), cur_off, 2),
            node("ID", str(vid), cur_off, 2),
            node("Type", f"0x{inner:04x} ({ETH_TYPES.get(inner, '未知')})", cur_off + 2, 2),
        ]))
        etype = inner
        cur_off += 4
        hdr_len += 4
    layers.append(node("Ethernet II", summary=f"Src: {src}, Dst: {_mac_desc(dst)}",
                       offset=off, length=hdr_len, children=children))
    _ethertype(data, cur_off, etype, layers, ctx)


def _mac_desc(mac: str) -> str:
    if mac == "ff:ff:ff:ff:ff:ff":
        return f"{mac} (Broadcast)"
    try:
        first = int(mac.split(":")[0], 16)
        if first & 0x01:
            return f"{mac} (Multicast)"
    except Exception:
        pass
    return mac


def _ethertype(data: bytes, off: int, etype: int, layers: list, ctx: _Ctx) -> None:
    if etype == ETH_IPV4:
        _ipv4(data, off, layers, ctx)
    elif etype == ETH_IPV6:
        _ipv6(data, off, layers, ctx)
    elif etype == ETH_ARP:
        _arp(data, off, layers, ctx)
    elif etype <= 1500:
        # 802.3 length，可能是 LLC
        ctx.protocol = "LLC"
        ctx.info = f"IEEE 802.3 长度 {etype}，未继续解析 LLC"
        layers.append(node("IEEE 802.3", f"Length {etype}（未解出 LLC）", off, max(0, len(data) - off)))
    else:
        ctx.protocol = ETH_TYPES.get(etype, f"0x{etype:04x}")
        ctx.info = f"EtherType 0x{etype:04x}（未解出上层）"
        layers.append(node("Data", f"未解出的 EtherType 0x{etype:04x}", off, max(0, len(data) - off)))


def _ip_or_ver(data: bytes, off: int, layers: list, ctx: _Ctx) -> None:
    if not _ok(data, off, 1):
        layers.append(node("IP", "截断", off, 0))
        return
    ver = data[off] >> 4
    if ver == 4:
        _ipv4(data, off, layers, ctx)
    elif ver == 6:
        _ipv6(data, off, layers, ctx)
    else:
        layers.append(node("IP", f"未知版本 {ver}", off, max(0, len(data) - off)))


def _ipv4(data: bytes, off: int, layers: list, ctx: _Ctx) -> None:
    if not _ok(data, off, 20):
        layers.append(node("Internet Protocol Version 4", "截断", off, max(0, len(data) - off)))
        ctx.protocol = "IPv4"
        return
    vihl = data[off]
    ver = vihl >> 4
    ihl = (vihl & 0x0F) * 4
    tos = data[off + 1]
    dscp = (tos >> 2) & 0x3F
    ecn = tos & 0x03
    total = u16(data, off + 2)
    ident = u16(data, off + 4)
    ff = u16(data, off + 6)
    flags = (ff >> 13) & 0x7
    frag = ff & 0x1FFF
    ttl = data[off + 8]
    proto = data[off + 9]
    csum = u16(data, off + 10)
    src = ipv4_str(data, off + 12)
    dst = ipv4_str(data, off + 16)
    ctx.src = src
    ctx.dst = dst
    ctx.ip_src = src
    ctx.ip_dst = dst
    ctx.protocol = "IPv4"
    flag_names = []
    if flags & 0x2:
        flag_names.append("DF")
    if flags & 0x1:
        flag_names.append("MF")
    if flags & 0x4:
        flag_names.append("Reserved")
    children = [
        node("Version", str(ver), off, 1),
        node("Header Length", f"{ihl} bytes ({ihl // 4})", off, 1),
        node("Differentiated Services Field", f"0x{tos:02x}", off + 1, 1, children=[
            node("DSCP", f"{dscp} ({_dscp_name(dscp)})", off + 1, 1),
            node("ECN", str(ecn), off + 1, 1),
        ]),
        node("Total Length", str(total), off + 2, 2),
        node("Identification", f"0x{ident:04x} ({ident})", off + 4, 2),
        node("Flags", f"0x{flags:x} ({', '.join(flag_names) or '无'})", off + 6, 2),
        node("Fragment Offset", str(frag), off + 6, 2),
        node("Time to Live", str(ttl), off + 8, 1),
        node("Protocol", f"{proto} ({IP_PROTOS.get(proto, '未知')})", off + 9, 1),
        node("Header Checksum", f"0x{csum:04x}", off + 10, 2),
        node("Source Address", src, off + 12, 4),
        node("Destination Address", dst, off + 16, 4),
    ]
    if ihl < 20:
        layers.append(node("Internet Protocol Version 4", "头部长度非法", off, 20, children=children))
        return
    if ihl > 20:
        opt_len = ihl - 20
        if _ok(data, off + 20, opt_len):
            children.append(node("Options", f"{opt_len} bytes", off + 20, opt_len))
        else:
            children.append(node("Options", "截断", off + 20, max(0, len(data) - off - 20)))
            ihl = min(ihl, len(data) - off)
    layers.append(node("Internet Protocol Version 4", summary=f"Src: {src}, Dst: {dst}",
                       offset=off, length=ihl, children=children))
    if frag and not (flags & 0x1 and frag == 0):
        # 非首片：不解析上层
        if frag != 0:
            ctx.protocol = IP_PROTOS.get(proto, "IPv4")
            ctx.info = f"Fragmented IP protocol {proto} (offset {frag * 8})"
            return
    payload_off = off + ihl
    payload_end = off + total if total and off + total <= len(data) else len(data)
    _l4(data, payload_off, payload_end, proto, layers, ctx)


def _ipv6(data: bytes, off: int, layers: list, ctx: _Ctx) -> None:
    if not _ok(data, off, 40):
        layers.append(node("Internet Protocol Version 6", "截断", off, max(0, len(data) - off)))
        ctx.protocol = "IPv6"
        return
    w0 = u32(data, off)
    ver = w0 >> 28
    tc = (w0 >> 20) & 0xFF
    fl = w0 & 0xFFFFF
    dscp = (tc >> 2) & 0x3F
    ecn = tc & 0x03
    plen = u16(data, off + 4)
    nxt = data[off + 6]
    hlim = data[off + 7]
    src = ipv6_str(data, off + 8)
    dst = ipv6_str(data, off + 24)
    ctx.src = src
    ctx.dst = dst
    ctx.ip_src = src
    ctx.ip_dst = dst
    ctx.protocol = "IPv6"
    children = [
        node("Version", str(ver), off, 4),
        node("Traffic Class", f"0x{tc:02x}", off, 4, children=[
            node("DSCP", f"{dscp} ({_dscp_name(dscp)})", off, 4),
            node("ECN", str(ecn), off, 4),
        ]),
        node("Flow Label", f"0x{fl:05x}", off, 4),
        node("Payload Length", str(plen), off + 4, 2),
        node("Next Header", f"{nxt} ({IP_PROTOS.get(nxt, '未知')})", off + 6, 1),
        node("Hop Limit", str(hlim), off + 7, 1),
        node("Source Address", src, off + 8, 16),
        node("Destination Address", dst, off + 24, 16),
    ]
    layers.append(node("Internet Protocol Version 6", summary=f"Src: {src}, Dst: {dst}",
                       offset=off, length=40, children=children))
    cur = off + 40
    proto = nxt
    # 跳过常见扩展头
    hops = 0
    while proto in (0, 43, 44, 60, 51) and hops < 8 and _ok(data, cur, 2):
        hops += 1
        ext_nxt = data[cur]
        if proto == 44:
            ext_len = 8
        elif proto == 51:  # AH
            ext_len = (data[cur + 1] + 2) * 4
        else:
            ext_len = (data[cur + 1] + 1) * 8
        layers.append(node(IP_PROTOS.get(proto, f"IPv6 ext {proto}"),
                           f"Next Header {ext_nxt}", cur, ext_len))
        if not _ok(data, cur, ext_len):
            return
        proto = ext_nxt
        cur += ext_len
    payload_end = off + 40 + plen if plen and off + 40 + plen <= len(data) else len(data)
    _l4(data, cur, payload_end, proto, layers, ctx)


def _arp(data: bytes, off: int, layers: list, ctx: _Ctx) -> None:
    ctx.protocol = "ARP"
    if not _ok(data, off, 8):
        layers.append(node("Address Resolution Protocol", "截断", off, max(0, len(data) - off)))
        return
    htype = u16(data, off)
    ptype = u16(data, off + 2)
    hlen = data[off + 4]
    plen = data[off + 5]
    oper = u16(data, off + 6)
    need = 8 + 2 * hlen + 2 * plen
    if not _ok(data, off, need):
        layers.append(node("Address Resolution Protocol", "截断", off, max(0, len(data) - off)))
        return
    sha_off = off + 8
    spa_off = sha_off + hlen
    tha_off = spa_off + plen
    tpa_off = tha_off + hlen
    sha = mac_str(data, sha_off) if hlen == 6 else data[sha_off:spa_off].hex()
    tha = mac_str(data, tha_off) if hlen == 6 else data[tha_off:tpa_off].hex()
    spa = ipv4_str(data, spa_off) if plen == 4 else data[spa_off:tha_off].hex()
    tpa = ipv4_str(data, tpa_off) if plen == 4 else data[tpa_off:tpa_off + plen].hex()
    ctx.src = spa
    ctx.dst = tpa
    op_name = {1: "request", 2: "reply"}.get(oper, str(oper))
    if oper == 1:
        ctx.info = f"Who has {tpa}? Tell {spa}"
    elif oper == 2:
        ctx.info = f"{spa} is at {sha}"
    else:
        ctx.info = f"ARP {op_name}"
    layers.append(node("Address Resolution Protocol", summary=ctx.info, offset=off, length=need, children=[
        node("Hardware type", str(htype), off, 2),
        node("Protocol type", f"0x{ptype:04x}", off + 2, 2),
        node("Hardware size", str(hlen), off + 4, 1),
        node("Protocol size", str(plen), off + 5, 1),
        node("Opcode", f"{oper} ({op_name})", off + 6, 2),
        node("Sender MAC address", sha, sha_off, hlen),
        node("Sender IP address", spa, spa_off, plen),
        node("Target MAC address", tha, tha_off, hlen),
        node("Target IP address", tpa, tpa_off, plen),
    ]))


def _l4(data: bytes, off: int, end: int, proto: int, layers: list, ctx: _Ctx) -> None:
    if off > end:
        end = len(data)
    end = min(end, len(data))
    if proto == IP_TCP:
        _tcp(data, off, end, layers, ctx)
    elif proto == IP_UDP:
        _udp(data, off, end, layers, ctx)
    elif proto == IP_ICMP:
        _icmp(data, off, end, layers, ctx)
    elif proto == IP_ICMPV6:
        _icmpv6(data, off, end, layers, ctx)
    else:
        name = IP_PROTOS.get(proto, f"IP proto {proto}")
        ctx.protocol = name
        ctx.info = f"{name} 数据 {max(0, end - off)} 字节"
        if end > off:
            layers.append(node(name, f"{end - off} bytes", off, end - off))


def _tcp(data: bytes, off: int, end: int, layers: list, ctx: _Ctx) -> None:
    ctx.l4 = "TCP"
    ctx.protocol = "TCP"
    if not _ok(data, off, 20) or off + 20 > end:
        layers.append(node("Transmission Control Protocol", "截断", off, max(0, end - off)))
        return
    sport = u16(data, off)
    dport = u16(data, off + 2)
    seq = u32(data, off + 4)
    ack = u32(data, off + 8)
    doff_flags = u16(data, off + 12)
    data_off = ((doff_flags >> 12) & 0xF) * 4
    flags = doff_flags & 0x1FF
    window = u16(data, off + 14)
    csum = u16(data, off + 16)
    urg = u16(data, off + 18)
    ctx.sport = sport
    ctx.dport = dport
    ctx.tcp_flags = flags
    ctx.tcp_seq = seq
    ctx.tcp_ack = ack
    _set_stream(ctx, "TCP")
    names = _tcp_flag_names(flags)
    flag_s = ", ".join(names) if names else "无"
    children = [
        node("Source Port", port_label(sport), off, 2),
        node("Destination Port", port_label(dport), off + 2, 2),
        node("Sequence Number", str(seq), off + 4, 4),
        node("Acknowledgment Number", str(ack), off + 8, 4),
        node("Header Length", f"{data_off} bytes", off + 12, 2),
        node("Flags", f"0x{flags:03x} ({flag_s})", off + 12, 2, children=[
            node(name, "Set" if flags & mask else "Not set", off + 12, 2)
            for name, mask in TCP_FLAGS
        ]),
        node("Window", str(window), off + 14, 2),
        node("Checksum", f"0x{csum:04x}", off + 16, 2),
        node("Urgent Pointer", str(urg), off + 18, 2),
    ]
    if data_off < 20:
        data_off = 20
    opt_info = []
    if data_off > 20 and _ok(data, off + 20, data_off - 20) and off + data_off <= end:
        opt_info = _tcp_options(data, off + 20, off + data_off, children)
    hdr_len = data_off if off + data_off <= end else min(data_off, end - off)
    payload_off = off + hdr_len
    payload_len = max(0, end - payload_off)
    ctx.payload_off = payload_off if payload_len else payload_off
    ctx.payload_len = payload_len
    children.append(node("TCP payload", f"{payload_len} bytes", payload_off, payload_len))
    layers.append(node("Transmission Control Protocol",
                       summary=f"{sport} → {dport} [{flag_s}] Seq={seq} Ack={ack} Win={window} Len={payload_len}",
                       offset=off, length=hdr_len, children=children))
    extra = (" " + " ".join(opt_info)) if opt_info else ""
    ctx.info = f"{sport} → {dport} [{flag_s}] Seq={seq} Ack={ack} Win={window} Len={payload_len}{extra}"
    if payload_len > 0:
        _tcp_payload(data, payload_off, end, sport, dport, layers, ctx)


def _tcp_options(data: bytes, off: int, end: int, children: list) -> list[str]:
    info = []
    cur = off
    opts = []
    while cur < end:
        kind = data[cur]
        if kind == 0:
            opts.append(node("End of Option List (EOL)", "", cur, 1))
            break
        if kind == 1:
            opts.append(node("No-Operation (NOP)", "", cur, 1))
            cur += 1
            continue
        if cur + 2 > end:
            break
        length = data[cur + 1]
        if length < 2 or cur + length > end:
            opts.append(node(f"Option {kind}", "截断或长度非法", cur, max(1, end - cur)))
            break
        val = data[cur + 2:cur + length]
        if kind == 2 and length == 4:
            mss = u16(data, cur + 2)
            opts.append(node("Maximum Segment Size", str(mss), cur, length))
            info.append(f"MSS={mss}")
        elif kind == 3 and length == 3:
            shift = val[0]
            opts.append(node("Window Scale", str(shift), cur, length))
            info.append(f"WS={shift}")
        elif kind == 4:
            opts.append(node("SACK Permitted", "", cur, length))
            info.append("SACK_PERM")
        elif kind == 5:
            opts.append(node("SACK", val.hex(), cur, length))
        elif kind == 8 and length == 10:
            tsval = u32(data, cur + 2)
            tsecr = u32(data, cur + 6)
            opts.append(node("Timestamps", f"TSval={tsval} TSecr={tsecr}", cur, length))
        else:
            opts.append(node(f"Option {kind}", val.hex() or "", cur, length))
        cur += length
    if opts:
        children.append(node("Options", f"{end - off} bytes", off, end - off, children=opts))
    return info


def _tcp_payload(data: bytes, off: int, end: int, sport: int, dport: int, layers: list, ctx: _Ctx) -> None:
    payload = data[off:end]
    if _looks_http(payload):
        _http(payload, off, layers, ctx)
        return
    if _looks_tls(payload) or sport == 443 or dport == 443 or sport == 8443 or dport == 8443:
        if _looks_tls(payload):
            _tls(payload, off, layers, ctx)
            return
    if sport == 53 or dport == 53 or sport == 5353 or dport == 5353:
        # DNS over TCP：前 2 字节长度
        if len(payload) >= 2:
            ln = u16(payload, 0)
            if 12 <= ln + 2 <= len(payload) + 2:
                _dns(data, off + 2, off + 2 + min(ln, len(payload) - 2), layers, ctx)
                return
    # 未识别的 TCP 载荷保持 TCP 摘要


def _looks_http(payload: bytes) -> bool:
    if len(payload) < 4:
        return False
    methods = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ",
               b"PATCH ", b"CONNECT ", b"TRACE ", b"HTTP/1.")
    return any(payload.startswith(m) for m in methods)


def _looks_tls(payload: bytes) -> bool:
    if len(payload) < 5:
        return False
    typ = payload[0]
    ver = u16(payload, 1)
    ln = u16(payload, 3)
    if typ not in (20, 21, 22, 23, 24):
        return False
    if ver < 0x0300 or ver > 0x0304:
        return False
    # 长度可以跨分段，只要头部像样即可
    return ln <= 16384 + 256


def _udp(data: bytes, off: int, end: int, layers: list, ctx: _Ctx) -> None:
    ctx.l4 = "UDP"
    ctx.protocol = "UDP"
    if not _ok(data, off, 8) or off + 8 > end:
        layers.append(node("User Datagram Protocol", "截断", off, max(0, end - off)))
        return
    sport = u16(data, off)
    dport = u16(data, off + 2)
    length = u16(data, off + 4)
    csum = u16(data, off + 6)
    ctx.sport = sport
    ctx.dport = dport
    _set_stream(ctx, "UDP")
    payload_off = off + 8
    payload_end = off + length if length >= 8 and off + length <= len(data) else end
    payload_end = min(payload_end, end)
    payload_len = max(0, payload_end - payload_off)
    ctx.payload_off = payload_off
    ctx.payload_len = payload_len
    ctx.info = f"{sport} → {dport} Len={payload_len}"
    layers.append(node("User Datagram Protocol", summary=ctx.info, offset=off, length=8, children=[
        node("Source Port", port_label(sport), off, 2),
        node("Destination Port", port_label(dport), off + 2, 2),
        node("Length", str(length), off + 4, 2),
        node("Checksum", f"0x{csum:04x}", off + 6, 2),
    ]))
    if payload_len <= 0:
        return
    if sport in (53, 5353) or dport in (53, 5353):
        _dns(data, payload_off, payload_end, layers, ctx)
        return
    if sport in (67, 68) or dport in (67, 68):
        _dhcp(data, payload_off, payload_end, layers, ctx)
        return
    if _looks_http(data[payload_off:payload_end]):
        _http(data[payload_off:payload_end], payload_off, layers, ctx)


def _set_stream(ctx: _Ctx, l4: str) -> None:
    if not ctx.ip_src or ctx.sport is None or ctx.dport is None:
        return
    a = (ctx.ip_src, ctx.sport)
    b = (ctx.ip_dst, ctx.dport)
    if a <= b:
        ctx.stream_key = (l4, a[0], a[1], b[0], b[1])
    else:
        ctx.stream_key = (l4, b[0], b[1], a[0], a[1])


def _icmp(data: bytes, off: int, end: int, layers: list, ctx: _Ctx) -> None:
    ctx.protocol = "ICMP"
    if not _ok(data, off, 8) or off + 4 > end:
        layers.append(node("Internet Control Message Protocol", "截断", off, max(0, end - off)))
        return
    typ = data[off]
    code = data[off + 1]
    csum = u16(data, off + 2)
    rest = u32(data, off + 4) if off + 8 <= end else 0
    typ_names = {
        0: "Echo (ping) reply", 3: "Destination unreachable", 4: "Source quench",
        5: "Redirect", 8: "Echo (ping) request", 11: "Time exceeded",
        12: "Parameter problem", 13: "Timestamp request", 14: "Timestamp reply",
    }
    tname = typ_names.get(typ, f"Type {typ}")
    ident = seq = None
    children = [
        node("Type", f"{typ} ({tname})", off, 1),
        node("Code", str(code), off + 1, 1),
        node("Checksum", f"0x{csum:04x}", off + 2, 2),
    ]
    if typ in (0, 8) and off + 8 <= end:
        ident = u16(data, off + 4)
        seq = u16(data, off + 6)
        children.append(node("Identifier", str(ident), off + 4, 2))
        children.append(node("Sequence Number", str(seq), off + 6, 2))
        ctx.info = f"{tname} id={ident} seq={seq}"
    else:
        children.append(node("Rest of header", f"0x{rest:08x}", off + 4, 4 if off + 8 <= end else 0))
        ctx.info = f"{tname} code={code}"
    layers.append(node("Internet Control Message Protocol", summary=ctx.info,
                       offset=off, length=min(8, end - off), children=children))


def _icmpv6(data: bytes, off: int, end: int, layers: list, ctx: _Ctx) -> None:
    ctx.protocol = "ICMPv6"
    if not _ok(data, off, 4) or off + 4 > end:
        layers.append(node("ICMPv6", "截断", off, max(0, end - off)))
        return
    typ = data[off]
    code = data[off + 1]
    csum = u16(data, off + 2)
    typ_names = {
        1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded",
        4: "Parameter Problem", 128: "Echo Request", 129: "Echo Reply",
        133: "Router Solicitation", 134: "Router Advertisement",
        135: "Neighbor Solicitation", 136: "Neighbor Advertisement",
        137: "Redirect",
    }
    tname = typ_names.get(typ, f"Type {typ}")
    ctx.info = f"{tname} code={code}"
    children = [
        node("Type", f"{typ} ({tname})", off, 1),
        node("Code", str(code), off + 1, 1),
        node("Checksum", f"0x{csum:04x}", off + 2, 2),
    ]
    if typ in (128, 129) and off + 8 <= end:
        ident = u16(data, off + 4)
        seq = u16(data, off + 6)
        children.append(node("Identifier", str(ident), off + 4, 2))
        children.append(node("Sequence Number", str(seq), off + 6, 2))
        ctx.info = f"{tname} id={ident} seq={seq}"
    layers.append(node("Internet Control Message Protocol v6", summary=ctx.info,
                       offset=off, length=min(end - off, 8), children=children))


def _read_dns_name(msg: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    """返回 (名称, 紧随本名称编码之后的偏移，相对 msg)。"""
    if depth > 16 or off < 0 or off >= len(msg):
        return "<malformed>", off
    labels: list[str] = []
    jumped = False
    end = off
    hops = 0
    cur = off
    while cur < len(msg) and hops < 128:
        hops += 1
        length = msg[cur]
        if length == 0:
            if not jumped:
                end = cur + 1
            break
        if (length & 0xC0) == 0xC0:
            if cur + 1 >= len(msg):
                return "<malformed>", cur + 1
            ptr = ((length & 0x3F) << 8) | msg[cur + 1]
            if not jumped:
                end = cur + 2
            jumped = True
            if ptr >= len(msg) or ptr < 0:
                return "<malformed>", end
            name, _ = _read_dns_name(msg, ptr, depth + 1)
            if name and name != "<malformed>":
                labels.append(name)
            else:
                return "<malformed>", end
            break
        if (length & 0xC0) != 0:
            return "<malformed>", cur + 1
        if cur + 1 + length > len(msg):
            return "<malformed>", len(msg)
        lab = msg[cur + 1:cur + 1 + length]
        try:
            labels.append(lab.decode("idna", errors="replace"))
        except Exception:
            labels.append(lab.decode("latin-1", errors="replace"))
        cur += 1 + length
        if not jumped:
            end = cur
    if not labels:
        return ".", end
    # 指针展开时已是完整后缀，用点拼接即可
    name = labels[0] if len(labels) == 1 else ".".join(labels)
    # 若后缀已含点且前面还有标签，join 已处理
    if len(labels) > 1 and "." in labels[-1]:
        name = ".".join(labels[:-1] + [labels[-1]])
    return name, end


def _dns_rr(msg: bytes, off: int, abs_base: int) -> tuple[dict, int, str]:
    name, off2 = _read_dns_name(msg, off)
    name_len = off2 - off
    if off2 + 10 > len(msg):
        return node("RR", "截断", abs_base + off, max(0, len(msg) - off)), len(msg), ""
    typ = u16(msg, off2)
    cls = u16(msg, off2 + 2)
    ttl = u32(msg, off2 + 4)
    rdlen = u16(msg, off2 + 8)
    rdata_rel = off2 + 10
    typ_n = DNS_TYPES.get(typ, f"TYPE{typ}")
    if rdata_rel + rdlen > len(msg):
        return node(name or "<root>", f"{typ_n} 截断", abs_base + off, max(0, len(msg) - off)), len(msg), ""
    rdata = msg[rdata_rel:rdata_rel + rdlen]
    rdata_s = ""
    if typ == 1 and rdlen == 4:
        rdata_s = ipv4_str(rdata, 0)
    elif typ == 28 and rdlen == 16:
        rdata_s = ipv6_str(rdata, 0)
    elif typ in (2, 5, 12):
        rdata_s, _ = _read_dns_name(msg, rdata_rel)
    elif typ == 15 and rdlen >= 2:
        pref = u16(rdata, 0)
        exch, _ = _read_dns_name(msg, rdata_rel + 2)
        rdata_s = f"{pref} {exch}"
    elif typ == 16:
        parts = []
        i = 0
        while i < len(rdata):
            ln = rdata[i]
            parts.append(rdata[i + 1:i + 1 + ln].decode("utf-8", errors="replace"))
            i += 1 + ln
        rdata_s = " ".join(parts)
    else:
        rdata_s = rdata.hex() if rdata else ""
    summary = f"{name} {typ_n} {rdata_s}".strip()
    total = 10 + rdlen + name_len
    n = node(name or "<root>", f"{typ_n} {cls} TTL={ttl} {rdata_s}".strip(),
             abs_base + off, total, children=[
        node("Name", name, abs_base + off, name_len),
        node("Type", typ_n, abs_base + off2, 2),
        node("Class", str(cls), abs_base + off2 + 2, 2),
        node("TTL", str(ttl), abs_base + off2 + 4, 4),
        node("Data length", str(rdlen), abs_base + off2 + 8, 2),
        node("RDATA", rdata_s, abs_base + rdata_rel, rdlen),
    ])
    return n, rdata_rel + rdlen, summary


def _dns(data: bytes, off: int, end: int, layers: list, ctx: _Ctx) -> None:
    ctx.protocol = "DNS"
    msg = data[off:end]
    if len(msg) < 12:
        layers.append(node("Domain Name System", "截断", off, len(msg)))
        ctx.info = "DNS 截断"
        return
    tid = u16(msg, 0)
    flags = u16(msg, 2)
    qd = u16(msg, 4)
    an = u16(msg, 6)
    ns = u16(msg, 8)
    ar = u16(msg, 10)
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 1
    tc = (flags >> 9) & 1
    rd = (flags >> 8) & 1
    ra = (flags >> 7) & 1
    rcode = flags & 0xF
    opcode_n = {0: "Standard query", 1: "Inverse query", 2: "Status", 4: "Notify", 5: "Update"}.get(opcode, f"OPCODE {opcode}")
    rcode_n = {0: "No error", 1: "Format error", 2: "Server failure", 3: "NXDOMAIN",
               4: "Not implemented", 5: "Refused"}.get(rcode, str(rcode))
    children = [
        node("Transaction ID", f"0x{tid:04x}", off, 2),
        node("Flags", f"0x{flags:04x}", off + 2, 2, children=[
            node("Response", "Message is a response" if qr else "Message is a query", off + 2, 2),
            node("Opcode", opcode_n, off + 2, 2),
            node("Authoritative", str(bool(aa)), off + 2, 2),
            node("Truncated", str(bool(tc)), off + 2, 2),
            node("Recursion desired", str(bool(rd)), off + 2, 2),
            node("Recursion available", str(bool(ra)), off + 2, 2),
            node("Reply code", rcode_n, off + 2, 2),
        ]),
        node("Questions", str(qd), off + 4, 2),
        node("Answer RRs", str(an), off + 6, 2),
        node("Authority RRs", str(ns), off + 8, 2),
        node("Additional RRs", str(ar), off + 10, 2),
    ]
    cur = 12
    qnames = []
    qsec = []
    for _ in range(qd):
        name, cur2 = _read_dns_name(msg, cur)
        if cur2 + 4 > len(msg):
            break
        typ = u16(msg, cur2)
        cls = u16(msg, cur2 + 2)
        typ_n = DNS_TYPES.get(typ, f"TYPE{typ}")
        qnames.append(f"{typ_n} {name}")
        qsec.append(node("Query", f"{name} {typ_n}", off + cur, cur2 + 4 - cur, children=[
            node("Name", name, off + cur, cur2 - cur),
            node("Type", typ_n, off + cur2, 2),
            node("Class", str(cls), off + cur2 + 2, 2),
        ]))
        cur = cur2 + 4
    if qsec:
        children.append(node("Queries", f"{len(qsec)}", off + 12, max(0, cur - 12), children=qsec))
    ans_sum: list[str] = []

    def eat(count: int, title: str) -> None:
        nonlocal cur
        items = []
        start = cur
        for _ in range(count):
            if cur >= len(msg):
                break
            n, cur, sm = _dns_rr(msg, cur, off)
            items.append(n)
            if sm:
                ans_sum.append(sm)
        if items:
            children.append(node(title, str(len(items)), off + start, max(0, cur - start), children=items))

    eat(an, "Answers")
    eat(ns, "Authoritative nameservers")
    eat(ar, "Additional records")

    if qr:
        ctx.info = f"Standard query response 0x{tid:04x} " + " ".join(qnames)
        if ans_sum:
            ctx.info += " " + ", ".join(ans_sum[:4])
        if rcode:
            ctx.info += f" {rcode_n}"
    else:
        ctx.info = f"{opcode_n} 0x{tid:04x} " + " ".join(qnames)
    layers.append(node("Domain Name System", summary=ctx.info, offset=off, length=end - off, children=children))


def _http(payload: bytes, off: int, layers: list, ctx: _Ctx) -> None:
    ctx.protocol = "HTTP"
    text = payload.split(b"\r\n\r\n", 1)[0]
    header_len = len(text) + (4 if b"\r\n\r\n" in payload else 0)
    try:
        header = text.decode("iso-8859-1", errors="replace")
    except Exception:
        header = text.decode("latin-1", errors="replace")
    lines = header.split("\r\n") if "\r\n" in header else header.split("\n")
    if not lines:
        ctx.info = "HTTP"
        return
    start = lines[0].strip()
    ctx.info = start[:200]
    children = [node("Request/Status Line", start, off, min(len(lines[0]), header_len))]
    host = method = path = status = ""
    if start.startswith("HTTP/"):
        parts = start.split(" ", 2)
        if len(parts) >= 2:
            status = parts[1]
            children.append(node("Status Code", " ".join(parts[1:]), off, len(start)))
    else:
        parts = start.split(" ", 2)
        if parts:
            method = parts[0]
            children.append(node("Method", method, off, len(method)))
        if len(parts) >= 2:
            path = parts[1]
            children.append(node("Request URI", path, off, len(start)))
    cur = off + len(lines[0]) + 2
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            k, v = k.strip(), v.strip()
            children.append(node(k, v, cur, len(line)))
            if k.lower() == "host":
                host = v
        cur += len(line) + 2
    if method and host:
        ctx.info = f"{method} {path} HTTP/1.1  (Host: {host})" if not start.endswith(host) else start
        if host and "Host:" not in ctx.info and host:
            ctx.info = f"{method} {path}  Host: {host}"
    layers.append(node("Hypertext Transfer Protocol", summary=ctx.info,
                       offset=off, length=min(header_len, len(payload)), children=children))


def _tls(payload: bytes, off: int, layers: list, ctx: _Ctx) -> None:
    ctx.protocol = "TLS"
    cur = 0
    recs = []
    infos = []
    while cur + 5 <= len(payload):
        typ = payload[cur]
        ver = u16(payload, cur + 1)
        ln = u16(payload, cur + 3)
        typ_n = TLS_RECORD.get(typ, f"Type {typ}")
        ver_n = TLS_VER.get(ver, f"0x{ver:04x}")
        rec_off = off + cur
        frag_off = rec_off + 5
        take = min(ln, len(payload) - cur - 5)
        children = [
            node("Content Type", typ_n, rec_off, 1),
            node("Version", ver_n, rec_off + 1, 2),
            node("Length", str(ln), rec_off + 3, 2),
        ]
        extra = ""
        if typ == 22 and take >= 4:
            hs = payload[cur + 5]
            hs_len = u24(payload, cur + 6)
            hs_n = TLS_HS.get(hs, f"Handshake {hs}")
            children.append(node("Handshake Type", hs_n, frag_off, 1))
            children.append(node("Handshake Length", str(hs_len), frag_off + 1, 3))
            extra = hs_n
            if hs == 1:
                sni, hs_children, ok = _tls_client_hello(payload, cur + 5, take, frag_off)
                children.extend(hs_children)
                if sni:
                    extra = f"Client Hello (SNI: {sni})"
                elif not ok:
                    extra = "Client Hello（SNI 未解出）"
                else:
                    extra = "Client Hello"
            elif hs == 2:
                extra = "Server Hello"
                if take >= 6:
                    sh_ver = u16(payload, cur + 9) if cur + 11 <= len(payload) else ver
                    children.append(node("Legacy Version", TLS_VER.get(sh_ver, f"0x{sh_ver:04x}"), frag_off + 4, 2))
        elif typ == 22 and take < 4:
            extra = "Handshake（未解出，记录可能被分段）"
        elif typ == 23:
            extra = "Application Data"
        elif typ == 21:
            extra = "Alert"
        recs.append(node("TLS Record", summary=f"{typ_n}, {ver_n}" + (f", {extra}" if extra else ""),
                         offset=rec_off, length=5 + take, children=children))
        infos.append(extra or typ_n)
        cur += 5 + ln
        if ln == 0:
            break
        if cur > len(payload):
            break
    ctx.info = "; ".join(infos) if infos else "TLS"
    layers.append(node("Transport Layer Security", summary=ctx.info,
                       offset=off, length=min(cur, len(payload)) if recs else len(payload),
                       children=recs or [node("TLS", "未解出记录层", off, len(payload))]))


def _tls_client_hello(payload: bytes, hs_off: int, take: int, abs_hs: int) -> tuple[str | None, list, bool]:
    """hs_off 相对 payload，指向 handshake type。返回 (sni, children, parsed_ok)."""
    children: list = []
    # handshake header 4 bytes already consumed by caller visually; body starts at hs_off+4
    body = hs_off + 4
    end = hs_off + take
    if body + 34 > end:  # version + random
        return None, [node("ClientHello", "未解出（报文过短或被分段）", abs_hs, take)], False
    ver = u16(payload, body)
    children.append(node("Client Version", TLS_VER.get(ver, f"0x{ver:04x}"), abs_hs + 4, 2))
    children.append(node("Random", payload[body + 2:body + 34].hex(), abs_hs + 6, 32))
    cur = body + 34
    if cur + 1 > end:
        return None, children, False
    sid_len = payload[cur]
    if cur + 1 + sid_len > end:
        return None, children + [node("Session ID", "未解出", abs_hs + (cur - hs_off), 1)], False
    children.append(node("Session ID Length", str(sid_len), abs_hs + (cur - hs_off), 1))
    cur += 1 + sid_len
    if cur + 2 > end:
        return None, children, False
    cs_len = u16(payload, cur)
    cur += 2 + cs_len
    if cur > end:
        return None, children, False
    if cur + 1 > end:
        return None, children, False
    comp_len = payload[cur]
    cur += 1 + comp_len
    if cur + 2 > end:
        # 没有扩展也算解析成功
        return None, children, True
    ext_len = u16(payload, cur)
    ext_end = cur + 2 + ext_len
    children.append(node("Extensions Length", str(ext_len), abs_hs + (cur - hs_off), 2))
    cur += 2
    sni = None
    parsed = True
    while cur + 4 <= end and cur + 4 <= ext_end:
        et = u16(payload, cur)
        el = u16(payload, cur + 2)
        ev_off = cur + 4
        if ev_off + el > end:
            parsed = False
            children.append(node(f"Extension 0x{et:04x}", "未解出（截断）", abs_hs + (cur - hs_off), 4))
            break
        if et == 0:  # server_name
            sni, sni_nodes = _parse_sni(payload, ev_off, el, abs_hs + (ev_off - hs_off))
            children.append(node("Extension: server_name", sni or "未解出",
                                 abs_hs + (cur - hs_off), 4 + el, children=sni_nodes))
        elif et == 43:
            children.append(node("Extension: supported_versions", payload[ev_off:ev_off + el].hex(),
                                 abs_hs + (cur - hs_off), 4 + el))
        cur += 4 + el
    return sni, children, parsed


def _parse_sni(data: bytes, off: int, length: int, abs_off: int) -> tuple[str | None, list]:
    nodes = []
    if length < 5:
        return None, [node("server_name", "未解出", abs_off, length)]
    list_len = u16(data, off)
    cur = off + 2
    end = off + length
    sni = None
    if cur + 3 <= end:
        ntype = data[cur]
        nlen = u16(data, cur + 1)
        cur += 3
        if ntype == 0 and cur + nlen <= end:
            try:
                sni = data[cur:cur + nlen].decode("idna", errors="replace")
            except Exception:
                sni = data[cur:cur + nlen].decode("latin-1", errors="replace")
            nodes.append(node("Host Name", sni, abs_off + (cur - off), nlen))
        else:
            nodes.append(node("server_name", "未解出", abs_off, length))
    else:
        nodes.append(node("server_name", "未解出", abs_off, length))
    return sni, nodes


def _dhcp(data: bytes, off: int, end: int, layers: list, ctx: _Ctx) -> None:
    ctx.protocol = "DHCP"
    payload = data[off:end]
    if len(payload) < 44:
        layers.append(node("DHCP", "截断", off, len(payload)))
        return
    op = payload[0]
    xid = u32(payload, 4)
    yiaddr = ipv4_str(payload, 16)
    op_n = {1: "Boot Request", 2: "Boot Reply"}.get(op, str(op))
    chaddr = mac_str(payload, 28) if len(payload) >= 34 else ""
    msg_type = ""
    # options after magic cookie
    if len(payload) >= 240 and payload[236:240] == b"\x63\x82\x53\x63":
        i = 240
        while i < len(payload):
            code = payload[i]
            if code == 255:
                break
            if code == 0:
                i += 1
                continue
            if i + 1 >= len(payload):
                break
            ln = payload[i + 1]
            if code == 53 and ln >= 1 and i + 2 < len(payload):
                msg_type = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline",
                            5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}.get(payload[i + 2], str(payload[i + 2]))
            i += 2 + ln
    ctx.info = f"DHCP {msg_type or op_n} xid=0x{xid:08x}"
    if yiaddr != "0.0.0.0":
        ctx.info += f" Your IP: {yiaddr}"
    layers.append(node("Dynamic Host Configuration Protocol", summary=ctx.info,
                       offset=off, length=end - off, children=[
        node("Message type", f"{op} ({op_n})", off, 1),
        node("Transaction ID", f"0x{xid:08x}", off + 4, 4),
        node("Your IP", yiaddr, off + 16, 4),
        node("Client MAC", chaddr, off + 28, 6),
        node("DHCP Message", msg_type or "未解出 option 53", off, 0),
    ]))


def match_filter(summary: dict, query: str) -> bool:
    """简单显示过滤：空白分隔为 AND，支持 or；可按协议、地址、端口、关键字。"""
    q = (query or "").strip()
    if not q:
        return True
    q = re.sub(r"\s*==\s*", "==", q)
    parts = []
    buf = ""
    for tok in q.replace("||", " or ").split():
        if tok.lower() == "or":
            if buf:
                parts.append(buf)
                buf = ""
        else:
            buf += (" " + tok if buf else tok)
    if buf:
        parts.append(buf)
    if len(parts) > 1:
        return any(match_filter(summary, p) for p in parts)

    text = " ".join(str(summary.get(k, "") or "") for k in
                    ("src", "dst", "protocol", "info", "ip_src", "ip_dst")).lower()
    proto = str(summary.get("protocol") or "").lower()
    src = str(summary.get("src") or "")
    dst = str(summary.get("dst") or "")
    ip_src = str(summary.get("ip_src") or "")
    ip_dst = str(summary.get("ip_dst") or "")
    sport = summary.get("sport")
    dport = summary.get("dport")

    raw_tokens = q.split()
    tokens: list[str] = []
    i = 0
    while i < len(raw_tokens):
        t = raw_tokens[i]
        tl = t.lower()
        nxt = raw_tokens[i + 1] if i + 1 < len(raw_tokens) else ""
        if "==" not in t and tl in ("port", "tcp.port", "udp.port") and nxt:
            tokens.append("port:" + nxt)
            i += 2
            continue
        if "==" not in t and tl in ("host", "ip", "ip.addr", "addr") and nxt:
            tokens.append("host:" + nxt)
            i += 2
            continue
        if "==" not in t and tl in ("src", "ip.src") and nxt:
            tokens.append("ip.src==" + nxt)
            i += 2
            continue
        if "==" not in t and tl in ("dst", "ip.dst") and nxt:
            tokens.append("ip.dst==" + nxt)
            i += 2
            continue
        tokens.append(t)
        i += 1

    for tok in tokens:
        t = tok.strip()
        if not t:
            continue
        tl = t.lower()
        if "==" in t:
            k, _, v = t.partition("==")
            k, v = k.strip().lower(), v.strip()
            if k in ("ip.addr", "host", "ip", "addr"):
                if v not in (src, dst, ip_src, ip_dst):
                    return False
                continue
            if k in ("ip.src", "src"):
                if v not in (src, ip_src):
                    return False
                continue
            if k in ("ip.dst", "dst"):
                if v not in (dst, ip_dst):
                    return False
                continue
            if k in ("tcp.port", "udp.port", "port"):
                try:
                    n = int(v)
                except ValueError:
                    return False
                if n not in (sport, dport):
                    return False
                continue
        if tl in ("tcp", "udp", "dns", "http", "tls", "arp", "icmp", "icmpv6", "ipv4", "ipv6", "dhcp"):
            aliases = {"tls": ("tls", "ssl"), "http": ("http",), "icmp": ("icmp", "icmpv6")}
            names = aliases.get(tl, (tl,))
            if proto not in names and tl not in text:
                return False
            continue
        if tl.startswith("port:"):
            try:
                n = int(t.split(":", 1)[1])
            except ValueError:
                return False
            if n not in (sport, dport):
                return False
            continue
        if tl.startswith("host:"):
            h = t.split(":", 1)[1]
            if h not in (src, dst, ip_src, ip_dst) and h.lower() not in text:
                return False
            continue
        if t.isdigit():
            n = int(t)
            if n in (sport, dport) or t in text:
                continue
            return False
        if tl not in text and t not in src and t not in dst:
            return False
    return True
