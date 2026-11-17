"""传统规则生成的报文分析与整次抓包离线诊断。不调用任何在线模型。"""
from __future__ import annotations

import base64
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
    4: "需要分片但设置了 DF", 13: "通信被管理员禁止",
}
ICMP6 = {
    1: "目的不可达", 2: "报文过大", 3: "超时", 4: "参数问题",
    128: "回显请求", 129: "回显应答",
    133: "路由器请求", 134: "路由器通告",
    135: "邻居请求", 136: "邻居通告",
}

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
        app["dns"] = {
            "response": is_resp, "qname": qname.rstrip("."), "qtype": qtype,
            "rcode": rcode, "answers": answers[:8],
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
        app["tls"] = {"record": rec, "version": ver, "handshake": hs, "sni": sni}

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
        app["icmp"] = {
            "type": typ, "code": code, "name": typ_s or info,
            "v6": proto == "ICMPv6" or (icmp and "v6" in (icmp.get("name") or "").lower()),
        }

    arp = _find_layer(layers, "address resolution protocol")
    if arp or proto == "ARP":
        op = _child_val(arp, "opcode") or _child_val(arp, "operation") or info
        spa = _child_val(arp, "sender ip") or view.get("src") or ""
        tpa = _child_val(arp, "target ip") or view.get("dst") or ""
        sha = _child_val(arp, "sender mac")
        app["arp"] = {"op": op, "spa": spa, "tpa": tpa, "sha": sha}

    return app


def _checksum_hints(view: dict, raw: bytes) -> list[dict]:
    hints = []
    if not raw:
        return hints
    caplen = int(view.get("caplen") or len(raw))
    wire = int(view.get("length") or caplen)
    if caplen < wire:
        # 截断时不做传输层校验
        truncated = True
    else:
        truncated = False
    ip = _find_layer(view.get("layers") or [], "internet protocol version 4")
    if ip:
        off = int(ip.get("offset") or 0)
        ihl = int(ip.get("length") or 20)
        ok = _verify_ipv4(raw, off, ihl)
        if ok is False:
            hints.append({"level": "error", "text": "IPv4 首部校验和异常。"})
        tcp = _find_layer(view.get("layers") or [], "transmission control protocol")
        udp = _find_layer(view.get("layers") or [], "user datagram protocol")
        if not truncated and tcp:
            t_off = int(tcp.get("offset") or 0)
            payload_len = int(view.get("payload_len") or 0)
            # TCP 层 length 是首部，加上载荷才是校验范围
            t_end = t_off + int(tcp.get("length") or 20) + payload_len
            t_end = min(t_end, len(raw))
            ok4 = _verify_l4_ipv4(raw, off, ihl, 6, t_off, t_end)
            if ok4 is False:
                hints.append({"level": "error", "text": "TCP 校验和异常。"})
        if not truncated and udp:
            u_off = int(udp.get("offset") or 0)
            u_len = int(udp.get("length") or 8)
            # UDP 节点 length 可能只是 8 字节首部，用首部中的长度字段更准
            if u_off + 6 <= len(raw):
                declared = int.from_bytes(raw[u_off + 4:u_off + 6], "big") or u_len
                u_end = min(u_off + declared, len(raw))
                csum = int.from_bytes(raw[u_off + 6:u_off + 8], "big")
                if csum != 0:  # 0 表示未计算
                    ok4 = _verify_l4_ipv4(raw, off, ihl, 17, u_off, u_end)
                    if ok4 is False:
                        hints.append({"level": "error", "text": "UDP 校验和异常。"})
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
        if not flags and (p.get("l4") or p.get("protocol") or "").upper() not in (
            "TCP", "HTTP", "TLS", "SSL"
        ):
            continue
        # 应用层协议也是 TCP 载荷
        is_tcp = (p.get("l4") == "TCP") or (p.get("tcp_flags") is not None) or (
            (p.get("protocol") or "").upper() in ("TCP", "HTTP", "TLS", "SSL")
        )
        if not is_tcp:
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

    if proto == "ARP" or app.get("arp"):
        arp = app.get("arp") or {}
        op = (arp.get("op") or view.get("info") or "")
        spa = arp.get("spa") or view.get("src") or ""
        tpa = arp.get("tpa") or view.get("dst") or ""
        sha = arp.get("sha") or ""
        ev = ev_end + (f"；{op}" if op else "")
        if "who has" in op.lower() or "request" in op.lower() or "请求" in op:
            add("info", "ARP 请求", f"{spa} 询问 {tpa} 的 MAC 地址。", ev)
            add("info", "局域网地址解析", "ARP 请求通常以广播发送，用于在局域网解析 IPv4 地址对应的硬件地址。")
        elif "is at" in op.lower() or "reply" in op.lower() or "应答" in op or "响应" in op:
            add("info", "ARP 应答", f"{spa} 宣称其 MAC 为 {sha or '（见字段）'}，回答对 {tpa} 的查询。", ev)
            add("info", "地址绑定", "ARP 应答把 IP 与 MAC 的对应关系告诉请求方。")
        else:
            add("info", "ARP 报文", summary or f"这是一条 ARP 报文，从 {src} 到 {dst}。", ev)

    elif proto in ("ICMP", "ICMPV6") or app.get("icmp"):
        icmp = app.get("icmp") or {}
        typ = icmp.get("type")
        code = icmp.get("code")
        v6 = proto == "ICMPv6" or icmp.get("v6")
        kind = "ICMPv6" if v6 else "ICMP"
        ev = ev_end + (f"；类型 {typ}，代码 {code}" if typ is not None else "")
        if typ == 3 and not v6:
            extra = ICMP4_UNREACH.get(code, f"代码 {code}")
            add("warn", "目的不可达", f"这是一条 ICMP 目的不可达报文，从 {src} 到 {dst}，含义是{extra}。", ev)
        elif typ == 1 and v6:
            add("warn", "目的不可达", f"这是一条 ICMPv6 目的不可达报文，从 {src} 到 {dst}。", ev)
        elif typ in (8, 128):
            add("info", f"{kind} 回显请求", f"这是一条 {kind} 回显请求（ping），从 {src} 到 {dst}，用于探测对端是否可达。", ev)
        elif typ in (0, 129):
            add("info", f"{kind} 回显应答", f"这是一条 {kind} 回显应答，从 {src} 到 {dst}，是对先前 ping 请求的回复。", ev)
        else:
            table = ICMP6 if v6 else ICMP4
            name = table.get(typ, icmp.get("name") or kind)
            add("info", f"{kind} 报文", summary or f"这是一条 {kind} 报文（{name}），从 {src} 到 {dst}。", ev)
        if ttl is not None:
            add("info", "生存时间", f"TTL / Hop Limit 为 {ttl}。")

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
                add("warn", "DNS 响应码", f"响应码为 {rcode}。", rcode)
            elif answers:
                add("info", "解析结果", f"应答记录：{answers}。", ev)
            else:
                add("info", "应答记录", "应答中未见已解出的资源记录，或记录类型未解析。")
        else:
            add("info", "DNS 查询", f"这是一条 DNS 查询，从 {src} 到 {dst}，询问 {qt} {qn}。", ev)
            add("info", "查询内容", f"查询类型 {qt}，名称 {qn}。")

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
                add("info", "目标主机", f"目标主机 {host}。", f"Host: {host}")
        elif status:
            level = "info"
            try:
                code = int(str(status).split()[0])
                if code >= 400:
                    level = "warn"
            except (TypeError, ValueError):
                pass
            add(level, "HTTP 响应", f"这是一条 HTTP 响应，从 {src} 到 {dst}，状态 {status}。", ev_end + f"；{status}")
        else:
            add("info", "HTTP 报文", summary or f"这是一条 HTTP 报文，从 {src} 到 {dst}。", ev_end)
        if is_tcp and flag_names:
            add("info", "TCP 承载", f"承载在 TCP 上，标志为 {'、'.join(flag_names)}，载荷 {plen} 字节。", ev_flags)

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
                add("info", "访问主机名", f"客户端在握手中声明要访问的主机名（SNI）是 {sni}。", f"SNI={sni}")
            add("info", "不解密内容", "只能看到握手明文字段；加密后的应用数据不会被解密。")
        elif "server hello" in blob:
            add("info", "TLS ServerHello", f"这是一条 TLS ServerHello，从 {src} 到 {dst}。本工具不解密 TLS 内容。", ev_end)
            if tls.get("version"):
                add("info", "TLS 版本字段", f"记录或遗留版本字段为 {tls.get('version')}。")
        elif "application data" in ((rec or "") + (view.get("info") or "")).lower():
            add("info", "TLS 应用数据", f"这是一条 TLS 应用数据，从 {src} 到 {dst}。内容已加密，本工具不解密。", ev_end)
        else:
            extra = hs_name or rec or view.get("info") or "握手或记录未完全解出"
            add("info", "TLS 报文", f"这是一条 TLS 报文，从 {src} 到 {dst}（{extra}）。本工具不解密 TLS 内容。", ev_end)

    elif is_tcp or proto == "TCP":
        role = _this_packet_role(view, hs, peers)
        ev = "；".join(x for x in (ev_end, ev_flags, ev_seq) if x)
        if _has(flags, "RST"):
            add("warn", "RST 中止连接", role or "这条报文用 RST 中止连接。", ev)
        elif _has(flags, "SYN") and not _has(flags, "ACK"):
            add("info", "三次握手第 1 拍", role or "这是 TCP 三次握手的第一拍（SYN），用于发起连接。", ev)
        elif _has(flags, "SYN") and _has(flags, "ACK"):
            add("info", "三次握手第 2 拍", role or "这是 TCP 三次握手的第二拍（SYN-ACK），对端同意建立连接。", ev)
        elif _has(flags, "FIN"):
            add("info", "连接正在关闭", role or "这是 TCP FIN+ACK，连接正在关闭。", ev)
        elif (
            _has(flags, "ACK")
            and not _has(flags, "SYN")
            and plen == 0
            and not _has(flags, "PSH")
            and not _has(flags, "FIN")
            and not _has(flags, "RST")
        ):
            if hs.get("syn") and hs.get("synack") and hs.get("ack_no") == view.get("no"):
                add("info", "三次握手第 3 拍", role or "这是 TCP 三次握手的第三拍（ACK），连接随后可以传输数据。", ev)
            else:
                add("info", "纯 ACK", role or "这是一条无载荷的纯 ACK，用于确认对端已收到的数据或控制报文。", ev)
        elif plen > 0:
            add("info", "携带有效载荷", role or f"这条报文携带有效载荷，共 {plen} 字节。", ev)
        else:
            add("info", "TCP 报文", role or summary or f"这是一条 TCP 报文，从 {src} 到 {dst}。", ev)
        if ev_flags:
            add("info", "TCP 标志", "TCP 标志：" + "、".join(flag_names) + "。", ev_seq or ev_flags)
        if window is not None:
            add("info", "通告窗口", f"通告窗口为 {window}。")
        if peers and hs:
            if hs.get("complete"):
                add("info", "流状态", "同一条流里已能看到完整或已在传输数据的握手过程。")
            elif hs.get("syn") and not hs.get("synack"):
                add("info", "流状态", "同一条流目前只见到 SYN，还没有看到 SYN-ACK。")
            elif hs.get("syn") and hs.get("synack") and not hs.get("ack"):
                add("info", "流状态", "同一条流已有 SYN 与 SYN-ACK，尚未看到第三拍 ACK。")

    elif proto == "UDP":
        add("info", "UDP 报文", summary or f"这是一条 UDP 报文，从 {src} 到 {dst}，载荷 {plen} 字节。", ev_end)
        add("info", "已识别到的层次", "已识别到 UDP。若端口不是常见协议，载荷未再往上解析。")
        sport, dport = view.get("sport"), view.get("dport")
        if sport not in (53, 5353) and dport not in (53, 5353, 67, 68, 123, 161, 162, 443, 853):
            add("info", "上层未解析", "其余上层协议未能解析，不假装已分析出应用内容。")

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

    # 通常保留 2～5 条，告警优先不被截掉
    if len(out) > 5:
        warns = [c for c in out if c["level"] in ("error", "warn")]
        infos = [c for c in out if c["level"] not in ("error", "warn")]
        keep = (warns + infos)[:5]
        # 保持相对原顺序
        order = {id(c): i for i, c in enumerate(out)}
        keep.sort(key=lambda c: order.get(id(c), 0))
        out = keep
    return out


def analyze_packet(view: dict, *, raw: Any = None, stream: list[dict] | None = None) -> dict:
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
    flags = int(view.get("tcp_flags") or 0)
    flag_names = _flag_names(flags)
    plen = int(view.get("payload_len") or 0)
    is_tcp = (view.get("l4") == "TCP") or (view.get("tcp_flags") is not None) or proto in (
        "TCP", "HTTP", "TLS", "SSL"
    )

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
            p.get("tcp_flags") is not None or p.get("l4") == "TCP" for p in pkts
        ):
            tcp_streams.append((key, pkts))

    complete = incomplete_syn = half = closing = reset = 0
    ev_complete = []
    ev_incomp = []
    ev_half = []
    ev_close = []
    ev_rst = []
    ev_retrans = []
    ev_zero = []
    ev_csum = []

    for key, pkts in tcp_streams:
        hs = _handshake_state(pkts)
        label = _stream_label(pkts[0])
        nos = ",".join(str(p.get("no")) for p in pkts[:8])
        if len(pkts) > 8:
            nos += "…"
        if hs["rst"]:
            reset += 1
            ev_rst.append(f"{label}（第 {hs['rst_no']} 号出现 RST）")
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
            ev_incomp.append(f"{label}（仅有 SYN，序号 {nos}）")
        else:
            # 只有 ACK/数据片段、没有看到开头，当作已在传输
            if any(int(p.get("payload_len") or 0) > 0 or _has(int(p.get("tcp_flags") or 0), "ACK") for p in pkts):
                complete += 1
                ev_complete.append(f"{label}（抓包窗口内未见完整握手，但已有确认或数据，序号 {nos}）")

        # 重传 / 零窗口（只在本集合内判断）
        seen_seq: dict[tuple, int] = {}
        for p in sorted(pkts, key=lambda x: (x.get("ts") or 0, x.get("no") or 0)):
            flags = int(p.get("tcp_flags") or 0)
            win = p.get("tcp_window")
            if win == 0 and _has(flags, "ACK") and not _has(flags, "RST"):
                ev_zero.append(f"{label} 第 {p.get('no')} 号通告窗口为 0")
            plen = int(p.get("payload_len") or 0)
            seq = p.get("tcp_seq")
            if seq is None:
                continue
            dir_key = (p.get("ip_src") or p.get("src"), p.get("sport"), plen, int(seq))
            if plen > 0 or _has(flags, "SYN") or _has(flags, "FIN"):
                prev = seen_seq.get((p.get("ip_src") or p.get("src"), p.get("sport"), int(seq), plen))
                if prev is not None:
                    ev_retrans.append(f"{label} 第 {p.get('no')} 号与第 {prev} 号 Seq={seq} 相同，可能为重传")
                else:
                    seen_seq[(p.get("ip_src") or p.get("src"), p.get("sport"), int(seq), plen)] = p.get("no")

    if tcp_streams:
        detail = f"共观察到 {len(tcp_streams)} 条 TCP 会话。"
        if complete:
            detail += f" 其中 {complete} 条已完成三次握手，或抓包窗口内已在传输数据。"
        if incomplete_syn:
            detail += f" 有 {incomplete_syn} 条只看到 SYN、未见 SYN-ACK，握手可能未完成或应答未被抓到。"
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
        conclusions.append({
            "level": "warn",
            "title": "连接被重置",
            "detail": f"有 {reset} 条 TCP 会话出现 RST，连接被中止。",
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
        conclusions.append({
            "level": "warn",
            "title": "零窗口",
            "detail": f"发现 {len(ev_zero)} 个通告窗口为 0 的 TCP 报文，接收方可能暂缓收数据。",
            "evidence": "；".join(ev_zero[:6]),
        })

    # 应用层事实
    http_reqs = []
    http_st = []
    dns_q = []
    dns_bad = []
    sni = []
    icmp_unreach = []
    for v in views:
        app = _extract_app(v)
        if app.get("http"):
            h = app["http"]
            if h.get("method"):
                http_reqs.append(
                    f"第 {v.get('no')} 号 {h.get('method')} {h.get('path') or '/'} Host={h.get('host') or '?'}"
                )
            if h.get("status"):
                http_st.append(f"第 {v.get('no')} 号 {h.get('status')}")
        if app.get("dns"):
            d = app["dns"]
            qn = d.get("qname") or ""
            if d.get("response"):
                rcode = (d.get("rcode") or "")
                if rcode and rcode.lower() not in ("no error", "0", "noerror", ""):
                    dns_bad.append(f"第 {v.get('no')} 号 {qn} {rcode}")
            elif qn:
                dns_q.append(qn)
        if app.get("tls") and app["tls"].get("sni"):
            sni.append(app["tls"]["sni"])
        icmp = app.get("icmp")
        if icmp and icmp.get("type") in (3, 1):
            icmp_unreach.append(f"第 {v.get('no')} 号 {v.get('info') or '目的不可达'}")

    if http_reqs or http_st:
        detail = ""
        if http_reqs:
            detail += f"见到 {len(http_reqs)} 条 HTTP 请求。"
        if http_st:
            detail += f" 见到 {len(http_st)} 条 HTTP 响应。"
        conclusions.append({
            "level": "info",
            "title": "HTTP",
            "detail": detail.strip(),
            "evidence": "；".join((http_reqs + http_st)[:8]),
        })
    if dns_q or dns_bad:
        uniq = list(dict.fromkeys(dns_q))
        detail = f"见到对 {len(uniq)} 个不同名称的 DNS 查询" if uniq else "见到 DNS 报文"
        if dns_bad:
            detail += f"，其中 {len(dns_bad)} 条应答含错误码。"
        else:
            detail += "。"
        conclusions.append({
            "level": "warn" if dns_bad else "info",
            "title": "DNS",
            "detail": detail,
            "evidence": "查询：" + "、".join(uniq[:8]) + (("；异常：" + "；".join(dns_bad[:4])) if dns_bad else ""),
        })
    if sni:
        uniq = list(dict.fromkeys(sni))
        conclusions.append({
            "level": "info",
            "title": "TLS SNI",
            "detail": f"在 ClientHello 中解出 {len(uniq)} 个服务器名称（不解密 TLS 内容）。",
            "evidence": "、".join(uniq[:10]),
        })
    if icmp_unreach:
        conclusions.append({
            "level": "warn",
            "title": "ICMP 目的不可达",
            "detail": f"发现 {len(icmp_unreach)} 条目的不可达报文。",
            "evidence": "；".join(icmp_unreach[:6]),
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
