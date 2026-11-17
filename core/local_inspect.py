"""本机路由表、ARP 表、网卡实时流量、NAT 类型检测。"""
from __future__ import annotations

import os
import random
import socket
import struct
import time

from .util import run_cmd, to_int


def _ps_rows(script: str, timeout=15):
    import base64
    import json
    import subprocess
    from .util import CREATE_NO_WINDOW
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    raw = (p.stdout or b"").decode("ascii", "ignore").strip()
    if not raw:
        return []
    try:
        data = json.loads(base64.b64decode(raw).decode("utf-8", "replace"))
    except (ValueError, json.JSONDecodeError):
        return []
    if isinstance(data, dict):
        data = [data]
    return data or []


def route_table(family: str = "all") -> dict:
    family = (family or "all").lower()
    rows = []
    if os.name == "nt":
        filt = ""
        if family == "4":
            filt = " | Where-Object { $_.AddressFamily -eq 2 -or $_.DestinationPrefix -match '\\.' }"
        elif family == "6":
            filt = " | Where-Object { $_.AddressFamily -eq 23 -or $_.DestinationPrefix -match ':' }"
        script = (
            "$r = Get-NetRoute -ErrorAction SilentlyContinue" + filt +
            " | Select-Object DestinationPrefix,NextHop,InterfaceAlias,InterfaceIndex,"
            "RouteMetric,InterfaceMetric,AddressFamily,Protocol,State; "
            "$j = ConvertTo-Json -InputObject @($r) -Compress -Depth 4; "
            "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j))"
        )
        for item in _ps_rows(script, 20):
            dest = str(item.get("DestinationPrefix") or "")
            if not dest:
                continue
            rows.append({
                "destination": dest,
                "gateway": str(item.get("NextHop") or "本机"),
                "interface": str(item.get("InterfaceAlias") or ""),
                "ifindex": item.get("InterfaceIndex") or "",
                "metric": item.get("RouteMetric") if item.get("RouteMetric") is not None else "",
                "ifmetric": item.get("InterfaceMetric") if item.get("InterfaceMetric") is not None else "",
                "protocol": str(item.get("Protocol") or ""),
                "family": "IPv6" if ":" in dest else "IPv4",
            })
        if not rows:
            rows = _parse_route_print(family)
    else:
        out, _ = run_cmd(["ip", "route"], 8)
        if not out:
            out, _ = run_cmd(["route", "-n"], 8)
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            rows.append({
                "destination": line, "gateway": "", "interface": "",
                "ifindex": "", "metric": "", "ifmetric": "", "protocol": "",
                "family": "IPv6" if ":" in line else "IPv4",
            })
    ipv4 = sum(1 for r in rows if r["family"] == "IPv4")
    ipv6 = sum(1 for r in rows if r["family"] == "IPv6")
    return {"rows": rows, "count": len(rows), "ipv4": ipv4, "ipv6": ipv6}


def _parse_route_print(family: str) -> list[dict]:
    out, _ = run_cmd(["route", "print"], 15)
    rows = []
    section = None
    for line in out.splitlines():
        s = line.strip()
        if "IPv4" in line and "Route" in line:
            section = "IPv4"
            continue
        if "IPv6" in line and "Route" in line:
            section = "IPv6"
            continue
        if not s or s.startswith("=") or s.startswith("---") or s.startswith("Network") or "目标" in s or "Active" in s:
            continue
        if family == "4" and section == "IPv6":
            continue
        if family == "6" and section == "IPv4":
            continue
        parts = s.split()
        if section == "IPv4" and len(parts) >= 5:
            rows.append({
                "destination": parts[0], "gateway": parts[2], "interface": parts[3],
                "ifindex": "", "metric": parts[4] if len(parts) > 4 else "",
                "ifmetric": "", "protocol": "", "family": "IPv4",
            })
        elif section == "IPv6" and len(parts) >= 3:
            rows.append({
                "destination": parts[2] if len(parts) > 2 else parts[0],
                "gateway": parts[3] if len(parts) > 3 else "",
                "interface": parts[0], "ifindex": "", "metric": parts[1] if len(parts) > 1 else "",
                "ifmetric": "", "protocol": "", "family": "IPv6",
            })
    return rows


def arp_table(query: str = "") -> dict:
    query = (query or "").strip().lower()
    rows = []
    if os.name == "nt":
        script = (
            "$r = Get-NetNeighbor -AddressFamily IPv4,IPv6 -ErrorAction SilentlyContinue "
            "| Where-Object { $_.Address -and $_.Address -notlike '224.*' -and $_.Address -notlike 'ff*' } "
            "| Select-Object IPAddress,LinkLayerAddress,InterfaceAlias,State,AddressFamily; "
            "$j = ConvertTo-Json -InputObject @($r) -Compress -Depth 4; "
            "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j))"
        )
        for item in _ps_rows(script, 15):
            ip = str(item.get("IPAddress") or "")
            mac = str(item.get("LinkLayerAddress") or "").replace("-", ":").upper()
            if not ip:
                continue
            rows.append({
                "ip": ip,
                "mac": mac or "—",
                "interface": str(item.get("InterfaceAlias") or ""),
                "state": str(item.get("State") or ""),
                "family": "IPv6" if ":" in ip else "IPv4",
            })
        if not rows:
            rows = _parse_arp_a()
    else:
        out, _ = run_cmd(["ip", "neigh"], 8)
        if not out:
            out, _ = run_cmd(["arp", "-an"], 8)
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            rows.append({
                "ip": line, "mac": "", "interface": "", "state": "",
                "family": "IPv6" if ":" in line else "IPv4",
            })
    if query:
        rows = [r for r in rows if query in (r["ip"] + " " + r["mac"] + " " + r["interface"] + " " + r["state"]).lower()]
    return {"rows": rows, "count": len(rows)}


def _parse_arp_a() -> list[dict]:
    out, _ = run_cmd(["arp", "-a"], 10)
    rows = []
    iface = ""
    for line in out.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.lower().startswith("interface") or s.startswith("接口"):
            iface = s.split(":", 1)[-1].strip()
            continue
        parts = s.split()
        if len(parts) < 2:
            continue
        ip, mac = parts[0], parts[1].replace("-", ":").upper()
        if mac.replace(":", "").lower() in ("000000000000", "ffffffffffff") or "internet" in ip.lower() or ip.lower() == "internet":
            continue
        typ = parts[2] if len(parts) > 2 else ""
        rows.append({"ip": ip, "mac": mac, "interface": iface, "state": typ, "family": "IPv6" if ":" in ip else "IPv4"})
    return rows


def _adapter_counters_windows() -> list[dict]:
    script = (
        "$a = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }; "
        "$s = Get-NetAdapterStatistics -ErrorAction SilentlyContinue; "
        "$rows = @(); "
        "foreach ($i in $a) { "
        "  $st = $s | Where-Object { $_.Name -eq $i.Name } | Select-Object -First 1; "
        "  if (-not $st) { continue }; "
        "  $rows += [pscustomobject]@{name=$i.Name; ifindex=$i.ifIndex; kind=[string]$i.MediaType; "
        "    speed=[string]$i.LinkSpeed; rx=[int64]$st.ReceivedBytes; tx=[int64]$st.SentBytes} "
        "}; "
        "$j = ConvertTo-Json -InputObject @($rows) -Compress -Depth 4; "
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j))"
    )
    rows = []
    for item in _ps_rows(script, 20):
        rows.append({
            "name": str(item.get("name") or ""),
            "ifindex": item.get("ifindex") or 0,
            "kind": str(item.get("kind") or ""),
            "speed": str(item.get("speed") or ""),
            "rx": int(item.get("rx") or 0),
            "tx": int(item.get("tx") or 0),
        })
    return rows


def _adapter_counters_posix() -> list[dict]:
    rows = []
    try:
        with open("/proc/net/dev", encoding="utf-8") as f:
            for line in f:
                if ":" not in line:
                    continue
                name, rest = line.split(":", 1)
                name = name.strip()
                if name == "lo":
                    continue
                parts = rest.split()
                if len(parts) < 9:
                    continue
                rows.append({
                    "name": name, "ifindex": 0, "kind": "", "speed": "",
                    "rx": int(parts[0]), "tx": int(parts[8]),
                })
    except OSError:
        pass
    return rows


def ifstat_stream(seconds: int | str = 0):
    seconds = to_int(seconds, 0, 0, 3600)
    yield {"type": "start", "seconds": seconds}
    prev = None
    prev_ts = None
    elapsed = 0
    while True:
        rows = _adapter_counters_windows() if os.name == "nt" else _adapter_counters_posix()
        now = time.monotonic()
        if prev is not None and prev_ts:
            dt = max(0.2, now - prev_ts)
            table = []
            total_rx = total_tx = 0
            for r in rows:
                p = prev.get(r["name"])
                if not p:
                    continue
                rx_bps = max(0, (r["rx"] - p["rx"]) / dt)
                tx_bps = max(0, (r["tx"] - p["tx"]) / dt)
                total_rx += rx_bps
                total_tx += tx_bps
                table.append({
                    "name": r["name"],
                    "kind": r.get("kind") or "",
                    "speed": r.get("speed") or "",
                    "down_bps": int(rx_bps),
                    "up_bps": int(tx_bps),
                    "down": r["rx"],
                    "up": r["tx"],
                })
            yield {
                "type": "sample",
                "elapsed": elapsed,
                "down_bps": int(total_rx),
                "up_bps": int(total_tx),
                "rows": table,
            }
        prev = {r["name"]: r for r in rows}
        prev_ts = now
        if seconds and elapsed >= seconds:
            break
        time.sleep(1)
        elapsed += 1
        if seconds and elapsed > seconds:
            break
    yield {"type": "done"}


# --------------- STUN / NAT ---------------

MAGIC = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_RESPONSE = 0x0101
XOR_MAPPED_ADDRESS = 0x0020
MAPPED_ADDRESS = 0x0001
CHANGE_REQUEST = 0x0003
XOR_RELAYED = 0x0016
OTHER_ADDRESS = 0x802C
CHANGED_ADDRESS = 0x0005

STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
]



def _pack_attr(typ: int, value: bytes) -> bytes:
    pad = (4 - (len(value) % 4)) % 4
    return struct.pack("!HH", typ, len(value)) + value + (b"\x00" * pad)


def _stun_request(change_ip=False, change_port=False) -> tuple[bytes, bytes]:
    tx = os.urandom(12)
    attrs = b""
    if change_ip or change_port:
        flags = 0
        if change_ip:
            flags |= 0x04
        if change_port:
            flags |= 0x02
        attrs += _pack_attr(CHANGE_REQUEST, struct.pack("!I", flags))
    body = struct.pack("!HHI", BINDING_REQUEST, len(attrs), MAGIC) + tx + attrs
    return body, tx


def _parse_addr(attr_type: int, value: bytes, txid: bytes):
    if len(value) < 4:
        return None
    family = value[1]
    port = struct.unpack("!H", value[2:4])[0]
    if attr_type in (XOR_MAPPED_ADDRESS, OTHER_ADDRESS):
        port ^= (MAGIC >> 16) & 0xFFFF
        if family == 0x01 and len(value) >= 8:
            ip_int = struct.unpack("!I", value[4:8])[0] ^ MAGIC
            ip = socket.inet_ntoa(struct.pack("!I", ip_int))
            return ip, port
        if family == 0x02 and len(value) >= 20:
            xored = bytes(a ^ b for a, b in zip(value[4:20], struct.pack("!I", MAGIC) + txid))
            ip = socket.inet_ntop(socket.AF_INET6, xored)
            return ip, port
    else:
        if family == 0x01 and len(value) >= 8:
            ip = socket.inet_ntoa(value[4:8])
            return ip, port
        if family == 0x02 and len(value) >= 20:
            ip = socket.inet_ntop(socket.AF_INET6, value[4:20])
            return ip, port
    return None


def _parse_stun(data: bytes, txid: bytes) -> dict:
    if len(data) < 20:
        return {}
    typ, length, magic = struct.unpack("!HHI", data[:8])
    if data[8:20] != txid or typ != BINDING_RESPONSE:
        return {}
    pos = 20
    end = 20 + length
    out = {}
    while pos + 4 <= len(data) and pos < end:
        atype, alen = struct.unpack("!HH", data[pos:pos + 4])
        pos += 4
        val = data[pos:pos + alen]
        pos += alen + ((4 - (alen % 4)) % 4)
        addr = _parse_addr(atype, val, txid)
        if atype == XOR_MAPPED_ADDRESS and addr:
            out["mapped"] = addr
        elif atype == MAPPED_ADDRESS and "mapped" not in out and addr:
            out["mapped"] = addr
        elif atype in (OTHER_ADDRESS, CHANGED_ADDRESS) and addr:
            out["other"] = addr
    return out


def _stun_query(host: str, port: int, sock: socket.socket, change_ip=False, change_port=False, timeout=2.2):
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
    except socket.gaierror:
        return None
    if not infos:
        return None
    dest = infos[0][4]
    req, txid = _stun_request(change_ip, change_port)
    sock.settimeout(timeout)
    try:
        sock.sendto(req, dest)
        while True:
            data, addr = sock.recvfrom(2048)
            parsed = _parse_stun(data, txid)
            if parsed:
                parsed["server"] = dest
                parsed["from"] = addr
                return parsed
    except (socket.timeout, OSError):
        return None


def _local_ipv4() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        s.close()


def nat_detect() -> dict:
    """RFC 3489 风格的 NAT 类型探测。CHANGE-REQUEST 若不被服务器支持会如实说明。"""
    logs = []
    local_ip = _local_ipv4()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", 0))
        local_port = sock.getsockname()[1]
        logs.append(f"本机 UDP {local_ip}:{local_port}")

        first = None
        server_used = None
        for host, port in STUN_SERVERS:
            logs.append(f"向 {host}:{port} 发送 Binding 请求…")
            first = _stun_query(host, port, sock)
            if first and first.get("mapped"):
                server_used = (host, port)
                logs.append(f"映射地址 {first['mapped'][0]}:{first['mapped'][1]}（{host}）")
                break
            logs.append(f"{host} 无响应")

        if not first or not first.get("mapped"):
            return {
                "type": "UDP 被拦截",
                "summary": "STUN 无响应，本机 UDP 可能被防火墙拦截，或当前网络无法访问公用 STUN 服务器。",
                "local": f"{local_ip}:{local_port}",
                "mapped": "",
                "mapped2": "",
                "logs": logs,
            }

        mapped = first["mapped"]
        same_as_local = mapped[0] == local_ip  # port usually differs even without NAT if we compare IP

        # Second server for symmetric check
        second = None
        for host, port in STUN_SERVERS:
            if server_used and (host, port) == server_used:
                continue
            logs.append(f"向第二台 {host}:{port} 发送 Binding 请求…")
            second = _stun_query(host, port, sock)
            if second and second.get("mapped"):
                logs.append(f"第二映射 {second['mapped'][0]}:{second['mapped'][1]}（{host}）")
                break
            logs.append(f"{host} 无响应")

        change_both = _stun_query(server_used[0], server_used[1], sock, True, True)
        if change_both and change_both.get("mapped"):
            logs.append("CHANGE-REQUEST（改 IP+端口）有响应")
        else:
            logs.append("CHANGE-REQUEST（改 IP+端口）无响应（不少公用 STUN 不支持该属性）")

        change_port = _stun_query(server_used[0], server_used[1], sock, False, True)
        if change_port and change_port.get("mapped"):
            logs.append("CHANGE-REQUEST（仅改端口）有响应")
        else:
            logs.append("CHANGE-REQUEST（仅改端口）无响应")

        mapped2 = second["mapped"] if second and second.get("mapped") else None

        if mapped[0] == local_ip:
            if change_both:
                typ = "公网 / 无 NAT"
                summary = "映射地址与本机公网地址一致，且能收到改写源地址的响应，像是直接暴露在公网。"
            else:
                typ = "公网或防火墙"
                summary = "映射地址与本机 IP 一致，但未收到 CHANGE-REQUEST 响应：可能是无 NAT，也可能是防火墙拦截了服务器从另一地址的回包。"
        elif mapped2 and (mapped2[0], mapped2[1]) != (mapped[0], mapped[1]):
            typ = "对称型 NAT（Symmetric）"
            summary = "两台 STUN 服务器看到的映射地址或端口不同。P2P 打洞较困难，适合走中继。"
        elif change_both:
            typ = "完全锥型 NAT（Full Cone）"
            summary = "NAT 后地址固定，且能接受来自任意主机的入站包（在映射存续期内）。"
        elif change_port:
            typ = "限制锥型 NAT（Restricted Cone）"
            summary = "映射地址固定，但只接受曾经向其发过包的对端 IP 的回包。"
        elif change_both is None and change_port is None and mapped2 and (mapped2[0], mapped2[1]) == (mapped[0], mapped[1]):
            typ = "锥型 NAT"
            summary = "两台服务器看到相同映射，属于锥型 NAT；当前 STUN 服务器不支持 CHANGE-REQUEST，无法进一步区分完全锥 / 限制锥 / 端口限制锥。"
        else:
            typ = "端口限制锥型 NAT（Port Restricted Cone）"
            summary = "映射地址固定，只接受曾经向其「同一端口」发过包的对端回包。"

        return {
            "type": typ,
            "summary": summary,
            "local": f"{local_ip}:{local_port}",
            "mapped": f"{mapped[0]}:{mapped[1]}",
            "mapped2": f"{mapped2[0]}:{mapped2[1]}" if mapped2 else "",
            "server": f"{server_used[0]}:{server_used[1]}",
            "logs": logs,
        }
    finally:
        sock.close()
