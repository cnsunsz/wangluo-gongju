"""TCP Ping、扫描、诊断、WHOIS、iperf3、无线与 NTP 等扩展工具。"""
from __future__ import annotations

import ipaddress
import os
import queue
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from .paths import exe_dir, resource_dir
from .util import CREATE_NO_WINDOW, decode_output, parse_ports, run_cmd, safe_host, to_int
from . import procs

RE_MAC = re.compile(r"([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}")
WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "cn": "whois.cnnic.cn",
    "io": "whois.nic.io",
    "xyz": "whois.nic.xyz",
    "top": "whois.nic.top",
    "cc": "ccwhois.verisign-grs.com",
}


def _stats(sent, rtts):
    recv = len(rtts)
    loss = round((sent - recv) * 100.0 / sent, 1) if sent else 0.0
    if not rtts:
        return {"sent": sent, "recv": 0, "loss": loss, "min": 0.0, "avg": 0.0, "max": 0.0, "jitter": 0.0}
    avg = sum(rtts) / len(rtts)
    jitter = (
        sum(abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))) / (len(rtts) - 1)
        if len(rtts) > 1 else 0.0
    )
    return {
        "sent": sent, "recv": recv, "loss": loss,
        "min": round(min(rtts), 1), "avg": round(avg, 1),
        "max": round(max(rtts), 1), "jitter": round(jitter, 1),
    }


def tcp_ping_stream(host, port=80, count=4, timeout=2, interval=1.0):
    host = safe_host(host)
    port = to_int(port, 80, 1, 65535)
    count = to_int(count, 4, 0, 1000)
    try:
        timeout = max(0.2, min(10, float(timeout)))
    except (TypeError, ValueError):
        timeout = 2
    try:
        interval = max(0.2, min(10, float(interval)))
    except (TypeError, ValueError):
        interval = 1.0
    yield {"type": "start", "host": host, "port": port, "count": count}
    sent, rtts = 0, []
    try:
        while True:
            sent += 1
            t0 = time.perf_counter()
            ok, err, ms = True, "", None
            try:
                sock = socket.create_connection((host, port), timeout=timeout)
                sock.close()
                ms = round((time.perf_counter() - t0) * 1000, 2)
                rtts.append(ms)
            except OSError as e:
                ok = False
                if isinstance(e, TimeoutError) or "timed out" in str(e).lower():
                    err = getattr(e, "strerror", None) or str(e)
                else:
                    err = e.strerror or type(e).__name__
                ms = round((time.perf_counter() - t0) * 1000, 2)
            yield {"type": "reply", "seq": sent, "ok": ok, "ms": ms, "error": err}
            stats = _stats(sent, rtts)
            yield {"type": "stats", **stats}
            if count and sent >= count:
                break
            time.sleep(interval)
    except GeneratorExit:
        return
    yield {"type": "done", **_stats(sent, rtts)}


def telnet_probe(host, port=23, timeout=5, send=""):
    host = safe_host(host)
    port = to_int(port, 23, 1, 65535)
    try:
        timeout = max(0.5, min(30, float(timeout)))
    except (TypeError, ValueError):
        timeout = 5
    t0 = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        ms = round((time.perf_counter() - t0) * 1000, 1)
        if isinstance(e, TimeoutError) or "timed out" in str(e).lower():
            err = "连接超时（端口未开放或被防火墙拦截）"
        elif isinstance(e, ConnectionRefusedError):
            err = "连接被拒绝（端口未开放）"
        else:
            err = e.strerror or type(e).__name__
        return {"host": host, "port": port, "ok": False, "ms": ms, "banner": "", "error": err}
    ms = round((time.perf_counter() - t0) * 1000, 1)
    banner = ""
    try:
        sock.settimeout(1.0)
        if send:
            sock.sendall((send + "\r\n").encode("utf-8", "replace"))
        data = sock.recv(2048)
        banner = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", data.decode("utf-8", "replace")).strip()
    except OSError:
        banner = ""
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return {"host": host, "port": port, "ok": True, "ms": ms, "banner": banner, "error": ""}


def wol(mac, broadcast="255.255.255.255", port=9):
    raw = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    if len(raw) != 12:
        raise ValueError("MAC 格式不正确，如 AA:BB:CC:DD:EE:FF")
    mac_bytes = bytes.fromhex(raw)
    packet = b"\xff" * 6 + mac_bytes * 16
    broadcast = broadcast or "255.255.255.255"
    try:
        ipaddress.IPv4Address(broadcast)
    except ValueError as e:
        raise ValueError("广播地址格式不正确") from e
    port = to_int(port, 9, 1, 65535)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(packet, (broadcast, port))
    finally:
        sock.close()
    pretty = ":".join(raw[i:i + 2].upper() for i in range(0, 12, 2))
    return {"mac": pretty, "broadcast": broadcast, "port": port, "bytes": len(packet)}


def _ping_host(ip, timeout_ms):
    from .ping import ping_once
    r = ping_once(ip, 4, 32, timeout_ms)
    return bool(r.get("ok")), r.get("rtt")


def ip_scan(cidr, timeout_ms=600, workers=64):
    try:
        net = ipaddress.ip_network((cidr or "").strip(), strict=False)
    except ValueError as e:
        raise ValueError("网段格式不正确，如 192.168.1.0/24") from e
    if net.version != 4:
        raise ValueError("仅支持 IPv4 网段")
    if net.num_addresses > 1024:
        raise ValueError("单次最多 1024 个地址（/22 及更小）")
    hosts = [str(h) for h in net.hosts()]
    if not hosts:
        raise ValueError("该网段没有可用地址")
    timeout_ms = to_int(timeout_ms, 600, 100, 5000)
    workers = to_int(workers, 64, 8, 256)
    started = time.perf_counter()
    alive = []
    with ThreadPoolExecutor(max_workers=min(workers, len(hosts))) as pool:
        for ip, (ok, rtt) in zip(hosts, pool.map(lambda h: _ping_host(h, timeout_ms), hosts)):
            if ok:
                alive.append({"ip": ip, "rtt": rtt})
    return {
        "cidr": str(net),
        "scanned": len(hosts),
        "alive": alive,
        "duration": round(time.perf_counter() - started, 1),
    }


def _gateway():
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop"],
            capture_output=True, timeout=10, creationflags=CREATE_NO_WINDOW,
        )
        gw = (p.stdout or b"").decode("ascii", "ignore").strip()
        ipaddress.IPv4Address(gw)
        return gw
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return ""


def _plausible_mac(mac):
    if not mac or mac in ("FF:FF:FF:FF:FF:FF", "FE:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
        return False
    try:
        if int(mac[:2], 16) & 1:  # multicast / 组播
            return False
    except ValueError:
        return False
    return True


def _arp_table():
    out, _ = run_cmd(["arp", "-a"], timeout=8)
    table = {}
    for line in out.splitlines():
        ip_m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        mac_m = RE_MAC.search(line)
        if not ip_m or not mac_m:
            continue
        mac = mac_m.group(0).replace("-", ":").upper()
        if _plausible_mac(mac):
            table[ip_m.group(1)] = mac
    return table


def _default_route_ifindex():
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex"],
            capture_output=True, timeout=10, creationflags=CREATE_NO_WINDOW,
        )
        return int((p.stdout or b"").decode("ascii", "ignore").strip() or 0)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return 0


def _local_net():
    from . import nettools
    addrs = nettools.local_addresses()
    want = _default_route_ifindex()
    fallback = None
    for a in addrs:
        if a.get("family") != "IPv4":
            continue
        try:
            ip = ipaddress.ip_address(a["ip"])
        except (ValueError, KeyError):
            continue
        if ip.is_loopback or ip.is_link_local:
            continue
        prefix = a.get("prefix") or 24
        try:
            net = ipaddress.ip_network(f"{a['ip']}/{prefix}", strict=False)
        except ValueError:
            continue
        if net.num_addresses > 1024:
            net = ipaddress.ip_network(f"{a['ip']}/24", strict=False)
        item = (str(net), a.get("adapter") or "", a["ip"])
        if want and a.get("ifindex") == want:
            return item
        if fallback is None:
            fallback = item
    if fallback:
        return fallback
    raise ValueError("未找到局域网 IPv4 地址")


def lan_scan(cidr=""):
    cidr = (cidr or "").strip()
    adapter = local_ip = ""
    if cidr:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            net = None
        if net is None or net.version != 4:
            raise ValueError("仅支持 IPv4 网段")
    else:
        net_s, adapter, local_ip = _local_net()
        net = ipaddress.ip_network(net_s, strict=False)
    result = ip_scan(str(net), 500, 96)
    arp = _arp_table()
    mac_counts = Counter(arp.values())
    by_ip = {d["ip"]: d for d in result["alive"]}
    devices = []
    for ip, mac in arp.items():
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr not in net:
            continue
        if mac_counts[mac] > 8:  # 代理 ARP 特征
            continue
        rtt = (by_ip.get(ip) or {}).get("rtt")
        devices.append({"ip": ip, "rtt": rtt, "mac": mac})
        by_ip.pop(ip, None)
    for ip, d in by_ip.items():
        devices.append({"ip": ip, "rtt": d.get("rtt"), "mac": ""})
    devices.sort(key=lambda x: ipaddress.ip_address(x["ip"]))
    return {
        "adapter": adapter,
        "local_ip": local_ip,
        "cidr": str(net),
        "gateway": _gateway(),
        "devices": devices,
        "scanned": result["scanned"],
        "duration": result["duration"],
    }


def _resolve_ips(domain, timeout=2):
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    ips, started = [], time.perf_counter()
    for rtype in ("AAAA", "A"):
        try:
            for r in resolver.resolve(domain, rtype):
                ips.append(r.to_text())
        except Exception:
            pass
    ms = round((time.perf_counter() - started) * 1000, 1)
    return ips, ms


def _fmt_size(n):
    n = int(n or 0)
    if n >= 1048576:
        return f"{n / 1048576:.2f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


def _cert_date(s):
    try:
        return time.strftime("%Y-%m-%d", time.strptime(s, "%b %d %H:%M:%S %Y %Z"))
    except (TypeError, ValueError):
        return s or "—"


def _cert_brief(name):
    if not name:
        return "—"
    cn = re.search(r"commonName=([^,]+)", name)
    org = re.search(r"organizationName=([^,]+)", name)
    parts = []
    if cn:
        parts.append(cn.group(1).strip())
    if org:
        parts.append(org.group(1).strip())
    return " / ".join(parts) if parts else name


def diagnose_stream(domain="www.baidu.com"):
    import platform
    from urllib.parse import urlsplit
    from . import http_tools, nettools
    from .trace import FINISH_MARKS, _iter_lines, _trace_cmd, parse_hop_line

    raw = (domain or "").strip() or "www.baidu.com"
    web_url = raw if "://" in raw else ""
    if web_url:
        parsed = urlsplit(web_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("网页地址格式不正确（示例 https://www.baidu.com/）")
        target = parsed.hostname
    else:
        target = raw.rstrip(".")
        if not re.fullmatch(r"[A-Za-z0-9_.:\-]+", target):
            raise ValueError("域名含非法字符")
        web_url = "https://" + target

    def log(text):
        return {"type": "log", "text": text}

    def stage(n, title):
        return {"type": "stage", "step": n, "text": title}

    yield {"type": "start", "domain": target}
    yield stage(1, "本机与网络信息")
    yield log("开始诊断...")

    try:
        v4, v4_src = nettools.public_ipv4()
    except Exception:
        v4, v4_src = None, ""
    try:
        geo = nettools.ip_location(v4) if v4 else {}
    except Exception:
        geo = {}
    isp = nettools._short_isp(geo.get("isp"))
    country = geo.get("country") or "未知"
    geo_src = geo.get("source") or "—"
    try:
        profile = nettools._network_bundle()
    except Exception:
        profile = {}
    local = profile.get("local") or []
    alias = profile.get("adapter") or ""
    local_ip = next((x["ip"] for x in local if x.get("family") == "IPv4" and (not alias or x.get("adapter") == alias)), None) \
        or next((x["ip"] for x in local if x.get("family") == "IPv4"), "") or "—"
    ssid = profile.get("ssid") or ""
    dns_list = profile.get("dns") or []
    net_type = f"WiFi（{ssid}）" if ssid else "以太网"
    online = bool(v4 or local_ip not in ("", "—"))
    ver = platform.version() or platform.platform()
    yield log("应用code: nettools.app")
    yield log("应用名称: 网络工具 Windows")
    yield log("应用版本: 1.1")
    yield log("机器类型: Windows  PC")
    yield log("系统版本: " + ver)
    yield log("机器ID: " + (platform.node() or "—"))
    yield log("公网IP: " + (v4 or "未知") + (f"（来源 {v4_src}）" if v4_src else ""))
    yield log("运营商: " + (isp or "未知"))
    yield log("ISOCountryCode: " + (geo.get("country_code") or "—"))
    yield log("IP归属地来源: " + geo_src + "（主用 ip-api.com / 备用 ipinfo.io，仅代表 IP 登记地，非实时位置，仅供参考）")
    yield log("诊断域名 " + target + "...")
    yield log("当前是否联网: " + ("已联网" if online else "未联网"))
    yield log("当前联网类型: " + net_type)
    yield log("本地IP: " + str(local_ip))
    yield log("本地DNS: " + (", ".join(dns_list) if dns_list else "—"))

    reg = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    with ThreadPoolExecutor(max_workers=5) as pool:
        f_winhttp = pool.submit(run_cmd, ["netsh", "winhttp", "show", "proxy"], 8)
        f_ie_on = pool.submit(run_cmd, ["reg", "query", reg, "/v", "ProxyEnable"], 6)
        f_ie_sv = pool.submit(run_cmd, ["reg", "query", reg, "/v", "ProxyServer"], 6)
        f_fw = pool.submit(run_cmd, ["netsh", "advfirewall", "show", "allprofiles", "state"], 8)
        f_ntp = pool.submit(ntp_offset, "ntp.aliyun.com", 2)
        winhttp, _ = f_winhttp.result()
        ie_on, _ = f_ie_on.result()
        ie_sv, _ = f_ie_sv.result()
        fw, _ = f_fw.result()
        try:
            off, src = f_ntp.result()
        except Exception:
            off, src = None, ""

    low = (winhttp or "").lower()
    if any(k.lower() in low for k in ("直接访问", "Direct access", "直连")):
        wh = "直连"
    else:
        mm = re.search(r"(?:代理服务器|Proxy Server\(s\))\s*:\s*(\S+)", winhttp or "", re.I)
        wh = mm.group(1) if mm else "未启用"
    ie = "未启用"
    if re.search(r"ProxyEnable\s+REG_DWORD\s+0x1", ie_on or "", re.I):
        mm = re.search(r"ProxyServer\s+REG_SZ\s+(\S+)", ie_sv or "", re.I)
        ie = "已启用" + (": " + mm.group(1) if mm else "")
    yield log(f"系统代理: WinHTTP={wh}；IE={ie}")
    states = re.findall(r"(?:状态|State)\s+(\S+)", fw or "", re.I)
    on = sum(1 for s in states if s in ("启用", "开启", "ON", "On"))
    yield log("防火墙: " + (f"{on}/{len(states)} 个配置文件启用" if states else "未获取到状态"))
    if off is None:
        ntp_text = "无法获取（UDP 123 与 HTTP 均不可达）"
    elif abs(off) < 1:
        ntp_text = f"正常（偏差 {off:+.2f} 秒，{src}）"
    else:
        ntp_text = f"偏差 {off:+.2f} 秒，本机偏{'慢' if off < 0 else '快'}（{src}）"
    yield log("时间偏差: " + ntp_text)
    yield log("远端域名: " + target)

    yield stage(2, "DNS 解析")
    ips, dns_ms = _resolve_ips(target, 2)
    if ips:
        yield log("DNS解析结果: " + ", ".join(ips) + f" ({dns_ms}ms)")
    else:
        yield log("DNS解析结果:  解析失败")

    yield stage(3, "TCP 连接（443）")
    yield log("开始TCP连接测试...")

    def probe(ip):
        started = time.perf_counter()
        try:
            s = socket.create_connection((ip, 443), timeout=2)
            s.close()
            return round((time.perf_counter() - started) * 1000, 1)
        except OSError:
            return "timeout"

    targets = ips[:4] or [target]
    times = list(ThreadPoolExecutor(max_workers=4).map(probe, targets)) if targets else []
    for i, t in enumerate(times):
        label = targets[i]
        val = "timeout" if t == "timeout" else f"{t}ms"
        yield log(f"Connect to host: {label}'s time={val}")
    ok_times = [t for t in times if t != "timeout"]
    if ok_times:
        yield log("average=" + str(round(sum(ok_times) / len(ok_times), 1)) + "ms")
    else:
        yield log("average=timeout")

    yield stage(4, "网页访问分析")
    yield log("开始网页分析（HTTP/HTTPS 分阶段耗时）...")
    candidates = [web_url]
    if not web_url.startswith("https://"):
        candidates.append("https://" + target)
    if not web_url.startswith("http://"):
        candidates.append("http://" + target)
    web, web_err = None, ""
    for cand in candidates:
        try:
            web = http_tools.web_probe(cand, 8, 5)
            web_url = cand
            break
        except (socket.gaierror,):
            web_err = "域名解析失败"
        except (TimeoutError, socket.timeout):
            web_err = "连接超时"
        except ConnectionRefusedError:
            web_err = "连接被拒绝"
        except ssl.SSLError as e:
            web_err = str(e)
        except Exception as e:
            web_err = str(e)
    if not web:
        yield log("网页分析: 失败 - " + (web_err or "无法访问"))
    else:
        m = web.get("metrics") or {}
        status, reason = web.get("status"), web.get("reason") or ""
        yield log("网页地址: " + (web.get("final_url") or web_url))
        yield log(f"状态码: {status} {reason}")
        yield log("    解析IP: " + (web.get("ip") or "—"))
        tls = m.get("tls")
        s = f" → SSL {tls} ms" if tls else ""
        yield log(
            "分阶段耗时: DNS {dns} ms → 建连 {tcp} ms{s} → 首包 {ttfb} ms → 下载 {dl} ms".format(
                dns=m.get("dns"), tcp=m.get("tcp"), s=s, ttfb=m.get("ttfb"), dl=m.get("download")
            )
        )
        rc = web.get("redirect_count") or 0
        yield log(f"整体耗时: {m.get('overall')} ms（含 {rc} 次重定向，末跳 {m.get('total')} ms）")
        size = web.get("size") or 0
        extra = "（已截断）" if web.get("truncated") else ""
        spd = web.get("speed_kbps")
        spd_s = f" · {spd} KB/s" if spd else ""
        yield log("下载大小: " + _fmt_size(size) + extra + spd_s)
        if web.get("server") or web.get("content_type"):
            yield log("服务器: " + (web.get("server") or "—") + "    内容类型: " + (web.get("content_type") or "—"))
        hops = web.get("hops") or []
        if len(hops) > 1:
            for i, h in enumerate(hops[:-1], 1):
                yield log(f"  跳转{i}: {h.get('url')} → {h.get('location')}")
        else:
            yield log("重定向: 无")
        cert = web.get("cert")
        if cert:
            days = cert.get("days_left")
            yield log(
                "证书: " + _cert_brief(cert.get("subject")) + " | 签发 " + _cert_brief(cert.get("issuer"))
                + " | 有效期至 " + _cert_date(cert.get("not_after"))
                + (f"（剩余 {days} 天）" if days is not None else "")
            )
            if cert.get("tls_version") or cert.get("cipher"):
                yield log("加密: " + (cert.get("tls_version") or "") + " / " + (cert.get("cipher") or ""))
        hints = []
        if (m.get("dns") or 0) > 100:
            hints.append("DNS 解析偏慢")
        if (m.get("tls") or 0) > 300:
            hints.append("SSL 握手偏慢")
        if (m.get("ttfb") or 0) > 500:
            hints.append("首包偏慢，服务端处理可能较重")
        if (m.get("download") or 0) > 1000:
            hints.append("内容下载偏慢")
        if status and status >= 400:
            hints.append(f"状态码异常 {status}")
        if days is not None and days < 15:
            hints.append(f"证书即将到期（{days}）")
        yield log("网页结论: " + ("；".join(hints) if hints else "各阶段耗时正常"))

    yield stage(5, "路径追踪 traceroute")
    yield log("开始traceroute...")
    last = 0
    for line in _iter_lines(_trace_cmd(target, 20, 800, 4), 60):
        line = (line or "").strip()
        if not line:
            continue
        if any(k in line.lower() for k in FINISH_MARKS):
            break
        parsed = parse_hop_line(line)
        if not parsed:
            continue
        hop, rtts, ip, _ = parsed
        last = hop
        rtt_s = " ".join(str(x) for x in rtts) if rtts else "timeout"
        yield log(f"{hop:2d}  {ip or '*'}  {rtt_s}")

    yield stage(6, "诊断完成")
    yield log("诊断完成。")
    yield {"type": "done"}


def _whois_query(server, query, timeout=8):
    sock = socket.create_connection((server, 43), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode("ascii", "ignore"))
        data = b""
        while len(data) < 300000:
            buf = sock.recv(8192)
            if not buf:
                break
            data += buf
        return data.decode("utf-8", "replace")
    finally:
        try:
            sock.close()
        except OSError:
            pass


def whois_lookup(domain):
    domain = (domain or "").strip().lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9\-]+(\.[a-z0-9\-]+)+", domain):
        raise ValueError("域名格式不正确")
    tld = domain.rsplit(".", 1)[-1]
    server = WHOIS_SERVERS.get(tld, "whois.iana.org")
    try:
        text = _whois_query(server, domain, 8)
    except OSError as e:
        raise RuntimeError("whois 查询失败: " + str(e)) from e
    m = re.search(r"(?im)^refer:\s*(\S+)", text)
    if m and m.group(1).lower() != server:
        ref = m.group(1)
        try:
            text = _whois_query(ref, domain, 8)
            server = ref
        except OSError:
            pass
    return {"domain": domain, "server": server, "text": text}


def superping_stream(hosts, count=4, interval=1.0, size=32, timeout_ms=1000):
    from . import ping as ping_mod
    raw = re.split(r"[,\s]+", hosts or "")
    targets = []
    for h in raw:
        h = h.strip()
        if h:
            targets.append(safe_host(h))
    if not targets:
        raise ValueError("请输入至少一个主机")
    # unique preserve order
    seen, uniq = set(), []
    for h in targets:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    targets = uniq
    if len(targets) > 8:
        raise ValueError("最多同时探测 8 个主机")
    count = to_int(count, 4, 0, 1000)
    size = to_int(size, 32, 1, 65500)
    timeout_ms = to_int(timeout_ms, 1000, 100, 10000)
    try:
        interval = max(0.2, min(10, float(interval)))
    except (TypeError, ValueError):
        interval = 1.0
    yield {"type": "start", "hosts": targets, "count": count, "interval": interval}
    acc = {h: {"sent": 0, "rtts": [], "ip": ""} for h in targets}
    seq = 0
    try:
        while True:
            seq += 1
            with ThreadPoolExecutor(max_workers=len(targets)) as pool:
                results = list(pool.map(lambda h: ping_mod.ping_once(h, 4, size, timeout_ms), targets))
            rows = []
            for h, r in zip(targets, results):
                a = acc[h]
                a["sent"] += 1
                if r.get("ok") and r.get("rtt") is not None:
                    a["rtts"].append(r["rtt"])
                if r.get("ip"):
                    a["ip"] = r["ip"]
                yield {
                    "type": "reply", "seq": seq, "host": h,
                    "ok": bool(r.get("ok")), "rtt": r.get("rtt"), "ip": r.get("ip") or a["ip"],
                }
                row = {"host": h, "ip": a["ip"]}
                row.update(_stats(a["sent"], a["rtts"]))
                rows.append(row)
            yield {"type": "stats", "seq": seq, "rows": rows}
            if count and seq >= count:
                break
            time.sleep(interval)
    except GeneratorExit:
        return
    yield {"type": "done", "rounds": seq}


def batch_check(hosts, mode="ping", ports="80,443", count=2, timeout_ms=1000):
    from . import ping as ping_mod
    from . import scan as scan_mod
    raw = [h.strip() for h in re.split(r"[,\s]+", hosts or "") if h.strip()]
    targets = list(dict.fromkeys(safe_host(h) for h in raw))
    if not targets:
        raise ValueError("请输入主机列表")
    if len(targets) > 30:
        raise ValueError("单次最多 30 个主机")
    timeout_ms = to_int(timeout_ms, 1000, 100, 10000)
    count = to_int(count, 2, 1, 10)

    if (mode or "").lower() == "port":
        port_list = parse_ports(ports or "80,443")

        def check(h):
            try:
                r = scan_mod.port_scan(h, ",".join(str(p) for p in port_list), 0.8, 64)
                return {"host": h, "ip": r.get("ip"), "open": [p["port"] for p in r.get("open") or []], "error": ""}
            except Exception as e:
                return {"host": h, "ip": "", "open": [], "error": str(e)}
    else:
        def check(h):
            rtts, ip = [], ""
            for _ in range(count):
                r = ping_mod.ping_once(h, 4, 32, timeout_ms)
                if r.get("ip"):
                    ip = r["ip"]
                if r.get("ok") and r.get("rtt") is not None:
                    rtts.append(r["rtt"])
            st = _stats(count, rtts)
            row = {"host": h, "ip": ip}
            row.update(st)
            return row

    with ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
        rows = list(pool.map(check, targets))
    return {"mode": "port" if (mode or "").lower() == "port" else "ping", "count": len(rows), "rows": rows}


def find_iperf3():
    exe = shutil.which("iperf3") or shutil.which("iperf3.exe")
    if exe:
        return exe
    bases = [exe_dir(), resource_dir()]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        bases.append(meipass)
    for base in bases:
        for rel in ("bin/iperf3.exe", "bin/iperf3", "iperf3.exe", "iperf3"):
            path = os.path.join(base, *rel.split("/"))
            if os.path.isfile(path):
                return path
    return ""


def iperf3_stream(host, port=5201, seconds=10, reverse=False):
    host = safe_host(host)
    port = to_int(port, 5201, 1, 65535)
    seconds = to_int(seconds, 10, 1, 60)
    exe = find_iperf3()
    yield {"type": "start", "host": host, "port": port, "seconds": seconds, "exe": exe or ""}
    if not exe:
        yield {"type": "log", "text": "本机未检测到 iperf3。"}
        yield {"type": "log", "text": "可从 https://iperf.fr/iperf-download.php 下载，或在 macOS 上用 brew install iperf3。"}
        yield {"type": "log", "text": "把 iperf3（Windows 为 iperf3.exe）放到系统 PATH 或本程序目录后再运行。"}
        yield {"type": "error", "message": "未找到 iperf3"}
        return
    cmd = [exe, "-c", host, "-p", str(port), "-t", str(seconds)]
    if str(reverse) in ("1", "true", "True") or reverse is True:
        cmd.append("-R")
    yield {"type": "cmd", "text": " ".join(cmd)}
    p = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        creationflags=CREATE_NO_WINDOW,
    )
    procs.register(p)
    q = queue.Queue()

    def reader():
        try:
            for raw in iter(p.stdout.readline, b""):
                q.put(decode_output(raw).rstrip())
        finally:
            q.put(None)

    threading.Thread(target=reader, daemon=True).start()
    deadline = time.time() + seconds + 30
    timed_out = False
    try:
        while True:
            timeout = max(0.0, min(0.5, deadline - time.time()))
            try:
                line = q.get(timeout=timeout)
            except queue.Empty:
                if time.time() > deadline or procs.cancelled():
                    timed_out = True
                    try:
                        p.kill()
                    except OSError:
                        pass
                    yield {"type": "log", "text": f"iperf3 超过 {seconds + 30} 秒无响应，已强制终止"}
                    break
                if p.poll() is not None and q.empty():
                    break
                continue
            if line is None:
                break
            if line:
                yield {"type": "log", "text": line}
    finally:
        try:
            p.wait(timeout=3)
        except (subprocess.TimeoutExpired, OSError):
            try:
                p.kill()
            except OSError:
                pass
        procs.unregister(p)
    yield {"type": "done", "code": p.returncode if p.returncode is not None else -1, "timed_out": timed_out}


def wlan_status():
    if os.name != "nt":
        return {"available": False, "ssid": "", "message": "WLAN 分析仅在 Windows 上提供"}
    out, _ = run_cmd(["netsh", "wlan", "show", "interfaces"], timeout=12)
    low = (out or "").lower()
    if any(k in low for k in ("没有无线接口", "no wireless interface")) or (
        "wireless autoconfig" in low and "not running" in low
    ) or ("无线自动配置服务" in out and "没有运行" in out):
        return {"available": False, "ssid": "", "state": "", "interfaces": 0}
    interfaces = len(re.findall(r"^\s*(?:名称|Name)\s*:", out, re.M))
    m = re.search(r"^\s*SSID\s*:\s*(.+)$", out, re.M)
    ssid = m.group(1).strip() if m and m.group(1).strip() and m.group(1).strip().upper() != "SSID" else ""
    m = re.search(r"^\s*(?:状态|State)\s*:\s*(.+)$", out, re.M)
    state = m.group(1).strip() if m else ""
    return {"available": True, "ssid": ssid, "state": state, "interfaces": max(interfaces, 1 if out.strip() else 0)}


def wlan_scan():
    status = wlan_status()
    if not status.get("available"):
        return {"available": False, "rows": [], "count": 0, "message": "未检测到无线网卡（台式机或无 WLAN 适配器）"}
    out, _ = run_cmd(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=20)
    rows, ssid, cur = [], "", None

    def val(pat):
        mm = re.search(pat, cur or "", re.I)
        return mm.group(1).strip() if mm else ""

    pending = None
    for line in (out or "").splitlines():
        m = re.match(r"^\s*SSID \d+\s*:\s*(.*)$", line)
        if m:
            if pending:
                rows.append(pending)
                pending = None
            ssid = m.group(1).strip()
            cur = ""
            continue
        m = re.match(r"^\s*BSSID \d+\s*:\s*([0-9a-fA-F:]{17})", line)
        if m:
            if pending:
                rows.append(pending)
            pending = {"ssid": ssid, "bssid": m.group(1).upper()}
            cur = line
            continue
        if pending is not None:
            cur = (cur or "") + "\n" + line
            pending["signal"] = int(val(r"(?:信号|Signal)\s*:\s*(\d+)\s*%") or 0)
            ch = val(r"(?:频道|Channel)\s*:\s*(\d+)")
            pending["channel"] = ch
            pending["radio"] = val(r"(?:无线电类型|Radio type)\s*:\s*(.+)")
            pending["auth"] = val(r"(?:身份验证|Authentication)\s*:\s*(.+)")
            pending["enc"] = val(r"(?:加密|Encryption)\s*:\s*(.+)")
            try:
                c = int(ch or 0)
            except ValueError:
                c = 0
            pending["band"] = "2.4G" if 0 < c < 15 else ("5G" if c >= 15 else "")
    if pending:
        rows.append(pending)
    rows.sort(key=lambda x: (-int(x.get("signal") or 0), x.get("ssid") or ""))
    return {"available": True, "rows": rows, "count": len(rows), "ssid": status.get("ssid") or ""}


def ntp_offset(server="ntp.aliyun.com", timeout=2):
    def ts(off):
        sec, frac = struct.unpack("!II", off)
        return sec - 2208988800 + frac / 4294967296

    try:
        addr = socket.getaddrinfo(server, 123, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        pkt = b"\x1b" + b"\x00" * 47
        t1 = time.time()
        s.sendto(pkt, addr)
        data, _ = s.recvfrom(64)
        t4 = time.time()
        s.close()
        if len(data) >= 48:
            t2 = ts(data[32:40])
            t3 = ts(data[40:48])
            off = ((t2 - t1) + (t3 - t4)) / 2
            return round(off, 3), "SNTP " + server
    except OSError:
        pass
    try:
        from email.utils import parsedate_to_datetime
        import requests
        r = requests.head(
            "https://www.baidu.com",
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 NetTools/1.1"},
        )
        server_ts = parsedate_to_datetime(r.headers["Date"]).timestamp()
        return round(server_ts - time.time(), 1), "HTTP Date（精度 1 秒）"
    except Exception:
        return None, ""
