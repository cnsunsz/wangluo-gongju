"""MTU 探测、本机连接查看、诊断报告导出。"""
from __future__ import annotations

import csv
import io
import os
import platform
import sys
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from .paths import reports_dir
from .util import run_cmd, safe_host, to_int


def _ping_df(host, size, timeout_ms, family):
    cmd = ["ping"]
    if int(family) == 6:
        cmd.append("-6")
    if os.name == "nt":
        cmd += ["-n", "1", "-w", str(timeout_ms)]
        if int(family) == 4:
            cmd.append("-f")  # Don't Fragment
        cmd += ["-l", str(size), host]
    else:
        cmd += ["-c", "1", "-s", str(size)]
        if sys.platform == "darwin":
            cmd += ["-W", str(max(1, int(timeout_ms)))]
            if int(family) == 4:
                cmd.append("-D")  # Don't Fragment
        else:
            cmd += ["-W", str(max(1, int((int(timeout_ms) + 999) // 1000)))]
            if int(family) == 4:
                cmd += ["-M", "do"]
        cmd.append(host)
    out, _ = run_cmd(cmd, timeout=max(1, timeout_ms // 1000 + 5))
    low = out.lower()
    if any(k in low for k in ("需要拆分", "fragmented", "fragmentation", "frag")):
        return "frag"
    if re.search(r"(?:time|时间)\s*[=<]\s*(\d+)\s*ms", out, re.I):
        return "ok"
    return "timeout"


def mtu_stream(host, family=4, timeout_ms=1200):
    host = safe_host(host)
    family = 6 if str(family) == "6" else 4
    timeout_ms = to_int(timeout_ms, 1200, 300, 5000)
    overhead = 48 if family == 6 else 28
    top = 1452 if family == 6 else 1472
    floor = 1280 - overhead if family == 6 else 576 - overhead
    yield {
        "type": "start", "host": host, "family": family,
        "overhead": overhead, "floor": floor, "top": top,
    }
    base = 64 if family == 4 else 96
    best = None
    top_result = _ping_df(host, top, timeout_ms, family)
    yield {"type": "probe", "size": top, "mtu": top + overhead, "result": top_result}
    if top_result == "ok":
        yield {
            "type": "result", "payload": top, "mtu": top + overhead,
            "overhead": overhead, "at_top": True,
        }
        yield {"type": "done"}
        return
    # floor must work
    floor_result = _ping_df(host, max(floor, 8), timeout_ms, family)
    yield {"type": "probe", "size": max(floor, 8), "mtu": max(floor, 8) + overhead, "result": floor_result}
    if floor_result != "ok":
        yield {
            "type": "error",
            "message": f"基础探测 {max(floor, 8)} 字节失败（{floor_result}），目标可能禁 ICMP 或链路异常",
        }
        yield {"type": "done"}
        return
    lo, hi = max(floor, 8), top
    best = lo
    while lo <= hi:
        mid = (lo + hi) // 2
        result = _ping_df(host, mid, timeout_ms, family)
        yield {"type": "probe", "size": mid, "mtu": mid + overhead, "result": result}
        if result == "ok":
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    yield {
        "type": "result", "payload": best, "mtu": best + overhead,
        "overhead": overhead, "at_top": best >= top,
    }
    yield {"type": "done"}


def _process_map():
    out, _ = run_cmd(["tasklist", "/FO", "CSV", "/NH"], timeout=15)
    names = {}
    for line in out.splitlines():
        line = line.strip()
        if not line or not line.startswith('"'):
            continue
        try:
            cols = next(csv.reader(io.StringIO(line)))
        except (StopIteration, csv.Error):
            continue
        if len(cols) >= 2 and cols[1].isdigit():
            names[int(cols[1])] = cols[0]
    return names


def local_connections(state="all", query=""):
    out, _ = run_cmd(["netstat", "-ano"], timeout=20)
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0].upper()
        if proto == "TCP" and len(parts) >= 5:
            local, remote, st, pid = parts[1], parts[2], parts[3], parts[4]
        elif proto == "UDP" and len(parts) >= 4:
            local, remote, st, pid = parts[1], "*:*", "UDP", parts[-1]
        else:
            continue
        try:
            pid = int(pid)
        except ValueError:
            continue
        rows.append({"proto": proto, "local": local, "remote": remote, "state": st, "pid": pid})

    procs = _process_map()
    for r in rows:
        r["process"] = procs.get(r["pid"], "")

    counts = {
        "listen": sum(1 for r in rows if r["state"] == "LISTENING"),
        "established": sum(1 for r in rows if r["state"] == "ESTABLISHED"),
        "udp": sum(1 for r in rows if r["proto"] == "UDP"),
        "processes": len({r["pid"] for r in rows}),
        "total": len(rows),
    }
    mode = (state or "all").lower()
    if mode in ("listen", "listening"):
        rows = [r for r in rows if r["state"] in ("LISTENING", "UDP")]
    q = (query or "").strip()
    if q:
        if q.isdigit():
            rows = [
                r for r in rows
                if q in r["local"] or q in r["remote"] or str(r["pid"]) == q
                or re.search(r":%s$" % re.escape(q), r["local"])
                or q.lower() in (r.get("process") or "").lower()
            ]
        else:
            ql = q.lower()
            rows = [
                r for r in rows
                if ql in r["local"].lower() or ql in r["remote"].lower()
                or ql in (r.get("process") or "").lower()
                or ql in str(r["pid"])
            ]

    def sort_key(r):
        try:
            port = int(r["local"].rsplit(":", 1)[1])
        except (ValueError, IndexError):
            port = 0
        pri = 0 if r["state"] in ("LISTENING", "UDP") else 1
        return (pri, r["proto"], port)

    rows.sort(key=sort_key)
    truncated = len(rows) > 800
    shown = rows[:800]
    return {
        "rows": shown,
        "shown": len(shown),
        "filtered": len(rows),
        "counts": counts,
        "truncated": truncated,
    }


def _section(title, text, limit=20000):
    text = (text or "").strip()
    if len(text) > limit:
        text = text[:limit] + "\n...（内容过长已截断）"
    return f"\n===== {title} =====\n{text}\n"


def build_report(note=""):
    from . import nettools

    started = time.perf_counter()
    parts = [
        "网络工具 - 诊断报告\n",
        "生成时间: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n",
        "应用版本: " + __import__("core.paths", fromlist=["APP_VERSION"]).APP_VERSION + "\n",
        "系统: " + platform.platform() + "\n",
        "主机名: " + platform.node() + "\n",
        "Python: " + platform.python_version() + "\n",
    ]
    if (note or "").strip():
        parts.append("备注: " + note.strip() + "\n")

    if os.name == "nt":
        reg_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        cmds = {
            "ipconfig": (["ipconfig", "/all"], 20),
            "route": (["route", "print"], 20),
            "arp": (["arp", "-a"], 10),
            "netstat": (["netstat", "-ano"], 20),
            "winhttp": (["netsh", "winhttp", "show", "proxy"], 10),
            "proxy_enable": (["reg", "query", reg_path, "/v", "ProxyEnable"], 8),
            "proxy_server": (["reg", "query", reg_path, "/v", "ProxyServer"], 8),
            "firewall": (["netsh", "advfirewall", "show", "allprofiles", "state"], 10),
        }
        ipcfg_title = "ipconfig /all"
        netstat_title = "netstat -ano"
    else:
        if sys.platform == "darwin":
            cmds = {
                "ipconfig": (["/sbin/ifconfig"], 20),
                "route": (["/usr/sbin/netstat", "-rn"], 20),
                "arp": (["arp", "-an"], 10),
                "netstat": (["/usr/sbin/netstat", "-anv"], 20),
                "winhttp": (["/usr/sbin/networksetup", "-getwebproxy", "Wi-Fi"], 8),
                "proxy_enable": (["/usr/sbin/scutil", "--proxy"], 8),
                "proxy_server": (["true"], 1),
                "firewall": (["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], 8),
            }
        else:
            cmds = {
                "ipconfig": (["ip", "addr"], 20),
                "route": (["ip", "route"], 20),
                "arp": (["ip", "neigh"], 10),
                "netstat": (["ss", "-tulpn"], 20),
                "winhttp": (["true"], 1),
                "proxy_enable": (["true"], 1),
                "proxy_server": (["true"], 1),
                "firewall": (["true"], 1),
            }
        ipcfg_title = "ifconfig / ip addr"
        netstat_title = "netstat / ss"

    def overview():
        try:
            ip, src = nettools.public_ipv4()
        except Exception:
            ip, src = None, ""
        try:
            info = nettools.ip_location(ip) if ip else {}
        except Exception:
            info = {}
        geo = info or {}
        parts_ = []
        if ip:
            parts_.append(f"公网 IPv4: {ip}" + (f"（{src}）" if src else ""))
        addr = " ".join(filter(None, [
            geo.get("country"), geo.get("region"), geo.get("city")
        ])) or "-"
        if geo:
            parts_.append("公网地址归属: " + addr + (" / " + (geo.get("isp") or "") if geo.get("isp") else ""))
        parts_.append("内网网卡 / 网关 / DNS 详见下方接口与路由输出")
        return "\n".join(parts_)

    with ThreadPoolExecutor(max_workers=7) as pool:
        f_info = pool.submit(overview)
        futures = {k: pool.submit(run_cmd, cmd, t) for k, (cmd, t) in cmds.items()}
        try:
            parts.append(_section("网络概况", f_info.result()))
        except Exception as e:
            parts.append(_section("网络概况", "获取失败: " + str(e)))
        mapping = [
            (ipcfg_title, "ipconfig", 30000),
            ("路由表", "route", 20000),
            ("ARP 表", "arp", 20000),
        ]
        for title, key, lim in mapping:
            out, err = futures[key].result()
            text = out or err
            parts.append(_section(title, text, lim))
        out, err = futures["netstat"].result()
        lines = (out or err).splitlines()
        text = "\n".join(lines[:400])
        if len(lines) > 400:
            text += f"\n...（共 {len(lines)} 行，已截断）"
        parts.append(_section(netstat_title, text, 40000))
        out, _ = futures["winhttp"].result()
        parts.append(_section("WinHTTP 代理", out))
        pe, _ = futures["proxy_enable"].result()
        ps, _ = futures["proxy_server"].result()
        parts.append(_section("IE / 系统代理", (pe + "\n" + ps).strip()))
        out, _ = futures["firewall"].result()
        parts.append(_section("防火墙状态", out))

    text = "".join(parts)
    folder = reports_dir()
    filename = "网络诊断报告_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".txt"
    path = os.path.join(folder, filename)
    with open(path, "w", encoding="utf-8-sig") as f:
        f.write(text)
    return {
        "filename": filename,
        "path": path,
        "size": round(os.path.getsize(path), 0),
        "text": text,
        "elapsed": round(time.perf_counter() - started, 2),
    }
