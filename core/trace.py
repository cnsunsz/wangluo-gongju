"""traceroute / tracert / MTR 风格路径探测。"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time

from . import procs
from .util import CREATE_NO_WINDOW, decode_output, safe_host, to_int

RE_HOP = re.compile(r"^\s*(\d+)\s+(\S.*)$")
RE_MS = re.compile(r"(\d+(?:\.\d+)?)\s*(?:ms|毫秒)", re.I)
RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_IPV6 = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f:]*\b")
FINISH_MARKS = ("跟踪完成", "trace complete", "追踪完成")


def _iter_lines(cmd, total_timeout):
    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        creationflags=CREATE_NO_WINDOW,
    )
    procs.register(p)
    started = time.time()
    try:
        while True:
            if procs.cancelled() or (time.time() - started) > total_timeout:
                break
            raw = p.stdout.readline() if p.stdout else b""
            if raw == b"" and p.poll() is not None:
                break
            if raw:
                yield decode_output(raw).rstrip()
    finally:
        try:
            if p.poll() is None:
                p.kill()
        except OSError:
            pass
        procs.unregister(p)


def parse_hop_line(line):
    m = RE_HOP.match(line)
    if not m:
        return None
    hop = int(m.group(1))
    body = m.group(2)
    low = body.lower()
    rtts = [float(x) for x in RE_MS.findall(body) if "ms" in low or "毫秒" in low or True]
    # findall already captures ms numbers
    rtts = [float(x) for x in RE_MS.findall(body)]
    ip_m = RE_IPV4.search(body) or RE_IPV6.search(body)
    ip = ip_m.group(0).strip() if ip_m else (None if "*" in body else None)
    return hop, rtts, ip, body


def _trace_cmd(host, maxhops, timeout_ms, family):
    if os.name == "nt":
        cmd = ["tracert"]
        if int(family) == 6:
            cmd.append("-6")
        cmd += ["-d", "-h", str(maxhops), "-w", str(int(timeout_ms)), host]
        return cmd
    exe = shutil.which("traceroute") or shutil.which("traceroute6" if int(family) == 6 else "") or "traceroute"
    cmd = [exe, "-n", "-m", str(maxhops)]
    # Unix -w 为秒
    wait_s = max(1, int((int(timeout_ms) + 999) // 1000))
    cmd += ["-w", str(wait_s)]
    if int(family) == 6 and "6" not in os.path.basename(exe):
        if sys.platform == "darwin":
            cmd.append("-6")
        else:
            cmd += ["-6"]
    cmd.append(host)
    return cmd


def traceroute_stream(host, maxhops=30, timeout_ms=1000, family=4):
    host = safe_host(host)
    maxhops = to_int(maxhops, 30, 1, 64)
    timeout_ms = to_int(timeout_ms, 1000, 100, 5000)
    family = 6 if str(family) == "6" else 4
    yield {"type": "start", "host": host, "maxhops": maxhops, "timeout": timeout_ms}
    hops = 0
    total = max(30, maxhops * (timeout_ms / 1000.0) * 3 + 30)
    for line in _iter_lines(_trace_cmd(host, maxhops, timeout_ms, family), total):
        line = line.strip()
        if not line:
            continue
        if any(k in line.lower() for k in FINISH_MARKS):
            yield {"type": "log", "text": line}
            break
        parsed = parse_hop_line(line)
        if not parsed:
            yield {"type": "log", "text": line}
            continue
        hop, rtts, ip, body = parsed
        hops = max(hops, hop)
        yield {"type": "hop", "hop": hop, "rtts": rtts, "ip": ip, "raw": body}
    yield {"type": "done", "hops": hops}


def _mtr_stats(rtts, sent):
    got = len(rtts)
    loss = round((sent - got) * 100.0 / sent, 1) if sent else 0.0
    if rtts:
        return {
            "loss": loss, "sent": sent,
            "min": round(min(rtts), 1),
            "avg": round(sum(rtts) / len(rtts), 1),
            "max": round(max(rtts), 1),
            "last": rtts[-1],
        }
    return {"loss": 100.0 if sent else 0.0, "sent": sent, "min": 0, "avg": 0, "max": 0, "last": -1}


def mtr_stream(host, maxhops=30, samples=3, timeout_ms=600, family=4):
    host = safe_host(host)
    maxhops = to_int(maxhops, 30, 1, 64)
    samples = to_int(samples, 3, 1, 10)
    timeout_ms = to_int(timeout_ms, 600, 100, 3000)
    family = 6 if str(family) == "6" else 4
    yield {
        "type": "start", "host": host, "maxhops": maxhops,
        "samples": samples, "timeout": timeout_ms,
    }
    acc = {}
    seen_max = 0
    for rnd in range(1, samples + 1):
        per_round = {}
        total = max(20, maxhops * (timeout_ms / 1000.0) * 3 + 15)
        for line in _iter_lines(_trace_cmd(host, maxhops, timeout_ms, family), total):
            line = line.strip()
            if not line:
                continue
            if any(k in line.lower() for k in FINISH_MARKS):
                break
            parsed = parse_hop_line(line)
            if not parsed:
                continue
            hop, rtts, ip, _ = parsed
            seen_max = max(seen_max, hop)
            a = acc.setdefault(hop, {"rtts": [], "sent": 0, "ip": None})
            a["sent"] += 1
            a["rtts"].extend(rtts)
            if ip:
                a["ip"] = ip
            per_round[hop] = (rtts, ip)
            yield {"type": "probe", "round": rnd, "hop": hop, "rtts": rtts, "ip": ip}
        rows = []
        for hop in sorted(acc):
            a = acc[hop]
            stats = _mtr_stats(a["rtts"], a["sent"])
            row = {"hop": hop, "ip": a.get("ip")}
            row.update(stats)
            rows.append(row)
        yield {"type": "round", "round": rnd, "hops": rows}
    yield {"type": "done", "rounds": samples}
