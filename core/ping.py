"""Windows ping 封装与流式输出。"""
from __future__ import annotations

import re
import time

from .util import run_cmd, safe_host, to_int

RE_RTT = re.compile(r"(?:time|时间)\s*[=<]\s*(\d+)\s*ms", re.I)
RE_TTL = re.compile(r"ttl\s*=\s*(\d+)", re.I)
RE_FROM = re.compile(r"(?:reply from|来自)\s*([0-9A-Fa-f.:]+)", re.I)
TIMEOUT_MARKS = (
    "请求超时", "request timed out", "无法访问目标主机",
    "destination host unreachable", "一般故障", "general failure",
    "传输失败", "transmit failed", "无法访问",
)
EXPIRED_MARKS = ("ttl 传输中过期", "ttl expired in transit", "ttl expired")


def _cmd(host, family, size, timeout_ms, ttl=None):
    cmd = ["ping"]
    if int(family) == 6:
        cmd.append("-6")
    cmd += ["-n", "1", "-w", str(timeout_ms), "-l", str(size)]
    if ttl is not None:
        cmd += ["-i", str(ttl)]
    cmd.append(host)
    return cmd


def ping_once(host, family=4, size=32, timeout_ms=1000, ttl=None):
    timeout = max(1, (int(timeout_ms) // 1000) + 1)
    out, _ = run_cmd(_cmd(host, family, size, timeout_ms, ttl), timeout=timeout)
    low = out.lower()
    m = RE_RTT.search(out)
    ip_m = RE_FROM.search(out)
    ttl_m = RE_TTL.search(out)
    expired = any(k in low for k in EXPIRED_MARKS)
    ok = bool(m) and not expired
    return {
        "ok": ok,
        "expired": expired,
        "rtt": float(m.group(1)) if m else None,
        "ip": ip_m.group(1).strip() if ip_m else None,
        "ttl": int(ttl_m.group(1)) if ttl_m else None,
        "raw": out,
    }


def _stats(sent, rtts):
    recv = len(rtts)
    loss = round((sent - recv) * 100.0 / sent, 1) if sent else 0.0
    if rtts:
        mn = min(rtts)
        mx = max(rtts)
        avg = sum(rtts) / len(rtts)
        mdev = (sum((x - avg) ** 2 for x in rtts) / len(rtts)) ** 0.5
        jitter = (
            sum(abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))) / (len(rtts) - 1)
            if len(rtts) > 1 else 0.0
        )
        return {
            "sent": sent, "recv": recv, "loss": loss,
            "min": round(mn, 1), "avg": round(avg, 1),
            "max": round(mx, 1), "mdev": round(mdev, 1),
            "jitter": round(jitter, 1),
        }
    return {
        "sent": sent, "recv": 0, "loss": loss,
        "min": 0.0, "avg": 0.0, "max": 0.0, "mdev": 0.0, "jitter": 0.0,
    }


def ping_stream(host, count=4, size=32, timeout_ms=1000, interval=1.0, family=4):
    host = safe_host(host)
    count = to_int(count, 4, 0, 100000)
    size = to_int(size, 32, 1, 65500)
    timeout_ms = to_int(timeout_ms, 1000, 100, 10000)
    family = 6 if str(family) == "6" else 4
    try:
        interval = max(0.2, min(10, float(interval)))
    except (TypeError, ValueError):
        interval = 1.0

    yield {
        "type": "start", "host": host, "count": count, "size": size,
        "timeout": timeout_ms, "interval": interval, "family": family,
    }
    sent = 0
    rtts = []
    resolved = None
    try:
        while True:
            sent += 1
            r = ping_once(host, family, size, timeout_ms)
            if r.get("ip"):
                resolved = r["ip"]
            if r.get("ok") and r.get("rtt") is not None:
                rtts.append(r["rtt"])
                lines = (r.get("raw") or "").splitlines()
                msg = next((ln for ln in lines if ln.strip()), "")
            else:
                msg = "超时"
            yield {
                "type": "reply", "seq": sent, "ok": bool(r.get("ok")),
                "rtt": r.get("rtt"), "ttl": r.get("ttl"),
                "ip": r.get("ip") or "", "msg": msg,
            }
            stats = _stats(sent, rtts)
            if resolved:
                stats["resolved"] = resolved
            yield {"type": "stats", **stats}
            if count and sent >= count:
                break
            time.sleep(interval)
    except GeneratorExit:
        return
    final = {"type": "done", **_stats(sent, rtts)}
    if resolved:
        final["resolved"] = resolved
    yield final
