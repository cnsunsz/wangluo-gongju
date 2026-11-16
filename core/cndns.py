"""多 DNS 节点对比解析。"""
from __future__ import annotations

import ipaddress
import re
import time
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver

DEFAULT_SERVERS = (
    "114.114.114.114", "223.5.5.5", "119.29.29.29", "180.76.76.76",
    "1.2.4.8", "8.8.8.8", "1.1.1.1",
)
TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS")


def parse_servers(servers):
    if isinstance(servers, str):
        parts = re.split(r"[,\s]+", servers)
    else:
        parts = list(servers or [])
    out = []
    for p in parts:
        p = str(p).strip()
        if not p:
            continue
        try:
            ipaddress.ip_address(p)
        except ValueError as e:
            raise ValueError("非法 DNS 服务器: " + p) from e
        out.append(p)
    return out or list(DEFAULT_SERVERS)


def _one(server, name, rtype, timeout):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server]
    resolver.timeout = timeout
    resolver.lifetime = timeout
    started = time.perf_counter()
    try:
        ans = resolver.resolve(name, rtype)
        answers = [r.to_text() for r in ans]
        ms = round((time.perf_counter() - started) * 1000, 2)
        return {"server": server, "ok": True, "answers": answers, "ms": ms, "error": ""}
    except dns.resolver.NXDOMAIN:
        err = "域名不存在"
    except dns.resolver.NoAnswer:
        err = "无该类型记录"
    except dns.exception.Timeout:
        err = "超时"
    except dns.resolver.NoNameservers:
        err = "无响应"
    except Exception as e:
        err = type(e).__name__
    ms = round((time.perf_counter() - started) * 1000, 2)
    return {"server": server, "ok": False, "answers": [], "ms": ms, "error": err}


def compare(name, servers=None, rtype="A", timeout=3):
    name = (name or "").strip().rstrip(".")
    if not name:
        raise ValueError("请输入域名")
    if not re.fullmatch(r"[A-Za-z0-9_.\-]+", name):
        raise ValueError("域名含非法字符")
    rtype = (rtype or "A").upper()
    if rtype not in TYPES:
        raise ValueError("仅支持 " + " / ".join(TYPES))
    servers = parse_servers(servers)
    try:
        timeout = max(1, min(10, int(timeout)))
    except (TypeError, ValueError):
        timeout = 3

    with ThreadPoolExecutor(max_workers=len(servers)) as pool:
        results = list(pool.map(lambda s: _one(s, name, rtype, timeout), servers))

    groups = {}
    for r in results:
        key = tuple(r["answers"]) if r["ok"] else ()
        groups.setdefault(key, []).append(r["server"])
    ok_results = [r for r in results if r["ok"]]
    fastest = min((r["ms"] for r in ok_results), default=None)
    return {
        "name": name,
        "type": rtype,
        "results": results,
        "consistent": len(groups) <= 1,
        "groups": len(groups),
        "fastest": fastest,
    }
