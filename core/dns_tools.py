"""DNS 查询与 dig 风格输出。"""
from __future__ import annotations

import ipaddress
import re
import time

import dns.exception
import dns.flags
import dns.rdatatype
import dns.resolver
import dns.reversename

SUPPORTED = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV")


def _valid_server(server):
    server = (server or "").strip()
    if not server:
        return ""
    try:
        ipaddress.ip_address(server)
    except ValueError as e:
        raise ValueError("DNS 服务器需为 IP 地址") from e
    return server


def dns_lookup(name, types=None, server=None, timeout=4):
    name = (name or "").strip().rstrip(".")
    if not name:
        raise ValueError("请输入域名或 IP")
    if not re.fullmatch(r"[A-Za-z0-9_.:\-]+", name):
        raise ValueError("域名/IP 含非法字符")
    server = _valid_server(server)
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    if server:
        resolver.nameservers = [server]

    records = {}
    errors = {}
    is_ip = False
    try:
        ipaddress.ip_address(name)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        try:
            rev = dns.reversename.from_address(name)
            ans = resolver.resolve(rev, "PTR")
            records["PTR"] = [r.to_text() for r in ans]
        except dns.resolver.NXDOMAIN:
            errors["PTR"] = "无 PTR 记录"
        except dns.exception.Timeout:
            errors["PTR"] = "查询超时"
        except Exception as e:
            errors["PTR"] = type(e).__name__
        return {
            "name": name,
            "server": server or "系统默认",
            "type": "PTR",
            "records": records,
            "errors": errors,
        }

    if isinstance(types, str):
        requested = [t.strip().upper() for t in re.split(r"[,\s]+", types) if t.strip()]
    elif types:
        requested = [str(t).upper() for t in types]
    else:
        requested = list(("A", "AAAA", "CNAME", "MX", "TXT", "NS"))
    if not requested:
        requested = ["A"]

    for t in requested:
        if t not in SUPPORTED:
            continue
        try:
            ans = resolver.resolve(name, t, raise_on_no_answer=False)
            if ans.rrset:
                records[t] = [r.to_text() for r in ans]
            else:
                records[t] = []
        except dns.resolver.NXDOMAIN:
            errors[t] = "域名不存在"
            break
        except dns.resolver.NoNameservers:
            errors[t] = "无可用的 DNS 服务器"
        except dns.exception.Timeout:
            errors[t] = "查询超时"
        except Exception as e:
            errors[t] = type(e).__name__

    return {
        "name": name,
        "server": server or "系统默认",
        "type": "域名",
        "records": records,
        "errors": errors,
    }


def dig(name, rtype="A", server=None, timeout=4):
    name = (name or "").strip().rstrip(".")
    if not name:
        raise ValueError("请输入域名")
    if not re.fullmatch(r"[A-Za-z0-9_.\-]+", name):
        raise ValueError("域名含非法字符")
    rtype = (rtype or "A").upper()
    allowed = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "PTR", "CAA", "ANY")
    if rtype not in allowed:
        raise ValueError("不支持的记录类型")
    server = _valid_server(server)
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    if server:
        resolver.nameservers = [server]

    started = time.perf_counter()
    status, response, error = "NOERROR", None, ""
    try:
        ans = resolver.resolve(name, rtype, raise_on_no_answer=False)
        response = ans.response
    except dns.resolver.NXDOMAIN as e:
        status = "NXDOMAIN"
        response = getattr(e, "response", None)
    except dns.exception.Timeout:
        status, error = "TIMEOUT", "查询超时"
    except dns.resolver.NoNameservers:
        status, error = "SERVFAIL", "无可用的 DNS 服务器"
    except Exception as e:
        status, error = "ERROR", type(e).__name__
    ms = round((time.perf_counter() - started) * 1000, 1)

    def section(sets):
        out = []
        for rrset in sets or []:
            for rdata in rrset:
                out.append({
                    "name": str(rrset.name),
                    "ttl": rrset.ttl,
                    "type": dns.rdatatype.to_text(rrset.rdtype),
                    "data": rdata.to_text(),
                })
        return out

    flags = []
    answer = authority = additional = []
    if response is not None:
        try:
            flags = dns.flags.to_text(response.flags).split()
        except Exception:
            flags = []
        answer = section(response.answer)
        authority = section(response.authority)
        additional = section(response.additional)

    return {
        "name": name,
        "type": rtype,
        "server": server or "系统默认",
        "status": status,
        "error": error,
        "flags": flags,
        "ms": ms,
        "answer": answer,
        "authority": authority,
        "additional": additional,
    }
