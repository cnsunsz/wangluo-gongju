"""TCP 端口扫描。"""
from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor

from .util import parse_ports, safe_host, to_int

SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 69: "tftp", 80: "http", 110: "pop3",
    123: "ntp", 135: "msrpc", 137: "netbios", 138: "netbios", 139: "netbios",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 587: "smtp-sub", 631: "ipp", 636: "ldaps",
    873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 2181: "zookeeper", 2375: "docker",
    2376: "docker-tls", 3306: "mysql", 3389: "rdp", 5060: "sip",
    5432: "postgres", 5672: "amqp", 5900: "vnc", 6379: "redis",
    6443: "k8s-api", 7001: "weblogic", 8000: "http-alt", 8080: "http-proxy",
    8081: "http-proxy", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
    9090: "elasticsearch", 9200: "elasticsearch", 9300: "es-node",
    11211: "memcached", 27017: "mongodb",
}
HTTP_PORTS = frozenset({8000, 9090, 9000, 8008, 80, 8080, 8081, 8888})


def _resolve(host):
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as e:
        raise ValueError("域名解析失败") from e
    if not infos:
        raise ValueError("域名解析失败")
    af, _, _, _, sockaddr = infos[0]
    return af, sockaddr[0]


def _probe(af, ip, port, timeout):
    s = socket.socket(af, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) != 0:
            return None
        banner = ""
        if port in HTTP_PORTS or port == 443:
            try:
                s.settimeout(0.35)
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip.encode("ascii", "ignore"))
                raw = s.recv(160).decode("utf-8", "replace")
                banner = (raw.splitlines() or [""])[0][:120]
            except (OSError, IndexError):
                banner = ""
        return {"port": port, "service": SERVICES.get(port, ""), "banner": banner}
    finally:
        try:
            s.close()
        except OSError:
            pass


def port_scan(host, ports_spec, timeout=0.8, workers=200):
    host = safe_host(host)
    ports = parse_ports(ports_spec)
    timeout = max(0.1, min(5, float(timeout) if timeout not in (None, "") else 0.8))
    workers = to_int(workers, 200, 10, 500)
    af, ip = _resolve(host)
    started = time.perf_counter()
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_probe, af, ip, p, timeout) for p in ports]
        for f in futures:
            r = f.result()
            if r:
                open_ports.append(r)
    open_ports.sort(key=lambda x: x["port"])
    return {
        "host": host,
        "ip": ip,
        "scanned": len(ports),
        "open": open_ports,
        "duration": round(time.perf_counter() - started, 2),
        "note": "仅 TCP 连接扫描；UDP 无回包不代表关闭，未做判定。",
    }
