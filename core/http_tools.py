"""HTTP 抓取、探测、计时、下载与测速。"""
from __future__ import annotations

import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlsplit

import requests

from .util import to_int

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetTools/1.1"
DEFAULT_DOWN_URL = "https://mirrors.aliyun.com/ubuntu/ls-lR.gz"
DEFAULT_UP_URL = "https://speed.cloudflare.com/__up"
BODY_CAP = 2097152  # 2 MiB for timing body cap; fetch uses a smaller default

STATUS_REASONS = {
    200: "OK", 201: "Created", 204: "No Content", 206: "Partial Content",
    301: "Moved Permanently", 302: "Found", 303: "See Other", 304: "Not Modified",
    307: "Temporary Redirect", 308: "Permanent Redirect",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
    405: "Method Not Allowed", 408: "Request Timeout", 429: "Too Many Requests",
    500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway",
    503: "Service Unavailable", 504: "Gateway Timeout",
}


def normalize_url(url):
    url = (url or "").strip()
    if not url:
        raise ValueError("请输入 URL")
    if "://" not in url:
        url = "http://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError("仅支持 http / https")
    if not parts.hostname:
        raise ValueError("URL 缺少主机名")
    return url


def _session():
    s = requests.Session()
    s.headers["User-Agent"] = UA
    return s


def fetch(url, method="GET", headers=None, body=None, follow=True, timeout=15, max_body=262144):
    url = normalize_url(url)
    timeout = to_int(timeout, 15, 1, 120)
    max_body = to_int(max_body, 262144, 1024, 2 * 1024 * 1024)
    started = time.perf_counter()
    s = _session()
    try:
        r = s.request(
            (method or "GET").upper(),
            url,
            headers=headers or {},
            data=(body.encode("utf-8") if isinstance(body, str) else body),
            timeout=timeout,
            allow_redirects=bool(follow),
            stream=True,
        )
        chunks = []
        total = 0
        for chunk in r.iter_content(65536):
            if not chunk:
                continue
            if total < max_body:
                need = max_body - total
                chunks.append(chunk[:need])
            total += len(chunk)
            if total >= max_body:
                # keep counting? original stops reading after cap? 
                # downloaded vs content_length, truncated flag
                # They likely stop after max_body to be safe
                break
        raw = b"".join(chunks)
        elapsed = round((time.perf_counter() - started) * 1000, 1)
        enc = r.encoding or "utf-8"
        try:
            text = raw.decode(enc, "replace")
        except (LookupError, TypeError):
            text = raw.decode("utf-8", "replace")
        clen = r.headers.get("Content-Length")
        try:
            clen = int(clen) if clen is not None else None
        except ValueError:
            clen = None
        return {
            "url": url,
            "status": r.status_code,
            "reason": r.reason,
            "final_url": r.url,
            "elapsed_ms": elapsed,
            "content_length": clen,
            "downloaded": total,
            "truncated": total > len(raw) or (clen is not None and clen > len(raw)),
            "headers": dict(r.headers),
            "body": text,
        }
    finally:
        try:
            r.close()
        except Exception:
            pass
        s.close()


def _fmt_cert_name(seq):
    out = []
    for item in seq or ():
        try:
            k, v = item
            out.append(f"{k}={v}")
        except (TypeError, ValueError):
            # openssl style ((('countryName', 'CN'),),)
            if isinstance(item, (list, tuple)) and item:
                inner = item[0] if isinstance(item[0], (list, tuple)) else item
                if len(inner) == 2:
                    out.append(f"{inner[0]}={inner[1]}")
    return ", ".join(out)


def _redirect_chain(url, timeout=8):
    hops = []
    cur = url
    s = requests.Session()
    try:
        for _ in range(8):
            try:
                r = s.request("HEAD", cur, allow_redirects=False, timeout=timeout,
                              headers={"User-Agent": UA})
                if r.status_code in (405, 501):
                    r.close()
                    r = s.request("GET", cur, allow_redirects=False, timeout=timeout,
                                  headers={"User-Agent": UA}, stream=True)
            except requests.RequestException:
                break
            loc = r.headers.get("Location") or ""
            hops.append({
                "url": cur,
                "status": r.status_code,
                "location": loc,
                "ms": round(r.elapsed.total_seconds() * 1000, 1),
            })
            r.close()
            if r.status_code not in (301, 302, 303, 307, 308) or not loc:
                break
            cur = urljoin(cur, loc)
    finally:
        s.close()
    return hops


def _tls_versions(host, port, timeout):
    versions = [
        ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
        ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
        ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
    ]

    def one(item):
        label, ver = item
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ver
            ctx.maximum_version = ver
        except ValueError:
            return None
        try:
            raw = socket.create_connection((host, port), timeout=timeout)
            try:
                with ctx.wrap_socket(raw, server_hostname=host):
                    return label
            finally:
                raw.close()
        except (ssl.SSLError, OSError, ValueError):
            return None

    with ThreadPoolExecutor(max_workers=3) as pool:
        return [x for x in pool.map(one, versions) if x]


def _cert_chain(host, port, timeout):
    ctx = ssl.create_default_context()
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        s = ctx.wrap_socket(raw, server_hostname=host)
    except OSError:
        return []
    try:
        ders = []
        if hasattr(s, "get_verified_chain"):
            try:
                ders = s.get_verified_chain() or []
            except ssl.SSLError:
                ders = []
        if not ders:
            cert = s.getpeercert(binary_form=True)
            ders = [cert] if cert else []
        try:
            from cryptography import x509
        except ImportError:
            return []
        now = time.time()
        out = []
        for der in ders:
            c = x509.load_der_x509_certificate(der)
            na = c.not_valid_after_utc.timestamp()
            out.append({
                "subject": c.subject.rfc4514_string(),
                "issuer": c.issuer.rfc4514_string(),
                "not_after": c.not_valid_after_utc.strftime("%Y-%m-%d"),
                "days_left": int((na - now) / 86400),
            })
        return out
    except Exception:
        return []
    finally:
        try:
            s.close()
        except Exception:
            pass


def http_timing(url, timeout=10):
    url = normalize_url(url)
    u = urlsplit(url)
    host = u.hostname
    is_tls = u.scheme == "https"
    port = u.port or (443 if is_tls else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    timeout = to_int(timeout, 10, 1, 60)
    t0 = time.perf_counter()
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    dns_ms = round((time.perf_counter() - t0) * 1000, 1)
    af, _, _, _, sockaddr = infos[0]
    ip = sockaddr[0]
    sock = socket.socket(af, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    t1 = time.perf_counter()
    sock.connect((ip, port))
    tcp_ms = round((time.perf_counter() - t1) * 1000, 1)
    tls_ms = 0
    cert = None
    if is_tls:
        ctx = ssl.create_default_context()
        t2 = time.perf_counter()
        sock = ctx.wrap_socket(sock, server_hostname=host)
        tls_ms = round((time.perf_counter() - t2) * 1000, 1)
        pc = sock.getpeercert() or {}
        expire = days = None
        if pc.get("notAfter"):
            try:
                expire = ssl.cert_time_to_seconds(pc["notAfter"])
                days = int((expire - time.time()) / 86400)
            except (TypeError, ValueError):
                days = None
        cert = {
            "subject": _fmt_cert_name(pc.get("subject")),
            "issuer": _fmt_cert_name(pc.get("issuer")),
            "not_before": pc.get("notBefore"),
            "not_after": pc.get("notAfter"),
            "days_left": days,
            "tls_version": sock.version(),
            "cipher": (sock.cipher() or (None, None, None))[0],
        }
    req = (
        "GET " + path + " HTTP/1.1\r\nHost: " + host +
        "\r\nUser-Agent: " + UA +
        "\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    )
    sock.sendall(req.encode("latin-1", "replace"))
    t3 = time.perf_counter()
    first = sock.recv(65536)
    ttfb_ms = round((time.perf_counter() - t3) * 1000, 1)
    data = [first]
    received = len(first)
    truncated = False
    while received < BODY_CAP:
        buf = sock.recv(65536)
        if not buf:
            break
        if received < BODY_CAP:
            data.append(buf[: BODY_CAP - received])
        received += len(buf)
        if received >= BODY_CAP:
            truncated = True
            break
    total_ms = round((time.perf_counter() - t0) * 1000, 1)
    try:
        sock.close()
    except OSError:
        pass
    raw = b"".join(data)
    head, _, body = raw.partition(b"\r\n\r\n")
    text = head.decode("iso-8859-1", "replace")
    lines = text.split("\r\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        status = 0
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip()] = v.strip()
    return {
        "url": url,
        "ip": ip,
        "status": status,
        "server": headers.get("Server"),
        "content_type": headers.get("Content-Type"),
        "size": received,
        "truncated": truncated,
        "metrics": {"dns": dns_ms, "tcp": tcp_ms, "tls": tls_ms, "ttfb": ttfb_ms, "total": total_ms},
        "headers": headers,
        "cert": cert,
    }


def server_probe(url):
    url = normalize_url(url)
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_timing = pool.submit(http_timing, url)
        f_chain = pool.submit(_redirect_chain, url)
        try:
            out = dict(f_timing.result())
        except Exception as e:
            raise
        hops = f_chain.result()
        out["redirects"] = hops
        out["final_url"] = hops[-1]["url"] if hops else url
        u = urlsplit(out.get("final_url") or url)
        if u.scheme == "https" and u.hostname:
            port = u.port or 443
            f_certs = pool.submit(_cert_chain, u.hostname, port, 8)
            f_vers = pool.submit(_tls_versions, u.hostname, port, 5)
            out["cert_chain"] = f_certs.result()
            out["tls_versions"] = f_vers.result()
        else:
            out["cert_chain"] = []
            out["tls_versions"] = []
    return out


def web_probe(url, timeout=8, max_hops=5):
    """完整网页探测（含跳转分段），保留以兼容调用。"""
    url = normalize_url(url)
    timeout = to_int(timeout, 8, 3, 30)
    hops, seen, current = [], set(), url
    for _ in range(max_hops + 1):
        if current in seen:
            break
        seen.add(current)
        try:
            m = http_timing(current, timeout)
        except (OSError, RuntimeError, ValueError) as e:
            if hops:
                raise RuntimeError(f"重定向后请求失败：{current}（{e}）") from e
            raise
        loc = (m.get("headers") or {}).get("Location") or ""
        hops.append({
            "url": current,
            "status": m.get("status"),
            "location": loc,
            "total": (m.get("metrics") or {}).get("total"),
        })
        st = m.get("status") or 0
        if 300 <= st < 400 and loc:
            current = urljoin(current, loc)
            continue
        final, last = current, m
        break
    else:
        final, last = current, m
    metrics = last.get("metrics") or {}
    size = last.get("size") or 0
    download_ms = max(0.0, (metrics.get("total") or 0) - (metrics.get("ttfb") or 0)
                      - (metrics.get("dns") or 0) - (metrics.get("tcp") or 0) - (metrics.get("tls") or 0))
    # simpler: total - ttfb after connection... original uses metrics fields
    download_ms = max(0.0, (metrics.get("total") or 0) - (metrics.get("ttfb") or 0))
    speed = round(size / 1024 * 1000 / download_ms, 1) if download_ms else 0
    overall = sum(h.get("total") or 0 for h in hops)
    return {
        "requested": url,
        "final_url": final,
        "status": last.get("status"),
        "reason": STATUS_REASONS.get(last.get("status"), ""),
        "ip": last.get("ip"),
        "redirect_count": max(len(hops) - 1, 0),
        "hops": hops,
        "metrics": {
            "dns": metrics.get("dns"), "tcp": metrics.get("tcp"),
            "tls": metrics.get("tls"), "ttfb": metrics.get("ttfb"),
            "download": round(download_ms, 1), "total": metrics.get("total"),
            "overall": overall,
        },
        "size": size,
        "truncated": last.get("truncated"),
        "speed_kbps": speed,
        "server": last.get("server"),
        "content_type": last.get("content_type"),
        "cert": last.get("cert"),
    }


def download_stream(url, seconds=10, max_mb=200):
    url = normalize_url(url)
    seconds = to_int(seconds, 10, 2, 120)
    max_mb = to_int(max_mb, 200, 1, 2048)
    limit = max_mb * 1024 * 1024
    yield {"type": "start", "url": url, "seconds": seconds, "max_mb": max_mb}
    s = _session()
    downloaded = 0
    total = None
    t0 = last_t = time.perf_counter()
    last_b = 0
    try:
        r = s.get(url, stream=True, timeout=20)
        try:
            cl = r.headers.get("Content-Length")
            total = int(cl) if cl else None
        except ValueError:
            total = None
        yield {"type": "resp", "status": r.status_code, "total": total}
        for chunk in r.iter_content(131072):
            if not chunk:
                continue
            downloaded += len(chunk)
            now = time.perf_counter()
            if now - last_t >= 0.3:
                dt = max(now - last_t, 1e-6)
                cur = round((downloaded - last_b) * 8 / dt / 1000000.0, 2)
                avg = round(downloaded * 8 / max(now - t0, 1e-6) / 1000000.0, 2)
                yield {
                    "type": "progress", "downloaded": downloaded, "total": total,
                    "elapsed": round(now - t0, 2), "cur_mbps": cur, "avg_mbps": avg,
                }
                last_t, last_b = now, downloaded
            if downloaded >= limit or (now - t0) >= seconds:
                break
    except requests.RequestException as e:
        yield {"type": "error", "message": "下载失败: " + str(e)}
        return
    finally:
        try:
            r.close()
        except Exception:
            pass
        s.close()
    elapsed = max(time.perf_counter() - t0, 1e-6)
    yield {
        "type": "done", "downloaded": downloaded, "elapsed": round(elapsed, 2),
        "avg_mbps": round(downloaded * 8 / elapsed / 1000000.0, 2),
    }


def _measure_download(url, seconds):
    s = _session()
    downloaded = 0
    t0 = time.perf_counter()
    try:
        r = s.get(url, stream=True, timeout=20)
        for chunk in r.iter_content(131072):
            if not chunk:
                continue
            downloaded += len(chunk)
            if (time.perf_counter() - t0) >= seconds:
                break
    finally:
        try:
            r.close()
        except Exception:
            pass
        s.close()
    el = max(time.perf_counter() - t0, 1e-6)
    return round(downloaded * 8 / el / 1000000.0, 2)


def _measure_upload(url, mb, seconds):
    s = _session()
    payload = b"0" * (mb * 1024 * 1024)
    t0 = time.perf_counter()
    try:
        r = s.post(url, data=payload, timeout=max(15, seconds + 30))
        if r.status_code >= 400:
            raise RuntimeError("HTTP " + str(r.status_code))
    finally:
        try:
            s.close()
        except Exception:
            pass
    el = max(time.perf_counter() - t0, 1e-6)
    return round(len(payload) * 8 / el / 1000000.0, 2)


def speed_stream(down_url=None, up_url=None):
    down_url = normalize_url(down_url) if down_url else DEFAULT_DOWN_URL
    up_url = normalize_url(up_url) if up_url else DEFAULT_UP_URL
    yield {"type": "stage", "stage": "latency", "status": "start"}
    from . import ping as ping_mod
    rtts = []
    for _ in range(4):
        r = ping_mod.ping_once("223.5.5.5", 4, 32, 1000)
        if r.get("ok") and r.get("rtt") is not None:
            rtts.append(r["rtt"])
    if rtts:
        avg = sum(rtts) / len(rtts)
        jitter = (
            sum(abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))) / (len(rtts) - 1)
            if len(rtts) > 1 else 0
        )
        yield {
            "type": "result", "stage": "latency",
            "avg": round(avg, 1), "min": round(min(rtts), 1),
            "max": round(max(rtts), 1), "jitter": round(jitter, 1),
            "loss": round((4 - len(rtts)) * 100 / 4, 1),
        }
    else:
        yield {"type": "result", "stage": "latency", "avg": None, "loss": 100}

    yield {"type": "stage", "stage": "download", "status": "start"}
    down = None
    try:
        down = _measure_download(down_url, 8)
        yield {"type": "result", "stage": "download", "mbps": down}
    except Exception as e:
        yield {"type": "stage_error", "stage": "download", "message": "下载测速失败: " + str(e)}

    yield {"type": "stage", "stage": "upload", "status": "start"}
    up = None
    try:
        up = _measure_upload(up_url, 10, 10)
        yield {"type": "result", "stage": "upload", "mbps": up}
    except Exception as e:
        yield {"type": "stage_error", "stage": "upload", "message": "上传测速失败: " + str(e)}

    yield {"type": "done", "download_mbps": down, "upload_mbps": up}


def site_compare(urls, timeout=10, status_only=False):
    import re as _re
    parts = _re.split(r"[,\s]+", urls or "")
    items = [p.strip() for p in parts if p.strip()]
    if not items:
        raise ValueError("请输入至少一个 URL")
    if len(items) > 20:
        raise ValueError("最多对比 20 个站点")
    timeout = to_int(timeout, 10, 1, 60)

    def one(u):
        started = time.perf_counter()
        try:
            if status_only:
                r = requests.get(
                    normalize_url(u), timeout=timeout, stream=True,
                    allow_redirects=True, headers={"User-Agent": UA},
                )
                try:
                    return {
                        "url": u, "ok": True, "status": r.status_code, "ip": "",
                        "server": r.headers.get("Server") or "",
                        "total": round((time.perf_counter() - started) * 1000, 1),
                        "dns": None, "tcp": None, "tls": None, "ttfb": None, "error": "",
                    }
                finally:
                    r.close()
            m = http_timing(u, timeout)
            met = m.get("metrics") or {}
            return {
                "url": u, "ok": True, "status": m.get("status"), "ip": m.get("ip"),
                "server": m.get("server"), "total": met.get("total"),
                "dns": met.get("dns"), "tcp": met.get("tcp"),
                "tls": met.get("tls"), "ttfb": met.get("ttfb"), "error": "",
            }
        except Exception as e:
            return {"url": u, "ok": False, "error": str(e)}

    with ThreadPoolExecutor(max_workers=min(8, len(items))) as pool:
        rows = list(pool.map(one, items))
    ok_rows = [r for r in rows if r.get("ok") and r.get("total") is not None]
    fastest = min((r["total"] for r in ok_rows), default=None)
    return {
        "rows": rows,
        "fastest": fastest,
        "count": len(rows),
        "mode": "status" if status_only else "full",
    }
