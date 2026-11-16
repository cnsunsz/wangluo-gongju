"""本机网络信息、公网 IP、IP 计算、时间转换、编解码与二维码。"""
from __future__ import annotations

import base64
import codecs
import hashlib
import io
import ipaddress
import json
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, unquote

import requests

from .util import CREATE_NO_WINDOW

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetTools/1.1"

CODEC_OPS = {
    "base64e": "Base64 编码",
    "base64d": "Base64 解码",
    "urle": "URL 编码",
    "urld": "URL 解码",
    "hexe": "Hex 编码",
    "hexd": "Hex 解码",
    "unicodee": "Unicode 转义",
    "unicoded": "Unicode 还原",
    "md5": "MD5",
    "sha1": "SHA1",
    "sha256": "SHA256",
}

PS_LOCAL_ADDRS = (
    "$l = Get-NetIPAddress -AddressFamily IPv4,IPv6 | "
    "Where-Object {$_.IPAddress -notlike '169.254*'} | "
    "Select-Object InterfaceAlias,InterfaceIndex,IPAddress,PrefixLength,AddressFamily; "
    "$j = ConvertTo-Json -InputObject @($l) -Compress -Depth 4; "
    "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j))"
)

PS_BUNDLE = (
    "$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1; "
    "$ad = Get-NetAdapter -InterfaceIndex $r.ifIndex -ErrorAction SilentlyContinue; "
    "$dns = Get-DnsClientServerAddress -InterfaceIndex $r.ifIndex -AddressFamily IPv4,IPv6 "
    "-ErrorAction SilentlyContinue | Select-Object -ExpandProperty ServerAddresses -Unique; "
    "$addrs = Get-NetIPAddress -AddressFamily IPv4,IPv6 | "
    "Where-Object {$_.IPAddress -notlike '169.254*'} | "
    "Select-Object InterfaceAlias,IPAddress,PrefixLength,AddressFamily; "
    "[pscustomobject]@{alias=$ad.Name; desc=$ad.InterfaceDescription; mac=$ad.MacAddress; "
    "speed=[string]$ad.LinkSpeed; status=[string]$ad.Status; ifIndex=$r.ifIndex; "
    "gateway=$r.NextHop; dns=@($dns); addrs=@($addrs)}"
)


def _ps_b64(script, timeout=12):
    cmd = ["powershell", "-NoProfile", "-Command", script]
    try:
        p = subprocess.run(
            cmd, capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    out = (p.stdout or b"").decode("ascii", "ignore").strip()
    if not out:
        return None
    try:
        return json.loads(base64.b64decode(out).decode("utf-8", "replace"))
    except (ValueError, json.JSONDecodeError):
        return None


def _ps_data(expr, timeout=10):
    script = "$d = & { " + expr + " }; $j = ConvertTo-Json -InputObject $d -Compress -Depth 5; " \
             "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j))"
    return _ps_b64(script, timeout)


def _run_cmd(cmd, timeout=6):
    try:
        p = subprocess.run(
            cmd, capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW
        )
    except (subprocess.TimeoutExpired, OSError):
        return ""
    out = p.stdout or b""
    for enc in ("utf-8", "gbk"):
        try:
            return out.decode(enc)
        except UnicodeDecodeError:
            continue
    return out.decode("utf-8", "replace")


def local_addresses():
    items = []
    data = _ps_b64(PS_LOCAL_ADDRS)
    if isinstance(data, dict):
        data = [data]
    for d in data or []:
        if not isinstance(d, dict):
            continue
        fam = d.get("AddressFamily")
        family = "IPv6" if fam in (23, "IPv6", 23.0) else "IPv4"
        items.append({
            "adapter": d.get("InterfaceAlias") or "",
            "ifindex": d.get("InterfaceIndex"),
            "ip": d.get("IPAddress"),
            "prefix": d.get("PrefixLength"),
            "family": family,
        })
    if not items:
        host = socket.gethostname()
        seen = set()
        try:
            for info in socket.getaddrinfo(host, None):
                ip = info[4][0]
                if ip in seen or ip.startswith("127.") or ip == "::1":
                    continue
                seen.add(ip)
                family = "IPv6" if ":" in ip else "IPv4"
                items.append({"adapter": "", "ip": ip, "prefix": None, "family": family})
        except OSError:
            pass
    items.sort(key=lambda x: (0 if x["family"] == "IPv4" else 1, x.get("ip") or ""))
    return items


def ip_location(ip):
    ip = (ip or "").strip()
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError as e:
            raise ValueError("IP 格式不正确") from e
    try:
        r = requests.get(
            "http://ip-api.com/json/" + ip + "?lang=zh-CN",
            timeout=6, headers={"User-Agent": UA},
        )
        d = r.json()
        if d.get("status") == "success":
            return {
                "ip": d.get("query") or ip,
                "country": d.get("country"),
                "country_code": d.get("countryCode"),
                "region": d.get("regionName"),
                "city": d.get("city"),
                "isp": d.get("isp"),
                "org": d.get("org"),
                "as": d.get("as"),
                "lat": d.get("lat"),
                "lon": d.get("lon"),
                "timezone": d.get("timezone"),
                "source": "ip-api.com",
            }
    except (requests.RequestException, ValueError):
        pass
    try:
        r = requests.get(
            "https://ipinfo.io/" + (ip + "/" if ip else "") + "json",
            timeout=6, headers={"User-Agent": UA},
        )
        d = r.json()
        lat = lon = None
        loc = (d.get("loc") or "").split(",")
        if len(loc) == 2:
            try:
                lat, lon = float(loc[0]), float(loc[1])
            except ValueError:
                pass
        return {
            "ip": d.get("ip") or ip,
            "country": d.get("country"),
            "country_code": d.get("country"),
            "region": d.get("region"),
            "city": d.get("city"),
            "isp": d.get("org"),
            "org": d.get("org"),
            "as": d.get("org"),
            "lat": lat, "lon": lon,
            "timezone": d.get("timezone"),
            "source": "ipinfo.io",
        }
    except (requests.RequestException, ValueError) as e:
        raise RuntimeError("IP 定位失败: " + str(e)) from e


def ip_calc(ip, mask=""):
    ip = (ip or "").strip()
    mask = str(mask or "").strip()
    if not ip:
        raise ValueError("请输入 IP 地址")
    if "/" not in ip:
        if mask:
            if mask.startswith("/"):
                ip = ip + mask
            elif mask.isdigit():
                ip = f"{ip}/{mask}"
            else:
                ip = f"{ip}/{mask}"
        else:
            ip = ip + ("/128" if ":" in ip else "/24")
    try:
        iface = ipaddress.ip_interface(ip)
        net = iface.network
    except ValueError as e:
        raise ValueError("IP 或掩码格式不正确") from e
    total = net.num_addresses
    out = {
        "version": f"IPv{iface.version}",
        "ip": str(iface.ip),
        "prefix": net.prefixlen,
        "netmask": str(net.netmask),
        "wildcard": str(net.hostmask),
        "network": str(net.network_address),
        "total": total,
        "private": iface.ip.is_private,
        "loopback": iface.ip.is_loopback,
        "link_local": iface.ip.is_link_local,
        "multicast": iface.ip.is_multicast,
    }
    if iface.version == 4:
        if net.prefixlen <= 30:
            usable = max(total - 2, 0)
            first = str(net.network_address + 1)
            last = str(net.broadcast_address - 1)
        else:
            usable = total
            first = str(net.network_address)
            last = str(net.broadcast_address)
        first_octet = int(str(iface.ip).split(".")[0])
        if first_octet < 128:
            klass = "A"
        elif first_octet < 192:
            klass = "B"
        elif first_octet < 224:
            klass = "C"
        else:
            klass = "D/E"

        def bits(n, width=32):
            return ".".join(f"{int(p):08b}" for p in n.packed) if hasattr(n, "packed") else format(int(n), f"0{width}b")

        # binary dotted
        def bin_dotted(addr):
            return ".".join(f"{int(x):08b}" for x in str(addr).split("."))

        out.update({
            "broadcast": str(net.broadcast_address),
            "first": first,
            "last": last,
            "usable": usable,
            "class": klass,
            "binary_ip": bin_dotted(iface.ip),
            "binary_mask": bin_dotted(net.netmask),
        })
    else:
        out.update({
            "broadcast": None,
            "first": str(net.network_address),
            "last": str(net.network_address + (total - 1) if total else net.network_address),
            "usable": total,
            "class": None,
            "binary_ip": None,
            "binary_mask": None,
        })
    return out


def time_convert(value="", offset=8):
    try:
        offset = max(-12, min(14, int(offset)))
    except (TypeError, ValueError):
        offset = 8
    now = datetime.now(timezone.utc)
    value = str(value or "").strip()
    if not value:
        dt_utc = now
        source = "当前时间"
    elif re.fullmatch(r"\d{9,17}(\.\d+)?", value):
        s = value
        if "." in s:
            ts = float(s)
        elif len(s) >= 16:
            ts = int(s) / 1000000.0
        elif len(s) >= 13:
            ts = int(s) / 1000.0
        else:
            ts = int(s)
        try:
            dt_utc = datetime.fromtimestamp(ts, tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as e:
            raise ValueError("时间戳超出范围") from e
        source = "时间戳"
    else:
        s = value.replace("T", " ")
        dt = None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
        if dt is None:
            raise ValueError("无法识别，请输入时间戳或 2026-11-13 23:30:00")
        tz = timezone(timedelta(hours=offset))
        dt_utc = dt.replace(tzinfo=tz).astimezone(timezone.utc)
        source = "日期时间"
    tz = timezone(timedelta(hours=offset))
    local = dt_utc.astimezone(tz)
    weekdays = "一二三四五六日"
    iso = dt_utc.isoformat()
    return {
        "source": source,
        "timestamp_s": int(dt_utc.timestamp()),
        "timestamp_ms": int(dt_utc.timestamp() * 1000),
        "utc": dt_utc.strftime("%Y-%m-%d %H:%M:%S") + " UTC",
        "local": local.strftime("%Y-%m-%d %H:%M:%S"),
        "offset": f"UTC{'+' if offset >= 0 else ''}{offset}",
        "iso": iso,
        "weekday": weekdays[local.weekday()],
        "week": local.isocalendar().week,
        "day_of_year": local.timetuple().tm_yday,
        "now_s": int(now.timestamp()),
    }


def codec(op, text):
    text = text if text is not None else ""
    if op not in CODEC_OPS:
        raise ValueError("不支持的转换类型")
    try:
        if op == "base64e":
            out = base64.b64encode(text.encode("utf-8")).decode("ascii")
        elif op == "base64d":
            out = base64.b64decode(text, validate=False).decode("utf-8", "replace")
        elif op == "urle":
            out = quote(text, safe="")
        elif op == "urld":
            out = unquote(text)
        elif op == "hexe":
            out = text.encode("utf-8").hex()
        elif op == "hexd":
            out = bytes.fromhex(re.sub(r"\s+", "", text)).decode("utf-8", "replace")
        elif op == "unicodee":
            out = text.encode("unicode_escape").decode("ascii")
        elif op == "unicoded":
            out = codecs.decode(text, "unicode_escape")
        else:
            out = hashlib.new(op, text.encode("utf-8")).hexdigest()
    except (UnicodeDecodeError, TypeError, ValueError) as e:
        raise ValueError("转换失败: " + str(e)) from e
    return {"op": CODEC_OPS.get(op, op), "result": out, "length": len(out)}


def qr_data_url(text, size=240):
    text = (text or "").strip()
    if not text:
        raise ValueError("请输入二维码内容")
    try:
        import qrcode
        from qrcode import constants
    except ImportError as e:
        raise RuntimeError("缺少 qrcode 库，请运行 pip install qrcode pillow") from e
    size = max(120, min(640, int(size) if size else 240))
    qr = qrcode.QRCode(error_correction=constants.ERROR_CORRECT_M, box_size=8, border=2)
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    try:
        from PIL import Image
        if img.size[0] != size:
            img = img.resize((size, size), Image.NEAREST)
    except Exception:
        pass
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return {
        "data_url": "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii"),
        "size": size,
    }


def public_ipv4():
    for url in ("https://api.ipify.org?format=json", "https://ipv4.icanhazip.com"):
        try:
            r = requests.get(url, timeout=3, headers={"User-Agent": UA})
            if not r.ok:
                continue
            raw = r.text.lstrip()
            if raw.startswith("{"):
                ip = (r.json().get("ip") or "").strip()
            else:
                ip = r.text.strip().split("/")[0]
            if ipaddress.ip_address(ip).version == 4:
                host = url.split("/")[2]
                return ip, host
        except (requests.RequestException, ValueError, KeyError):
            continue
    return None, ""


def public_ipv6():
    def one(url):
        try:
            r = requests.get(url, timeout=3, headers={"User-Agent": UA})
            if not r.ok:
                return None
            raw = r.text.lstrip()
            if raw.startswith("{"):
                ip = (r.json().get("ip") or "").strip()
            else:
                ip = r.text.strip().split("/")[0]
            if ipaddress.ip_address(ip).version == 6:
                return ip, url.split("/")[2]
        except (requests.RequestException, ValueError, KeyError):
            return None
        return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        for ip in pool.map(one, ("https://api6.ipify.org?format=json", "https://ipv6.icanhazip.com")):
            if ip:
                return ip
    return None, ""


def _short_isp(isp):
    s = (isp or "").lower()
    if "telecom" in s or "电信" in (isp or ""):
        return "电信"
    if "unicom" in s or "联通" in (isp or ""):
        return "联通"
    if "mobile" in s or "移动" in (isp or ""):
        return "移动"
    return isp or ""


def _network_bundle():
    data = _ps_data(PS_BUNDLE, 10) or {}
    raw_addrs = data.get("addrs") or []
    if isinstance(raw_addrs, dict):
        raw_addrs = [raw_addrs]
    local = []
    for a in raw_addrs:
        if not isinstance(a, dict):
            continue
        fam = a.get("AddressFamily")
        family = "IPv6" if fam in (23, "IPv6", 23.0) else "IPv4"
        local.append({
            "adapter": a.get("InterfaceAlias") or "",
            "ip": a.get("IPAddress"),
            "prefix": a.get("PrefixLength"),
            "family": family,
        })
    local.sort(key=lambda x: (0 if x["family"] == "IPv4" else 1, x.get("ip") or ""))
    dns = list(data.get("dns") or [])
    mac = str(data.get("mac") or "").replace("-", ":").upper()
    profile = {
        "adapter": data.get("alias") or "",
        "desc": data.get("desc") or "",
        "mac": mac,
        "speed": data.get("speed") or "",
        "status": data.get("status") or "",
        "gateway": data.get("gateway") or "",
        "ssid": "",
        "dns": dns,
        "local": local,
    }
    if re.search(r"Wi-?Fi|Wireless|WLAN|802\.11", profile["adapter"] + " " + profile["desc"], re.I):
        out = _run_cmd(["netsh", "wlan", "show", "interfaces"], 6)
        m = re.search(r"(?im)^\s*SSID\s*:\s*(.+)$", out)
        if m:
            profile["ssid"] = m.group(1).strip()
    if not local:
        host = socket.gethostname()
        seen = set()
        try:
            for info in socket.getaddrinfo(host, None):
                ip = info[4][0]
                if ip in seen:
                    continue
                seen.add(ip)
                family = "IPv6" if ":" in ip else "IPv4"
                local.append({"adapter": "", "ip": ip, "prefix": None, "family": family})
        except OSError:
            pass
        profile["local"] = local
    return profile


def network_info(local=0):
    with ThreadPoolExecutor(max_workers=5) as pool:
        f_bundle = pool.submit(_network_bundle)
        f_v4 = pool.submit(public_ipv4)
        f_v6 = pool.submit(public_ipv6)

        def geo_job():
            try:
                ip, _ = f_v4.result()
                return ip_location(ip) if ip else {}
            except Exception:
                return {}

        f_geo = pool.submit(geo_job)
        profile = f_bundle.result() or {}
        try:
            v4, v4_src = f_v4.result()
        except Exception:
            v4, v4_src = None, ""
        try:
            v6, v6_src = f_v6.result()
        except Exception:
            v6, v6_src = None, ""
        try:
            geo = f_geo.result() or {}
        except Exception:
            geo = {}

    alias = profile.get("adapter") or ""
    addrs = profile.get("local") or []
    local_ipv4 = next((x["ip"] for x in addrs if x.get("family") == "IPv4" and (not alias or x.get("adapter") == alias)), None) \
        or next((x["ip"] for x in addrs if x.get("family") == "IPv4"), "")
    local_ipv6 = next((x["ip"] for x in addrs if x.get("family") == "IPv6" and (not alias or x.get("adapter") == alias)), None) \
        or next((x["ip"] for x in addrs if x.get("family") == "IPv6"), "")
    parts = [geo.get("country"), geo.get("region"), geo.get("city")]
    isp = _short_isp(geo.get("isp"))
    address = " ".join(p for p in parts if p and p != "-")
    if isp:
        address = (address + " " + isp).strip()
    out = {
        "local": addrs,
        "local_ipv4": local_ipv4 or "",
        "local_ipv6": local_ipv6 or "",
        "public_v4": v4,
        "public_v4_source": v4_src,
        "public_v6": v6,
        "public_v6_source": v6_src,
        "geo": geo,
        "address": address,
    }
    out.update({
        "adapter": profile.get("adapter"),
        "desc": profile.get("desc"),
        "mac": profile.get("mac"),
        "speed": profile.get("speed"),
        "status": profile.get("status"),
        "gateway": profile.get("gateway"),
        "ssid": profile.get("ssid"),
        "dns": profile.get("dns") or [],
    })
    return out
