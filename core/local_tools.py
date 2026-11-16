"""本地工具：JSON 格式化、进制转换、UA 解析。"""
from __future__ import annotations

import json
import re

DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz"


def json_format(text, mode="pretty"):
    text = (text or "").strip()
    if not text:
        raise ValueError("请输入 JSON 内容")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON 格式错误：第 {e.lineno} 行第 {e.colno} 列 {e.msg}") from e
    if mode == "minify":
        out = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        label = "压缩"
    else:
        out = json.dumps(data, ensure_ascii=False, indent=2)
        label = "格式化"
    return {"result": out, "mode": label, "length": len(out), "type": type(data).__name__}


def _to_base(n, base):
    if n == 0:
        return "0"
    sign = "-" if n < 0 else ""
    n = abs(n)
    out = []
    while n:
        n, r = divmod(n, base)
        out.append(DIGITS[r])
    return sign + "".join(reversed(out))


def base_convert(value, from_base=10, to_base=16):
    raw = str(value or "").strip().lower().replace(" ", "").replace("_", "")
    if not raw:
        raise ValueError("请输入数值")
    try:
        fb = int(from_base)
        tb = int(to_base)
    except (TypeError, ValueError) as e:
        raise ValueError("进制需为 2-36 的整数") from e
    if not (2 <= fb <= 36 and 2 <= tb <= 36):
        raise ValueError("进制需在 2-36 之间")
    neg = raw.startswith("-")
    body = raw[1:] if neg else raw
    try:
        n = int(body, fb)
    except ValueError as e:
        raise ValueError(f"无法按 {fb} 进制解析该数值") from e
    if neg:
        n = -n
    result = _to_base(n, tb)
    if tb > 10:
        result = result.upper() if tb == 16 else result
    return {
        "value": raw,
        "from": fb,
        "to": tb,
        "result": result,
        "dec": str(n),
        "bin": _to_base(n, 2),
        "oct": _to_base(n, 8),
        "hex": _to_base(n, 16).upper(),
    }


def ua_parse(ua):
    ua = (ua or "").strip()
    if not ua:
        raise ValueError("请输入 User-Agent")
    browser, version = "未知", ""
    patterns = (
        ("Edge", r"Edg/([\d.]+)"),
        ("Opera", r"OPR/([\d.]+)"),
        ("Chrome", r"Chrome/([\d.]+)"),
        ("Firefox", r"Firefox/([\d.]+)"),
        ("Safari", r"Version/([\d.]+)[^)]*Safari"),
        ("curl", r"curl/([\d.]+)"),
        ("requests", r"requests/([\d.]+)"),
    )
    for name, pat in patterns:
        m = re.search(pat, ua)
        if m:
            browser, version = name, m.group(1)
            break

    if "Windows NT 10.0" in ua:
        os_name = "Windows 10 / 11"
    elif "Windows NT" in ua:
        os_name = "Windows"
    elif "Android" in ua:
        os_name = "Android"
    elif "iPhone" in ua:
        os_name = "iOS (iPhone)"
    elif "iPad" in ua:
        os_name = "iPadOS"
    elif "Mac OS X" in ua:
        os_name = "macOS"
    elif "Linux" in ua:
        os_name = "Linux"
    else:
        os_name = "未知"

    if browser in ("Chrome", "Edge", "Opera"):
        engine = "Blink"
    elif browser == "Firefox":
        engine = "Gecko"
    elif browser == "Safari":
        engine = "WebKit"
    else:
        engine = "—"

    if "Tablet" in ua or "iPad" in ua:
        device = "平板"
    elif any(k in ua for k in ("Mobile", "Android", "iPhone")):
        device = "手机"
    else:
        device = "桌面"

    return {
        "ua": ua,
        "browser": browser,
        "version": version,
        "os": os_name,
        "engine": engine,
        "device": device,
        "length": len(ua),
    }
