"""抓包会话：后台线程、环形缓冲、打开/保存、统计与跟踪流。"""
from __future__ import annotations

import base64
import logging
import os
import sys
import threading
import time
from collections import deque
from typing import Optional

from core.pktcap import libpcap as lp
from core.pktcap.analysis import (
    _checksum_hints,
    analyze_packet,
    build_ai_brief,
    diagnose_capture,
)
from core.pktcap.dissect import dissect, match_filter
from core.pktcap.pcapfile import PcapError, read_packets, write_pcap

log = logging.getLogger("pktcap")

DEFAULT_MAX_PACKETS = 10000
DEFAULT_MAX_BYTES = 128 * 1024 * 1024
NPCAP_URL = "https://npcap.com/"

BPF_PRESETS = [
    {"id": "", "label": "全部（无过滤）", "expr": ""},
    {"id": "tcp", "label": "TCP", "expr": "tcp"},
    {"id": "udp", "label": "UDP", "expr": "udp"},
    {"id": "icmp", "label": "ICMP", "expr": "icmp or icmp6"},
    {"id": "arp", "label": "ARP", "expr": "arp"},
    {"id": "dns", "label": "DNS", "expr": "port 53 or port 5353"},
    {"id": "http", "label": "HTTP", "expr": "tcp port 80 or tcp port 8080"},
    {"id": "tls", "label": "TLS / 443", "expr": "tcp port 443 or tcp port 8443"},
]


def _platform() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return sys.platform


def capability() -> dict:
    plat = _platform()
    lib, path, err = lp.load()
    messages: list[str] = []
    hints: list[str] = []
    npcap = False
    npcap_dir = ""
    live = bool(lib)
    if plat == "windows":
        npcap, npcap_dir = lp.npcap_installed()
        if not npcap or not lib:
            live = False
            messages.append(
                "未检测到 Npcap，无法进行实时抓包。请到官网安装 Npcap（安装时建议勾选 "
                "“Install Npcap in WinPcap API-compatible Mode”），装好后重新打开本程序。"
            )
            hints.append(f"官方下载：{NPCAP_URL}")
            hints.append("本程序不会内置或再分发 Npcap。即使未安装，仍可打开 .pcap / .pcapng 做离线分析。")
        else:
            messages.append("已检测到 Npcap，可以实时抓包。部分网卡或混杂模式可能需要以管理员身份运行本程序。")
            hints.append("打开或分析 pcap 文件不需要管理员权限。")
        if err and not lib:
            hints.append(f"加载 wpcap 失败：{err}")
    elif plat == "macos":
        if not lib:
            live = False
            messages.append("未能加载系统 libpcap，实时抓包不可用。仍可打开 pcap 文件做离线分析。")
            if err:
                hints.append(err)
        else:
            bpf_ok, bpf_msg = _macos_bpf_access()
            if not bpf_ok:
                messages.append(
                    "实时抓包需要访问 /dev/bpf*。若开始抓包时提示权限不足，请用管理员权限运行本程序，"
                    "或在「系统设置 → 隐私与安全性」中授予相关权限。"
                )
                if bpf_msg:
                    hints.append(bpf_msg)
            else:
                messages.append("已加载 libpcap，可以实时抓包。")
            hints.append("打开或分析 pcap 文件不需要这些权限。")
    else:
        if lib:
            messages.append("已加载 libpcap。列出网卡或开始抓包可能需要相应权限。")
        else:
            live = False
            messages.append("未加载 libpcap，实时抓包不可用。仍可打开 pcap 文件。")
            if err:
                hints.append(err)
    if plat == "windows" and not live:
        banner_short = "未安装 Npcap，无法实时抓包；打开 pcap 仍可用。"
        banner_kind = "warn"
    elif plat == "macos" and not live:
        banner_short = "未能加载 libpcap，无法实时抓包；打开 pcap 仍可用。"
        banner_kind = "warn"
    elif plat == "macos" and live and messages and "bpf" in messages[0].lower():
        banner_short = "实时抓包可能缺少 BPF 权限；打开 pcap 仍可用。"
        banner_kind = "warn"
    elif not live:
        banner_short = "实时抓包不可用；打开 pcap 仍可用。"
        banner_kind = "warn"
    else:
        banner_short = ""
        banner_kind = ""

    hints.append("明文协议（如 HTTP、DNS、Telnet）可能含账号、密码或 Cookie，仅在本机分析，流量不会上传。")
    hints.append("本工具是独立实现的报文查看器，不是 Wireshark，也不会把流量发到云端。")
    return {
        "platform": plat,
        "live_available": live,
        "libpcap_loaded": bool(lib),
        "libpcap_path": path or "",
        "load_error": err or "",
        "npcap_installed": npcap,
        "npcap_dir": npcap_dir,
        "npcap_url": NPCAP_URL,
        "can_offline": True,
        "banner_short": banner_short,
        "banner_kind": banner_kind,
        "messages": messages,
        "hints": hints,
        "presets": BPF_PRESETS,
        "default_max_packets": DEFAULT_MAX_PACKETS,
        "default_max_bytes": DEFAULT_MAX_BYTES,
    }


def _macos_bpf_access() -> tuple[bool, str]:
    for i in range(4):
        path = f"/dev/bpf{i}"
        if not os.path.exists(path):
            continue
        if os.access(path, os.R_OK | os.W_OK):
            return True, ""
        return False, f"{path} 当前用户不可读写"
    if any(os.path.exists(f"/dev/bpf{i}") for i in range(8)):
        return False, "存在 /dev/bpf* 设备，但当前用户没有读写权限"
    return False, "未找到 /dev/bpf* 设备"


def list_interfaces() -> dict:
    cap = capability()
    devs, err = [], ""
    if cap["libpcap_loaded"]:
        try:
            devs, err = lp.list_devices()
        except Exception as e:
            log.exception("list_devices")
            err = f"{type(e).__name__}: {e}"
    return {
        **cap,
        "interfaces": devs,
        "error": err or "",
    }


class _Session:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.packets: deque[dict] = deque()
        self.max_packets = DEFAULT_MAX_PACKETS
        self.max_bytes = DEFAULT_MAX_BYTES
        self.on_limit = "drop"  # drop | stop
        self.running = False
        self.stop_evt = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.handle = None
        self.error = ""
        self.warning = ""
        self.source = ""  # live / file / upload
        self.iface = ""
        self.bpf = ""
        self.linktype = 1
        self.next_no = 1
        self.dropped_old = 0
        self.limit_hit = False
        self.stopped_reason = ""
        self.started_at = 0.0
        self.bytes_held = 0
        self.file_name = ""
        self.file_warnings: list[str] = []
        self.capture_stats = {"recv": 0, "drop": 0, "ifdrop": 0}
        self._summaries_cache: list[dict] = []
        self._cache_dirty = True

    def reset_packets(self) -> None:
        with self.lock:
            self.packets.clear()
            self.next_no = 1
            self.dropped_old = 0
            self.limit_hit = False
            self.stopped_reason = ""
            self.warning = ""
            self.error = ""
            self.bytes_held = 0
            self.file_name = ""
            self.file_warnings = []
            self.source = ""
            self._cache_dirty = True


SESS = _Session()


def _summary_of(rec: dict) -> dict:
    v = rec.get("view")
    if not v:
        v = dissect(rec["data"], ts=rec["ts"], number=rec["no"],
                    orig_len=rec.get("orig_len"), linktype=rec.get("linktype", 1),
                    iface=rec.get("iface") or "")
        rec["view"] = v
    return {
        "no": v["no"],
        "ts": v["ts"],
        "length": v["length"],
        "caplen": v["caplen"],
        "src": v["src"],
        "dst": v["dst"],
        "protocol": v["protocol"],
        "info": v["info"],
        "sport": v.get("sport"),
        "dport": v.get("dport"),
        "ip_src": v.get("ip_src") or "",
        "ip_dst": v.get("ip_dst") or "",
        "l4": v.get("l4") or "",
        "stream_key": v.get("stream_key"),
        "tcp_flags": v.get("tcp_flags") or 0,
        "tcp_seq": v.get("tcp_seq"),
        "tcp_ack": v.get("tcp_ack"),
        "tcp_window": v.get("tcp_window"),
        "payload_len": v.get("payload_len") or 0,
        "ttl": v.get("ttl"),
    }


def _ensure_view(rec: dict) -> dict:
    if not rec.get("view"):
        rec["view"] = dissect(rec["data"], ts=rec["ts"], number=rec["no"],
                              orig_len=rec.get("orig_len"), linktype=rec.get("linktype", 1),
                              iface=rec.get("iface") or "")
    return rec["view"]


def _append(rec_base: dict) -> None:
    with SESS.lock:
        if SESS.on_limit == "stop" and len(SESS.packets) >= SESS.max_packets:
            SESS.limit_hit = True
            SESS.stopped_reason = f"已达到上限 {SESS.max_packets} 个包，已停止抓包。"
            SESS.warning = SESS.stopped_reason
            SESS.stop_evt.set()
            return
        while SESS.packets and (
            len(SESS.packets) >= SESS.max_packets
            or SESS.bytes_held + len(rec_base["data"]) > SESS.max_bytes
        ):
            old = SESS.packets.popleft()
            SESS.bytes_held -= len(old.get("data") or b"")
            old.pop("view", None)
            SESS.dropped_old += 1
            SESS.limit_hit = True
            SESS.warning = (
                f"已达到内存上限（最多 {SESS.max_packets} 个包或 {SESS.max_bytes // (1024 * 1024)} MB），"
                f"已丢弃最旧的 {SESS.dropped_old} 个包。"
            )
            SESS._cache_dirty = True
        rec = {
            "no": SESS.next_no,
            "ts": rec_base.get("ts") or time.time(),
            "data": rec_base["data"],
            "orig_len": rec_base.get("orig_len") or len(rec_base["data"]),
            "linktype": rec_base.get("linktype", SESS.linktype),
            "iface": rec_base.get("iface") or SESS.iface,
        }
        SESS.next_no += 1
        SESS.packets.append(rec)
        SESS.bytes_held += len(rec["data"])
        SESS._cache_dirty = True


def start_capture(iface: str, bpf: str = "", snaplen: int = 65535,
                  max_packets: int = DEFAULT_MAX_PACKETS, max_bytes: int = DEFAULT_MAX_BYTES,
                  on_limit: str = "drop", promiscuous: bool = True) -> dict:
    cap = capability()
    if not cap["live_available"]:
        raise RuntimeError(cap["messages"][0] if cap["messages"] else "实时抓包不可用")
    iface = (iface or "").strip()
    if not iface:
        raise ValueError("请选择要抓包的网卡")
    with SESS.lock:
        if SESS.running:
            raise RuntimeError("已经在抓包，请先停止")
        SESS.reset_packets()
        SESS.max_packets = max(1, min(int(max_packets or DEFAULT_MAX_PACKETS), 200000))
        SESS.max_bytes = max(1 * 1024 * 1024, min(int(max_bytes or DEFAULT_MAX_BYTES), 1024 * 1024 * 1024))
        SESS.on_limit = "stop" if on_limit == "stop" else "drop"
        SESS.iface = iface
        SESS.bpf = (bpf or "").strip()
        SESS.source = "live"
        SESS.error = ""
        SESS.warning = ""
        SESS.stop_evt.clear()
        SESS.started_at = time.time()
        SESS.running = True

    def worker():
        handle = None
        try:
            handle = lp.open_live(iface, snaplen=snaplen or 65535, promiscuous=promiscuous, timeout_ms=250)
            if SESS.bpf:
                lp.set_filter(handle, SESS.bpf)
            link = lp.datalink(handle)
            with SESS.lock:
                SESS.handle = handle
                SESS.linktype = int(link)
            while not SESS.stop_evt.is_set():
                try:
                    rc, pkt = lp.next_ex(handle)
                except Exception as e:
                    log.exception("pcap_next_ex")
                    with SESS.lock:
                        SESS.error = f"抓包读取失败：{type(e).__name__}: {e}"
                    break
                if rc == 1 and pkt:
                    pkt["linktype"] = SESS.linktype
                    pkt["iface"] = iface
                    _append(pkt)
                    if SESS.stop_evt.is_set():
                        break
                    continue
                if rc == 0:
                    continue
                if rc == -2:
                    break
                if rc < 0:
                    with SESS.lock:
                        SESS.error = lp._geterr(handle) or "抓包出错"
                    log.error("pcap error: %s", SESS.error)
                    break
        except Exception as e:
            log.exception("capture thread")
            with SESS.lock:
                SESS.error = _friendly_live_error(str(e))
        finally:
            try:
                if handle:
                    SESS.capture_stats = lp.stats(handle)
                    lp.close(handle)
            except Exception:
                log.exception("close pcap")
            with SESS.lock:
                SESS.handle = None
                SESS.running = False

    t = threading.Thread(target=worker, name="pktcap", daemon=True)
    SESS.thread = t
    t.start()
    return status()


def _friendly_live_error(msg: str) -> str:
    low = (msg or "").lower()
    plat = _platform()
    extra = ""
    if plat == "windows":
        if any(s in low for s in ("not found", "no such device", "adapter")):
            extra = " 请确认已选择有效网卡，并已安装 Npcap。"
        elif any(s in low for s in ("permission", "access", "administrator", "denied")):
            extra = " 请尝试以管理员身份重新运行本程序。"
        elif any(s in low for s in ("npcap", "wpcap", "packet.dll")):
            extra = f" 请安装 Npcap：{NPCAP_URL}"
    elif plat == "macos":
        if any(s in low for s in ("permission", "denied", "operation not permitted", "bpf")):
            extra = " 请用管理员权限运行，或检查「隐私与安全性」中的相关权限（/dev/bpf*）。"
    return f"无法开始抓包：{msg}{extra}"


def stop_capture() -> dict:
    with SESS.lock:
        SESS.stop_evt.set()
        handle = SESS.handle
    try:
        if handle:
            lp.breakloop(handle)
    except Exception:
        log.exception("breakloop")
    t = SESS.thread
    if t and t.is_alive() and t is not threading.current_thread():
        t.join(timeout=2.5)
    with SESS.lock:
        SESS.running = False
        SESS.handle = None
    return status()


def clear_packets() -> dict:
    running = False
    with SESS.lock:
        running = SESS.running
    if running:
        stop_capture()
    SESS.reset_packets()
    return status()


def status() -> dict:
    with SESS.lock:
        cap = capability()
        return {
            "running": SESS.running,
            "count": len(SESS.packets),
            "next_no": SESS.next_no,
            "dropped_old": SESS.dropped_old,
            "limit_hit": SESS.limit_hit,
            "warning": SESS.warning,
            "error": SESS.error,
            "source": SESS.source,
            "iface": SESS.iface,
            "bpf": SESS.bpf,
            "linktype": SESS.linktype,
            "bytes": SESS.bytes_held,
            "max_packets": SESS.max_packets,
            "max_bytes": SESS.max_bytes,
            "on_limit": SESS.on_limit,
            "started_at": SESS.started_at,
            "file_name": SESS.file_name,
            "file_warnings": list(SESS.file_warnings),
            "stopped_reason": SESS.stopped_reason,
            "capture_stats": dict(SESS.capture_stats),
            "live_available": cap["live_available"],
        }


def packet_summaries(after: int = 0, limit: int = 500, query: str = "") -> dict:
    after = max(0, int(after or 0))
    limit = max(1, min(int(limit or 500), 20000))
    rows = []
    with SESS.lock:
        recs = list(SESS.packets)
        st = status()
    for rec in recs:
        if rec["no"] <= after:
            continue
        try:
            s = _summary_of(rec)
        except Exception as e:
            log.exception("dissect summary %s", rec.get("no"))
            s = {
                "no": rec["no"], "ts": rec.get("ts") or 0, "length": rec.get("orig_len") or len(rec["data"]),
                "caplen": len(rec["data"]), "src": "—", "dst": "—", "protocol": "DATA",
                "info": f"解析失败：{type(e).__name__}: {e}",
                "sport": None, "dport": None, "ip_src": "", "ip_dst": "", "l4": "", "stream_key": None,
            }
        if query and not match_filter(s, query):
            continue
        rows.append(s)
        if len(rows) >= limit:
            break
    return {"packets": rows, **{k: st[k] for k in (
        "running", "count", "next_no", "dropped_old", "limit_hit", "warning", "error", "source", "bytes"
    )}}


def _stream_views_locked(key) -> list[dict]:
    if not key:
        return []
    out = []
    for rec in SESS.packets:
        try:
            v = _ensure_view(rec)
        except Exception:
            continue
        if v.get("stream_key") == key:
            out.append(v)
    return out


def _analysis_fields(view: dict) -> dict:
    keys = (
        "no", "ts", "length", "caplen", "src", "dst", "protocol", "info",
        "sport", "dport", "ip_src", "ip_dst", "l4", "stream_key",
        "tcp_flags", "tcp_seq", "tcp_ack", "tcp_window", "payload_len", "ttl",
        "layers",
    )
    return {k: view.get(k) for k in keys}


def packet_detail(no: int) -> dict:
    no = int(no)
    with SESS.lock:
        rec = next((p for p in SESS.packets if p["no"] == no), None)
        if rec is None:
            raise KeyError(f"没有序号为 {no} 的报文（可能已被上限策略丢弃）")
        view = _ensure_view(rec)
        raw = rec["data"]
        peers = _stream_views_locked(view.get("stream_key"))
    analysis = analyze_packet(view, raw=raw, stream=peers)
    return {
        "no": view["no"],
        "ts": view["ts"],
        "length": view["length"],
        "caplen": view["caplen"],
        "src": view["src"],
        "dst": view["dst"],
        "protocol": view["protocol"],
        "info": view["info"],
        "layers": view["layers"],
        "raw_b64": base64.b64encode(raw).decode("ascii"),
        "sport": view.get("sport"),
        "dport": view.get("dport"),
        "stream_key": view.get("stream_key"),
        "tcp_flags": view.get("tcp_flags") or 0,
        "tcp_seq": view.get("tcp_seq"),
        "tcp_ack": view.get("tcp_ack"),
        "tcp_window": view.get("tcp_window"),
        "payload_len": view.get("payload_len") or 0,
        "ttl": view.get("ttl"),
        "analysis": analysis,
    }


def diagnose(query: str = "") -> dict:
    """对当前会话（可选显示过滤）做离线诊断。"""
    query = (query or "").strip()
    with SESS.lock:
        recs = list(SESS.packets)
    views = []
    checksum_hits = []
    for rec in recs:
        try:
            view = _ensure_view(rec)
        except Exception:
            continue
        summary = {
            "no": view["no"],
            "ts": view["ts"],
            "length": view["length"],
            "caplen": view["caplen"],
            "src": view["src"],
            "dst": view["dst"],
            "protocol": view["protocol"],
            "info": view["info"],
            "sport": view.get("sport"),
            "dport": view.get("dport"),
            "ip_src": view.get("ip_src") or "",
            "ip_dst": view.get("ip_dst") or "",
            "l4": view.get("l4") or "",
            "stream_key": view.get("stream_key"),
            "tcp_flags": view.get("tcp_flags") or 0,
            "tcp_seq": view.get("tcp_seq"),
            "tcp_ack": view.get("tcp_ack"),
            "tcp_window": view.get("tcp_window"),
            "payload_len": view.get("payload_len") or 0,
            "ttl": view.get("ttl"),
            "layers": view.get("layers"),
        }
        if query and not match_filter(summary, query):
            continue
        # 校验和提示（仅未截断）
        for h in _checksum_hints(view, rec.get("data") or b""):
            if h.get("level") == "error":
                checksum_hits.append(f"第 {view.get('no')} 号 {h.get('text')}")
        if checksum_hits and views is not None:
            summary["_checksum_hints"] = [h for h in checksum_hits if f"第 {view.get('no')} 号" in h]
        views.append(summary)
    result = diagnose_capture(views, filtered=bool(query))
    return result


def deep_analyze_brief(no: int | None = None, query: str = "") -> dict:
    """准备发给大模型的脱敏摘要。不含完整原始报文。"""
    diag = diagnose(query=query)
    stats = protocol_stats()
    conv = conversations().get("conversations") or []
    selected = None
    selected_analysis = None
    if no:
        try:
            detail = packet_detail(int(no))
            selected = {
                "no": detail["no"],
                "protocol": detail["protocol"],
                "src": detail["src"],
                "dst": detail["dst"],
                "length": detail["length"],
                "info": detail["info"],
            }
            selected_analysis = detail.get("analysis")
        except KeyError:
            selected = None
    with SESS.lock:
        recs = list(SESS.packets)
    summaries = []
    for rec in recs:
        try:
            s = _summary_of(rec)
        except Exception:
            continue
        if query and not match_filter(s, query):
            continue
        summaries.append(s)
    text = build_ai_brief(
        diag,
        selected=selected,
        selected_analysis=selected_analysis,
        stats=stats,
        conversations=conv,
        more_packets=summaries,
    )
    return {
        "text": text,
        "count": diag.get("count") or 0,
        "has_selection": bool(selected),
    }


def open_path(path: str, max_packets: int = DEFAULT_MAX_PACKETS) -> dict:
    path = os.path.expanduser(path or "")
    if not path or not os.path.isfile(path):
        raise FileNotFoundError("找不到该文件")
    with open(path, "rb") as f:
        data = f.read()
    return open_bytes(data, name=os.path.basename(path), max_packets=max_packets)


def open_bytes(data: bytes, name: str = "capture.pcap", max_packets: int = DEFAULT_MAX_PACKETS) -> dict:
    if not data:
        raise PcapError("文件是空的")
    parsed = read_packets(data)
    pkts = parsed["packets"]
    warnings = list(parsed.get("warnings") or [])
    total = len(pkts)
    max_packets = max(1, min(int(max_packets or DEFAULT_MAX_PACKETS), 200000))
    if total > max_packets:
        pkts = pkts[:max_packets]
        warnings.append(f"文件共有 {total} 个包，仅载入前 {max_packets} 个，以免占用过多内存。")
    running = False
    with SESS.lock:
        running = SESS.running
    if running:
        stop_capture()
    SESS.reset_packets()
    with SESS.lock:
        SESS.source = "file"
        SESS.file_name = name
        SESS.linktype = int(parsed.get("linktype") or 1)
        SESS.max_packets = max_packets
        SESS.file_warnings = warnings
        SESS.warning = "；".join(warnings)
        SESS.iface = ""
        SESS.bpf = ""
    for p in pkts:
        _append({
            "ts": p.get("ts") or 0.0,
            "data": p["data"],
            "orig_len": p.get("orig_len") or len(p["data"]),
            "linktype": p.get("linktype") or SESS.linktype,
            "iface": "",
        })
    st = status()
    st["format"] = parsed.get("format")
    st["file_total"] = total
    return st


def save_path(path: str) -> dict:
    path = os.path.expanduser(path or "")
    if not path:
        raise ValueError("未指定保存路径")
    data, count, linktype = _dump_bytes()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return {"path": path, "count": count, "bytes": len(data), "linktype": linktype}


def save_bytes() -> tuple[bytes, str]:
    data, count, _ = _dump_bytes()
    name = SESS.file_name or "capture.pcap"
    if not name.lower().endswith((".pcap", ".cap")):
        name = os.path.splitext(name)[0] + ".pcap"
    return data, name


def _dump_bytes() -> tuple[bytes, int, int]:
    with SESS.lock:
        recs = list(SESS.packets)
        linktype = SESS.linktype or 1
        # 若包来自不同链路类型，按第一包
        if recs:
            types = {r.get("linktype") or linktype for r in recs}
            if len(types) > 1:
                # 仍写出，但用出现最多的类型；不同 DLT 混写会不准确
                log.warning("mixed linktypes when saving: %s", types)
            linktype = recs[0].get("linktype") or linktype
        payload = [{"ts": r["ts"], "data": r["data"], "orig_len": r.get("orig_len")} for r in recs]
    blob = write_pcap(payload, linktype=linktype)
    return blob, len(payload), linktype


def protocol_stats() -> dict:
    counts: dict[str, dict] = {}
    with SESS.lock:
        recs = list(SESS.packets)
    for rec in recs:
        try:
            s = _summary_of(rec)
        except Exception:
            proto = "DATA"
            length = rec.get("orig_len") or len(rec.get("data") or b"")
            counts.setdefault(proto, {"protocol": proto, "count": 0, "bytes": 0})
            counts[proto]["count"] += 1
            counts[proto]["bytes"] += length
            continue
        proto = s.get("protocol") or "DATA"
        counts.setdefault(proto, {"protocol": proto, "count": 0, "bytes": 0})
        counts[proto]["count"] += 1
        counts[proto]["bytes"] += int(s.get("length") or 0)
    rows = sorted(counts.values(), key=lambda x: (-x["count"], x["protocol"]))
    return {"protocols": rows, "total": len(recs)}


def conversations() -> dict:
    conv: dict[tuple, dict] = {}
    with SESS.lock:
        recs = list(SESS.packets)
    for rec in recs:
        try:
            s = _summary_of(rec)
        except Exception:
            continue
        key = s.get("stream_key")
        if not key:
            a = s.get("ip_src") or s.get("src") or "?"
            b = s.get("ip_dst") or s.get("dst") or "?"
            proto = s.get("protocol") or "DATA"
            pair = tuple(sorted((a, b)))
            key = (proto, pair[0], None, pair[1], None)
        item = conv.get(key)
        length = int(s.get("length") or 0)
        if item is None:
            conv[key] = {
                "protocol": key[0],
                "endpoint_a": f"{key[1]}" + (f":{key[2]}" if key[2] is not None else ""),
                "endpoint_b": f"{key[3]}" + (f":{key[4]}" if key[4] is not None else ""),
                "packets": 1,
                "bytes": length,
                "first_no": s["no"],
                "last_no": s["no"],
            }
        else:
            item["packets"] += 1
            item["bytes"] += length
            item["last_no"] = s["no"]
    rows = sorted(conv.values(), key=lambda x: (-x["packets"], x["protocol"]))
    return {"conversations": rows, "total": len(rows)}


def follow_stream(no: int) -> dict:
    no = int(no)
    with SESS.lock:
        recs = list(SESS.packets)
    target = next((r for r in recs if r["no"] == no), None)
    if target is None:
        raise KeyError(f"没有序号为 {no} 的报文")
    view = _ensure_view(target)
    key = view.get("stream_key")
    if not key or key[0] != "TCP":
        # 仍尽量按四元组跟
        if not (view.get("ip_src") and view.get("sport") is not None):
            raise ValueError("该报文没有 TCP 四元组，无法跟踪流")
        a = (view["ip_src"], view["sport"])
        b = (view["ip_dst"], view["dport"])
        key = ("TCP",) + (a + b if a <= b else b + a)
    segs = []
    for rec in recs:
        v = _ensure_view(rec)
        if v.get("stream_key") != key:
            continue
        if (v.get("payload_len") or 0) <= 0 or v.get("payload_off") is None:
            # 仍记录用于序号
            segs.append(v)
            continue
        raw = rec["data"]
        start = int(v["payload_off"])
        end = start + int(v["payload_len"])
        payload = raw[start:end] if start < len(raw) else b""
        segs.append({**v, "_payload": payload})
    # 按时间排列，拼接 payload（尽力按 seq 重组）
    # 以发起方向：第一个带 SYN 的，否则第一包的 src
    origin = None
    for v in segs:
        if (v.get("tcp_flags") or 0) & 0x02:
            origin = (v.get("ip_src"), v.get("sport"))
            break
    if origin is None and segs:
        origin = (segs[0].get("ip_src"), segs[0].get("sport"))
    # 每方向独立重组
    dirs = {}
    for v in segs:
        dkey = (v.get("ip_src"), v.get("sport"))
        dirs.setdefault(dkey, []).append(v)

    def reassemble(items: list[dict]) -> bytes:
        pieces = []
        for v in items:
            payload = v.get("_payload") or b""
            if not payload:
                continue
            seq = v.get("tcp_seq")
            if seq is None:
                pieces.append((len(pieces), payload))
                continue
            # SYN 占一序号
            first = seq
            if (v.get("tcp_flags") or 0) & 0x02:
                first = (seq + 1) & 0xFFFFFFFF
            pieces.append((first, payload))
        if not pieces:
            return b""
        pieces.sort(key=lambda x: x[0])
        out = bytearray()
        expected = pieces[0][0]
        for seq, payload in pieces:
            # 处理回绕：若差距很大，按无符号距离
            gap = (seq - expected) & 0xFFFFFFFF
            if gap > 0x80000000:
                # 完全重叠的旧数据
                continue
            if seq != expected and gap != 0:
                # 有缺口
                if gap < 16 * 1024 * 1024:
                    # 不填空洞，直接拼接（避免巨大空洞）
                    pass
            # 重叠裁剪
            if ((seq - expected) & 0xFFFFFFFF) == 0 or not out:
                out.extend(payload)
                expected = (seq + len(payload)) & 0xFFFFFFFF
            elif (seq - expected) & 0xFFFFFFFF < 0x80000000:
                out.extend(payload)
                expected = (seq + len(payload)) & 0xFFFFFFFF
            else:
                skip = (expected - seq) & 0xFFFFFFFF
                if skip < len(payload):
                    out.extend(payload[skip:])
                    expected = (seq + len(payload)) & 0xFFFFFFFF
        return bytes(out)

    parts = []
    nos = []
    for v in segs:
        if v.get("no") is not None:
            nos.append(v["no"])
        payload = v.get("_payload") or b""
        if payload:
            src = f"{v.get('ip_src')}:{v.get('sport')}"
            parts.append((v.get("ts") or 0, src, payload))
    # 展示：按到达顺序交替（更接近 Follow Stream 的时间序），而不是完全按 seq 混在一起
    # 同时提供重组后的各方向
    assembled = {}
    for dkey, items in dirs.items():
        assembled[f"{dkey[0]}:{dkey[1]}"] = reassemble(items)
    timeline = b""
    for _, _, payload in parts:
        timeline += payload
    blob = timeline or b"".join(assembled.values())
    is_binary = _mostly_binary(blob)
    text = _to_follow_text(blob)
    return {
        "protocol": "TCP",
        "stream_key": list(key),
        "endpoint_a": f"{key[1]}:{key[2]}",
        "endpoint_b": f"{key[3]}:{key[4]}",
        "packet_count": len(nos),
        "packets": nos,
        "bytes": len(blob),
        "is_binary": is_binary,
        "text": text,
        "hex": _hexdump(blob[: 256 * 1024]),
        "directions": {k: _to_follow_text(v) for k, v in assembled.items()},
    }


def _mostly_binary(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:8192]
    if b"\x00" in sample:
        return True
    ctrl = sum(1 for b in sample if b < 9 or (13 < b < 32))
    return (ctrl / max(1, len(sample))) > 0.15


def _to_follow_text(data: bytes) -> str:
    if not data:
        return ""
    # 限制前端体积
    chunk = data[: 512 * 1024]
    out = []
    for b in chunk:
        if b in (9, 10, 13) or 32 <= b < 127:
            out.append(chr(b))
        elif b >= 128:
            out.append(".")
        else:
            out.append(".")
    text = "".join(out)
    if len(data) > len(chunk):
        text += f"\n… 已截断，共 {len(data)} 字节"
    return text


def _hexdump(data: bytes) -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hexpart:<47}  {ascii_part}")
    return "\n".join(lines)
