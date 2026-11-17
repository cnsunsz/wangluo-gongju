"""通过 ctypes 调用系统 libpcap / Npcap。缺少库时不得在 import 阶段失败。"""
from __future__ import annotations

import ctypes
import os
import sys
from ctypes import (
    POINTER, Structure, c_char, c_char_p, c_int, c_int32, c_int64,
    c_uint, c_uint32, c_void_p, c_ubyte, sizeof,
)
from typing import Optional

PCAP_ERRBUF_SIZE = 256
PCAP_IF_LOOPBACK = 0x00000001
PCAP_IF_UP = 0x00000002
PCAP_IF_RUNNING = 0x00000004
PCAP_IF_WIRELESS = 0x00000008

_lib = None
_lib_path = ""
_load_error = ""


class sockaddr(Structure):
    _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", c_char * 14)]


class pcap_addr(Structure):
    pass


pcap_addr._fields_ = [
    ("next", POINTER(pcap_addr)),
    ("addr", POINTER(sockaddr)),
    ("netmask", POINTER(sockaddr)),
    ("broadaddr", POINTER(sockaddr)),
    ("dstaddr", POINTER(sockaddr)),
]


class pcap_if(Structure):
    pass


pcap_if._fields_ = [
    ("next", POINTER(pcap_if)),
    ("name", c_char_p),
    ("description", c_char_p),
    ("addresses", POINTER(pcap_addr)),
    ("flags", c_uint32),
]


class bpf_program(Structure):
    _fields_ = [("bf_len", c_uint), ("bf_insns", c_void_p)]


class pcap_stat(Structure):
    _fields_ = [("ps_recv", c_uint), ("ps_drop", c_uint), ("ps_ifdrop", c_uint)]


def _timeval_and_pkthdr():
    if sys.platform == "win32":
        class timeval(Structure):
            _fields_ = [("tv_sec", c_int32), ("tv_usec", c_int32)]

        class pcap_pkthdr(Structure):
            _fields_ = [("ts", timeval), ("caplen", c_uint32), ("len", c_uint32)]

        return timeval, pcap_pkthdr
    if sys.platform == "darwin":
        class pcap_pkthdr(Structure):
            _fields_ = [
                ("tv_sec", c_int64),
                ("tv_usec", c_int32),
                ("_pad", c_int32),
                ("caplen", c_uint32),
                ("len", c_uint32),
            ]

        return None, pcap_pkthdr

    class timeval(Structure):
        _fields_ = [("tv_sec", c_int64), ("tv_usec", c_int64)]

    class pcap_pkthdr(Structure):
        _fields_ = [("ts", timeval), ("caplen", c_uint32), ("len", c_uint32)]

    return timeval, pcap_pkthdr


_timeval, pcap_pkthdr = _timeval_and_pkthdr()


def _npcap_dirs() -> list[str]:
    dirs = []
    windir = os.environ.get("WINDIR") or r"C:\Windows"
    for sub in ("System32\\Npcap", "SysWOW64\\Npcap"):
        dirs.append(os.path.join(windir, sub))
    dirs.append(os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Npcap"))
    dirs.append(os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Npcap"))
    return dirs


def npcap_installed() -> tuple[bool, str]:
    if sys.platform != "win32":
        return False, ""
    for d in _npcap_dirs():
        for name in ("wpcap.dll", "Packet.dll"):
            p = os.path.join(d, name)
            if os.path.isfile(p):
                return True, d
    return False, ""


def candidate_paths() -> list[str]:
    if sys.platform == "win32":
        out = []
        for d in _npcap_dirs():
            out.append(os.path.join(d, "wpcap.dll"))
        out.extend(["wpcap.dll", "pcap.dll"])
        return out
    if sys.platform == "darwin":
        return [
            "/usr/lib/libpcap.dylib",
            "/usr/lib/libpcap.A.dylib",
            "libpcap.dylib",
            "/opt/homebrew/opt/libpcap/lib/libpcap.dylib",
            "/usr/local/opt/libpcap/lib/libpcap.dylib",
        ]
    return [
        "libpcap.so.1",
        "libpcap.so",
        "/usr/lib/x86_64-linux-gnu/libpcap.so.1",
        "/usr/lib/aarch64-linux-gnu/libpcap.so.1",
        "/usr/lib/libpcap.so.1",
    ]


def load() -> tuple[Optional[object], str, str]:
    """返回 (lib, path, error)。失败时 lib 为 None，不抛到调用方以外。"""
    global _lib, _lib_path, _load_error
    if _lib is not None:
        return _lib, _lib_path, ""
    if _load_error and _lib is None and _lib_path == "failed":
        return None, "", _load_error
    last = ""
    if sys.platform == "win32":
        ok, d = npcap_installed()
        if ok and d:
            try:
                # 让依赖的 Packet.dll 能被找到
                if hasattr(os, "add_dll_directory"):
                    os.add_dll_directory(d)
                else:
                    os.environ["PATH"] = d + os.pathsep + os.environ.get("PATH", "")
            except Exception as e:
                last = str(e)
    for path in candidate_paths():
        try:
            if os.path.isabs(path) and not os.path.isfile(path):
                continue
            lib = ctypes.CDLL(path)
            _bind(lib)
            _lib = lib
            _lib_path = path
            _load_error = ""
            return lib, path, ""
        except Exception as e:
            last = f"{path}: {e}"
            continue
    _lib_path = "failed"
    _load_error = last or "未找到 libpcap / Npcap"
    return None, "", _load_error


def _bind(lib) -> None:
    lib.pcap_findalldevs.argtypes = [POINTER(POINTER(pcap_if)), c_char_p]
    lib.pcap_findalldevs.restype = c_int
    lib.pcap_freealldevs.argtypes = [POINTER(pcap_if)]
    lib.pcap_freealldevs.restype = None
    lib.pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]
    lib.pcap_open_live.restype = c_void_p
    lib.pcap_close.argtypes = [c_void_p]
    lib.pcap_close.restype = None
    lib.pcap_next_ex.argtypes = [c_void_p, POINTER(POINTER(pcap_pkthdr)), POINTER(POINTER(c_ubyte))]
    lib.pcap_next_ex.restype = c_int
    lib.pcap_compile.argtypes = [c_void_p, POINTER(bpf_program), c_char_p, c_int, c_uint32]
    lib.pcap_compile.restype = c_int
    lib.pcap_setfilter.argtypes = [c_void_p, POINTER(bpf_program)]
    lib.pcap_setfilter.restype = c_int
    lib.pcap_freecode.argtypes = [POINTER(bpf_program)]
    lib.pcap_freecode.restype = None
    lib.pcap_geterr.argtypes = [c_void_p]
    lib.pcap_geterr.restype = c_char_p
    lib.pcap_datalink.argtypes = [c_void_p]
    lib.pcap_datalink.restype = c_int
    lib.pcap_stats.argtypes = [c_void_p, POINTER(pcap_stat)]
    lib.pcap_stats.restype = c_int
    if hasattr(lib, "pcap_breakloop"):
        lib.pcap_breakloop.argtypes = [c_void_p]
        lib.pcap_breakloop.restype = None


def _c_err(buf) -> str:
    try:
        return buf.value.decode("utf-8", errors="replace") if buf.value else ""
    except Exception:
        return ""


def _decode(s: Optional[bytes]) -> str:
    if not s:
        return ""
    if isinstance(s, str):
        return s
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return s.decode(enc)
        except Exception:
            continue
    return s.decode("utf-8", errors="replace")


def _ip_from_sockaddr(ptr) -> str:
    if not ptr:
        return ""
    try:
        sa = ptr.contents
        fam = sa.sa_family
        raw = bytes(sa.sa_data)
        # Linux 可能用 2 字节 family；Windows 也是 ushort
        if fam in (2,):  # AF_INET
            # sa_data: port(2) + addr(4)
            return ".".join(str(b) for b in raw[2:6])
        if fam in (10, 23, 24, 28, 30):  # AF_INET6 各平台
            # 完整 sockaddr_in6 比 sa_data 长，尽力读取：Windows AF_INET6=23
            # 这里信息不足，忽略以免误读
            return ""
    except Exception:
        return ""
    return ""


def _ipv4_from_addr_node(node) -> str:
    try:
        if not node or not node.addr:
            return ""
        # 重新按平台解析：把 sockaddr 当原始字节
        base = ctypes.addressof(node.addr.contents)
        # family
        fam = ctypes.c_ushort.from_address(base).value
        if sys.platform == "win32" and fam == 23:
            return ""
        if fam == 2 or (sys.platform == "win32" and fam == 2):
            # offset of sin_addr: 4
            b = (c_ubyte * 4).from_address(base + 4)
            return ".".join(str(x) for x in b)
        # Linux AF_INET=2, AF_INET6=10; sockaddr_in6 sin6_addr at offset 8
        if fam in (10, 24, 28, 30):
            import ipaddress
            addr_off = 8
            b = (c_ubyte * 16).from_address(base + addr_off)
            return str(ipaddress.IPv6Address(bytes(b)))
    except Exception:
        return ""
    return ""


def list_devices() -> tuple[list[dict], str]:
    lib, path, err = load()
    if lib is None:
        return [], err or "未加载抓包库"
    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    head = POINTER(pcap_if)()
    rc = lib.pcap_findalldevs(ctypes.byref(head), errbuf)
    if rc != 0:
        return [], _c_err(errbuf) or "pcap_findalldevs 失败"
    out = []
    try:
        cur = head
        while cur:
            dev = cur.contents
            name = _decode(dev.name)
            desc = _decode(dev.description)
            flags = int(dev.flags)
            addrs = []
            ap = dev.addresses
            while ap:
                ip = _ipv4_from_addr_node(ap.contents)
                if ip:
                    addrs.append(ip)
                ap = ap.contents.next
            out.append({
                "id": name,
                "name": desc or name,
                "description": desc,
                "addresses": addrs,
                "loopback": bool(flags & PCAP_IF_LOOPBACK),
                "up": bool(flags & PCAP_IF_UP) if flags else True,
                "running": bool(flags & PCAP_IF_RUNNING) if flags else True,
                "wireless": bool(flags & PCAP_IF_WIRELESS),
                "flags": flags,
            })
            cur = dev.next
    finally:
        if head:
            lib.pcap_freealldevs(head)
    return out, ""


def open_live(device: str, snaplen: int = 65535, promiscuous: bool = True, timeout_ms: int = 200):
    lib, path, err = load()
    if lib is None:
        raise RuntimeError(err or "未加载抓包库")
    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    handle = lib.pcap_open_live(device.encode("utf-8"), int(snaplen), 1 if promiscuous else 0,
                                int(timeout_ms), errbuf)
    if not handle:
        msg = _c_err(errbuf) or "pcap_open_live 失败"
        raise RuntimeError(msg)
    return handle


def set_filter(handle, expr: str, netmask: int = 0) -> None:
    if not expr or not expr.strip():
        return
    lib, _, err = load()
    if lib is None:
        raise RuntimeError(err or "未加载抓包库")
    prog = bpf_program()
    rc = lib.pcap_compile(handle, ctypes.byref(prog), expr.encode("utf-8"), 1, c_uint32(netmask))
    if rc != 0:
        raise RuntimeError(_geterr(handle) or "BPF 过滤表达式编译失败")
    try:
        rc = lib.pcap_setfilter(handle, ctypes.byref(prog))
        if rc != 0:
            raise RuntimeError(_geterr(handle) or "设置 BPF 过滤失败")
    finally:
        lib.pcap_freecode(ctypes.byref(prog))


def datalink(handle) -> int:
    lib, _, _ = load()
    return int(lib.pcap_datalink(handle))


def next_ex(handle) -> tuple[int, Optional[dict]]:
    """返回 (rc, packet)。rc=1 有包，0 超时，-1 出错，-2 被 break。"""
    lib, _, _ = load()
    hdr_p = POINTER(pcap_pkthdr)()
    data_p = POINTER(c_ubyte)()
    rc = lib.pcap_next_ex(handle, ctypes.byref(hdr_p), ctypes.byref(data_p))
    if rc != 1:
        return int(rc), None
    hdr = hdr_p.contents
    caplen = int(hdr.caplen)
    orig = int(hdr.len)
    if sys.platform == "darwin":
        ts = float(hdr.tv_sec) + float(hdr.tv_usec) / 1_000_000.0
    else:
        ts = float(hdr.ts.tv_sec) + float(hdr.ts.tv_usec) / 1_000_000.0
    if caplen < 0 or caplen > 16 * 1024 * 1024:
        return 1, {"ts": ts, "incl_len": 0, "orig_len": orig, "data": b""}
    buf = ctypes.string_at(data_p, caplen)
    return 1, {"ts": ts, "incl_len": caplen, "orig_len": orig, "data": buf}


def stats(handle) -> dict:
    lib, _, _ = load()
    st = pcap_stat()
    try:
        rc = lib.pcap_stats(handle, ctypes.byref(st))
        if rc == 0:
            return {"recv": int(st.ps_recv), "drop": int(st.ps_drop), "ifdrop": int(st.ps_ifdrop)}
    except Exception:
        pass
    return {"recv": 0, "drop": 0, "ifdrop": 0}


def close(handle) -> None:
    if not handle:
        return
    lib, _, _ = load()
    if lib is None:
        return
    try:
        lib.pcap_close(handle)
    except Exception:
        pass


def breakloop(handle) -> None:
    if not handle:
        return
    lib, _, _ = load()
    if lib is None or not hasattr(lib, "pcap_breakloop"):
        return
    try:
        lib.pcap_breakloop(handle)
    except Exception:
        pass


def _geterr(handle) -> str:
    lib, _, _ = load()
    try:
        p = lib.pcap_geterr(handle)
        return _decode(p) if p else ""
    except Exception:
        return ""
