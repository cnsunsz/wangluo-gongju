"""通用辅助：命令执行、主机名校验、端口解析。"""
from __future__ import annotations

import locale
import os
import re
import subprocess

from . import procs

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0  # 134217728


def decode_output(b: bytes | None) -> str:
    if not b:
        return ""
    enc = locale.getpreferredencoding(False) or "utf-8"
    for e in (enc, "utf-8", "gbk"):
        try:
            return b.decode(e)
        except (UnicodeDecodeError, LookupError):
            continue
    return b.decode("utf-8", "replace")


def run_cmd(cmd, timeout=15):
    try:
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=CREATE_NO_WINDOW,
        )
        procs.register(p)
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                p.kill()
                p.communicate(timeout=2)
            except Exception:
                pass
            return "", ""
        finally:
            procs.unregister(p)
        return decode_output(out), decode_output(err)
    except OSError:
        return "", ""


def safe_host(host) -> str:
    host = (host or "").strip().strip("[]")
    if not host:
        raise ValueError("请输入主机名或 IP")
    if len(host) > 253:
        raise ValueError("主机名过长")
    if not re.fullmatch(r"[A-Za-z0-9_.:\-]+", host):
        raise ValueError("主机名/IP 含非法字符")
    if host.startswith("-") or host.startswith("."):
        raise ValueError("非法主机名")
    return host


def parse_ports(spec):
    ports = set()
    for part in re.split(r"[,\s]+", spec or ""):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                a, b = part.split("-", 1)
                a, b = int(a), int(b)
                if a > b:
                    a, b = b, a
                if a < 1 or b > 65535:
                    raise ValueError("端口范围需在 1-65535")
                ports.update(range(a, b + 1))
            else:
                p = int(part)
                if p < 1 or p > 65535:
                    raise ValueError("端口范围需在 1-65535")
                ports.add(p)
        except ValueError as e:
            msg = str(e)
            if "端口" in msg or "单次" in msg:
                raise
            raise ValueError("请输入端口，如 80,443,1-1024") from e
    if not ports:
        raise ValueError("请输入端口，如 80,443,1-1024")
    if len(ports) > 2000:
        raise ValueError("单次最多扫描 2000 个端口")
    return sorted(ports)


def to_int(value, default=None, lo=None, hi=None):
    try:
        try:
            v = int(value)
        except (TypeError, ValueError):
            v = int(float(value))
    except (TypeError, ValueError):
        return default
    if lo is not None and v < lo:
        v = lo
    if hi is not None and v > hi:
        v = hi
    return v
