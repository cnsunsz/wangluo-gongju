"""连接级多网卡聚合：本机 HTTP / SOCKS5 代理，把新连接分配到选中网卡。

每个新建 TCP 绑定到一张已选网卡的 IPv4，并在 Windows 上设置 IP_UNICAST_IF，
避免被默认路由抢走出口。这不是拆单条 TCP，也不是 L2 bonding，不能让
单连接测速变成多条链路之和。适合浏览器、下载器、Steam 等多连接场景。

独立实现，未使用任何第三方聚合软件的源码。
"""
from __future__ import annotations

import json
import os
import select
import socket
import struct
import threading
import time
from collections import deque
from typing import Any
from urllib.parse import urlsplit

from .paths import runtime_dir
from .util import CREATE_NO_WINDOW, run_cmd, to_int

IP_UNICAST_IF = 31  # Windows IPPROTO_IP
BACKUP_NAME = "mux_proxy_backup.json"

_lock = threading.RLock()
_engine: "MuxEngine | None" = None


def _backup_path() -> str:
    return os.path.join(runtime_dir(), BACKUP_NAME)


def list_adapters() -> list[dict]:
    """列出活动且具有 IPv4 的网卡（名称、类型、IP、网关、接口索引）。"""
    if os.name == "nt":
        rows = _list_adapters_windows()
        if rows:
            return rows
    return _list_adapters_posix()


def _list_adapters_windows() -> list[dict]:
    script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$nics = @()
$addrs = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
  $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254*'
}
$routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
foreach ($a in $addrs) {
  $ad = Get-NetAdapter -InterfaceIndex $a.InterfaceIndex -ErrorAction SilentlyContinue
  if (-not $ad) { continue }
  $name = [string]$ad.Name
  $low = ($name + ' ' + [string]$ad.InterfaceDescription).ToLower()
  if ($low -match 'loopback|isatap|teredo|6to4') { continue }
  $up = [string]$ad.Status
  if ($up -and $up -notmatch 'Up|up') { continue }
  $gw = ''
  foreach ($r in $routes) {
    if ($r.ifIndex -eq $a.InterfaceIndex -and $r.NextHop -and $r.NextHop -ne '0.0.0.0') {
      $gw = [string]$r.NextHop; break
    }
  }
  $media = [string]$ad.MediaType
  $kind = '其他'
  if ($media -match '802.3' -or $low -match 'ethernet|gigabit|rtl|i2[0-9]{2}|e1[0-9]{3}|realtek|intel') { $kind = '有线' }
  if ($media -match '802.11|Native802' -or $low -match 'wi-?fi|wireless|wlan|802\.11|intel.*wi') { $kind = 'Wi-Fi' }
  if ($low -match 'vpn|tap|tun|wintun|wireguard|ppp|virtual|hyper-v|vethernet|npcap|loopback') {
    if ($kind -eq '其他') { $kind = '虚拟/VPN' }
  }
  $nics += [pscustomobject]@{
    id = [string]$a.InterfaceIndex
    name = $name
    description = [string]$ad.InterfaceDescription
    kind = $kind
    ipv4 = [string]$a.IPAddress
    prefix = [int]$a.PrefixLength
    gateway = $gw
    ifindex = [int]$a.InterfaceIndex
    mac = ([string]$ad.MacAddress).Replace('-', ':')
    status = [string]$ad.Status
    speed = [string]$ad.LinkSpeed
  }
}
$j = ConvertTo-Json -InputObject @($nics) -Compress -Depth 5
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j))
"""
    import base64
    import subprocess
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, timeout=20, creationflags=CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    raw = (p.stdout or b"").decode("ascii", "ignore").strip()
    if not raw:
        return []
    try:
        data = json.loads(base64.b64decode(raw).decode("utf-8", "replace"))
    except (ValueError, json.JSONDecodeError):
        return []
    if isinstance(data, dict):
        data = [data]
    out = []
    seen = set()
    for row in data or []:
        if not isinstance(row, dict):
            continue
        ipv4 = str(row.get("ipv4") or "").strip()
        idx = to_int(row.get("ifindex"), 0)
        key = (idx, ipv4)
        if not ipv4 or key in seen:
            continue
        seen.add(key)
        out.append({
            "id": str(idx or ipv4),
            "name": str(row.get("name") or ""),
            "description": str(row.get("description") or ""),
            "kind": str(row.get("kind") or "其他"),
            "ipv4": ipv4,
            "prefix": to_int(row.get("prefix"), 24),
            "gateway": str(row.get("gateway") or ""),
            "ifindex": idx,
            "mac": str(row.get("mac") or ""),
            "status": str(row.get("status") or ""),
            "speed": str(row.get("speed") or ""),
        })
    out.sort(key=lambda x: (0 if x["kind"] == "有线" else 1 if x["kind"] == "Wi-Fi" else 2, x["name"]))
    return out


def _list_adapters_posix() -> list[dict]:
    out = []
    try:
        import ipaddress
        for info in socket.if_nameindex():
            idx, name = info[0], info[1]
            if name.startswith("lo"):
                continue
            ipv4 = ""
            try:
                import fcntl
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    ipv4 = socket.inet_ntoa(fcntl.ioctl(
                        s.fileno(), 0x8915, struct.pack("256s", name.encode("utf-8")[:15])
                    )[20:24])
                finally:
                    s.close()
            except Exception:
                ipv4 = ""
            if not ipv4 or ipv4.startswith("127."):
                continue
            kind = "其他"
            low = name.lower()
            if low.startswith("wl") or "wlan" in low or "wifi" in low:
                kind = "Wi-Fi"
            elif low.startswith(("en", "eth", "em", "eno", "ens", "enp")):
                kind = "有线"
            out.append({
                "id": str(idx), "name": name, "description": name, "kind": kind,
                "ipv4": ipv4, "prefix": 24, "gateway": "", "ifindex": idx,
                "mac": "", "status": "Up", "speed": "",
            })
    except Exception:
        return out
    return out


def pick_port(preferred: int, host: str = "127.0.0.1") -> int:
    want = int(preferred)
    for p in range(want, want + 80):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, p))
                return p
        except OSError:
            continue
    return want


def bind_outbound(sock: socket.socket, ipv4: str, ifindex: int) -> None:
    sock.bind((ipv4, 0))
    if os.name == "nt" and ifindex:
        try:
            # MSDN: IP_UNICAST_IF takes the interface index in network byte order
            sock.setsockopt(socket.IPPROTO_IP, IP_UNICAST_IF, struct.pack("!I", int(ifindex)))
        except OSError:
            try:
                sock.setsockopt(socket.IPPROTO_IP, IP_UNICAST_IF, socket.htonl(int(ifindex)))
            except OSError:
                pass


def _connect_via(host: str, port: int, nic: dict, timeout: float = 15.0) -> socket.socket:
    port = int(port)
    # Resolve preferring IPv4
    infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    if not infos:
        raise OSError(f"无法解析 {host}")
    dest = infos[0][4]
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        bind_outbound(sock, nic["ipv4"], int(nic.get("ifindex") or 0))
        sock.settimeout(timeout)
        sock.connect(dest)
        sock.settimeout(None)
        return sock
    except Exception:
        try:
            sock.close()
        except OSError:
            pass
        raise


class Scheduler:
    def __init__(self, nics: list[dict], strategy: str = "rr"):
        self._lock = threading.Lock()
        self.set_nics(nics, strategy)

    def set_nics(self, nics: list[dict], strategy: str | None = None) -> None:
        with self._lock:
            self.nics = list(nics)
            if strategy:
                self.strategy = "weighted" if strategy == "weighted" else "rr"
            self._i = 0
            self._wrr = []
            self._rebuild_wrr()

    def set_strategy(self, strategy: str, weights: dict | None = None) -> None:
        with self._lock:
            self.strategy = "weighted" if strategy == "weighted" else "rr"
            if weights:
                for nic in self.nics:
                    if nic["id"] in weights:
                        nic["weight"] = max(1, min(100, int(weights[nic["id"]])))
            self._i = 0
            self._rebuild_wrr()

    def _rebuild_wrr(self) -> None:
        seq = []
        for nic in self.nics:
            w = max(1, min(100, int(nic.get("weight") or 1)))
            seq.extend([nic] * w)
        self._wrr = seq or list(self.nics)

    def pick(self) -> dict:
        with self._lock:
            if not self.nics:
                raise RuntimeError("没有可用网卡")
            if self.strategy == "weighted" and self._wrr:
                nic = self._wrr[self._i % len(self._wrr)]
                self._i += 1
                return nic
            nic = self.nics[self._i % len(self.nics)]
            self._i += 1
            return nic


class NicStats:
    def __init__(self, nic: dict):
        self.id = nic["id"]
        self.name = nic.get("name") or ""
        self.ipv4 = nic.get("ipv4") or ""
        self.ifindex = nic.get("ifindex") or 0
        self.kind = nic.get("kind") or ""
        self.weight = int(nic.get("weight") or 1)
        self.connections = 0
        self.bytes_up = 0
        self.bytes_down = 0
        self._up_hist: deque = deque(maxlen=8)
        self._down_hist: deque = deque(maxlen=8)
        self._last_up = 0
        self._last_down = 0
        self._last_ts = time.monotonic()
        self.up_bps = 0.0
        self.down_bps = 0.0

    def tick(self) -> None:
        now = time.monotonic()
        dt = max(0.2, now - self._last_ts)
        self.up_bps = (self.bytes_up - self._last_up) / dt
        self.down_bps = (self.bytes_down - self._last_down) / dt
        self._last_up = self.bytes_up
        self._last_down = self.bytes_down
        self._last_ts = now
        self._up_hist.append(self.up_bps)
        self._down_hist.append(self.down_bps)

    def snapshot(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "ipv4": self.ipv4,
            "ifindex": self.ifindex,
            "kind": self.kind,
            "weight": self.weight,
            "connections": self.connections,
            "bytes_up": self.bytes_up,
            "bytes_down": self.bytes_down,
            "up_bps": int(self.up_bps),
            "down_bps": int(self.down_bps),
        }


class SystemProxy:
    KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

    def __init__(self):
        self._saved: dict | None = None
        self._applied = False

    def _read(self) -> dict:
        import winreg
        out = {"ProxyEnable": 0, "ProxyServer": "", "ProxyOverride": ""}
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.KEY, 0, winreg.KEY_READ)
            try:
                for name, default in list(out.items()):
                    try:
                        val, typ = winreg.QueryValueEx(key, name)
                        out[name] = val
                        out["_" + name + "_type"] = typ
                    except OSError:
                        out[name] = default
            finally:
                winreg.CloseKey(key)
        except OSError:
            pass
        return out

    def _write(self, enable, server, override) -> None:
        import winreg
        key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, self.KEY, 0, winreg.KEY_SET_VALUE)
        try:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
            if server is None:
                try:
                    winreg.DeleteValue(key, "ProxyServer")
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, str(server))
            if override is None:
                try:
                    winreg.DeleteValue(key, "ProxyOverride")
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, str(override))
        finally:
            winreg.CloseKey(key)
        self._notify()

    @staticmethod
    def _notify() -> None:
        try:
            import ctypes
            wininet = ctypes.windll.wininet
            wininet.InternetSetOptionW(None, 39, None, 0)
            wininet.InternetSetOptionW(None, 37, None, 0)
        except Exception:
            pass

    def apply(self, http_port: int) -> None:
        if os.name != "nt":
            return
        saved = self._read()
        # 避免把我们自己刚写入的代理当成“原先设置”
        server = str(saved.get("ProxyServer") or "")
        if self._applied and "127.0.0.1" in server:
            pass
        else:
            self._saved = saved
            self._persist_backup(saved, http_port)
        bypass = str(saved.get("ProxyOverride") or "")
        parts = [p.strip() for p in bypass.split(";") if p.strip()]
        for extra in ("localhost", "127.0.0.1", "::1", "<local>"):
            if extra.lower() not in {p.lower() for p in parts}:
                parts.append(extra)
        self._write(True, f"127.0.0.1:{http_port}", ";".join(parts))
        self._applied = True

    def restore(self) -> None:
        if os.name != "nt":
            self._applied = False
            return
        saved = self._saved or _load_backup()
        if not saved:
            self._applied = False
            return
        try:
            self._write(
                bool(int(saved.get("ProxyEnable") or 0)),
                saved.get("ProxyServer") if "ProxyServer" in saved else "",
                saved.get("ProxyOverride") if "ProxyOverride" in saved else "",
            )
        except Exception:
            pass
        self._applied = False
        self._saved = None
        _clear_backup()

    def _persist_backup(self, saved: dict, http_port: int) -> None:
        payload = {
            "active": True,
            "http_port": http_port,
            "ProxyEnable": int(saved.get("ProxyEnable") or 0),
            "ProxyServer": saved.get("ProxyServer") or "",
            "ProxyOverride": saved.get("ProxyOverride") or "",
            "saved_at": time.time(),
        }
        path = _backup_path()
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
        except OSError:
            pass


def _load_backup() -> dict | None:
    try:
        with open(_backup_path(), encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and data.get("active"):
            return data
    except (OSError, ValueError):
        return None
    return None


def _clear_backup() -> None:
    try:
        os.remove(_backup_path())
    except OSError:
        pass


def restore_proxy_if_dirty() -> bool:
    """上次异常退出时恢复系统代理。"""
    saved = _load_backup()
    if not saved:
        return False
    if os.name != "nt":
        _clear_backup()
        return False
    try:
        SystemProxy().restore() if False else None
        sp = SystemProxy()
        sp._saved = saved
        sp.restore()
        return True
    except Exception:
        return False


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("连接已关闭")
        buf += chunk
    return buf


def _recv_headers(sock: socket.socket, limit: int = 65536) -> bytes:
    sock.settimeout(20)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            raise ValueError("请求头过大")
    sock.settimeout(None)
    return data


def _parse_hostport(authority: str, default_port: int) -> tuple[str, int]:
    authority = authority.strip()
    if authority.startswith("["):
        end = authority.find("]")
        host = authority[1:end]
        rest = authority[end + 1:]
        port = int(rest[1:]) if rest.startswith(":") else default_port
        return host, port
    if ":" in authority:
        host, _, p = authority.rpartition(":")
        try:
            return host, int(p)
        except ValueError:
            return authority, default_port
    return authority, default_port


def _relay(a: socket.socket, b: socket.socket, on_ab, on_ba, stop: threading.Event) -> None:
    sockets = [a, b]
    try:
        a.setblocking(False)
        b.setblocking(False)
        while not stop.is_set():
            try:
                r, _, x = select.select(sockets, [], sockets, 1.0)
            except (OSError, ValueError):
                break
            if x:
                break
            if not r:
                continue
            for src in r:
                dst = b if src is a else a
                try:
                    data = src.recv(65536)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    return
                if not data:
                    return
                try:
                    dst.sendall(data)
                except OSError:
                    return
                if src is a:
                    on_ab(len(data))
                else:
                    on_ba(len(data))
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


class MuxEngine:
    def __init__(self, nics: list[dict], strategy: str, system_proxy: bool,
                 http_port: int | None, socks_port: int | None):
        if len(nics) < 1:
            raise ValueError("请至少选择一张网卡")
        for nic in nics:
            nic["weight"] = max(1, min(100, int(nic.get("weight") or 1)))
        self.nics = nics
        self.scheduler = Scheduler(nics, strategy)
        self.want_system_proxy = bool(system_proxy)
        self.proxy = SystemProxy()
        self.stop_event = threading.Event()
        self.started_at = time.time()
        self.http_port = pick_port(http_port or 10801)
        self.socks_port = pick_port(socks_port or 10800)
        if self.socks_port == self.http_port:
            self.socks_port = pick_port(self.http_port + 1)
        self.stats = {n["id"]: NicStats(n) for n in nics}
        self._stats_lock = threading.Lock()
        self._sessions: set[socket.socket] = set()
        self._http_sock: socket.socket | None = None
        self._socks_sock: socket.socket | None = None
        self._threads: list[threading.Thread] = []
        self.error: str | None = None

    def start(self) -> None:
        self._http_sock = self._listen(self.http_port)
        self._socks_sock = self._listen(self.socks_port)
        self._threads.append(threading.Thread(target=self._accept_loop, args=(self._http_sock, self._handle_http), daemon=True, name="mux-http"))
        self._threads.append(threading.Thread(target=self._accept_loop, args=(self._socks_sock, self._handle_socks), daemon=True, name="mux-socks"))
        self._threads.append(threading.Thread(target=self._ticker, daemon=True, name="mux-tick"))
        for t in self._threads:
            t.start()
        if self.want_system_proxy:
            try:
                self.proxy.apply(self.http_port)
            except Exception as e:
                self.error = f"系统代理设置失败：{e}"

    def _listen(self, port: int) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(128)
        s.settimeout(1.0)
        return s

    def _accept_loop(self, lsock: socket.socket, handler) -> None:
        while not self.stop_event.is_set():
            try:
                conn, addr = lsock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self.stop_event.is_set():
                    break
                time.sleep(0.05)
                continue
            self._track(conn)
            threading.Thread(target=self._safe_handle, args=(handler, conn), daemon=True).start()

    def _safe_handle(self, handler, conn: socket.socket) -> None:
        try:
            handler(conn)
        except Exception:
            try:
                conn.close()
            except OSError:
                pass
        finally:
            self._untrack(conn)

    def _track(self, sock: socket.socket) -> None:
        with self._stats_lock:
            self._sessions.add(sock)

    def _untrack(self, sock: socket.socket) -> None:
        with self._stats_lock:
            self._sessions.discard(sock)
        try:
            sock.close()
        except OSError:
            pass

    def _ticker(self) -> None:
        while not self.stop_event.is_set():
            with self._stats_lock:
                for st in self.stats.values():
                    st.tick()
            self.stop_event.wait(1.0)

    def _begin(self, nic: dict) -> NicStats:
        st = self.stats[nic["id"]]
        with self._stats_lock:
            st.connections += 1
        return st

    def _end(self, st: NicStats | None) -> None:
        if st is None:
            return
        with self._stats_lock:
            st.connections = max(0, st.connections - 1)

    def _tunnel(self, client: socket.socket, remote: socket.socket, st: NicStats) -> None:
        def on_up(n):
            with self._stats_lock:
                st.bytes_up += n

        def on_down(n):
            with self._stats_lock:
                st.bytes_down += n

        _relay(client, remote, on_up, on_down, self.stop_event)

    def _handle_http(self, client: socket.socket) -> None:
        st = None
        remote = None
        try:
            raw = _recv_headers(client)
            if not raw:
                return
            head, _, rest = raw.partition(b"\r\n\r\n")
            lines = head.split(b"\r\n")
            if not lines:
                return
            parts = lines[0].decode("iso-8859-1", "replace").split()
            if len(parts) < 2:
                client.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                return
            method, target = parts[0].upper(), parts[1]
            headers = {}
            for line in lines[1:]:
                if b":" in line:
                    k, _, v = line.partition(b":")
                    headers[k.decode("iso-8859-1", "replace").lower()] = v.decode("iso-8859-1", "replace").strip()
            if method == "CONNECT":
                host, port = _parse_hostport(target, 443)
                if host in ("127.0.0.1", "localhost", "::1"):
                    client.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                    return
                nic = self.scheduler.pick()
                st = self._begin(nic)
                remote = _connect_via(host, port, nic, 15)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if rest:
                    remote.sendall(rest)
                self._tunnel(client, remote, st)
                remote = None
                return
            # Regular HTTP
            host_hdr = headers.get("host", "")
            if target.startswith("http://") or target.startswith("https://"):
                sp = urlsplit(target)
                host = sp.hostname or host_hdr
                port = sp.port or (443 if sp.scheme == "https" else 80)
                path = sp.path or "/"
                if sp.query:
                    path += "?" + sp.query
            else:
                host, port = _parse_hostport(host_hdr, 80)
                path = target
            if not host or host in ("127.0.0.1", "localhost", "::1"):
                client.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                return
            # rebuild origin-form request
            out_lines = [f"{method} {path} HTTP/1.1".encode("iso-8859-1")]
            skip = {"proxy-connection", "connection", "proxy-authorization"}
            has_host = False
            for line in lines[1:]:
                if b":" not in line:
                    continue
                k, _, v = line.partition(b":")
                key = k.decode("iso-8859-1", "replace").lower()
                if key in skip:
                    continue
                if key == "host":
                    has_host = True
                out_lines.append(k + b":" + v)
            if not has_host:
                hp = host if port == 80 else f"{host}:{port}"
                out_lines.append(f"Host: {hp}".encode("iso-8859-1"))
            out_lines.append(b"Connection: close")
            out_lines.append(b"")
            req = b"\r\n".join(out_lines) + b"\r\n"
            if rest:
                req += rest
            nic = self.scheduler.pick()
            st = self._begin(nic)
            remote = _connect_via(host, port, nic, 15)
            remote.sendall(req)
            # If there's more body (Content-Length), pump remaining then relay
            try:
                clen = int(headers.get("content-length") or 0)
            except ValueError:
                clen = 0
            already = len(rest)
            remain = max(0, clen - already)
            while remain > 0 and not self.stop_event.is_set():
                chunk = client.recv(min(65536, remain))
                if not chunk:
                    break
                remote.sendall(chunk)
                remain -= len(chunk)
                with self._stats_lock:
                    st.bytes_up += len(chunk)
            with self._stats_lock:
                st.bytes_up += len(req)
            # read response and send back (one-shot, then close)
            remote.settimeout(30)
            while not self.stop_event.is_set():
                data = remote.recv(65536)
                if not data:
                    break
                client.sendall(data)
                with self._stats_lock:
                    st.bytes_down += len(data)
        except Exception:
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
        finally:
            if remote is not None:
                try:
                    remote.close()
                except OSError:
                    pass
            self._end(st)

    def _handle_socks(self, client: socket.socket) -> None:
        st = None
        remote = None
        try:
            client.settimeout(15)
            head = _recv_exact(client, 2)
            if head[0] != 0x05:
                return
            nmethods = head[1]
            _recv_exact(client, nmethods)
            client.sendall(b"\x05\x00")  # no auth
            req = _recv_exact(client, 4)
            if req[0] != 0x05:
                return
            cmd, atyp = req[1], req[3]
            if atyp == 1:
                host = socket.inet_ntoa(_recv_exact(client, 4))
            elif atyp == 3:
                ln = _recv_exact(client, 1)[0]
                host = _recv_exact(client, ln).decode("utf-8", "replace")
            elif atyp == 4:
                # IPv6 not bound in this IPv4-only engine
                _recv_exact(client, 16)
                _recv_exact(client, 2)
                client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            else:
                client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            port = struct.unpack("!H", _recv_exact(client, 2))[0]
            if cmd != 1:
                client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            if host in ("127.0.0.1", "localhost", "::1"):
                client.sendall(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            nic = self.scheduler.pick()
            st = self._begin(nic)
            try:
                remote = _connect_via(host, port, nic, 15)
            except Exception:
                client.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            bind_ip = remote.getsockname()[0]
            bind_port = remote.getsockname()[1]
            try:
                packed = socket.inet_aton(bind_ip)
            except OSError:
                packed = b"\x00\x00\x00\x00"
            client.sendall(b"\x05\x00\x00\x01" + packed + struct.pack("!H", bind_port))
            client.settimeout(None)
            self._tunnel(client, remote, st)
            remote = None
        except Exception:
            pass
        finally:
            if remote is not None:
                try:
                    remote.close()
                except OSError:
                    pass
            self._end(st)

    def status(self) -> dict:
        with self._stats_lock:
            adapters = [st.snapshot() for st in self.stats.values()]
        return {
            "running": not self.stop_event.is_set(),
            "strategy": self.scheduler.strategy,
            "http": f"127.0.0.1:{self.http_port}",
            "socks": f"127.0.0.1:{self.socks_port}",
            "http_port": self.http_port,
            "socks_port": self.socks_port,
            "system_proxy": self.want_system_proxy and self.proxy._applied,
            "started_at": self.started_at,
            "adapters": adapters,
            "error": self.error,
        }

    def update_strategy(self, strategy: str, weights: dict | None = None) -> None:
        if weights:
            for nic in self.nics:
                if nic["id"] in weights:
                    nic["weight"] = max(1, min(100, int(weights[nic["id"]])))
                    if nic["id"] in self.stats:
                        self.stats[nic["id"]].weight = nic["weight"]
        self.scheduler.set_strategy(strategy, None)
        self.scheduler.set_nics(self.nics, strategy)

    def stop(self) -> None:
        self.stop_event.set()
        for s in (self._http_sock, self._socks_sock):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
        with self._stats_lock:
            sessions = list(self._sessions)
        for s in sessions:
            try:
                s.close()
            except OSError:
                pass
        try:
            self.proxy.restore()
        except Exception:
            pass


def start(adapters: list[dict], strategy: str = "rr", system_proxy: bool = True,
          http_port: int | None = None, socks_port: int | None = None) -> dict:
    global _engine
    with _lock:
        if _engine is not None and not _engine.stop_event.is_set():
            raise RuntimeError("聚合已在运行，请先停止")
        # resolve adapters against live list
        live = {a["id"]: a for a in list_adapters()}
        chosen = []
        for item in adapters:
            if not isinstance(item, dict):
                continue
            aid = str(item.get("id") or item.get("ifindex") or "")
            if aid not in live:
                continue
            nic = dict(live[aid])
            nic["weight"] = max(1, min(100, to_int(item.get("weight"), 1, 1, 100)))
            chosen.append(nic)
        if len(chosen) < 1:
            raise ValueError("请勾选至少一张有效网卡")
        if _engine is not None:
            try:
                _engine.stop()
            except Exception:
                pass
        eng = MuxEngine(chosen, strategy, system_proxy, http_port, socks_port)
        eng.start()
        _engine = eng
        return eng.status()


def stop() -> dict:
    global _engine
    with _lock:
        eng = _engine
        _engine = None
        if eng is not None:
            eng.stop()
        else:
            # 仍尝试恢复可能残留的系统代理
            sp = SystemProxy()
            sp._saved = _load_backup()
            if sp._saved:
                sp.restore()
        return {"running": False}


def running() -> bool:
    with _lock:
        return _engine is not None and not _engine.stop_event.is_set()


def status() -> dict:
    with _lock:
        if _engine is None or _engine.stop_event.is_set():
            return {
                "running": False,
                "strategy": "rr",
                "http": "",
                "socks": "",
                "system_proxy": False,
                "adapters": [],
                "error": None,
            }
        return _engine.status()


def update_config(strategy: str | None = None, weights: dict | None = None) -> dict:
    with _lock:
        if _engine is None or _engine.stop_event.is_set():
            raise RuntimeError("聚合未运行")
        if strategy or weights:
            _engine.update_strategy(strategy or _engine.scheduler.strategy, weights)
        return _engine.status()


def shutdown_cleanup() -> None:
    """程序退出时关闭代理并恢复系统代理。"""
    try:
        stop()
    except Exception:
        try:
            sp = SystemProxy()
            sp._saved = _load_backup()
            if sp._saved:
                sp.restore()
        except Exception:
            pass
