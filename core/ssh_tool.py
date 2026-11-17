"""SSH 会话与常用主机保存。

主机列表存在运行时配置目录 config/ssh_hosts.json。
密码默认不保存；若用户勾选「记住密码」：Windows 用 DPAPI（当前用户）加密，其它平台用本机 Fernet 密钥加密后另存。
私钥只保存用户选择的本地路径，不把密钥内容写入文件或仓库。
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from queue import Empty, Queue

from .paths import config_dir

HOSTS_FILE = "ssh_hosts.json"
_SESSIONS: dict[str, "SshSession"] = {}
_SESS_LOCK = threading.Lock()


def _hosts_path() -> str:
    return os.path.join(config_dir(), HOSTS_FILE)


def _public_host(h: dict, include_secret: bool = False) -> dict:
    out = {
        "id": h.get("id"),
        "name": h.get("name") or "",
        "host": h.get("host") or "",
        "port": int(h.get("port") or 22),
        "username": h.get("username") or "",
        "auth": h.get("auth") or "password",
        "key_path": h.get("key_path") or "",
        "remember": bool(h.get("remember")),
        "has_password": bool(h.get("secret")),
        "updated_at": h.get("updated_at") or 0,
    }
    if include_secret and h.get("secret"):
        try:
            out["password"] = _unprotect(h["secret"])
        except Exception:
            out["password"] = ""
            out["has_password"] = False
    else:
        out["password"] = ""
    return out


def list_hosts(include_secret: bool = False) -> list[dict]:
    rows = _load_raw()
    rows.sort(key=lambda x: (str(x.get("name") or "").lower(), str(x.get("host") or "")))
    return [_public_host(h, include_secret) for h in rows]


def _load_raw() -> list[dict]:
    try:
        with open(_hosts_path(), encoding="utf-8") as f:
            data = json.load(f)
        rows = data.get("hosts") if isinstance(data, dict) else data
        if isinstance(rows, list):
            return [r for r in rows if isinstance(r, dict) and r.get("host")]
    except (OSError, ValueError):
        pass
    return []


def _save_raw(rows: list[dict]) -> None:
    path = _hosts_path()
    tmp = path + ".tmp"
    payload = {"hosts": rows}
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _protect(text: str) -> str:
    data = (text or "").encode("utf-8")
    if os.name == "nt":
        return "dpapi:" + _dpapi_protect(data)
    return "fernet:" + _fernet_protect(data)


def _unprotect(blob: str) -> str:
    if not blob:
        return ""
    if blob.startswith("dpapi:"):
        return _dpapi_unprotect(blob[6:]).decode("utf-8", "replace")
    if blob.startswith("fernet:"):
        return _fernet_unprotect(blob[7:]).decode("utf-8", "replace")
    raise ValueError("未知的密码存储格式")


def _dpapi_protect(data: bytes) -> str:
    import ctypes
    from ctypes import wintypes
    import base64

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_buf = ctypes.create_string_buffer(data)
    in_blob = DATA_BLOB(len(data), ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_char)))
    out_blob = DATA_BLOB()
    if not crypt32.CryptProtectData(ctypes.byref(in_blob), "网络工具SSH", None, None, None, 0, ctypes.byref(out_blob)):
        raise OSError("CryptProtectData 失败")
    try:
        raw = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)
    return base64.b64encode(raw).decode("ascii")


def _dpapi_unprotect(b64: str) -> bytes:
    import ctypes
    from ctypes import wintypes
    import base64

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    raw = base64.b64decode(b64)
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_buf = ctypes.create_string_buffer(raw)
    in_blob = DATA_BLOB(len(raw), ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_char)))
    out_blob = DATA_BLOB()
    if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        raise OSError("CryptUnprotectData 失败")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _fernet_key() -> bytes:
    from cryptography.fernet import Fernet
    path = os.path.join(config_dir(), "ssh_secret.key")
    if os.path.isfile(path):
        with open(path, "rb") as f:
            return f.read().strip()
    key = Fernet.generate_key()
    with open(path, "wb") as f:
        f.write(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def _fernet_protect(data: bytes) -> str:
    from cryptography.fernet import Fernet
    return Fernet(_fernet_key()).encrypt(data).decode("ascii")


def _fernet_unprotect(token: str) -> bytes:
    from cryptography.fernet import Fernet
    return Fernet(_fernet_key()).decrypt(token.encode("ascii"))


def save_host(data: dict) -> dict:
    name = str(data.get("name") or "").strip()
    host = str(data.get("host") or "").strip()
    if not host:
        raise ValueError("请填写主机地址")
    port = int(data.get("port") or 22)
    if port < 1 or port > 65535:
        raise ValueError("端口需在 1–65535")
    username = str(data.get("username") or "").strip()
    auth = "key" if str(data.get("auth") or "password") == "key" else "password"
    key_path = str(data.get("key_path") or "").strip()
    if auth == "key" and key_path:
        # 只存路径，确认用户给的是本地路径而不是密钥正文
        if "\n" in key_path or key_path.startswith("-----"):
            raise ValueError("私钥请填写本机文件路径，不要粘贴密钥内容")
    remember = bool(data.get("remember"))
    password = data.get("password")
    hid = str(data.get("id") or "").strip() or uuid.uuid4().hex
    if not name:
        name = f"{username + '@' if username else ''}{host}:{port}"

    rows = _load_raw()
    existing = None
    for r in rows:
        if r.get("id") == hid:
            existing = r
            break
    rec = existing or {"id": hid}
    rec.update({
        "id": hid,
        "name": name,
        "host": host,
        "port": port,
        "username": username,
        "auth": auth,
        "key_path": key_path,
        "remember": remember,
        "updated_at": int(time.time()),
    })
    if remember:
        if password:
            rec["secret"] = _protect(str(password))
        elif not rec.get("secret"):
            rec["remember"] = False
    else:
        rec.pop("secret", None)
        rec["remember"] = False
    if existing is None:
        rows.append(rec)
    else:
        for i, r in enumerate(rows):
            if r.get("id") == hid:
                rows[i] = rec
                break
    _save_raw(rows)
    return _public_host(rec)


def delete_host(hid: str) -> None:
    hid = str(hid or "").strip()
    if not hid:
        raise ValueError("缺少主机 id")
    rows = [r for r in _load_raw() if r.get("id") != hid]
    _save_raw(rows)


def get_host(hid: str, include_secret: bool = False) -> dict | None:
    for r in _load_raw():
        if r.get("id") == hid:
            return _public_host(r, include_secret)
    return None


class SshSession:
    def __init__(self, sid: str, client, chan, meta: dict):
        self.sid = sid
        self.client = client
        self.chan = chan
        self.meta = meta
        self.q: Queue = Queue(maxsize=2000)
        self.closed = threading.Event()
        self.thread = threading.Thread(target=self._reader, daemon=True, name=f"ssh-{sid[:8]}")
        self.thread.start()

    def _reader(self) -> None:
        try:
            while not self.closed.is_set():
                if self.chan.recv_ready() or self.chan.recv_stderr_ready():
                    data = b""
                    if self.chan.recv_ready():
                        data += self.chan.recv(32768)
                    if self.chan.recv_stderr_ready():
                        data += self.chan.recv_stderr(32768)
                    if data:
                        try:
                            self.q.put(data, timeout=1)
                        except Exception:
                            pass
                    continue
                if self.chan.exit_status_ready() or self.chan.closed:
                    break
                time.sleep(0.02)
        except Exception as e:
            try:
                self.q.put(("\r\n[SSH] " + str(e) + "\r\n").encode("utf-8", "replace"), timeout=0.2)
            except Exception:
                pass
        finally:
            self.closed.set()
            try:
                self.q.put(None, timeout=0.2)
            except Exception:
                pass

    def write(self, data: bytes) -> None:
        if self.closed.is_set():
            raise RuntimeError("会话已断开")
        self.chan.sendall(data)

    def resize(self, cols: int, rows: int) -> None:
        try:
            self.chan.resize_pty(width=max(20, int(cols)), height=max(8, int(rows)))
        except Exception:
            pass

    def close(self) -> None:
        self.closed.set()
        try:
            self.chan.close()
        except Exception:
            pass
        try:
            self.client.close()
        except Exception:
            pass
        try:
            self.q.put(None, timeout=0.1)
        except Exception:
            pass


def open_session(data: dict) -> dict:
    try:
        import paramiko
    except ImportError as e:
        raise RuntimeError("未安装 paramiko，无法使用 SSH") from e

    hid = str(data.get("host_id") or data.get("id") or "").strip()
    saved = get_host(hid, include_secret=True) if hid else None
    host = str(data.get("host") or (saved or {}).get("host") or "").strip()
    if not host:
        raise ValueError("请填写主机地址")
    port = int(data.get("port") or (saved or {}).get("port") or 22)
    username = str(data.get("username") or (saved or {}).get("username") or "").strip()
    if not username:
        raise ValueError("请填写用户名")
    auth = str(data.get("auth") or (saved or {}).get("auth") or "password")
    key_path = str(data.get("key_path") or (saved or {}).get("key_path") or "").strip()
    password = data.get("password")
    if not password and saved and saved.get("password"):
        password = saved["password"]
    passphrase = data.get("passphrase") or ""
    cols = int(data.get("cols") or 120)
    rows = int(data.get("rows") or 32)

    if auth == "key":
        if not key_path or not os.path.isfile(key_path):
            raise ValueError("找不到私钥文件，请选择本机上的密钥路径")
    else:
        if not password:
            raise ValueError("请填写密码，或改用私钥登录")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    known = os.path.join(config_dir(), "ssh_known_hosts")
    try:
        if os.path.isfile(known):
            client.load_host_keys(known)
    except Exception:
        pass

    connect_kwargs = dict(
        hostname=host,
        port=port,
        username=username,
        timeout=20,
        allow_agent=False,
        look_for_keys=False,
        auth_timeout=20,
        banner_timeout=20,
    )
    if auth == "key":
        connect_kwargs["key_filename"] = key_path
        if passphrase:
            connect_kwargs["passphrase"] = passphrase
        if password:
            connect_kwargs["password"] = password  # 某些环境密钥+密码二次验证
    else:
        connect_kwargs["password"] = password

    try:
        client.connect(**connect_kwargs)
    except Exception:
        try:
            client.close()
        except Exception:
            pass
        raise
    try:
        client.save_host_keys(known)
    except Exception:
        pass

    chan = client.invoke_shell(term="xterm-256color", width=cols, height=rows)
    chan.settimeout(0.0)
    sid = uuid.uuid4().hex
    sess = SshSession(sid, client, chan, {
        "host": host, "port": port, "username": username, "name": (saved or {}).get("name") or host,
    })
    with _SESS_LOCK:
        _SESSIONS[sid] = sess
    return {"sid": sid, "host": host, "port": port, "username": username}


def get_session(sid: str) -> SshSession:
    with _SESS_LOCK:
        sess = _SESSIONS.get(sid)
    if sess is None or sess.closed.is_set():
        raise RuntimeError("SSH 会话不存在或已断开")
    return sess


def write_session(sid: str, data) -> None:
    if isinstance(data, str):
        raw = data.encode("utf-8")
    else:
        raw = bytes(data)
    get_session(sid).write(raw)


def resize_session(sid: str, cols: int, rows: int) -> None:
    get_session(sid).resize(cols, rows)


def close_session(sid: str) -> None:
    with _SESS_LOCK:
        sess = _SESSIONS.pop(sid, None)
    if sess:
        sess.close()


def close_all() -> None:
    with _SESS_LOCK:
        items = list(_SESSIONS.items())
        _SESSIONS.clear()
    for _, sess in items:
        try:
            sess.close()
        except Exception:
            pass


def event_stream(sid: str):
    try:
        sess = get_session(sid)
    except RuntimeError as e:
        yield {"type": "error", "message": str(e)}
        yield {"type": "closed"}
        return
    yield {"type": "ready", "sid": sid, **sess.meta}
    import base64
    while True:
        try:
            item = sess.q.get(timeout=0.5)
        except Empty:
            if sess.closed.is_set():
                break
            continue
        if item is None:
            break
        yield {"type": "data", "b64": base64.b64encode(item).decode("ascii")}
    yield {"type": "closed"}
