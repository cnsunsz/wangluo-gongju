"""网络工具 — 桌面版入口（Windows / macOS）。

默认用 pywebview 打开独立窗口。关闭窗口会隐藏到托盘（Windows）或保持在菜单栏 / Dock（macOS）；
只有托盘「退出」或设置里的「退出程序」才会彻底结束进程。
点减号最小化到任务栏 / Dock；点关闭才隐藏到后台。需要打开的网页在软件内的子窗口访问，不跳系统浏览器。
运行时文件位于各平台用户数据目录，不会在程序旁创建 data 目录。
"""
from __future__ import annotations

import atexit
import json
import logging
import os
import shutil
import socket
import sys
import threading
import time

from flask import Flask, Response, jsonify, request, send_from_directory, stream_with_context

from core import (
    ai, browse, cndns, dns_tools, http_tools, inspect_tools, local_inspect, local_tools,
    mux, net_extra, nettools, ping, pktcap, scan, ssh_tool, trace, win_diag,
)
from core import procs, settings as app_settings
from core.paths import (
    APP_NAME, APP_VERSION, exe_dir, is_frozen, is_macos,
    resource_dir, runtime_dir, tray_image_path, window_icon_path,
)

FROZEN = is_frozen()
ROOT = exe_dir()
RES = resource_dir()
WEB = os.path.join(RES, "web")
RUN_DIR = runtime_dir()

_LOCK_HANDLE = None
_window = None
_tray = None
_shutting_down = threading.Event()
_flask_started = threading.Event()


def _migrate_legacy():
    """把旧版 exe 旁 data/ 中的配置与日志迁到 LocalAppData，并尝试结束残留进程。"""
    legacy = os.path.join(ROOT, "data")
    if not os.path.isdir(legacy):
        return

    def move(src, dst):
        if not os.path.isfile(src):
            return
        if os.path.exists(dst):
            return
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        try:
            shutil.move(src, dst)
        except OSError:
            pass

    def merge_log(src, dst):
        if not os.path.isfile(src):
            return
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        try:
            if os.path.isfile(dst):
                with open(src, "rb") as fi, open(dst, "ab") as fo:
                    fo.write(b"\n")
                    fo.write(fi.read())
                os.remove(src)
            else:
                shutil.move(src, dst)
        except OSError:
            pass

    move(os.path.join(legacy, "config", "ai.json"), os.path.join(RUN_DIR, "config", "ai.json"))
    move(os.path.join(legacy, "ai.json"), os.path.join(RUN_DIR, "config", "ai.json"))
    merge_log(os.path.join(legacy, "logs", "app.log"), os.path.join(RUN_DIR, "logs", "app.log"))
    merge_log(os.path.join(legacy, "app.log"), os.path.join(RUN_DIR, "logs", "app.log"))
    merge_log(os.path.join(legacy, "logs", "app.log.1"), os.path.join(RUN_DIR, "logs", "app.log.1"))

    # 尝试让仍在跑的旧实例退出
    if FROZEN and not os.environ.get("NETMETER_BG"):
        for name in ("run/url.txt", "url.txt"):
            path = os.path.join(legacy, *name.split("/"))
            try:
                with open(path, encoding="utf-8") as f:
                    legacy_url = f.read().strip()
            except OSError:
                continue
            if not legacy_url:
                continue
            try:
                from urllib.request import Request, urlopen
                urlopen(Request(legacy_url.rstrip("/") + "/api/shutdown", method="POST", data=b""), timeout=1.5)
                time.sleep(0.5)
            except Exception:
                pass

    for name in ("url.txt", "pid.txt", "app.lock"):
        try:
            os.remove(os.path.join(legacy, name))
        except OSError:
            pass
        try:
            os.remove(os.path.join(legacy, "run", name))
        except OSError:
            pass
    for name in ("logs", "run", "config"):
        try:
            os.rmdir(os.path.join(legacy, name))
        except OSError:
            pass
    try:
        os.rmdir(legacy)
    except OSError:
        pass


def _log_path() -> str:
    return os.path.join(RUN_DIR, "logs", "app.log")


def _rotate_log_if_needed(path: str) -> None:
    try:
        if os.path.isfile(path) and os.path.getsize(path) > 5 * 1024 * 1024:
            os.replace(path, path + ".1")
    except OSError:
        pass


def _log(msg: str, exc: bool = False) -> None:
    import traceback
    from datetime import datetime
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    text = f"{ts} {msg}"
    if exc:
        text += "\n" + traceback.format_exc()
    try:
        os.makedirs(os.path.dirname(_log_path()), exist_ok=True)
        with open(_log_path(), "a", encoding="utf-8") as f:
            f.write(text + "\n")
            f.flush()
    except OSError:
        pass
    try:
        print(text, flush=True)
    except Exception:
        pass


def _install_exception_hooks() -> None:
    def hook(exc_type, exc, tb):
        import traceback
        try:
            os.makedirs(os.path.dirname(_log_path()), exist_ok=True)
            with open(_log_path(), "a", encoding="utf-8") as f:
                f.write("未捕获异常:\n")
                traceback.print_exception(exc_type, exc, tb, file=f)
                f.flush()
        except OSError:
            pass
        try:
            traceback.print_exception(exc_type, exc, tb)
        except Exception:
            pass

    sys.excepthook = hook

    if hasattr(threading, "excepthook"):
        def thread_hook(args):
            hook(args.exc_type, args.exc_value, args.exc_traceback)
        threading.excepthook = thread_hook


def _setup_background_logging():
    os.makedirs(os.path.join(RUN_DIR, "logs"), exist_ok=True)
    path = _log_path()
    _rotate_log_if_needed(path)
    _install_exception_hooks()
    # 冻结的 exe 没有控制台，把 stdout/stderr 接到同一日志，避免静默失败
    if os.environ.get("NETMETER_BG") or FROZEN:
        try:
            stream = open(path, "a", encoding="utf-8", buffering=1)
            sys.stdout = stream
            sys.stderr = stream
        except OSError:
            pass


def _write_runtime(url):
    os.makedirs(RUN_DIR, exist_ok=True)
    try:
        with open(os.path.join(RUN_DIR, "url.txt"), "w", encoding="utf-8") as f:
            f.write(url)
        with open(os.path.join(RUN_DIR, "pid.txt"), "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))
    except OSError:
        pass

    def cleanup():
        for name in ("url.txt", "pid.txt"):
            try:
                os.remove(os.path.join(RUN_DIR, name))
            except OSError:
                pass
        _release_lock_file()

    atexit.register(cleanup)


def _release_lock_file():
    global _LOCK_HANDLE
    handle = _LOCK_HANDLE
    _LOCK_HANDLE = None
    if handle is not None:
        try:
            handle.close()
        except OSError:
            pass
    try:
        os.remove(os.path.join(RUN_DIR, "app.lock"))
    except OSError:
        pass


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            STILL_ACTIVE = 259
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                return False
            try:
                code = ctypes.c_ulong()
                if ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                    return code.value == STILL_ACTIVE
                return True
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _lock_pid():
    for name in ("app.lock", "pid.txt"):
        try:
            with open(os.path.join(RUN_DIR, name), encoding="utf-8") as f:
                text = f.read().strip()
            if not text:
                continue
            return int(text.split()[0])
        except (OSError, ValueError, IndexError):
            continue
    return 0


def _process_image(pid: int) -> str:
    if pid <= 0:
        return ""
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                return ""
            try:
                buf = ctypes.create_unicode_buffer(32768)
                size = wintypes.DWORD(32768)
                if ctypes.windll.kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                    return buf.value
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            return ""
        return ""
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return ""


def _pid_is_our_app(pid: int) -> bool:
    if not _pid_alive(pid):
        return False
    image = (_process_image(pid) or "").replace("\\", "/")
    if not image:
        return False
    base = os.path.basename(image).lower()
    ours = (os.path.basename(sys.executable) or "").lower()
    if ours and base == ours:
        return True
    if is_frozen() and os.path.normcase(_process_image(pid)) == os.path.normcase(sys.executable):
        return True
    if "wangluogongju" in base or base == "网络工具.exe":
        return True
    if is_macos() and ("网络工具" in image or "wangluogongju" in base):
        return True
    return False


def _instance_http_alive() -> bool:
    try:
        with open(os.path.join(RUN_DIR, "url.txt"), encoding="utf-8") as f:
            url = (f.read() or "").strip()
    except OSError:
        return False
    if not url.startswith("http"):
        return False
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        host = p.hostname or "127.0.0.1"
        port = int(p.port or 80)
        with socket.create_connection((host, port), timeout=0.4):
            return True
    except Exception:
        return False


def _other_instance_running() -> bool:
    if _instance_http_alive():
        return True
    return _pid_is_our_app(_lock_pid())


def _write_pid_into_lock(handle) -> None:
    try:
        handle.seek(0)
        handle.truncate()
        handle.write(str(os.getpid()).encode("ascii"))
        handle.flush()
    except Exception:
        pass


def _acquire_single_instance(force: bool = False):
    global _LOCK_HANDLE
    os.makedirs(RUN_DIR, exist_ok=True)
    path = os.path.join(RUN_DIR, "app.lock")

    def _busy() -> bool:
        return (not force) and _other_instance_running()

    try:
        import msvcrt
    except ImportError:
        for _ in range(3):
            handle = None
            try:
                handle = open(path, "a+b")
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                _write_pid_into_lock(handle)
                _LOCK_HANDLE = handle
                return True
            except Exception:
                if handle is not None:
                    try:
                        handle.close()
                    except Exception:
                        pass
                if _busy():
                    return False
                try:
                    os.remove(path)
                except OSError:
                    time.sleep(0.05)
        return False

    for _ in range(3):
        handle = None
        try:
            handle = open(path, "a+b")
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            _write_pid_into_lock(handle)
            _LOCK_HANDLE = handle
            return True
        except OSError:
            if handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass
            if _busy():
                return False
            try:
                os.remove(path)
            except OSError:
                time.sleep(0.05)
    return False


def _bring_existing_to_front(url=""):
    """唤醒已运行实例的窗口；失败则至少探测其 HTTP 服务。"""
    # 先试 Win32 按标题找窗口
    if os.name == "nt":
        try:
            import ctypes
            user32 = ctypes.windll.user32
            hwnd = user32.FindWindowW(None, APP_NAME)
            if hwnd:
                SW_RESTORE = 9
                user32.ShowWindow(hwnd, SW_RESTORE)
                user32.SetForegroundWindow(hwnd)
                return True
        except Exception:
            pass
    if not url:
        try:
            with open(os.path.join(RUN_DIR, "url.txt"), encoding="utf-8") as f:
                url = f.read().strip()
        except OSError:
            url = ""
    if not url:
        return False
    try:
        from urllib.request import Request, urlopen
        urlopen(Request(url.rstrip("/") + "/api/focus", method="POST", data=b""), timeout=1)
        return True
    except Exception:
        try:
            from urllib.request import urlopen
            r = urlopen(url, timeout=1)
            return 200 <= getattr(r, "status", 200) < 500
        except Exception:
            return False


def _open_existing_instance():
    url = ""
    try:
        with open(os.path.join(RUN_DIR, "url.txt"), encoding="utf-8") as f:
            url = f.read().strip()
    except OSError:
        url = ""
    ok = _bring_existing_to_front(url)
    msg = "已有实例在运行"
    if url:
        msg += "：" + url
    elif not ok:
        msg += "（未找到可用地址）"
    print(msg)
    return ok


def _full_exit(code=0):
    """停止工具线程、杀掉子进程、释放锁，然后彻底退出。"""
    if _shutting_down.is_set():
        return
    _shutting_down.set()
    try:
        mux.shutdown_cleanup()
    except Exception:
        pass
    try:
        ssh_tool.close_all()
    except Exception:
        pass
    try:
        procs.kill_all()
    except Exception:
        pass
    try:
        if _tray is not None:
            _tray.stop()
    except Exception:
        pass
    for name in ("url.txt", "pid.txt"):
        try:
            os.remove(os.path.join(RUN_DIR, name))
        except OSError:
            pass
    _release_lock_file()
    os._exit(code)


# --------------- Flask app ---------------

app = Flask(__name__, static_folder=WEB, static_url_path="")
logging.getLogger("werkzeug").setLevel(logging.WARNING)


@app.get("/")
def index():
    return send_from_directory(WEB, "index.html")


def sse(gen):
    def wrap():
        try:
            for ev in gen:
                if procs.cancelled() or _shutting_down.is_set():
                    break
                yield "data: " + json.dumps(ev, ensure_ascii=False) + "\n\n"
        except GeneratorExit:
            return
        except Exception as e:
            payload = {"type": "error", "message": f"{type(e).__name__}: {e}"}
            yield "data: " + json.dumps(payload, ensure_ascii=False) + "\n\n"

    return Response(
        stream_with_context(wrap()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


def _arg(name, default=None):
    return request.args.get(name, default)


def _headers(raw):
    if isinstance(raw, dict):
        return {str(k).strip(): str(v) for k, v in raw.items() if str(k).strip()}
    out = {}
    for line in str(raw or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip()
            if k:
                out[k] = v.strip()
    return out


def _json_ok(data):
    if not isinstance(data, dict):
        data = {"result": data}
    payload = dict(data)
    payload["ok"] = True
    return jsonify(payload)


def _json_err(e, status=400):
    return jsonify(ok=False, error=str(e)), status


def _json_exc(e, status=500):
    return jsonify(ok=False, error=f"{type(e).__name__}: {e}"), status


@app.get("/api/ping/stream")
def api_ping():
    return sse(ping.ping_stream(_arg("host"), _arg("count", "4"), _arg("size", "32"),
                                _arg("timeout", "1000"), _arg("interval", "1"), _arg("family")))


@app.get("/api/traceroute/stream")
def api_traceroute():
    return sse(trace.traceroute_stream(_arg("host"), _arg("maxhops", "30"),
                                       _arg("timeout", "1000"), _arg("family")))


@app.get("/api/mtr/stream")
def api_mtr():
    return sse(trace.mtr_stream(_arg("host"), _arg("maxhops", "30"), _arg("samples", "3"),
                                _arg("timeout", "600"), _arg("family")))


@app.get("/api/download/stream")
def api_download():
    return sse(http_tools.download_stream(_arg("url"), _arg("seconds", "10"), _arg("max_mb", "200")))


@app.get("/api/speed/stream")
def api_speed():
    return sse(http_tools.speed_stream(_arg("down_url"), _arg("up_url")))


@app.post("/api/portscan")
def api_portscan():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(scan.port_scan(d.get("host"), d.get("ports", "1-1024"), d.get("timeout", 0.8), d.get("workers")))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/fetch")
def api_fetch():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(http_tools.fetch(
            d.get("url"), d.get("method", "GET"), _headers(d.get("headers")),
            d.get("body"), d.get("follow", True), d.get("timeout", 15),
        ))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/probe")
def api_probe():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(http_tools.server_probe(d.get("url")))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/timing")
def api_timing():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(http_tools.http_timing(d.get("url"), d.get("timeout")))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/httpadv")
def api_httpadv():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(http_tools.fetch(
            d.get("url"), d.get("method", "GET"), _headers(d.get("headers")),
            d.get("body"), d.get("follow", True), d.get("timeout", 20),
        ))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/dns")
def api_dns():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(dns_tools.dns_lookup(d.get("name"), d.get("types"), d.get("server"), d.get("timeout", 4)))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/iplocal")
def api_iplocal():
    try:
        info = nettools.network_info()
        local = info.pop("local", [])
        return jsonify(ok=True, local=local, **info)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/iploc")
def api_iploc():
    try:
        d = request.get_json(silent=True) or {}
        ip = (d.get("ip") or "").strip()
        is_self = not ip
        if is_self:
            pub, _ = nettools.public_ipv4()
            ip = pub or ""
            info = nettools.ip_location(ip)
            info["requested"] = "本机公网出口"
            info["is_self"] = True
        else:
            info = nettools.ip_location(ip)
            info["requested"] = ip
            info["is_self"] = False
        return _json_ok(info)
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/dnsip")
def api_dnsip():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(dns_tools.dns_lookup(d.get("value"), d.get("types"), d.get("server"), d.get("timeout", 4)))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/ipcalc")
def api_ipcalc():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(nettools.ip_calc(d.get("ip"), d.get("mask")))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/time")
def api_time():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(nettools.time_convert(d.get("value"), d.get("offset", 8)))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/codec")
def api_codec():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(nettools.codec(d.get("op"), d.get("text")))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/qr")
def api_qr():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(nettools.qr_data_url(d.get("text"), d.get("size", 240)))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/cndns")
def api_cndns():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(cndns.compare(d.get("name"), d.get("servers"), d.get("type", "A"), d.get("timeout", 3)))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.get("/api/tcping/stream")
def api_tcping():
    return sse(net_extra.tcp_ping_stream(_arg("host"), _arg("port", "80"), _arg("count", "4"),
                                         _arg("timeout", "2"), _arg("interval", "1")))


@app.get("/api/superping/stream")
def api_superping():
    return sse(net_extra.superping_stream(_arg("hosts"), _arg("count", "4"), _arg("interval", "1"),
                                          _arg("size", "32"), _arg("timeout", "1000")))


@app.get("/api/iperf3/stream")
def api_iperf3():
    return sse(net_extra.iperf3_stream(_arg("host"), _arg("port", "5201"),
                                       _arg("seconds", "10"), _arg("reverse")))


@app.post("/api/telnet")
def api_telnet():
    try:
        d = request.get_json(silent=True) or {}
        res = net_extra.telnet_probe(d.get("host"), d.get("port", 23), d.get("timeout", 5), d.get("send", ""))
        res["reachable"] = res.pop("ok")
        return _json_ok(res)
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/ipscan")
def api_ipscan():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(net_extra.ip_scan(d.get("cidr"), d.get("timeout", 600), d.get("workers", 64)))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/lanscan")
def api_lanscan():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(net_extra.lan_scan(d.get("cidr")))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.get("/api/diagnose/stream")
def api_diagnose():
    return sse(net_extra.diagnose_stream(_arg("domain", "www.baidu.com")))


@app.post("/api/whois")
def api_whois():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(net_extra.whois_lookup(d.get("domain") or d.get("name") or d.get("value")))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/sitecompare")
def api_sitecompare():
    try:
        d = request.get_json(silent=True) or {}
        mode = str(d.get("mode") or "full").lower()
        return _json_ok(http_tools.site_compare(d.get("urls"), d.get("timeout", 10), mode == "status"))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/dig")
def api_dig():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(dns_tools.dig(d.get("name"), d.get("type", "A"), d.get("server"), d.get("timeout", 4)))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/json")
def api_json():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(local_tools.json_format(d.get("text"), d.get("mode", "pretty")))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/base")
def api_base():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(local_tools.base_convert(d.get("value"), d.get("from_base", 10), d.get("to_base", 16)))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/wol")
def api_wol():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(net_extra.wol(d.get("mac"), d.get("broadcast"), d.get("port", 9)))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/ua")
def api_ua():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(local_tools.ua_parse(d.get("ua")))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/batch")
def api_batch():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(net_extra.batch_check(
            d.get("hosts"), d.get("mode", "ping"), d.get("ports", "80,443"),
            d.get("count", 2), d.get("timeout", 1000),
        ))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.get("/api/mtu/stream")
def api_mtu():
    return sse(inspect_tools.mtu_stream(_arg("host"), _arg("family"), _arg("timeout", "1200")))


@app.post("/api/netstat")
def api_netstat():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(inspect_tools.local_connections(d.get("state", "all"), d.get("query", "")))
    except Exception as e:
        return _json_exc(e)


@app.get("/api/ai/config")
def api_ai_config():
    return jsonify(ok=True, **ai.public_config())


@app.post("/api/ai/config")
def api_ai_config_save():
    try:
        d = request.get_json(silent=True) or {}
        return jsonify(ok=True, **ai.save_config(d))
    except ValueError as e:
        return _json_err(e)


@app.post("/api/ai/test")
def api_ai_test():
    try:
        return jsonify(ok=True, **ai.test_connection())
    except ValueError as e:
        return _json_err(e)
    except RuntimeError as e:
        return _json_err(e, 400)


@app.post("/api/ai/analyze/stream")
def api_ai_analyze():
    d = request.get_json(silent=True) or {}
    return sse(ai.analyze_stream(d.get("tool"), d.get("params"), d.get("result"), d.get("focus", "")))


@app.get("/api/windiag/stream")
def api_windiag():
    return sse(win_diag.windiag_stream(_arg("scope", "all"), _arg("focus", "")))


@app.get("/api/wlan/status")
def api_wlan_status():
    return jsonify(ok=True, **net_extra.wlan_status())


@app.post("/api/wlan")
@app.get("/api/wlan")
def api_wlan():
    try:
        return jsonify(ok=True, **net_extra.wlan_scan())
    except Exception as e:
        return _json_exc(e)


@app.post("/api/report")
def api_report():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(inspect_tools.build_report(d.get("note", "")))
    except Exception as e:
        return _json_exc(e)


@app.post("/api/routes")
@app.get("/api/routes")
def api_routes():
    try:
        d = request.get_json(silent=True) or {}
        family = d.get("family") or _arg("family", "all")
        return _json_ok(local_inspect.route_table(family))
    except Exception as e:
        return _json_exc(e)


@app.post("/api/arp")
def api_arp():
    try:
        d = request.get_json(silent=True) or {}
        return _json_ok(local_inspect.arp_table(d.get("query", "")))
    except Exception as e:
        return _json_exc(e)


@app.get("/api/ifstat/stream")
def api_ifstat():
    return sse(local_inspect.ifstat_stream(_arg("seconds", "0")))


@app.post("/api/nat")
def api_nat():
    try:
        return _json_ok(local_inspect.nat_detect())
    except Exception as e:
        return _json_exc(e)



@app.get("/api/pcap/capability")
def api_pcap_capability():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        return jsonify(ok=True, **pktcap.capability())
    except Exception as e:
        _log("pcap capability", exc=True)
        return _json_exc(e)


@app.get("/api/pcap/interfaces")
def api_pcap_interfaces():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        return jsonify(ok=True, **pktcap.list_interfaces())
    except Exception as e:
        _log("pcap interfaces", exc=True)
        return _json_exc(e)


@app.post("/api/pcap/start")
def api_pcap_start():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        d = request.get_json(silent=True) or {}
        st = pktcap.start_capture(
            d.get("iface") or d.get("interface") or "",
            bpf=d.get("bpf") or "",
            snaplen=int(d.get("snaplen") or 65535),
            max_packets=int(d.get("max_packets") or pktcap.DEFAULT_MAX_PACKETS),
            max_bytes=int(d.get("max_bytes") or pktcap.DEFAULT_MAX_BYTES),
            on_limit=d.get("on_limit") or "drop",
            promiscuous=bool(d.get("promiscuous", True)),
        )
        return jsonify(ok=True, **st)
    except (ValueError, RuntimeError) as e:
        return _json_err(e)
    except Exception as e:
        _log("pcap start", exc=True)
        return _json_exc(e)


@app.post("/api/pcap/stop")
def api_pcap_stop():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        return jsonify(ok=True, **pktcap.stop_capture())
    except Exception as e:
        _log("pcap stop", exc=True)
        return _json_exc(e)


@app.post("/api/pcap/clear")
def api_pcap_clear():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        return jsonify(ok=True, **pktcap.clear_packets())
    except Exception as e:
        _log("pcap clear", exc=True)
        return _json_exc(e)


@app.get("/api/pcap/status")
def api_pcap_status():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        return jsonify(ok=True, **pktcap.status())
    except Exception as e:
        return _json_exc(e)


@app.get("/api/pcap/packets")
def api_pcap_packets():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        after = int(request.args.get("after") or 0)
        limit = int(request.args.get("limit") or 500)
        query = request.args.get("q") or request.args.get("filter") or ""
        return jsonify(ok=True, **pktcap.packet_summaries(after=after, limit=limit, query=query))
    except Exception as e:
        _log("pcap packets", exc=True)
        return _json_exc(e)


@app.get("/api/pcap/packet/<int:no>")
def api_pcap_packet(no):
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        return jsonify(ok=True, **pktcap.packet_detail(no))
    except KeyError as e:
        return _json_err(e, 404)
    except Exception as e:
        _log("pcap packet", exc=True)
        return _json_exc(e)


@app.get("/api/pcap/diagnose")
def api_pcap_diagnose():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        query = request.args.get("q") or request.args.get("filter") or ""
        return jsonify(ok=True, **pktcap.diagnose(query=query))
    except Exception as e:
        _log("pcap diagnose", exc=True)
        return _json_exc(e)


@app.post("/api/pcap/deep-analyze")
def api_pcap_deep_analyze():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    d = request.get_json(silent=True) or {}
    try:
        brief = pktcap.deep_analyze_brief(no=d.get("no"), query=d.get("filter") or d.get("q") or "")
    except Exception as e:
        _log("pcap deep brief", exc=True)
        return _json_exc(e)
    if not brief.get("count"):
        return jsonify(ok=False, error="请先打开 pcap 或开始抓包，再做深度分析"), 400
    cfg = ai.public_config()
    if not cfg.get("configured"):
        return jsonify(ok=False, need_config=True, error="AI 尚未配置，请先打开「AI 设置」填写接口地址、模型和 API Key"), 400
    note = "（已向模型发送脱敏后的摘要与统计，未发送完整原始报文）"
    return sse(ai.analyze_stream(
        "抓包分析",
        note,
        brief.get("text") or "",
        d.get("focus") or "请依据摘要做深度解读：握手与会话是否异常、可能的故障点、还需要哪些本机检查。不要编造摘要中未出现的地址、域名或标志。",
    ))


@app.post("/api/pcap/open")
def api_pcap_open():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        d = request.get_json(silent=True) or {}
        path = d.get("path") or ""
        max_packets = int(d.get("max_packets") or pktcap.DEFAULT_MAX_PACKETS)
        return jsonify(ok=True, **pktcap.open_path(path, max_packets=max_packets))
    except FileNotFoundError as e:
        return _json_err(e)
    except Exception as e:
        _log("pcap open", exc=True)
        return _json_err(e)


@app.post("/api/pcap/upload")
def api_pcap_upload():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        f = request.files.get("file") or request.files.get("pcap")
        if f is None:
            return _json_err("请选择 .pcap / .pcapng 文件")
        data = f.read()
        if len(data) > 400 * 1024 * 1024:
            return _json_err("文件过大（超过 400 MB）")
        name = f.filename or "capture.pcap"
        max_packets = int(request.form.get("max_packets") or pktcap.DEFAULT_MAX_PACKETS)
        return jsonify(ok=True, **pktcap.open_bytes(data, name=name, max_packets=max_packets))
    except Exception as e:
        _log("pcap upload", exc=True)
        return _json_err(e)


@app.post("/api/pcap/save")
def api_pcap_save():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        d = request.get_json(silent=True) or {}
        path = d.get("path") or ""
        return jsonify(ok=True, **pktcap.save_path(path))
    except Exception as e:
        _log("pcap save", exc=True)
        return _json_err(e)


@app.get("/api/pcap/download")
def api_pcap_download():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        from flask import send_file
        from io import BytesIO
        data, name = pktcap.save_bytes()
        bio = BytesIO(data)
        bio.seek(0)
        return send_file(bio, mimetype="application/vnd.tcpdump.pcap", as_attachment=True,
                         download_name=name)
    except Exception as e:
        _log("pcap download", exc=True)
        return _json_err(e)


@app.get("/api/pcap/stats")
def api_pcap_stats():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        ps = pktcap.protocol_stats()
        cv = pktcap.conversations()
        return jsonify(ok=True, protocols=ps["protocols"], total=ps["total"],
                       conversations=cv["conversations"], conversation_count=cv["total"])
    except Exception as e:
        return _json_exc(e)


@app.get("/api/pcap/follow/<int:no>")
def api_pcap_follow(no):
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        return jsonify(ok=True, **pktcap.follow_stream(no))
    except (KeyError, ValueError) as e:
        return _json_err(e)
    except Exception as e:
        _log("pcap follow", exc=True)
        return _json_exc(e)


@app.get("/api/mux/adapters")
def api_mux_adapters():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        return jsonify(ok=True, adapters=mux.list_adapters())
    except Exception as e:
        return _json_exc(e)


@app.get("/api/mux/status")
def api_mux_status():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    return jsonify(ok=True, **mux.status())


@app.post("/api/mux/start")
def api_mux_start():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        d = request.get_json(silent=True) or {}
        adapters = d.get("adapters") or d.get("interfaces") or []
        st = mux.start(
            adapters,
            strategy=d.get("strategy") or "rr",
            system_proxy=bool(d.get("system_proxy", True)),
            http_port=d.get("http_port"),
            socks_port=d.get("socks_port"),
        )
        return jsonify(ok=True, **st)
    except (ValueError, RuntimeError) as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/mux/stop")
def api_mux_stop():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        return jsonify(ok=True, **mux.stop())
    except Exception as e:
        return _json_exc(e)


@app.post("/api/mux/config")
def api_mux_config():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        d = request.get_json(silent=True) or {}
        return jsonify(ok=True, **mux.update_config(d.get("strategy"), d.get("weights")))
    except (ValueError, RuntimeError) as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.get("/api/ssh/hosts")
def api_ssh_hosts():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    return jsonify(ok=True, hosts=ssh_tool.list_hosts())


@app.post("/api/ssh/hosts")
def api_ssh_hosts_save():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        d = request.get_json(silent=True) or {}
        return jsonify(ok=True, host=ssh_tool.save_host(d))
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/ssh/hosts/delete")
def api_ssh_hosts_delete():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        d = request.get_json(silent=True) or {}
        ssh_tool.delete_host(d.get("id"))
        return jsonify(ok=True, hosts=ssh_tool.list_hosts())
    except ValueError as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.get("/api/ssh/hosts/<hid>")
def api_ssh_host_get(hid):
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    row = ssh_tool.get_host(hid, include_secret=True)
    if not row:
        return jsonify(ok=False, error="未找到该主机"), 404
    return jsonify(ok=True, host=row)


@app.post("/api/ssh/open")
def api_ssh_open():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        d = request.get_json(silent=True) or {}
        return jsonify(ok=True, **ssh_tool.open_session(d))
    except (ValueError, RuntimeError) as e:
        return _json_err(e)
    except Exception as e:
        # paramiko 认证失败等
        return _json_err(e, 400)


@app.get("/api/ssh/stream")
def api_ssh_stream():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    return sse(ssh_tool.event_stream(_arg("sid", "")))


@app.post("/api/ssh/write")
def api_ssh_write():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        d = request.get_json(silent=True) or {}
        data = d.get("data")
        if d.get("b64"):
            import base64
            data = base64.b64decode(d["b64"])
        ssh_tool.write_session(d.get("sid"), data or "")
        return jsonify(ok=True)
    except (ValueError, RuntimeError) as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/ssh/resize")
def api_ssh_resize():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        d = request.get_json(silent=True) or {}
        ssh_tool.resize_session(d.get("sid"), d.get("cols") or 120, d.get("rows") or 32)
        return jsonify(ok=True)
    except (ValueError, RuntimeError) as e:
        return _json_err(e)
    except Exception as e:
        return _json_exc(e)


@app.post("/api/ssh/close")
def api_ssh_close():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    d = request.get_json(silent=True) or {}
    ssh_tool.close_session(d.get("sid") or "")
    return jsonify(ok=True)


@app.post("/api/open_url")
def api_open_url():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    d = request.get_json(silent=True) or {}
    result = browse.open_browser_window(d.get("url") or "", d.get("title") or "")
    status = 200 if result.get("ok") else 400
    return jsonify(**result), status


def _is_local():
    return request.remote_addr in ("127.0.0.1", "::1")


@app.get("/api/settings")
def api_settings_get():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    return jsonify(ok=True, **app_settings.public())


@app.post("/api/settings")
def api_settings_save():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    try:
        d = request.get_json(silent=True) or {}
        cfg = app_settings.save(d)
        _sync_tray()
        return jsonify(ok=True, **app_settings.public())
    except Exception as e:
        return _json_exc(e)


@app.post("/api/focus")
def api_focus():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403
    show_window()
    return jsonify(ok=True)


@app.post("/api/shutdown")
def api_shutdown():
    if not _is_local():
        return jsonify(ok=False, error="forbidden"), 403

    def stop():
        time.sleep(0.2)
        _full_exit(0)

    threading.Thread(target=stop, daemon=True).start()
    return jsonify(ok=True)


def _pick_port(start=8899):
    for p in range(start, start + 50):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", p))
                return p
        except OSError:
            continue
    return start


# --------------- window / tray ---------------

def show_window():
    win = _window
    if win is None:
        return
    try:
        win.show()
        if hasattr(win, "restore"):
            win.restore()
    except Exception:
        pass
    if os.name == "nt":
        try:
            import ctypes
            hwnd = ctypes.windll.user32.FindWindowW(None, APP_NAME)
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 9)
                ctypes.windll.user32.SetForegroundWindow(hwnd)
        except Exception:
            pass


def hide_window():
    if _window is not None:
        try:
            _window.hide()
        except Exception:
            pass


def _on_closing():
    if _shutting_down.is_set():
        return True
    try:
        _ensure_tray(force=True)
    except Exception:
        _log("关闭时创建托盘失败", exc=True)
    hide_window()
    return False


def _on_closed():
    # 关闭窗口只是隐藏；进程在托盘退出或 _full_exit 时结束
    if _shutting_down.is_set():
        return


def _stop_tray():
    global _tray
    icon = _tray
    _tray = None
    if icon is None:
        return
    try:
        icon.stop()
    except Exception:
        pass


def _sync_tray():
    """关闭窗口会留在后台，因此始终显示托盘图标（用于打开窗口或退出）。"""
    _ensure_tray()


def _load_tray_image():
    """用 Pillow 解码为 RGBA，绝不把路径直接丢给 System.Drawing.Icon / Cocoa NSImage。"""
    from PIL import Image
    candidates = []
    chosen = tray_image_path()
    if chosen:
        candidates.append(chosen)
    for name in ("app-64.png", "app-source.png", "app.ico"):
        path = os.path.join(RES, "icons", name)
        if path not in candidates:
            candidates.append(path)
    for path in candidates:
        if not path or not os.path.isfile(path):
            continue
        ext = os.path.splitext(path)[1].lower()
        if ext == ".icns":
            continue
        try:
            im = Image.open(path)
            im = im.convert("RGBA")
            im.load()
            return im.copy()
        except Exception as e:
            _log(f"托盘图标无法解码 {path}: {e}", exc=True)
    return Image.new("RGBA", (64, 64), (58, 74, 158, 255))


def _ensure_tray(force: bool = False):
    global _tray
    if _tray is not None:
        return
    # macOS：等 Cocoa 跑起来再创建菜单栏图标，失败也不影响主窗口 / Dock。
    # 关窗口进后台时若尚未就绪，仍尝试创建，否则可能既无窗口也无托盘。
    if is_macos() and not _gui_ready.is_set() and not force:
        return
    try:
        import pystray
        from PIL import Image  # noqa: F401
    except Exception as e:
        _log(f"未加载托盘库，将仅使用任务栏 / Dock: {e}", exc=True)
        return
    try:
        image = _load_tray_image()
        menu = pystray.Menu(
            pystray.MenuItem("打开窗口", lambda: show_window(), default=True),
            pystray.MenuItem("退出", lambda: _full_exit(0)),
        )
        icon = pystray.Icon("netmeter", image, APP_NAME, menu)
        _tray = icon

        def _run_tray():
            try:
                icon.run()
            except Exception:
                _log("托盘线程退出", exc=True)

        threading.Thread(target=_run_tray, daemon=True, name="tray").start()
    except Exception:
        _log("创建托盘失败，继续启动主窗口", exc=True)
        _tray = None


def _run_flask(port):
    app.run(host="127.0.0.1", port=port, threaded=True, debug=False, use_reloader=False)


def main():
    procs.reset_cancel()
    _migrate_legacy()
    os.makedirs(RUN_DIR, exist_ok=True)
    _setup_background_logging()
    _log(f"启动 {APP_NAME} v{APP_VERSION} frozen={FROZEN} platform={sys.platform}")

    if not _acquire_single_instance():
        if _open_existing_instance():
            _log("已有实例在运行，已尝试唤醒后退出")
            sys.exit(0)
        _log("未能唤醒已有实例（可能是上次异常退出留下的锁），尝试接管")
        if not _acquire_single_instance(force=True):
            _log("仍无法取得单实例锁，退出")
            sys.exit(0)

    want = 8899
    raw = os.environ.get("NETMETER_PORT", "")
    if raw:
        try:
            want = int(raw)
        except ValueError:
            want = 8899
    port = _pick_port(want)
    url = f"http://127.0.0.1:{port}"
    _write_runtime(url)

    banner = [
        "==============================================",
        f"  {APP_NAME} Windows 版  v{APP_VERSION}",
        f"  地址: {url}",
    ]
    if port != want:
        banner.append(f"  提示: 端口 {want} 被占用，已改用 {port}")
    banner.append("  点减号最小化到任务栏；点关闭隐藏到托盘。托盘「退出」可结束进程")
    banner.append("")
    print("\n".join(banner), flush=True)

    threading.Thread(target=_run_flask, args=(port,), daemon=True).start()
    # 等待服务就绪
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)

    try:
        mux.restore_proxy_if_dirty()
    except Exception:
        pass

    # 开机自启也正常显示主窗口；只有点关闭才会进托盘。减号是普通最小化。
    hidden = False
    no_window = os.environ.get("NETMETER_NO_WINDOW") or os.environ.get("NETMETER_HEADLESS")

    if no_window:
        # 调试：仅 HTTP 服务
        try:
            while not _shutting_down.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            _full_exit(0)
        return

    try:
        import webview
    except ImportError:
        print("未安装 pywebview，回退为仅本地服务。请 pip install pywebview")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            _full_exit(0)
        return

    global _window
    browse.set_local_port(port)
    browse.configure_settings(webview)
    try:
        from webview.platforms import edgechromium  # noqa: F401
    except Exception:
        pass
    browse.patch_edge_new_window()

    ico = window_icon_path()
    if ico:
        _log(f"窗口图标: {ico}")
    else:
        _log("未找到平台匹配的窗口图标，将不带 icon 启动")
    js_api = browse.JsBridge()
    kwargs = dict(title=APP_NAME, url=url, width=1280, height=860, min_size=(960, 640),
                  confirm_close=False, text_select=True, js_api=js_api)
    # hidden / icon 兼容不同 pywebview 版本
    try:
        _window = webview.create_window(hidden=hidden, **kwargs)
    except TypeError:
        kwargs.pop("js_api", None)
        try:
            _window = webview.create_window(js_api=js_api, **kwargs)
        except TypeError:
            _window = webview.create_window(**kwargs)
        if hidden:
            try:
                _window.hidden = True
            except Exception:
                pass
    browse.set_main_window(_window)

    try:
        _window.events.closing += _on_closing
    except Exception:
        pass
    try:
        _window.events.closed += _on_closed
    except Exception:
        pass
    # 不监听 minimized：减号必须走系统普通最小化，窗口留在任务栏。
    # 只有 closing 才会 hide 到托盘。

    if not is_macos():
        try:
            _sync_tray()
        except Exception:
            _log("启动前创建托盘失败", exc=True)

    def _on_gui_ready():
        _gui_ready.set()
        try:
            browse.patch_edge_new_window()
            browse.guard_main_navigation(_window)
        except Exception:
            _log("GUI 就绪钩子部分失败", exc=True)
        try:
            _sync_tray()
        except Exception:
            _log("GUI 就绪后创建托盘失败", exc=True)

    start_kwargs = {"debug": False}
    if sys.platform == "darwin":
        default_gui = "cocoa"
    elif os.name == "nt":
        default_gui = "edgechromium"
    else:
        default_gui = "gtk"
    gui = os.environ.get("NETMETER_GUI", default_gui)
    started = False
    # Windows 只把 .ico 传给 webview；失败则自动去掉 icon 再试，避免 System.Drawing.Icon 打死进程
    attempts = []
    if ico:
        attempts.append(("gui+icon", dict(func=_on_gui_ready, gui=gui, icon=ico, **start_kwargs)))
    attempts.extend([
        ("gui", dict(func=_on_gui_ready, gui=gui, **start_kwargs)),
        ("func", dict(func=_on_gui_ready, **start_kwargs)),
        ("gui-only", dict(gui=gui, **start_kwargs)),
        ("plain", dict(**start_kwargs)),
    ])
    for name, kw in attempts:
        try:
            _log(f"webview.start 尝试: {name}")
            webview.start(**kw)
            started = True
            break
        except TypeError as e:
            _log(f"webview.start {name} 参数不兼容: {e}")
            continue
        except Exception:
            _log(f"webview.start {name} 失败", exc=True)
            if started:
                raise
            continue
    if not started:
        try:
            _log("webview.start 回退到无参数")
            webview.start()
        except Exception:
            _log("webview.start 无参数仍失败", exc=True)
            raise

    # start() 返回通常表示所有窗口已关闭。关闭主窗口只会隐藏，
    # 但仍可能因异常导致循环结束，此时保持 Flask + 托盘。
    if not _shutting_down.is_set():
        _ensure_tray()
        try:
            while not _shutting_down.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
    _full_exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        try:
            _log("main 异常退出", exc=True)
        except Exception:
            pass
        raise
