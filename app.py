"""网络工具 — Windows 桌面版入口。

默认用 pywebview 打开独立窗口；关闭窗口即停止 Flask、杀掉子进程并退出。
仅当用户在设置中开启「保留后台运行」时，关闭窗口才会隐藏到托盘。
运行时文件位于 %LOCALAPPDATA%\\网络工具\\，不会在 exe 旁创建 data 目录。
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
    ai, cndns, dns_tools, http_tools, inspect_tools, local_tools,
    net_extra, nettools, ping, scan, trace, win_diag,
)
from core import procs, settings as app_settings
from core.paths import APP_NAME, APP_VERSION, exe_dir, icon_path, is_frozen, resource_dir, runtime_dir

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


def _setup_background_logging():
    if not (os.environ.get("NETMETER_BG") or FROZEN):
        return
    os.makedirs(os.path.join(RUN_DIR, "logs"), exist_ok=True)
    path = os.path.join(RUN_DIR, "logs", "app.log")
    try:
        if os.path.isfile(path) and os.path.getsize(path) > 5 * 1024 * 1024:
            os.replace(path, path + ".1")
    except OSError:
        pass
    stream = open(path, "a", encoding="utf-8", buffering=1)
    sys.stdout = stream
    sys.stderr = stream


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
    try:
        with open(os.path.join(RUN_DIR, "pid.txt"), encoding="utf-8") as f:
            return int(f.read().strip() or 0)
    except (OSError, ValueError):
        return 0


def _acquire_single_instance():
    global _LOCK_HANDLE
    os.makedirs(RUN_DIR, exist_ok=True)
    path = os.path.join(RUN_DIR, "app.lock")
    try:
        import msvcrt
    except ImportError:
        # 非 Windows：用独占打开模拟
        try:
            flags = os.O_CREAT | os.O_RDWR
            if hasattr(os, "O_EXCL"):
                pass
            handle = open(path, "a+b")
            try:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except Exception:
                handle.close()
                return False
            _LOCK_HANDLE = handle
            return True
        except OSError:
            return False
    for _ in range(2):
        try:
            handle = open(path, "a+b")
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            _LOCK_HANDLE = handle
            return True
        except OSError:
            try:
                handle.close()
            except Exception:
                pass
            if _pid_alive(_lock_pid()):
                return False
            try:
                os.remove(path)
            except OSError:
                return False
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
    cfg = app_settings.load()
    if cfg.get("keep_background") and not _shutting_down.is_set():
        _ensure_tray()
        hide_window()
        return False
    # 默认：关闭窗口即完全退出
    threading.Thread(target=lambda: (time.sleep(0.05), _full_exit(0)), daemon=True).start()
    return True


def _on_closed():
    cfg = app_settings.load()
    if cfg.get("keep_background") and not _shutting_down.is_set():
        return
    _full_exit(0)


def _on_minimized():
    if app_settings.load().get("minimize_to_tray"):
        _ensure_tray()
        hide_window()


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
    """仅在开启最小化到托盘或保留后台时显示托盘图标。"""
    cfg = app_settings.load()
    if cfg.get("keep_background") or cfg.get("minimize_to_tray"):
        _ensure_tray()
    else:
        _stop_tray()


def _ensure_tray():
    global _tray
    if _tray is not None:
        return
    try:
        import pystray
        from PIL import Image
    except ImportError:
        return
    ico = icon_path()
    image = None
    if ico:
        try:
            image = Image.open(ico)
        except Exception:
            image = None
    if image is None:
        png = os.path.join(RES, "icons", "app-64.png")
        if os.path.isfile(png):
            image = Image.open(png)
        else:
            image = Image.new("RGBA", (64, 64), (58, 74, 158, 255))

    menu = pystray.Menu(
        pystray.MenuItem("打开窗口", lambda: show_window(), default=True),
        pystray.MenuItem("退出", lambda: _full_exit(0)),
    )
    icon = pystray.Icon("netmeter", image, APP_NAME, menu)
    _tray = icon
    threading.Thread(target=icon.run, daemon=True).start()


def _run_flask(port):
    app.run(host="127.0.0.1", port=port, threaded=True, debug=False, use_reloader=False)


def main():
    procs.reset_cancel()
    _migrate_legacy()
    os.makedirs(RUN_DIR, exist_ok=True)
    _setup_background_logging()

    startup = "--startup" in sys.argv
    if not _acquire_single_instance():
        _open_existing_instance()
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
    banner.append("  关闭窗口即停止服务；可在设置中改为托盘后台")
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

    cfg = app_settings.load()
    hidden = startup and (cfg.get("keep_background") or cfg.get("minimize_to_tray"))
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
    ico = icon_path()
    kwargs = dict(title=APP_NAME, url=url, width=1280, height=860, min_size=(960, 640),
                  confirm_close=False, text_select=True)
    # hidden / icon 兼容不同 pywebview 版本
    try:
        _window = webview.create_window(hidden=hidden, **kwargs)
    except TypeError:
        _window = webview.create_window(**kwargs)
        if hidden:
            try:
                _window.hidden = True
            except Exception:
                pass

    try:
        _window.events.closing += _on_closing
    except Exception:
        pass
    try:
        _window.events.closed += _on_closed
    except Exception:
        pass
    for ev_name in ("minimized", "moved"):
        ev = getattr(_window.events, ev_name, None)
        if ev_name == "minimized" and ev is not None:
            try:
                ev += _on_minimized
            except Exception:
                pass

    _sync_tray()

    start_kwargs = {"debug": False}
    gui = os.environ.get("NETMETER_GUI", "edgechromium")
    try:
        webview.start(gui=gui, icon=ico, **start_kwargs)
    except TypeError:
        try:
            webview.start(gui=gui, **start_kwargs)
        except Exception:
            webview.start(**start_kwargs)

    # start() 返回通常表示窗口循环已结束。
    # 若用户开启了「保留后台运行」，尽量保持 Flask + 托盘，避免误退出。
    if app_settings.load().get("keep_background") and not _shutting_down.is_set():
        _ensure_tray()
        try:
            while not _shutting_down.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
    _full_exit(0)


if __name__ == "__main__":
    main()
