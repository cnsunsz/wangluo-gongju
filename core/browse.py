"""在软件内打开外部网页：新建 pywebview 子窗口，不跳系统浏览器，也不导航主窗口。"""
from __future__ import annotations

import logging
import re
import threading
from urllib.parse import urlparse

log = logging.getLogger("netmeter")

_lock = threading.Lock()
_child_windows: list = []
_main_window = None
_local_port = None
_patched = False


def set_main_window(win) -> None:
    global _main_window
    _main_window = win


def set_local_port(port: int) -> None:
    global _local_port
    _local_port = int(port)


def is_http_url(url: str) -> bool:
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


def is_app_local(url: str) -> bool:
    try:
        p = urlparse(url)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        # about:blank, data:, file: used by webview internals
        if not p.scheme or p.scheme in ("about", "data", "blob"):
            return True
        return False
    host = (p.hostname or "").lower()
    if host in ("127.0.0.1", "localhost", "::1"):
        if _local_port is None:
            return True
        try:
            return int(p.port or (443 if p.scheme == "https" else 80)) == int(_local_port)
        except (TypeError, ValueError):
            return False
    return False


def _title_from_url(url: str) -> str:
    try:
        host = urlparse(url).hostname or "网页"
    except Exception:
        host = "网页"
    return host


def configure_settings(webview) -> None:
    """禁止 target=_blank 跳到系统浏览器。随后由我们的补丁把新窗口改成子窗口。

    若不做补丁，pywebview 在 False 时会把外链 load 进当前窗口，必须再配合
    主窗口导航拦截。
    """
    try:
        webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = False
    except Exception:
        pass


def open_browser_window(url: str, title: str | None = None) -> dict:
    url = (url or "").strip()
    if not is_http_url(url):
        return {"ok": False, "error": "地址无效，仅支持 http/https"}
    if is_app_local(url):
        return {"ok": False, "error": "本地界面请在主窗口访问"}
    title = (title or "").strip() or _title_from_url(url)
    try:
        import webview
    except ImportError:
        return {"ok": False, "error": "未安装 pywebview"}
    try:
        from core.paths import icon_path
        ico = icon_path()
        kwargs = dict(
            title=title,
            url=url,
            width=1200,
            height=820,
            min_size=(640, 480),
            text_select=True,
            confirm_close=False,
        )
        try:
            win = webview.create_window(**kwargs)
        except TypeError:
            win = webview.create_window(title, url, width=1200, height=820)
        with _lock:
            _child_windows.append(win)

        def _cleanup():
            with _lock:
                try:
                    _child_windows.remove(win)
                except ValueError:
                    pass

        try:
            win.events.closed += _cleanup
        except Exception:
            pass
        return {"ok": True, "title": title, "url": url}
    except Exception as e:
        log.exception("open_browser_window")
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def _on_new_window_request(self, sender, args):
    try:
        args.set_Handled(True)
    except Exception:
        try:
            args.Handled = True
        except Exception:
            pass
    try:
        uri = str(args.get_Uri())
    except Exception:
        try:
            uri = str(args.Uri)
        except Exception:
            return
    if not uri or uri in ("about:blank", "about:srcdoc"):
        return
    if is_app_local(uri):
        # 同源新窗口仍在软件内打开，避免主界面被替换
        open_browser_window(uri, "网络工具")
        return
    open_browser_window(uri)


def patch_edge_new_window() -> bool:
    """替换 Edge WebView2 的新窗口处理：一律开子窗口，不走系统浏览器、不导航当前窗。"""
    global _patched
    try:
        from webview.platforms import edgechromium
        edgechromium.EdgeChrome.on_new_window_request = _on_new_window_request
        _patched = True
        return True
    except Exception:
        return False


def guard_main_navigation(window) -> None:
    """主窗口若被导航到外部站点则取消，改为子窗口打开。"""
    if window is None:
        return
    try:
        from webview.platforms.winforms import BrowserView
    except Exception:
        return
    try:
        inst = BrowserView.instances.get(window.uid)
        browser = getattr(inst, "browser", None)
        core = None
        if browser is not None:
            wv = getattr(browser, "webview", None)
            if wv is not None:
                core = getattr(wv, "CoreWebView2", None)
        if core is None:
            return

        def on_nav(sender, args):
            try:
                uri = str(args.get_Uri())
            except Exception:
                return
            if is_app_local(uri):
                return
            if not is_http_url(uri):
                return
            try:
                args.set_Cancel(True)
            except Exception:
                try:
                    args.Cancel = True
                except Exception:
                    return
            open_browser_window(uri)

        core.NavigationStarting += on_nav
    except Exception:
        log.exception("guard_main_navigation")


class JsBridge:
    def open_url(self, url, title=""):
        return open_browser_window(str(url or ""), str(title or ""))

    def pick_file(self, title="选择文件"):
        try:
            import webview
            win = _main_window
            if win is None:
                return ""
            dialog = getattr(webview, "FileDialog", None)
            kind = getattr(dialog, "OPEN", None) if dialog is not None else None
            if kind is None:
                kind = getattr(webview, "OPEN_DIALOG", None)
            result = win.create_file_dialog(kind) if kind is not None else win.create_file_dialog()
            if result:
                if isinstance(result, (list, tuple)):
                    return str(result[0] or "")
                return str(result)
        except Exception:
            log.exception("pick_file")
        return ""
