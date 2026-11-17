r"""用户偏好：开机自启等。

全部保存在各平台运行时目录下的 settings.json。
关闭窗口一律隐藏到托盘（Windows）或菜单栏/程序坞后台（macOS），keep_background 恒为 True。
点减号只做普通最小化，窗口留在任务栏 / Dock，不会进托盘。
彻底退出只能通过托盘「退出」或窗口内的「退出程序」。
"""
from __future__ import annotations

import json
import os
import sys

from .paths import (
    APP_NAME, BUNDLE_ID, app_bundle_path, is_frozen, is_macos, is_windows,
    os_label, platform_id, runtime_dir,
)

KEYS = ("minimize_to_tray", "autostart", "keep_background")
DEFAULTS = {
    "minimize_to_tray": False,
    "autostart": False,
    "keep_background": True,
}

RUN_VALUE = APP_NAME
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def settings_path() -> str:
    return os.path.join(runtime_dir(), "settings.json")


def load() -> dict:
    cfg = dict(DEFAULTS)
    try:
        with open(settings_path(), encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            for k in KEYS:
                if k in data:
                    cfg[k] = bool(data[k])
    except (OSError, ValueError):
        pass
    # 关闭窗口必须留在后台；减号最小化不再进托盘，不被旧配置覆盖
    cfg["keep_background"] = True
    cfg["minimize_to_tray"] = False
    return cfg


def save(data: dict) -> dict:
    cfg = load()
    for k in KEYS:
        if k in data and k not in ("keep_background", "minimize_to_tray"):
            cfg[k] = bool(data[k])
    cfg["keep_background"] = True
    cfg["minimize_to_tray"] = False
    path = settings_path()
    tmp = path + ".tmp"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    apply_autostart(cfg["autostart"])
    return cfg


def launch_command() -> str:
    if is_frozen():
        return f'"{sys.executable}" --startup'
    script = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))
    return f'"{sys.executable}" "{script}" --startup'


def _launch_agent_plist() -> str:
    return os.path.expanduser(f"~/Library/LaunchAgents/{BUNDLE_ID}.plist")


def _macos_program_args() -> list[str]:
    bundle = app_bundle_path()
    if bundle:
        return ["/usr/bin/open", "-a", bundle, "--args", "--startup"]
    if is_frozen():
        return [sys.executable, "--startup"]
    script = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))
    return [sys.executable, script, "--startup"]


def _apply_autostart_macos(enabled: bool) -> None:
    import subprocess
    plist = _launch_agent_plist()
    label = BUNDLE_ID
    os.makedirs(os.path.dirname(plist), exist_ok=True)
    uid = os.getuid()
    target = f"gui/{uid}/{label}"

    def _run(cmd):
        try:
            subprocess.run(cmd, capture_output=True, timeout=8)
        except (OSError, subprocess.TimeoutExpired):
            pass

    if enabled:
        args = _macos_program_args()
        arg_xml = "\n".join(f"    <string>{_xml_escape(a)}</string>" for a in args)
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0"><dict>\n'
            f"  <key>Label</key><string>{label}</string>\n"
            "  <key>ProgramArguments</key><array>\n"
            f"{arg_xml}\n"
            "  </array>\n"
            "  <key>RunAtLoad</key><true/>\n"
            "  <key>LimitLoadToSessionType</key><string>Aqua</string>\n"
            "</dict></plist>\n"
        )
        with open(plist, "w", encoding="utf-8") as f:
            f.write(body)
        _run(["launchctl", "bootout", target])
        _run(["launchctl", "bootstrap", f"gui/{uid}", plist])
        _run(["launchctl", "enable", target])
        # 旧接口兜底
        _run(["launchctl", "load", "-w", plist])
    else:
        _run(["launchctl", "bootout", target])
        _run(["launchctl", "unload", "-w", plist])
        try:
            os.remove(plist)
        except OSError:
            pass


def _xml_escape(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def apply_autostart(enabled: bool) -> None:
    if is_macos():
        try:
            _apply_autostart_macos(enabled)
        except OSError:
            pass
        return
    if not is_windows():
        return
    try:
        import winreg
        key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE)
        try:
            if enabled:
                winreg.SetValueEx(key, RUN_VALUE, 0, winreg.REG_SZ, launch_command())
            else:
                try:
                    winreg.DeleteValue(key, RUN_VALUE)
                except FileNotFoundError:
                    pass
            if RUN_VALUE != "网络万用表":
                try:
                    winreg.DeleteValue(key, "网络万用表")
                except FileNotFoundError:
                    pass
        finally:
            winreg.CloseKey(key)
    except OSError:
        pass


def autostart_enabled() -> bool:
    if is_macos():
        return os.path.isfile(_launch_agent_plist())
    if not is_windows():
        return False
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ)
        try:
            winreg.QueryValueEx(key, RUN_VALUE)
            return True
        finally:
            winreg.CloseKey(key)
    except OSError:
        return False


def public() -> dict:
    cfg = load()
    cfg["run_dir"] = runtime_dir()
    cfg["autostart_applied"] = autostart_enabled()
    cfg["platform"] = platform_id()
    cfg["os_label"] = os_label()
    cfg["features"] = {
        "system_proxy": is_windows(),
        "autostart": is_windows() or is_macos(),
        "win_diag": is_windows(),
        "wlan": is_windows(),
    }
    return cfg
