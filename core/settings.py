r"""用户偏好：最小化到托盘、开机自启、关闭后保留后台。

全部保存在 %LOCALAPPDATA%\网络工具\settings.json，默认均为关闭。
关闭窗口的默认行为仍然是完全退出。
"""
from __future__ import annotations

import json
import os
import sys

from .paths import APP_NAME, is_frozen, runtime_dir

KEYS = ("minimize_to_tray", "autostart", "keep_background")
DEFAULTS = {
    "minimize_to_tray": False,
    "autostart": False,
    "keep_background": False,
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
    return cfg


def save(data: dict) -> dict:
    cfg = load()
    for k in KEYS:
        if k in data:
            cfg[k] = bool(data[k])
    path = settings_path()
    tmp = path + ".tmp"
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


def apply_autostart(enabled: bool) -> None:
    if os.name != "nt":
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
            # 清理旧版「网络万用表」开机自启项
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
    if os.name != "nt":
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
    return cfg
