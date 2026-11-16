"""应用路径：资源目录、可执行文件目录，以及 LocalAppData 运行时目录。"""
from __future__ import annotations

import os
import sys

APP_NAME = "网络工具"
APP_VERSION = "1.1"
APP_AUTHOR = "Lorenzo"
APP_DESCRIPTION = "网络工具"
LEGACY_APP_NAME = "网络万用表"


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def exe_dir() -> str:
    if is_frozen():
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resource_dir() -> str:
    if is_frozen():
        return getattr(sys, "_MEIPASS", exe_dir())
    return exe_dir()


def runtime_dir() -> str:
    """日志、锁、配置等一律放在 %LOCALAPPDATA%\\网络工具\\，绝不在 exe 旁建 data 目录。"""
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_DATA_HOME")
    if not base:
        if os.name == "nt":
            base = os.path.join(os.path.expanduser("~"), "AppData", "Local")
        else:
            base = os.path.join(os.path.expanduser("~"), ".local", "share")
    path = os.path.join(base, APP_NAME)
    legacy = os.path.join(base, LEGACY_APP_NAME)
    if not os.path.isdir(path) and os.path.isdir(legacy):
        try:
            os.rename(legacy, path)
        except OSError:
            pass
    os.makedirs(path, exist_ok=True)
    return path


def config_dir() -> str:
    path = os.path.join(runtime_dir(), "config")
    os.makedirs(path, exist_ok=True)
    return path


def logs_dir() -> str:
    path = os.path.join(runtime_dir(), "logs")
    os.makedirs(path, exist_ok=True)
    return path


def reports_dir() -> str:
    path = os.path.join(runtime_dir(), "reports")
    os.makedirs(path, exist_ok=True)
    return path


def icon_path() -> str | None:
    candidates = [
        os.path.join(resource_dir(), "icons", "app.ico"),
        os.path.join(exe_dir(), "icons", "app.ico"),
        os.path.join(resource_dir(), "app.ico"),
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None
