"""应用路径：资源目录、可执行文件目录，以及各平台运行时目录。"""
from __future__ import annotations

import os
import sys

APP_NAME = "网络工具"
APP_VERSION = "1.2.1"
APP_AUTHOR = "Lorenzo"
APP_DESCRIPTION = "网络工具"
LEGACY_APP_NAME = "网络万用表"
BUNDLE_ID = "com.cnsunsz.wangluogongju"


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def is_windows() -> bool:
    return os.name == "nt"


def is_macos() -> bool:
    return sys.platform == "darwin"


def platform_id() -> str:
    if is_windows():
        return "windows"
    if is_macos():
        return "macos"
    return "linux"


def os_label() -> str:
    return {"windows": "Windows", "macos": "macOS", "linux": "Linux"}[platform_id()]


def exe_dir() -> str:
    if is_frozen():
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resource_dir() -> str:
    if is_frozen():
        return getattr(sys, "_MEIPASS", exe_dir())
    return exe_dir()


def app_bundle_path() -> str | None:
    """frozen 的 .app 路径（仅 macOS 打包）。"""
    if not (is_frozen() and is_macos()):
        return None
    cur = sys.executable
    for _ in range(4):
        if cur.endswith(".app"):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return None


def runtime_dir() -> str:
    """日志、锁、配置放在系统用户数据目录，绝不在可执行文件旁建 data 目录。

    Windows: %LOCALAPPDATA%\\网络工具\\
    macOS:   ~/Library/Application Support/网络工具/
    其它:    $XDG_DATA_HOME/网络工具 或 ~/.local/share/网络工具
    """
    if is_macos():
        base = os.path.join(os.path.expanduser("~"), "Library", "Application Support")
    else:
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
    names = ("app.icns", "app-64.png", "app.ico", "app-source.png")
    bases = (
        os.path.join(resource_dir(), "icons"),
        os.path.join(exe_dir(), "icons"),
        resource_dir(),
        os.path.join(exe_dir()),
    )
    for base in bases:
        for name in names:
            p = os.path.join(base, name)
            if os.path.isfile(p):
                return p
    return None
