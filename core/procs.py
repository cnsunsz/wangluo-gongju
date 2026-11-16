"""跟踪外部子进程（ping / tracert / iperf3 等），窗口关闭时一并杀掉。"""
from __future__ import annotations

import os
import signal
import threading

_lock = threading.Lock()
_procs: set = set()
_cancel = threading.Event()


def cancelled() -> bool:
    return _cancel.is_set()


def request_cancel() -> None:
    _cancel.set()


def reset_cancel() -> None:
    _cancel.clear()


def register(proc) -> None:
    with _lock:
        _procs.add(proc)


def unregister(proc) -> None:
    with _lock:
        _procs.discard(proc)


def kill_all() -> None:
    request_cancel()
    with _lock:
        procs = list(_procs)
        _procs.clear()
    for p in procs:
        try:
            if p.poll() is None:
                p.kill()
        except Exception:
            try:
                os.kill(p.pid, signal.SIGTERM)
            except Exception:
                pass
