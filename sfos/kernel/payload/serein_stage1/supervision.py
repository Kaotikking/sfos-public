"""Minimal sd_notify and watchdog support without external dependencies."""

from __future__ import annotations

import os
import socket
import threading
import time


def watchdog_interval_seconds(environment: dict[str, str] | None = None) -> float | None:
    environment = environment or os.environ
    value = environment.get("WATCHDOG_USEC")
    if not value:
        return None
    try:
        usec = int(value)
    except ValueError:
        return None
    return usec / 2_000_000 if usec > 0 else None


def notify(message: str, environment: dict[str, str] | None = None) -> bool:
    environment = environment or os.environ
    address = environment.get("NOTIFY_SOCKET")
    if not address:
        return False
    if address.startswith("@"):
        address = "\0" + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as channel:
        channel.connect(address)
        channel.sendall(message.encode("utf-8"))
    return True


def inherited_systemd_socket(environment: dict[str, str] | None = None,
                             *, fd: int = 3) -> socket.socket:
    """Return one validated systemd-activated Unix stream listener."""
    environment = environment or os.environ
    if environment.get("LISTEN_PID") != str(os.getpid()):
        raise RuntimeError("systemd listener PID mismatch")
    if environment.get("LISTEN_FDS") != "1":
        raise RuntimeError("exactly one systemd listener is required")
    duplicated = os.dup(fd)
    try:
        inherited = socket.socket(fileno=duplicated)
    except Exception:
        os.close(duplicated)
        raise
    if inherited.family != socket.AF_UNIX or inherited.type & socket.SOCK_STREAM != socket.SOCK_STREAM:
        inherited.close()
        raise RuntimeError("systemd listener must be an AF_UNIX stream socket")
    if inherited.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1:
        inherited.close()
        raise RuntimeError("systemd listener is not accepting connections")
    return inherited


def start_watchdog(environment: dict[str, str] | None = None) -> threading.Thread | None:
    interval = watchdog_interval_seconds(environment)
    if interval is None:
        return None

    def pulse() -> None:
        while True:
            notify("WATCHDOG=1", environment)
            time.sleep(interval)

    worker = threading.Thread(target=pulse, name="serein-stage1-watchdog", daemon=True)
    worker.start()
    return worker


def ready_and_watch(environment: dict[str, str] | None = None) -> threading.Thread | None:
    if not notify("READY=1\nSTATUS=Serein Stage-1 ready", environment):
        raise RuntimeError("systemd notification socket is required")
    return start_watchdog(environment)
