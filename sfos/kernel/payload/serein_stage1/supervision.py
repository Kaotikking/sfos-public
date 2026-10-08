"""Minimal sd_notify and watchdog support without external dependencies."""

from __future__ import annotations

import os
import socket
import threading
import time


def operations_service_controls():
    """Unprivileged read of the same two fixed units Outpost observes.

    Adapt the existing installer's systemctl-show road. Never start, restart,
    reload, enable, or infer recovery from this observation. No environment
    credential or caller-selected unit crosses the process boundary.
    """
    import re
    import subprocess
    properties=('Id','LoadState','ActiveState','SubState','FragmentPath','DropInPaths',
        'NeedDaemonReload','MainPID','ExecMainStartTimestampMonotonic','InvocationID',
        'User','Group','Restart','RestartUSec','NRestarts','Result','KillMode')
    controls={}
    for name,restart,delay in (
            ('serein-kernel-operations-heartbeat.service','on-failure','1s'),
            ('serein-observation-audit.service','always','2s')):
        result=subprocess.run(['/usr/bin/systemctl','show','--all','--no-pager',
            '--property='+','.join(properties),name],capture_output=True,text=True,
            timeout=2,check=True,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},
            stdin=subprocess.DEVNULL,close_fds=True)
        if len(result.stdout)>16384:raise RuntimeError('operations_service_output_denied')
        row={}
        for line in result.stdout.splitlines():
            key,separator,value=line.partition('=')
            if not separator or key in row:raise RuntimeError('operations_service_output_denied')
            row[key]=value
        expected={'Id':name,'LoadState':'loaded','ActiveState':'active','SubState':'running',
            'FragmentPath':'/etc/systemd/system/'+name,'DropInPaths':'','NeedDaemonReload':'no',
            'User':'serein-stage1','Group':'serein-stage1','Restart':restart,'RestartUSec':delay,
            'Result':'success','KillMode':'control-group'}
        if (set(row)!=set(properties) or any(row[key]!=value for key,value in expected.items())
                or any(not re.fullmatch('[0-9]{1,20}',row[key]) for key in
                    ('MainPID','ExecMainStartTimestampMonotonic','NRestarts'))
                or int(row['MainPID'])<=0 or int(row['ExecMainStartTimestampMonotonic'])<=0
                or not re.fullmatch('[0-9a-f]{32}',row['InvocationID']) or row['InvocationID']=='0'*32):
            raise RuntimeError('operations_service_not_current')
        controls[name]=row
    return controls


def watchdog_interval_seconds(environment: dict[str, str] | None = None) -> float | None:
    environment = os.environ if environment is None else environment
    value = environment.get("WATCHDOG_USEC")
    if not value:
        return None
    try:
        usec = int(value)
    except ValueError:
        return None
    return usec / 2_000_000 if usec > 0 else None


def notify(message: str, environment: dict[str, str] | None = None) -> bool:
    environment = os.environ if environment is None else environment
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
    environment = os.environ if environment is None else environment
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
    # sd_notify readiness describes this process, never Kernel/Stage-1
    # admission. Only Outpost plus the named independent witness proves that.
    if not notify("READY=1\nSTATUS=Kernel constituent listener ready; Stage-1 unverified", environment):
        raise RuntimeError("systemd notification socket is required")
    return start_watchdog(environment)
