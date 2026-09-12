"""Small systemd socket-activation boundary used by portable Kernel services."""
from __future__ import annotations
import os,socket

def inherited_systemd_socket():
 if os.environ.get("LISTEN_PID")!=str(os.getpid()) or os.environ.get("LISTEN_FDS")!="1":raise RuntimeError("SYSTEMD_SOCKET_DENIED")
 return socket.socket(fileno=3)

def ready_and_watch():
 address=os.environ.get("NOTIFY_SOCKET")
 if not address:return
 with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as client:client.connect(address);client.sendall(b"READY=1")
