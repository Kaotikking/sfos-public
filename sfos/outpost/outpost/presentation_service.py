"""Outpost-owned, local-only read-only presentation API."""
from __future__ import annotations

import base64
import json
import os
import socketserver
import socket
from pathlib import Path

from .host_vitality import HostVitalityStore
from .http_readonly import present

SOCKET_PATH = Path("/run/serein/outpost-presentation/status.sock")
HOST_VITALITY_ROOT = Path("/var/lib/serein-outpost/host-vitality")
MAX_REQUEST_BYTES = 4096
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")


class PresentationHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        raw = self.rfile.readline(MAX_REQUEST_BYTES + 1)
        try:
            request = json.loads(raw)
            if len(raw) > MAX_REQUEST_BYTES or set(request) != {"method", "path", "accept"}:
                raise ValueError("REQUEST_DENIED")
            if not all(isinstance(request[name], str) for name in request):
                raise ValueError("REQUEST_DENIED")
            result = present(
                self.server.host_vitality_store,  # type: ignore[attr-defined]
                request["method"], request["path"], request["accept"],
                BOOT_ID_PATH.read_text(encoding="ascii").strip(),
            )
            response = {
                "status": result.status,
                "content_type": result.content_type,
                "headers": list(result.headers),
                "body_base64": base64.b64encode(result.body).decode("ascii"),
            }
        except OSError:
            response = {
                "status": 503,
                "content_type": "application/json",
                "headers": [["Cache-Control", "no-store"]],
                "body_base64": base64.b64encode(b'{"error":"VITALITY_UNAVAILABLE"}\n').decode("ascii"),
            }
        except (ValueError, TypeError, json.JSONDecodeError):
            response = {
                "status": 400,
                "content_type": "application/json",
                "headers": [["Cache-Control", "no-store"]],
                "body_base64": base64.b64encode(b'{"error":"REQUEST_DENIED"}\n').decode("ascii"),
            }
        self.wfile.write(json.dumps(response, sort_keys=True, separators=(",", ":")).encode() + b"\n")


_PresentationServerBase = (
    socketserver.UnixStreamServer
    if hasattr(socketserver, "UnixStreamServer")
    else socketserver.ThreadingTCPServer
)


class PresentationServer(_PresentationServerBase):
    def __init__(self, address, store: HostVitalityStore):
        super().__init__(address, PresentationHandler)
        self.host_vitality_store = store


def serve() -> None:
    if not hasattr(socket, "AF_UNIX") or not hasattr(socketserver, "UnixStreamServer"):
        raise SystemExit("AF_UNIX_REQUIRED")
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    if SOCKET_PATH.exists() or SOCKET_PATH.is_symlink():
        SOCKET_PATH.unlink()
    server = PresentationServer(str(SOCKET_PATH), HostVitalityStore(HOST_VITALITY_ROOT))
    os.chmod(SOCKET_PATH, 0o660)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        if SOCKET_PATH.exists() and not SOCKET_PATH.is_symlink():
            SOCKET_PATH.unlink()


if __name__ == "__main__":
    serve()
