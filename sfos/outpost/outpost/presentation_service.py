"""Outpost-owned local read-only presentation API; no Gateway dependency.

Adapted from the attributed Outpost presentation_service.py. Runtime directory
ownership belongs to its service manager; this module never replaces a socket
or repairs directory permissions to force startup.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import socketserver
import time
from pathlib import Path

from .http_readonly import present
from .vitals_runtime import VitalsRuntimeStore

SOCKET_PATH = Path("/run/serein/outpost-presentation/status.sock")
HOST_VITALITY_ROOT = Path("/var/lib/serein-outpost/host-vitality")
PRODUCER_ROOT = Path("/var/lib/serein-outpost/vitals-producers")
DOMAIN_STATE_PATH = Path("/var/lib/serein-outpost/domains/state.json")
RECOVERY_PATH = Path("/var/lib/serein-outpost/recovery/current.json")
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
MAX_REQUEST_BYTES = 4096
REQUEST_TIMEOUT_SECONDS = 2.0  # Same bounded local exchange as the existing edge.


class PresentationHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        try:
            deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
            raw = b""
            while not raw.endswith(b"\n") and len(raw) <= MAX_REQUEST_BYTES:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("PRESENTATION_REQUEST_TIMEOUT")
                self.connection.settimeout(remaining)
                block = self.connection.recv(MAX_REQUEST_BYTES + 1 - len(raw))
                if not block:
                    break
                raw += block
            request = json.loads(raw)
            if (not raw.endswith(b"\n") or len(raw) > MAX_REQUEST_BYTES
                    or not isinstance(request, dict) or set(request) != {"method", "path", "accept"}
                    or not all(isinstance(value, str) for value in request.values())):
                raise ValueError("REQUEST_DENIED")
            result = present(self.server.host_vitality_store,
                             request["method"], request["path"], request["accept"],
                             BOOT_ID_PATH.read_text(encoding="ascii").strip())
            response = {"status":result.status, "content_type":result.content_type,
                        "headers":list(result.headers),
                        "body_base64":base64.b64encode(result.body).decode("ascii")}
        except OSError:
            response = {"status":503, "content_type":"application/json",
                        "headers":[["Cache-Control","no-store"]],
                        "body_base64":base64.b64encode(b'{"error":"VITALITY_UNAVAILABLE"}\n').decode("ascii")}
        except (ValueError, TypeError):
            response = {"status":400, "content_type":"application/json",
                        "headers":[["Cache-Control","no-store"]],
                        "body_base64":base64.b64encode(b'{"error":"REQUEST_DENIED"}\n').decode("ascii")}
        self.wfile.write(json.dumps(response, sort_keys=True, separators=(",", ":")).encode() + b"\n")


class PresentationServer(socketserver.UnixStreamServer):
    def __init__(self, address, store: VitalsRuntimeStore):
        if os.path.lexists(address):
            raise ValueError("PRESENTATION_SOCKET_COLLISION_DENIED")
        super().__init__(address, PresentationHandler)
        self.host_vitality_store = store


def serve() -> None:
    if not hasattr(socket, "AF_UNIX"):
        raise SystemExit("AF_UNIX_REQUIRED")
    # The canonical service manager supplies this directory. Never mkdir,
    # unlink a predecessor, or change an existing parent's permissions here.
    if SOCKET_PATH.parent.is_symlink() or not SOCKET_PATH.parent.is_dir():
        raise SystemExit("PRESENTATION_RUNTIME_DIRECTORY_REQUIRED")
    with PresentationServer(str(SOCKET_PATH), VitalsRuntimeStore(
            HOST_VITALITY_ROOT, PRODUCER_ROOT, DOMAIN_STATE_PATH, RECOVERY_PATH)) as server:
        # RuntimeDirectory creation/custody/cleanup is systemd-owned. Binding
        # creates the socket under the service's existing umask. Do not chmod
        # or unlink a pathname whose occupant could change after a check.
        server.serve_forever()


if __name__ == "__main__":
    serve()
