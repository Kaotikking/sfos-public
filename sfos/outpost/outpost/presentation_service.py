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
import threading
import time
from pathlib import Path

from .http_readonly import present
from .vitals_runtime import VitalsRuntimeStore
from .reboot_vitality import RebootVitalityError

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
                             BOOT_ID_PATH.read_text(encoding="ascii").strip(),
                             # Reserve response encoding/flush time inside the
                             # existing exchange deadline. Slow evidence means
                             # a readable unavailable witness, never old success.
                             snapshot_timeout=max(0.0, deadline - time.monotonic() - 0.25))
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
        try:
            self.wfile.write(json.dumps(response, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            self.wfile.flush()
        except OSError:
            return
        if response['status'] == 200:
            self.server.warm_cold_chronology()


class PresentationServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    # Bound local work without letting one slow/partial client hold the accept
    # loop. Every admitted request still acquires its own complete snapshot.
    MAX_CONCURRENT_REQUESTS = 4

    def warm_cold_chronology(self):
        store = self.host_vitality_store
        if (not isinstance(store, VitalsRuntimeStore)
                or not store.chronology_needs_validation()
                or not store._presentation_acquisition.acquire(blocking=False)):
            return
        try:
            # This same bounded handler has already flushed truthful unavailable
            # evidence. Acquire only parsing evidence, never a cached readiness
            # verdict; later requests still hash all bytes via read_summary.
            if not self._cold_chronology_slot.acquire(blocking=False):
                return
            try:
                if store.chronology_needs_validation():
                    try:
                        store.chronology.read_summary()
                    except (OSError, ValueError, TypeError):
                        pass
            finally:
                self._cold_chronology_slot.release()
        finally:
            store._presentation_acquisition.release()

    def process_request(self, request, client_address):
        if not self._request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()

    def __init__(self, address, store: VitalsRuntimeStore):
        self._request_slots = threading.BoundedSemaphore(self.MAX_CONCURRENT_REQUESTS)
        self._cold_chronology_slot = threading.Lock()
        if os.path.lexists(address):
            raise ValueError("PRESENTATION_SOCKET_COLLISION_DENIED")
        # Validate the existing history before exposing the request socket.
        # Subsequent requests still rehash every prefix byte and validate all
        # additions. A broken/absent history must not prevent recovery Vitals.
        if isinstance(store, VitalsRuntimeStore):
            store.host.defer_cold_validation = True
            # The writer holds an exclusive chronology lock while appending.
            # A transient collision is not a completed cold validation: warm
            # the same reader before the first bounded edge request. Keep the
            # retries finite and specific; missing/broken history still permits
            # the independent recovery page, and every request rehashes bytes.
            for attempt in range(3):
                try:
                    store.chronology.read_summary()
                    break
                except RebootVitalityError as error:
                    if str(error) != 'VITALITY_CHRONOLOGY_BUSY' or attempt == 2:
                        break
                    time.sleep(1.0)
                except (OSError, ValueError, TypeError):
                    break
            store.defer_cold_chronology = True
            # Prepare the small attempt reader before starting the large Host
            # scan, so first-request parsing does not compete with that worker.
            # These are parsing indexes only; each request still verifies all
            # current bytes and derives its own attempt/Host result.
            try:
                store.host_attempts.latest()
            except (OSError, ValueError, TypeError):
                pass
            # Large Host history is validated by one bounded read-only worker.
            # The first page reports UNVALIDATED, never a cached Host verdict.
            try:
                store.host.snapshot()
            except (OSError, ValueError, TypeError):
                pass
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
