"""Outpost-owned TLS edge for the fixed, read-only Serein Vitals tails.

This process has no Kernel, Gateway, companion, or domain-credential
dependency. Its own TLS credentials are supplied by systemd. It forwards
only the already-defined Vitals status endpoint to
the local Outpost presentation socket. Edge availability is independent of
Host admission: a failed or absent Host must remain observable.
"""
from __future__ import annotations

import base64
import json
import socket
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .host_vitality import validate_state
from .vitals_aggregation import aggregate_vitals


BACKEND_ADDRESS = "192.168.40.10"
BACKEND_PORT = 8444
PRESENTATION_SOCKET = Path("/run/serein/outpost-presentation/status.sock")
CERTIFICATE = Path("/run/credentials/serein-https-gateway-adapter.service/serein-backend-cert.pem")
PRIVATE_KEY = Path("/run/credentials/serein-https-gateway-adapter.service/serein-backend-key.pem")
STATUS_PATH = "/v1/runtime/status"
READY_PATH = "/health/ready"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class VitalsEdgeError(ValueError):
    pass


def _presentation(method: str, path: str, accept: str) -> tuple[int, str, list[list[str]], bytes]:
    request = json.dumps({"method": method, "path": path, "accept": accept}, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2.0)
            client.connect(str(PRESENTATION_SOCKET))
            client.sendall(request)
            response = b""
            while not response.endswith(b"\n") and len(response) <= MAX_RESPONSE_BYTES:
                chunk = client.recv(65536)
                if not chunk:
                    break
                response += chunk
    except OSError as error:
        raise VitalsEdgeError("VITALS_PRESENTATION_UNAVAILABLE") from error
    if not response.endswith(b"\n") or len(response) > MAX_RESPONSE_BYTES:
        raise VitalsEdgeError("VITALS_PRESENTATION_FRAME_DENIED")
    try:
        value = json.loads(response)
        if set(value) != {"status", "content_type", "headers", "body_base64"}:
            raise ValueError
        body = base64.b64decode(value["body_base64"], validate=True)
        if type(value["status"]) is not int or not 100 <= value["status"] <= 599 or value["content_type"] not in {"application/json", "text/html; charset=utf-8"} or len(body) > MAX_RESPONSE_BYTES:
            raise ValueError
        headers = value["headers"]
        if not isinstance(headers, list) or any(not isinstance(row, list) or len(row) != 2 or not all(isinstance(item, str) and "\r" not in item and "\n" not in item and len(item) <= 8192 for item in row) for row in headers):
            raise ValueError
    except (ValueError, TypeError, json.JSONDecodeError) as error:
        raise VitalsEdgeError("VITALS_PRESENTATION_RESPONSE_DENIED") from error
    return value["status"], value["content_type"], headers, body


def _surface_ready(body: bytes) -> bool:
    """A valid recovery view is available; this never asserts Host admission."""
    try:
        state = json.loads(body)
        sources = {name: [{key: value for key, value in item.items() if key != "freshness"} for item in section["perspectives"]] for name, section in state["sections"].items()}
        # Reuse the canonical aggregator: it checks every producer digest and
        # reconstructs all derived claims/freshness plus the full projection hash.
        return aggregate_vitals(sources, current_boot_id=state["current_boot_id"], generated_at=state["generated_at"]) == state
    except (KeyError, IndexError, TypeError, ValueError, AttributeError):
        return False


def _ready(body: bytes) -> bool:
    """Healthy Host-gate acceptance, stronger than Outpost availability."""
    if not _surface_ready(body):
        return False
    try:
        state = json.loads(body)
        host = state["sections"]["host"]
        witnesses = [item for item in host["perspectives"] if item.get("producer") == "OUTPOST_HOST_WITNESS"]
        if state.get("schema") != "SereinVitalsAggregation/v1" or host.get("state") != "OBSERVED" or len(witnesses) != 1:
            return False
        witness = witnesses[0]
        host_state = validate_state(witness["payload"], active=True)
        return (
            host["claim"] in {"FIRST_BOOT_OBSERVED", "CURRENT_BOOT_STABLE", "RECOVERED_AFTER_BOOT_CHANGE"}
            and witness.get("claim") == host["claim"]
            and witness.get("freshness") == "CURRENT_BOOT_ATTRIBUTABLE"
            and witness.get("boot_id") == state.get("current_boot_id") == host_state["current_boot_id"]
            and host_state["classification"] == host["claim"]
        )
    except (KeyError, IndexError, TypeError, ValueError, AttributeError):
        return False


def edge_response(method: str, path: str, accept: str) -> tuple[int, str, list[tuple[str, str]], bytes]:
    headers = [("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff")]
    if method != "GET":
        return 405, "application/json", headers, b'{"error":"READ_ONLY"}\n'
    if path not in {STATUS_PATH, READY_PATH}:
        return 404, "application/json", headers, b'{"error":"NOT_FOUND"}\n'
    try:
        status, content_type, upstream_headers, body = _presentation("GET", STATUS_PATH, accept if path == STATUS_PATH else "application/json")
    except VitalsEdgeError:
        return 503, "application/json", headers, b'{"error":"VITALS_UNAVAILABLE"}\n'
    if (type(status) is not int or not 100 <= status <= 599
            or content_type not in {"application/json", "text/html; charset=utf-8"}
            or any(len(row) != 2 or not all(isinstance(item,str) and "\r" not in item and "\n" not in item and len(item) <= 8192 for item in row) for row in upstream_headers)):
        return 503, "application/json", headers, b'{"error":"VITALS_PRESENTATION_RESPONSE_DENIED"}\n'
    if path == READY_PATH:
        # HAProxy must not remove the recovery surface when its subject fails.
        # Healthy Host admission still uses _ready(), never this surface check.
        if status != 200 or not _surface_ready(body):
            return 503, "application/json", headers, b'{"status":"NOT_READY"}\n'
        return 200, "application/json", headers, b'{"status":"READY"}\n'
    safe_headers = [tuple(row) for row in upstream_headers if row[0].lower() == "content-security-policy"]
    return status, content_type, headers + safe_headers, body


class VitalsHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        status, content_type, headers, body = edge_response("GET", self.path, self.headers.get("Accept", "application/json"))
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        self._readonly()

    def do_PUT(self) -> None:  # noqa: N802
        self._readonly()

    def do_DELETE(self) -> None:  # noqa: N802
        self._readonly()

    def _readonly(self) -> None:
        status, content_type, headers, body = edge_response(self.command, self.path, self.headers.get("Accept", "application/json"))
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *args: object) -> None:
        return


def serve() -> None:
    if not CERTIFICATE.is_file() or CERTIFICATE.is_symlink() or not PRIVATE_KEY.is_file() or PRIVATE_KEY.is_symlink():
        raise SystemExit("VITALS_TLS_MATERIAL_DENIED")
    server = ThreadingHTTPServer((BACKEND_ADDRESS, BACKEND_PORT), VitalsHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(CERTIFICATE), keyfile=str(PRIVATE_KEY))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    serve()
