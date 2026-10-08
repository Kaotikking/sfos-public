"""Outpost-owned TLS edge for the fixed, read-only Serein Vitals tails.

This transport process has no Kernel imports or domain-credential startup
dependency. Its own TLS credentials are supplied by systemd. Vitals GETs go
only to Outpost presentation; the historical voice POST tail goes only to the
separate private Kernel process. Neither tail calls the other. Edge/Vitals
availability is independent of Host admission and Kernel availability.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import grp
import socket
import ssl
import stat
import struct
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .host_vitality import canonical, validate_state
from .vitals_aggregation import aggregate_vitals


BACKEND_ADDRESS = "192.168.40.10"
BACKEND_PORT = 8444
PRESENTATION_SOCKET = Path("/run/serein/outpost-presentation/status.sock")
CERTIFICATE = Path("/run/credentials/serein-https-gateway-adapter.service/serein-backend-cert.pem")
PRIVATE_KEY = Path("/run/credentials/serein-https-gateway-adapter.service/serein-backend-key.pem")
STATUS_PATH = "/v1/runtime/status"
READY_PATH = "/health/ready"
CONVERSATION_PATH = "/v1/voice/conversation"
GATEWAY_SOCKET = Path('/run/serein/kernel/gateway-haos.sock')
MAX_CONVERSATION_REQUEST_BYTES = 128 * 1024
MAX_GATEWAY_RESPONSE_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class VitalsEdgeError(ValueError):
    pass


def _gateway_exchange(wire: bytes, *, root=Path('/')) -> tuple[int, bytes]:
    """One fixed private HTTP exchange, never an authority or retry boundary.

    ADAPT the existing Kernel exchange_private_service descriptor/peer custody
    checks, but retain the public HTTP frame for authentication inside Kernel.
    Do not import Kernel code into this independently booted transport.
    """
    root = Path(root)
    if not root.is_absolute() or '..' in root.parts:
        raise VitalsEdgeError('GATEWAY_ROOT_DENIED')
    if (type(wire) is not bytes or not wire.startswith(b'POST /v1/voice/conversation HTTP/1.0\r\n')
            or len(wire) > MAX_CONVERSATION_REQUEST_BYTES + 8192):
        raise VitalsEdgeError('GATEWAY_REQUEST_DENIED')
    group = grp.getgrnam('serein-stage1')
    handles, parents = [], []
    deadline = time.monotonic() + 30
    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError('GATEWAY_DEADLINE')
        return value
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        handles.append(fd); parents.append(identity(os.fstat(fd)))
        parts = GATEWAY_SOCKET.parts[1:]
        for part in parts[:-1]:
            info = os.fstat(fd)
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                raise VitalsEdgeError('GATEWAY_PARENT_CUSTODY_DENIED')
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            handles.append(fd); parents.append(identity(os.fstat(fd)))
        info = os.fstat(fd)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise VitalsEdgeError('GATEWAY_PARENT_CUSTODY_DENIED')
        before = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
        if (not stat.S_ISSOCK(before.st_mode) or before.st_nlink != 1
                or (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode))
                != (0, group.gr_gid, 0o660)):
            raise VitalsEdgeError('GATEWAY_SOCKET_CUSTODY_DENIED')
        def stable():
            current = root
            for part, opened, original in zip(('', *parts[:-1]), handles, parents):
                if part:
                    current = current / part
                if identity(current.lstat()) != original or identity(os.fstat(opened)) != original:
                    raise VitalsEdgeError('GATEWAY_PARENT_CHANGED')
            if identity(os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)) != identity(before):
                raise VitalsEdgeError('GATEWAY_SOCKET_CHANGED')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(remaining())
            connection.connect(f'/proc/self/fd/{fd}/{parts[-1]}')
            _, uid, gid = struct.unpack('3i', connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
            if (uid, gid) != (0, 0):
                raise VitalsEdgeError('GATEWAY_LISTENER_IDENTITY_DENIED')
            stable()
            connection.settimeout(remaining()); connection.sendall(wire)
            response = bytearray()
            maximum = MAX_GATEWAY_RESPONSE_BYTES + 8192
            while True:
                connection.settimeout(remaining())
                block = connection.recv(min(16384, maximum + 1 - len(response)))
                if not block:
                    break
                response.extend(block)
                if len(response) > maximum:
                    raise VitalsEdgeError('GATEWAY_RESPONSE_SIZE_DENIED')
            stable()
        return _gateway_http_response(bytes(response))
    finally:
        for opened in reversed(handles):
            os.close(opened)


def _gateway_http_response(response: bytes) -> tuple[int, bytes]:
    """Bound the existing private handler response; never forward its headers."""
    try:
        head, body = response.split(b'\r\n\r\n', 1)
        lines = head.decode('ascii').split('\r\n')
        version, status, _ = lines[0].split(' ', 2)
        if version != 'HTTP/1.0' or not status.isdigit() or int(status) not in {200, 400, 403, 405, 415, 503}:
            raise ValueError
        headers = {}
        for line in lines[1:]:
            name, value = line.split(':', 1)
            name = name.lower()
            if name in headers:
                raise ValueError
            headers[name] = value.strip()
        if (len(head) > 8192 or len(body) > MAX_GATEWAY_RESPONSE_BYTES
                or headers.get('content-type') != 'application/json'
                or headers.get('content-length') != str(len(body))
                or headers.get('connection') != 'close'
                or 'transfer-encoding' in headers or 'content-encoding' in headers):
            raise ValueError
        return int(status), body
    except (ValueError, UnicodeError) as error:
        raise VitalsEdgeError('GATEWAY_RESPONSE_DENIED') from error


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


def current_host_evidence(body: bytes, *, current_boot_id: str, expected_generation: dict,
                          requested_at: float, received_at: float) -> dict:
    """Validate one authenticated, uncached API read, never grant execution.

    The caller owns exact-endpoint TLS authentication and reads its own boot
    before/after that request. The generation time must fall inside this read;
    there is deliberately no invented Host-sample TTL. A later collection can
    invalidate this observation: callers must reread at their point of use.
    This is also not whole-Kernel or Stage-1 verification.
    """
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate field')
            value[key] = item
        return value

    def constant(_value):
        raise ValueError('nonfinite value')

    try:
        if (type(body) is not bytes or not 0 < len(body) <= MAX_RESPONSE_BYTES
                or any(type(at) not in (int, float) or not math.isfinite(at)
                       for at in (requested_at, received_at))
                or not 0 <= requested_at <= received_at):
            raise ValueError('invalid request interval')
        state = json.loads(body, object_pairs_hook=pairs, parse_constant=constant)
        if (not _ready(body) or state['current_boot_id'] != current_boot_id
                or not requested_at <= state['generated_at'] <= received_at):
            raise ValueError('Host evidence unavailable or outside this read')
        host = next(item for item in state['sections']['host']['perspectives']
                    if item['producer'] == 'OUTPOST_HOST_WITNESS')
        if host['observed_at'] > state['generated_at']:
            raise ValueError('future Host observation')
        coordinators = [item for item in state['sections']['domains']['perspectives']
                        if item['producer'] == 'OUTPOST_DOMAIN_COORDINATOR']
        if len(coordinators) != 1:
            raise ValueError('missing or contradictory Outpost generation')
        coordinator = coordinators[0]
        identity = coordinator['payload']['coordinator']
        if (not isinstance(expected_generation, dict) or not expected_generation
                or identity.get('schema') != 'SereinOutpostCoordinatorWitness/v2'
                or identity.get('generation_identity') != expected_generation
                or identity.get('host_gate') != 'CURRENT_BOOT_OBSERVED'
                or identity.get('boot_id') != current_boot_id
                or coordinator['boot_id'] != current_boot_id
                or coordinator['freshness'] != 'CURRENT_BOOT_ATTRIBUTABLE'
                or type(identity.get('observed_at')) not in (int,float)
                or not 0 <= identity['observed_at'] <= state['generated_at']):
            raise ValueError('unbound Outpost generation claim')
        return {'state': 'CURRENT_HOST_EVIDENCE_ONLY',
                'boot_id': current_boot_id, 'claim': host['claim'],
                'host_projection_digest': host['payload']['projection_digest'],
                'host_facts_sha256': hashlib.sha256(canonical({
                    key: value for key, value in host['payload']['latest'].items()
                    if key not in {'observed_at', 'evidence_digest'}
                })).hexdigest(),
                'vitals_projection_digest': state['projection_digest'],
                'response_sha256': hashlib.sha256(body).hexdigest(),
                'observed_at': host['observed_at'],
                'generated_at': state['generated_at'],
                'requested_at': requested_at, 'received_at': received_at,
                'outpost_generation': dict(expected_generation),
                'generation_evidence': 'COORDINATOR_CLAIM_NOT_PROCESS_ATTESTATION',
                'authority_effect': 'NONE', 'admission_effect': 'NONE',
                'dispatch_effect': 'NONE'}
    except (KeyError, IndexError, TypeError, ValueError, AttributeError,
            UnicodeError, RecursionError, StopIteration) as error:
        raise VitalsEdgeError('CURRENT_HOST_EVIDENCE_DENIED') from error


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
    # Reuse the Kernel adapter's bounded, per-request TLS handshake road.
    # A client that never sends ClientHello must not occupy the accept loop.
    timeout = 2.0

    def handle_expect_100(self):
        # BaseHTTPRequestHandler otherwise sends an interim success before
        # do_POST can reject this unsupported framing.
        self._gateway_reply(400, b'{"status":"DENIED","reason":"conversation_request_invalid"}')
        return False

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
        if self.path != CONVERSATION_PATH:
            self._readonly()
            return
        self.close_connection = True
        try:
            lengths = self.headers.get_all('Content-Length', [])
            types = self.headers.get_all('Content-Type', [])
            tokens = self.headers.get_all('X-Serein-Client-Token', [])
            if (len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit()
                    or len(lengths[0]) > 6 or not 0 < int(lengths[0]) <= MAX_CONVERSATION_REQUEST_BYTES
                    or len(types) != 1 or self.headers.get_content_type() != 'application/json'
                    or len(types[0]) > 256 or not types[0].isascii()
                    or any(ord(char) < 32 or ord(char) > 126 for char in types[0]) or len(tokens) > 1
                    or any(not token.isascii() or not token or len(token) > 4096
                           or any(ord(char) < 33 or ord(char) > 126 for char in token) for token in tokens)
                    or any(self.headers.get_all(name) for name in
                           ('Transfer-Encoding', 'Content-Encoding', 'Expect'))):
                raise ValueError('framing')
            deadline = time.monotonic() + self.timeout
            body = bytearray()
            length = int(lengths[0])
            while len(body) < length:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                self.connection.settimeout(remaining)
                part = self.rfile.read1(min(16384, length - len(body)))
                if not part:
                    raise ValueError('incomplete')
                body.extend(part)
            # Fresh fixed framing; no caller-selected host, hop-by-hop header,
            # path or extra/pipelined bytes enter the private Kernel connection.
            head = (f'POST {CONVERSATION_PATH} HTTP/1.0\r\n'
                    f'Content-Type: {types[0]}\r\nContent-Length: {length}\r\nConnection: close\r\n')
            if tokens:
                head += f'X-Serein-Client-Token: {tokens[0]}\r\n'
            wire = (head + '\r\n').encode('ascii') + bytes(body)
        except (OSError, ValueError, UnicodeError):
            self._gateway_reply(400, b'{"status":"DENIED","reason":"conversation_request_invalid"}')
            return
        try:
            status, response = _gateway_exchange(wire)
        except (OSError, ValueError, KeyError):
            status, response = 503, b'{"status":"UNAVAILABLE","reason":"gateway_unavailable"}'
        self._gateway_reply(status, response)

    def _gateway_reply(self, status, body):
        self.close_connection = True
        self.send_response(status)
        for name, value in [('Content-Type', 'application/json'), ('Content-Length', str(len(body))),
                            ('Connection', 'close'), ('Cache-Control', 'no-store'),
                            ('Pragma', 'no-cache'), ('X-Content-Type-Options', 'nosniff')]:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

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
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(CERTIFICATE), keyfile=str(PRIVATE_KEY))
    server = ThreadingHTTPServer((BACKEND_ADDRESS, BACKEND_PORT), VitalsHandler,
                                 bind_and_activate=False)
    try:
        server.socket = context.wrap_socket(server.socket, server_side=True,
                                           do_handshake_on_connect=False)
        server.server_bind()
        server.server_activate()
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    serve()
