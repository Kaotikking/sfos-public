"""One-client-per-process canonical Kernel Gateway runtime."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
import struct
import sys

from .kernel import classify_request, respond
from .conversation_runtime import handle_payload as conversation_handle
from .supervision import inherited_systemd_socket, ready_and_watch

CLIENTS = {"haos": "HAOS", "android": "ANDROID", "esp32": "ESP32", "internal": "INTERNAL"}
MAX = 256 * 1024
MAX_RUNTIME = 16 * 1024
REPLAY_SOCKET = Path("/run/serein/kernel/replay-store.sock")
AUDIT_SOCKET = Path("/run/serein/stage1/audit.sock")
HEX64 = re.compile(r"[0-9a-f]{64}\\Z")


def _peer_allowed(connection, client):
    prefix = "SEREIN_GATEWAY" if client == "HAOS" else "SEREIN_OUTPOST"
    expected_uid = os.environ.get(prefix + "_UID")
    expected_gid = os.environ.get(prefix + "_GID")
    if expected_uid is None or expected_gid is None:
        return False
    try:
        _, uid, gid = struct.unpack(
            "3i",
            connection.getsockopt(
                socket.SOL_SOCKET, getattr(socket, "SO_PEERCRED", 17), struct.calcsize("3i")
            ),
        )
    except (AttributeError, OSError, struct.error):
        return False
    return str(uid) == expected_uid and str(gid) == expected_gid


def replay_request(request_id, operation, *, socket_path=REPLAY_SOCKET,
                   expected_hash=None, chain_id=None):
    value = {"operation": operation, "request_id": request_id}
    now = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if operation == "RESERVE":
        value["at"] = now
    elif operation == "CONSUME":
        if not HEX64.fullmatch(str(expected_hash or "")) or not HEX64.fullmatch(str(chain_id or "")):
            raise RuntimeError("replay_binding_missing")
        value.update(expected_hash=expected_hash, chain_id=chain_id, at=now)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(str(socket_path))
        client.sendall(encoded)
        raw = client.recv(16_385)
    if not raw or len(raw) > 16_384 or b"\0" in raw:
        raise RuntimeError("replay_response_invalid")
    response = json.loads(raw)
    required = {"ok", "state", "chain_id", "receipt_sha256"}
    if not isinstance(response, dict) or not required.issubset(response) or response.get("ok") is not True:
        raise RuntimeError("replay_request_rejected")
    if response["state"] not in {"ABSENT", "RESERVED", "CONSUMED"}:
        raise RuntimeError("replay_state_invalid")
    if not HEX64.fullmatch(str(response.get("chain_id", ""))):
        raise RuntimeError("replay_chain_invalid")
    receipt = response.get("receipt_sha256")
    if receipt is not None and not HEX64.fullmatch(str(receipt)):
        raise RuntimeError("replay_receipt_invalid")
    return response


def record_terminal_event(response, *, socket_path=AUDIT_SOCKET):
    encoded = (json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2);client.connect(str(socket_path));client.sendall(encoded);raw=client.recv(4097)
    value=json.loads(raw)
    if value!={"status":"RECORDED"}:raise RuntimeError("gateway_audit_denied")


def _machine_matches(client, machine_identity):
    value = str(machine_identity).upper()
    return value == client or value.startswith(client + "_")


def _runtime_request(request):
    conversation = request["conversation"]
    return {
        "schema": "SereinStage1ConversationRuntimeRequest/v1",
        "request_id": request["request_id"],
        "conversation_id": conversation["conversation_id"],
        "machine_identity": conversation["machine_identity"],
        "requested_operation": conversation["requested_operation"],
        "utterance": conversation["utterance"],
        "observed_at": conversation["observed_at"],
    }


def handle_client_payload(payload, client, *, runtime_call=conversation_handle,
                          replay_call=replay_request, audit_call=record_terminal_event, now=None):
    request_id = None
    reservation = None
    try:
        if not payload or len(payload) > MAX:
            raise ValueError("request_too_large")
        request = json.loads(payload.decode("utf-8"))
        request_id = request.get("request_id") if isinstance(request, dict) else None
        admitted, reason = classify_request(request, now=now)
        if not admitted:
            response = respond(request, now=now)
        elif request.get("action") != "companion":
            response = respond(request, now=now)
        elif not _machine_matches(client, request["conversation"]["machine_identity"]):
            response = {
                "schema": "SereinStage1Response/v1", "request_id": request_id,
                "status": "DENIED", "reason": "gateway_client_identity_denied",
                "timestamp": (now or datetime.now(timezone.utc)).isoformat(),
            }
        else:
            current = replay_call(request_id, "WITNESS")
            if current["state"] != "ABSENT":
                raise RuntimeError("replay_duplicate")
            reserved = replay_call(request_id, "RESERVE")
            if reserved["state"] != "RESERVED":
                raise RuntimeError("replay_reserve_invalid")
            reservation = (reserved["chain_id"], reserved["receipt_sha256"])
            result = json.loads(runtime_call(
                (json.dumps(_runtime_request(request), sort_keys=True, separators=(",", ":")) + "\n").encode()
            ))
            if result.get("status") == "ANSWERED":
                response = {
                    "schema": "SereinStage1Response/v1", "request_id": request_id,
                    "status": "ANSWERED", "reason": reason,
                    "timestamp": result["completed_at"],
                    "result": {
                        "state": result["state"], "response": result["response"],
                        "scope": result["scope"], "conversation_id": result["conversation_id"],
                        "authority_effect": result["authority_effect"], "effects": result["effects"],
                        "compute_receipt": result.get("compute_receipt"),
                    },
                }
                replay_call(request_id, "CONSUME", chain_id=reservation[0],
                            expected_hash=reservation[1])
            else:
                response = {
                    "schema": "SereinStage1Response/v1", "request_id": request_id,
                    "status": result.get("status", "UNAVAILABLE"),
                    "reason": result.get("reason", "conversation_runtime_unavailable"),
                    "timestamp": result.get("completed_at"),
                }
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        response = {
            "schema": "SereinStage1Response/v1", "request_id": request_id,
            "status": "DENIED", "reason": "invalid_json",
            "timestamp": (now or datetime.now(timezone.utc)).isoformat(),
        }
    except Exception:
        response = {
            "schema": "SereinStage1Response/v1", "request_id": request_id,
            "status": "UNAVAILABLE", "reason": "gateway_transaction_failed",
            "timestamp": (now or datetime.now(timezone.utc)).isoformat(),
        }
    try:audit_call(response)
    except Exception:
        if response.get("status")=="ANSWERED":response={"schema":"SereinStage1Response/v1","request_id":request_id,"status":"UNAVAILABLE","reason":"gateway_audit_unavailable","timestamp":(now or datetime.now(timezone.utc)).isoformat()}
    return (json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n").encode()


def serve(client_name):
    client = CLIENTS.get(client_name)
    if client is None:
        raise SystemExit("GATEWAY_CLIENT_DENIED")
    with inherited_systemd_socket() as server:
        ready_and_watch()
        while True:
            connection, _ = server.accept()
            with connection:
                raw = connection.recv(MAX + 1)
                encoded = (
                    handle_client_payload(raw, client)
                    if _peer_allowed(connection, client)
                    else b'{"schema":"SereinStage1Response/v1","status":"DENIED","reason":"gateway_client_isolation_denied"}\n'
                )
                connection.sendall(encoded)


if __name__ == "__main__":
    serve(sys.argv[1] if len(sys.argv) == 2 else "")
