"""Minimum private Stage-1 conversation runtime backed by loopback Ollama."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import socket
from typing import Any

from .companion_provider import CompanionUnavailable, infer
from .supervision import inherited_systemd_socket, ready_and_watch

REQUEST_SCHEMA = "SereinStage1ConversationRuntimeRequest/v1"
RESPONSE_SCHEMA = "SereinStage1ConversationRuntimeResponse/v1"
FIELDS = frozenset({
    "schema", "request_id", "conversation_id", "machine_identity",
    "requested_operation", "utterance", "observed_at",
})
MAX_REQUEST_BYTES = 16 * 1024
MAX_TEXT_CHARS = 1024
MAX_AGE_SECONDS = 120
MAX_FUTURE_SKEW_SECONDS = 5


def _validate(value: object, *, now: datetime) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != FIELDS or value.get("schema") != REQUEST_SCHEMA:
        raise ValueError("conversation_runtime_envelope_invalid")
    for field, maximum in (
        ("request_id", 128), ("conversation_id", 256), ("machine_identity", 128),
        ("utterance", MAX_TEXT_CHARS),
    ):
        item = value.get(field)
        if not isinstance(item, str) or not item.strip() or len(item) > maximum or "\x00" in item:
            raise ValueError(f"conversation_runtime_{field}_invalid")
    if value.get("requested_operation") != "conversation_only":
        raise ValueError("conversation_runtime_operation_not_admitted")
    try:
        observed = datetime.fromisoformat(str(value.get("observed_at", "")).replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("conversation_runtime_observed_at_invalid") from error
    if observed.tzinfo is None:
        raise ValueError("conversation_runtime_observed_at_invalid")
    age = (now - observed.astimezone(timezone.utc)).total_seconds()
    if age > MAX_AGE_SECONDS:
        raise ValueError("conversation_runtime_request_stale")
    if age < -MAX_FUTURE_SKEW_SECONDS:
        raise ValueError("conversation_runtime_request_future")
    return value


def handle_payload(payload: bytes, *, now: datetime | None = None, inference=infer) -> bytes:
    current = now or datetime.now(timezone.utc)
    request_id: str | None = None
    conversation_id: str | None = None
    try:
        if not payload or len(payload) > MAX_REQUEST_BYTES:
            raise ValueError("conversation_runtime_request_size_invalid")
        value = _validate(json.loads(payload.decode("utf-8")), now=current)
        request_id = value["request_id"]
        conversation_id = value["conversation_id"]
        answer = inference(" ".join(value["utterance"].split()))
        response: dict[str, Any] = {
            "schema": RESPONSE_SCHEMA,
            "request_id": request_id,
            "conversation_id": conversation_id,
            "status": "ANSWERED",
            "state": "READY",
            "response": answer,
            "scope": "stage1-bounded-companion",
            "completed_at": current.isoformat(),
            "authority_effect": "NONE",
            "effects": [],
        }
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        response = {
            "schema": RESPONSE_SCHEMA, "request_id": request_id,
            "conversation_id": conversation_id, "status": "DENIED",
            "reason": str(error), "completed_at": current.isoformat(),
            "authority_effect": "NONE", "effects": [],
        }
    except CompanionUnavailable:
        response = {
            "schema": RESPONSE_SCHEMA, "request_id": request_id,
            "conversation_id": conversation_id, "status": "UNAVAILABLE",
            "reason": "loopback_inference_unavailable", "completed_at": current.isoformat(),
            "authority_effect": "NONE", "effects": [],
        }
    return (json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n").encode()


def serve_socket(server: socket.socket, *, max_requests: int | None = None) -> None:
    handled = 0
    while max_requests is None or handled < max_requests:
        connection, _ = server.accept()
        with connection:
            payload = connection.recv(MAX_REQUEST_BYTES + 1)
            connection.sendall(handle_payload(payload))
        handled += 1


def serve() -> None:
    with inherited_systemd_socket() as inherited:
        ready_and_watch()
        serve_socket(inherited)
