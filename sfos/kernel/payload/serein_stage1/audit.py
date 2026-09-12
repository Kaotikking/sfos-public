"""Append-only JSON-lines audit writer for Stage-1 decisions."""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from typing import Any

from .supervision import inherited_systemd_socket, ready_and_watch

MAX_EVENT_BYTES = 16 * 1024
BASE_EVENT_FIELDS = frozenset({"schema", "request_id", "status", "reason", "timestamp"})


def append_event(path: Path, event: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def decode_event(payload: bytes) -> dict[str, Any]:
    if len(payload) > MAX_EVENT_BYTES:
        raise ValueError("event_too_large")
    try:
        event = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid_event_json") from error
    if not isinstance(event, dict) or not BASE_EVENT_FIELDS.issubset(event):
        raise ValueError("invalid_event_shape")
    expected = BASE_EVENT_FIELDS | ({"result"} if event.get("status") == "ANSWERED" else set())
    if set(event) != expected:
        raise ValueError("invalid_event_shape")
    if event["schema"] != "SereinStage1Response/v1" or event["status"] not in {"ANSWERED", "DENIED", "UNAVAILABLE"}:
        raise ValueError("event_not_admitted")
    if not isinstance(event["request_id"], str) or not event["request_id"] or not isinstance(event["reason"], str) or not event["reason"] or not isinstance(event["timestamp"], str) or not event["timestamp"]:
        raise ValueError("invalid_event_correlation")
    return event


def serve_socket(server: socket.socket, audit_path: Path, *, max_events: int | None = None) -> None:
    handled = 0
    while max_events is None or handled < max_events:
        connection, _ = server.accept()
        with connection:
            try:
                append_event(audit_path, decode_event(connection.recv(MAX_EVENT_BYTES + 1)))
            except ValueError as error:
                connection.sendall((json.dumps({"status": "DENIED", "reason": str(error)}) + "\n").encode())
            else:
                connection.sendall(b'{"status":"RECORDED"}\n')
        handled += 1


def serve(audit_path: Path) -> None:
    with inherited_systemd_socket() as inherited:
        ready_and_watch()
        serve_socket(inherited, audit_path)
