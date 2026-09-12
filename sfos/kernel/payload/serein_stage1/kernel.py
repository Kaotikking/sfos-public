"""Fail-closed request classification and deterministic companion response."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

ALLOWED_ACTIONS = frozenset({"health", "identity", "companion"})
MAX_COMPANION_TEXT_CHARS = 1024
MAX_COMPANION_AGE_SECONDS = 120
MAX_COMPANION_FUTURE_SKEW_SECONDS = 5


def _classify_companion(request: dict[str, Any], *, now: datetime) -> tuple[bool, str]:
    if set(request) != {"schema", "request_id", "authority", "action", "conversation"}:
        return False, "companion_envelope_invalid"
    conversation = request.get("conversation")
    if not isinstance(conversation, dict) or set(conversation) != {
        "conversation_id", "machine_identity", "requested_operation", "utterance", "observed_at"
    }:
        return False, "companion_input_invalid"
    for field in ("conversation_id", "machine_identity"):
        value = conversation.get(field)
        if not isinstance(value, str) or not value.strip() or "\x00" in value:
            return False, f"companion_{field}_invalid"
    if conversation.get("requested_operation") != "conversation_only":
        return False, "companion_operation_not_admitted"
    utterance = conversation.get("utterance")
    if (not isinstance(utterance, str) or not utterance.strip()
            or len(utterance) > MAX_COMPANION_TEXT_CHARS or "\x00" in utterance):
        return False, "companion_utterance_invalid"
    try:
        observed_at = datetime.fromisoformat(str(conversation.get("observed_at", "")).replace("Z", "+00:00"))
    except ValueError:
        return False, "companion_observed_at_invalid"
    if observed_at.tzinfo is None:
        return False, "companion_observed_at_invalid"
    age = (now - observed_at.astimezone(timezone.utc)).total_seconds()
    if age > MAX_COMPANION_AGE_SECONDS:
        return False, "companion_observation_stale"
    if age < -MAX_COMPANION_FUTURE_SKEW_SECONDS:
        return False, "companion_observation_future"
    return True, "admitted_bounded_companion"


def classify_request(request: Any, *, now: datetime | None = None) -> tuple[bool, str]:
    if not isinstance(request, dict):
        return False, "request_not_object"
    if request.get("schema") != "SereinStage1Request/v1":
        return False, "schema_not_admitted"
    if request.get("authority") != "local-operator":
        return False, "authority_not_admitted"
    if request.get("action") not in ALLOWED_ACTIONS:
        return False, "action_not_admitted"
    if not isinstance(request.get("request_id"), str) or not request["request_id"]:
        return False, "request_id_required"
    if request["action"] == "companion":
        return _classify_companion(request, now=now or datetime.now(timezone.utc))
    return True, "admitted"


def respond(request: Any, *, now: datetime | None = None) -> dict[str, Any]:
    admitted, reason = classify_request(request)
    timestamp = (now or datetime.now(timezone.utc)).isoformat()
    request_id = request.get("request_id") if isinstance(request, dict) else None
    if not admitted:
        return {
            "schema": "SereinStage1Response/v1",
            "request_id": request_id,
            "status": "DENIED",
            "reason": reason,
            "timestamp": timestamp,
        }
    result = (
        {"state": "READY", "scope": "minimum-gateway-answering-seed"}
        if request["action"] == "health"
        else {"product": "SFOS", "base_family": "debian", "profile": None}
    )
    return {
        "schema": "SereinStage1Response/v1",
        "request_id": request_id,
        "status": "ANSWERED",
        "reason": reason,
        "timestamp": timestamp,
        "result": result,
    }
