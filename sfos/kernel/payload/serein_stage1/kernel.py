"""Fail-closed request classification and deterministic companion response."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from typing import Any

from .companion_provider import CompanionUnavailable, chat, infer, list_models

ALLOWED_ACTIONS = frozenset({"health", "identity", "companion", "ollama_list", "ollama_chat"})
VOICE_REQUEST_SCHEMA = "GovernedGatewayVoiceRequest/v1"
VOICE_RESPONSE_SCHEMA = "GovernedGatewayCompanionResponse/v1"
VOICE_PERSONALITY_SCHEMA = "AudioVoiceLayerCompanionEnvelope/v1"
LOWER_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
LOWER_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
MAX_VOICE_REQUEST_ID_CHARS = 128
MAX_VOICE_CONTENT_CHARS = 8192
MAX_STAGE1_COMPANION_TEXT_CHARS = 1024
MAX_STAGE1_COMPANION_AGE_SECONDS = 120
MAX_STAGE1_COMPANION_FUTURE_SKEW_SECONDS = 5
MAX_OLLAMA_MESSAGES = 40
MAX_OLLAMA_TOOLS = 64
MAX_OLLAMA_CONTENT_CHARS = 8192
MAX_OLLAMA_TOOL_NAME_CHARS = 128
MAX_OLLAMA_REQUEST_BYTES = 128 * 1024
MAX_OLLAMA_NESTED_JSON_BYTES = 16 * 1024
MIN_OLLAMA_NUM_CTX = 2048
MAX_OLLAMA_NUM_CTX = 32768
MAX_OLLAMA_KEEP_ALIVE_SECONDS = 300
OLLAMA_REQUEST_KEYS = {
    "model", "messages", "stream", "tools", "keep_alive", "options", "think", "format"
}


def _bounded_json(value: Any, *, maximum: int = MAX_OLLAMA_NESTED_JSON_BYTES) -> bool:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        return False
    return len(encoded) <= maximum


def _valid_tool_call(value: Any) -> bool:
    if not isinstance(value, dict) or not set(value).issubset({"id", "function"}) \
            or "function" not in value:
        return False
    call_id = value.get("id")
    if call_id is not None and (
        not isinstance(call_id, str)
        or not call_id
        or len(call_id) > MAX_OLLAMA_CONTENT_CHARS
        or "\x00" in call_id
    ):
        return False
    function = value.get("function")
    if not isinstance(function, dict) or set(function) != {"name", "arguments"}:
        return False
    name = function.get("name")
    return (
        isinstance(name, str)
        and 0 < len(name) <= MAX_OLLAMA_TOOL_NAME_CHARS
        and "\x00" not in name
        and isinstance(function.get("arguments"), dict)
        and _bounded_json(function["arguments"])
    )


def _valid_message(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    role = value.get("role")
    allowed = {"role", "content"}
    if role == "assistant":
        allowed |= {"thinking", "tool_calls"}
    elif role == "tool":
        allowed |= {"tool_call_id"}
    if not set(value).issubset(allowed) or "role" not in value:
        return False
    if role not in {"system", "user", "assistant", "tool"}:
        return False
    content_present = "content" in value
    content = value.get("content")
    if content_present and (
        not isinstance(content, str)
        or len(content) > MAX_OLLAMA_CONTENT_CHARS
        or "\x00" in content
    ):
        return False
    thinking = value.get("thinking")
    if thinking is not None and (
        not isinstance(thinking, str)
        or len(thinking) > MAX_OLLAMA_CONTENT_CHARS
        or "\x00" in thinking
    ):
        return False
    calls = value.get("tool_calls")
    if calls is not None and (
        not isinstance(calls, list)
        or not calls
        or len(calls) > MAX_OLLAMA_TOOLS
        or any(not _valid_tool_call(call) for call in calls)
    ):
        return False
    tool_call_id = value.get("tool_call_id")
    if role == "tool" and (
        not isinstance(tool_call_id, str)
        or not tool_call_id
        or len(tool_call_id) > MAX_OLLAMA_CONTENT_CHARS
        or "\x00" in tool_call_id
    ):
        return False
    if role in {"system", "user", "tool"}:
        return content_present and bool(content)
    return (content_present and bool(content)) or bool(calls)


def _valid_tool(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {"type", "function"} or value.get("type") != "function":
        return False
    function = value.get("function")
    if not isinstance(function, dict) or set(function) not in (
        {"name", "parameters"}, {"name", "description", "parameters"}
    ):
        return False
    name = function.get("name")
    description = function.get("description")
    return (
        isinstance(name, str)
        and 0 < len(name) <= MAX_OLLAMA_TOOL_NAME_CHARS
        and "\x00" not in name
        and (description is None or (
            isinstance(description, str)
            and len(description) <= MAX_OLLAMA_CONTENT_CHARS
            and "\x00" not in description
        ))
        and isinstance(function.get("parameters"), dict)
        and _bounded_json(function["parameters"])
    )


def _valid_keep_alive(value: Any) -> bool:
    if type(value) is int:
        return value == -1
    if not isinstance(value, str) or not value.endswith("s") or not value[:-1].isdigit():
        return False
    return 0 <= int(value[:-1]) <= MAX_OLLAMA_KEEP_ALIVE_SECONDS


def _classify_ollama_chat(value: Any) -> tuple[bool, str]:
    if not isinstance(value, dict) or not set(value).issubset(OLLAMA_REQUEST_KEYS):
        return False, "ollama_request_fields_invalid"
    if not _bounded_json(value, maximum=MAX_OLLAMA_REQUEST_BYTES):
        return False, "ollama_request_size_invalid"
    if not {"model", "messages", "stream"}.issubset(value):
        return False, "ollama_request_fields_invalid"
    if value.get("model") != "qwen3:4b-instruct":
        return False, "ollama_model_not_admitted"
    if type(value.get("stream")) is not bool:
        return False, "ollama_stream_invalid"
    messages = value.get("messages")
    if (
        not isinstance(messages, list)
        or not messages
        or len(messages) > MAX_OLLAMA_MESSAGES
        or any(not _valid_message(item) for item in messages)
    ):
        return False, "ollama_messages_invalid"
    tools = value.get("tools")
    if tools is not None and (
        not isinstance(tools, list)
        or not tools
        or len(tools) > MAX_OLLAMA_TOOLS
        or any(not _valid_tool(tool) for tool in tools)
    ):
        return False, "ollama_tools_invalid"
    if "keep_alive" in value and not _valid_keep_alive(value["keep_alive"]):
        return False, "ollama_keep_alive_invalid"
    options = value.get("options")
    if options is not None:
        if not isinstance(options, dict) or set(options) != {"num_ctx"}:
            return False, "ollama_options_invalid"
        num_ctx = options.get("num_ctx")
        if type(num_ctx) is not int or not MIN_OLLAMA_NUM_CTX <= num_ctx <= MAX_OLLAMA_NUM_CTX:
            return False, "ollama_num_ctx_invalid"
    if "think" in value and type(value["think"]) is not bool:
        return False, "ollama_think_invalid"
    response_format = value.get("format")
    if response_format is not None and not (
        response_format in {"", "json"}
        if isinstance(response_format, str)
        else isinstance(response_format, dict) and _bounded_json(response_format)
    ):
        return False, "ollama_format_invalid"
    return True, "admitted_haos_ollama_chat"


def _classify_stage1_companion_request(
    request: dict[str, Any], *, now: datetime
) -> tuple[bool, str]:
    if set(request) != {"schema", "request_id", "authority", "action", "conversation"}:
        return False, "companion_envelope_invalid"
    conversation = request.get("conversation")
    if not isinstance(conversation, dict) or set(conversation) != {
        "conversation_id", "machine_identity", "requested_operation", "utterance",
        "observed_at"
    }:
        return False, "companion_input_invalid"
    conversation_id = conversation.get("conversation_id")
    utterance = conversation.get("utterance")
    if not isinstance(conversation_id, str) or not conversation_id.strip() or "\x00" in conversation_id:
        return False, "companion_conversation_id_invalid"
    if (
        not isinstance(conversation.get("machine_identity"), str)
        or not conversation["machine_identity"].strip()
        or "\x00" in conversation["machine_identity"]
    ):
        return False, "companion_machine_identity_invalid"
    if conversation.get("requested_operation") != "conversation_only":
        return False, "companion_operation_not_admitted"
    if (
        not isinstance(utterance, str)
        or not utterance.strip()
        or len(utterance) > MAX_STAGE1_COMPANION_TEXT_CHARS
        or "\x00" in utterance
    ):
        return False, "companion_utterance_invalid"
    try:
        observed_at = datetime.fromisoformat(str(conversation.get("observed_at", "")).replace("Z", "+00:00"))
    except ValueError:
        return False, "companion_observed_at_invalid"
    if observed_at.tzinfo is None:
        return False, "companion_observed_at_invalid"
    age_seconds = (now - observed_at.astimezone(timezone.utc)).total_seconds()
    if age_seconds > MAX_STAGE1_COMPANION_AGE_SECONDS:
        return False, "companion_observation_stale"
    if age_seconds < -MAX_STAGE1_COMPANION_FUTURE_SKEW_SECONDS:
        return False, "companion_observation_future"
    return True, "admitted_bounded_companion"


def _classify_voice_request(request: dict[str, Any]) -> tuple[bool, str]:
    if set(request) != {
        "schema", "request_id", "personality_envelope", "authority", "effects"
    }:
        return False, "voice_envelope_invalid"
    request_id = request.get("request_id")
    if (
        not isinstance(request_id, str)
        or not request_id
        or len(request_id) > MAX_VOICE_REQUEST_ID_CHARS
        or "\x00" in request_id
    ):
        return False, "voice_request_id_invalid"
    if request.get("authority") != {"state": "ABSENT", "receipt": None}:
        return False, "voice_authority_not_admitted"
    if request.get("effects") != {
        "playback": False, "device": False, "external_action": False
    }:
        return False, "voice_effect_not_admitted"

    personality = request.get("personality_envelope")
    if not isinstance(personality, dict) or set(personality) != {
        "schema", "profile", "source_generation", "model", "content", "authority", "effects"
    }:
        return False, "voice_personality_envelope_invalid"
    if personality.get("schema") != VOICE_PERSONALITY_SCHEMA:
        return False, "voice_personality_schema_invalid"
    if personality.get("profile") != "AUDIO_VOICE_LAYER":
        return False, "voice_personality_profile_invalid"
    content = personality.get("content")
    if (
        not isinstance(content, str)
        or not content
        or len(content) > MAX_VOICE_CONTENT_CHARS
        or "\x00" in content
    ):
        return False, "voice_content_invalid"
    if personality.get("authority") != {"state": "ABSENT", "receipt": None}:
        return False, "voice_personality_authority_not_admitted"
    if personality.get("effects") != {"playback": False, "external_action": False}:
        return False, "voice_personality_effect_not_admitted"

    generation = personality.get("source_generation")
    if not isinstance(generation, dict) or set(generation) != {
        "repository", "commit", "tree", "currentness", "admission", "receipt"
    }:
        return False, "voice_generation_invalid"
    if (
        not isinstance(generation.get("repository"), str)
        or not generation["repository"]
        or not LOWER_HEX_40.fullmatch(str(generation.get("commit", "")))
        or not LOWER_HEX_40.fullmatch(str(generation.get("tree", "")))
        or generation.get("currentness") != "CURRENT"
        or generation.get("admission") != "ADMITTED"
        or not isinstance(generation.get("receipt"), str)
        or not generation["receipt"]
    ):
        return False, "voice_generation_invalid"

    model = personality.get("model")
    if not isinstance(model, dict) or set(model) != {"tag", "manifest_sha256"}:
        return False, "voice_model_invalid"
    if (
        not isinstance(model.get("tag"), str)
        or not model["tag"]
        or not LOWER_HEX_64.fullmatch(str(model.get("manifest_sha256", "")))
    ):
        return False, "voice_model_invalid"
    return True, "admitted_zero_effect_voice"


def classify_request(request: Any, *, now: datetime | None = None) -> tuple[bool, str]:
    if not isinstance(request, dict):
        return False, "request_not_object"
    if request.get("schema") == VOICE_REQUEST_SCHEMA:
        return _classify_voice_request(request)
    if request.get("schema") != "SereinStage1Request/v1":
        return False, "schema_not_admitted"
    if request.get("authority") != "local-operator":
        return False, "authority_not_admitted"
    if request.get("action") not in ALLOWED_ACTIONS:
        return False, "action_not_admitted"
    if not isinstance(request.get("request_id"), str) or not request["request_id"]:
        return False, "request_id_required"
    if request["action"] == "companion":
        return _classify_stage1_companion_request(
            request, now=now or datetime.now(timezone.utc)
        )
    if request["action"] == "ollama_list":
        return (set(request) == {"schema", "request_id", "authority", "action"}, "admitted_ollama_list")
    if request["action"] == "ollama_chat":
        if set(request) != {"schema", "request_id", "authority", "action", "ollama"}:
            return False, "ollama_envelope_invalid"
        return _classify_ollama_chat(request.get("ollama"))
    return True, "admitted"


def respond(request: Any, *, now: datetime | None = None, companion_infer=infer) -> dict[str, Any]:
    current = now or datetime.now(timezone.utc)
    admitted, reason = classify_request(request, now=current)
    timestamp = current.isoformat()
    request_id = request.get("request_id") if isinstance(request, dict) else None
    if not admitted:
        schema = (
            VOICE_RESPONSE_SCHEMA
            if isinstance(request, dict) and request.get("schema") == VOICE_REQUEST_SCHEMA
            else "SereinStage1Response/v1"
        )
        return {
            "schema": schema,
            "request_id": request_id,
            "status": "DENIED",
            "reason": reason,
            "timestamp": timestamp,
        }
    if request["schema"] == VOICE_REQUEST_SCHEMA:
        return {
            "schema": VOICE_RESPONSE_SCHEMA,
            "request_id": request_id,
            "state": "READY",
            "text": "Serein Gateway accepted the governed Voice request.",
            "device_effects": 0,
            "external_actions": 0,
            "authority_granted": False,
        }
    if request["action"] == "ollama_list":
        try:
            result = {"state": "READY", "ollama": list_models(), "authority_effect": "NONE", "effects": []}
        except CompanionUnavailable:
            return {"schema": "SereinStage1Response/v1", "request_id": request_id, "status": "UNAVAILABLE", "reason": "companion_provider_unavailable", "timestamp": timestamp}
    elif request["action"] == "ollama_chat":
        try:
            result = {"state": "READY", "ollama": chat(request["ollama"]), "authority_effect": "NONE", "effects": []}
        except CompanionUnavailable:
            return {"schema": "SereinStage1Response/v1", "request_id": request_id, "status": "UNAVAILABLE", "reason": "companion_provider_unavailable", "timestamp": timestamp}
    elif request["action"] == "health":
        result = {"state": "READY", "scope": "minimum-gateway-answering-seed"}
    elif request["action"] == "identity":
        result = {"product": "SFOS", "base_family": "debian", "profile": None}
    else:
        conversation = request["conversation"]
        normalized = " ".join(conversation["utterance"].split())
        try:
            answer = companion_infer(normalized)
        except CompanionUnavailable:
            return {
                "schema": "SereinStage1Response/v1", "request_id": request_id,
                "status": "UNAVAILABLE", "reason": "companion_provider_unavailable",
                "timestamp": timestamp,
            }
        result = {
            "state": "READY",
            "response": answer,
            "scope": "stage1-bounded-companion",
            "conversation_id": conversation["conversation_id"],
            "authority_effect": "NONE",
            "effects": [],
        }
    return {
        "schema": "SereinStage1Response/v1",
        "request_id": request_id,
        "status": "ANSWERED",
        "reason": reason,
        "timestamp": timestamp,
        "result": result,
    }
