"""Bounded loopback inference provider for the Stage-1 companion."""

from __future__ import annotations

import json
import urllib.request
from typing import Callable

ENDPOINT = "http://127.0.0.1:11434/api/generate"
CHAT_ENDPOINT = "http://127.0.0.1:11434/api/chat"
TAGS_ENDPOINT = "http://127.0.0.1:11434/api/tags"
MODEL = "qwen3:4b-instruct"
MAX_RESPONSE_BYTES = 32 * 1024
MAX_ANSWER_CHARS = 4096
MAX_TOOL_CALLS = 64
MAX_TOOL_NAME_CHARS = 128
MAX_TOOL_ARGUMENT_BYTES = 16 * 1024
BOUNDED_KEEP_ALIVE = "300s"
SYSTEM = (
    "You are Serein, the bounded SFOS companion. Answer only from the supplied "
    "request and entity context. State uncertainty explicitly. Never claim or "
    "perform actions, authority, device effects, or external effects."
)


class CompanionUnavailable(RuntimeError):
    pass


def _request_json(endpoint: str, body: bytes | None, *, opener: Callable) -> dict:
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST" if body is not None else "GET",
        headers={"Content-Type": "application/json"},
    )
    try:
        with opener(request, timeout=90) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except Exception as error:
        raise CompanionUnavailable("companion_provider_unavailable") from error
    if not raw or len(raw) > MAX_RESPONSE_BYTES:
        raise CompanionUnavailable("companion_response_too_large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CompanionUnavailable("companion_response_invalid") from error
    if not isinstance(value, dict):
        raise CompanionUnavailable("companion_response_invalid")
    return value


def list_models(*, opener: Callable = urllib.request.urlopen) -> dict:
    """Return the loopback model list through the live Kernel."""
    value = _request_json(TAGS_ENDPOINT, None, opener=opener)
    models = value.get("models")
    if not isinstance(models, list):
        raise CompanionUnavailable("companion_response_invalid")
    admitted = [model for model in models if isinstance(model, dict) and model.get("model") == MODEL]
    if len(admitted) != 1:
        raise CompanionUnavailable("companion_model_unavailable")
    return {"models": admitted}


def _valid_tool_calls(value: object) -> bool:
    if value is None:
        return True
    if not isinstance(value, list) or len(value) > MAX_TOOL_CALLS:
        return False
    for call in value:
        if not isinstance(call, dict) or not set(call).issubset({"id", "function"}) \
                or "function" not in call:
            return False
        call_id = call.get("id")
        if call_id is not None and (
            not isinstance(call_id, str)
            or not call_id
            or len(call_id) > MAX_TOOL_NAME_CHARS
            or "\x00" in call_id
        ):
            return False
        function = call.get("function")
        if not isinstance(function, dict) or not set(function).issubset(
            {"index", "name", "arguments"}
        ) or not {"name", "arguments"}.issubset(function):
            return False
        index = function.get("index")
        if index is not None and (type(index) is not int or index < 0):
            return False
        name = function.get("name")
        arguments = function.get("arguments")
        if (
            not isinstance(name, str)
            or not name
            or len(name) > MAX_TOOL_NAME_CHARS
            or "\x00" in name
            or not isinstance(arguments, dict)
        ):
            return False
        try:
            encoded = json.dumps(arguments, sort_keys=True, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError, UnicodeEncodeError):
            return False
        if len(encoded) > MAX_TOOL_ARGUMENT_BYTES:
            return False
    return True


def chat(request: dict, *, opener: Callable = urllib.request.urlopen) -> dict:
    """Run one bounded Ollama chat request, including HAOS Assist tool calls."""
    upstream = {**request, "model": MODEL, "stream": False}
    if upstream.get("keep_alive") == -1:
        upstream["keep_alive"] = BOUNDED_KEEP_ALIVE
    body = json.dumps(upstream, sort_keys=True, separators=(",", ":")).encode()
    value = _request_json(CHAT_ENDPOINT, body, opener=opener)
    if value.get("model") != MODEL or value.get("done") is not True or not isinstance(value.get("message"), dict):
        raise CompanionUnavailable("companion_response_invalid")
    message = value["message"]
    if message.get("role") != "assistant":
        raise CompanionUnavailable("companion_response_invalid")
    content = message.get("content")
    tool_calls = message.get("tool_calls")
    if not isinstance(content, str) or len(content) > MAX_ANSWER_CHARS or "\x00" in content:
        raise CompanionUnavailable("companion_answer_invalid")
    if not _valid_tool_calls(tool_calls):
        raise CompanionUnavailable("companion_response_invalid")
    if isinstance(tool_calls, list):
        message["tool_calls"] = [
            {
                **({"id": call["id"]} if "id" in call else {}),
                "function": {
                    "name": call["function"]["name"],
                    "arguments": call["function"]["arguments"],
                },
            }
            for call in tool_calls
        ]
    return value


def infer(utterance: str, *, opener: Callable = urllib.request.urlopen) -> str:
    body = json.dumps({
        "model": MODEL,
        "prompt": f"{SYSTEM}\n\nUser request and governed context:\n{utterance}",
        "stream": False,
        "options": {"temperature": 0},
    }, sort_keys=True, separators=(",", ":")).encode()
    request = urllib.request.Request(
        ENDPOINT, data=body, method="POST", headers={"Content-Type": "application/json"}
    )
    try:
        with opener(request, timeout=20) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except Exception as error:
        raise CompanionUnavailable("companion_provider_unavailable") from error
    if len(raw) > MAX_RESPONSE_BYTES:
        raise CompanionUnavailable("companion_response_too_large")
    try:
        result = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CompanionUnavailable("companion_response_invalid") from error
    if not isinstance(result, dict) or result.get("model") != MODEL or result.get("done") is not True:
        raise CompanionUnavailable("companion_response_invalid")
    answer = result.get("response")
    if not isinstance(answer, str) or not answer.strip() or len(answer) > MAX_ANSWER_CHARS or "\x00" in answer:
        raise CompanionUnavailable("companion_answer_invalid")
    return " ".join(answer.split())
