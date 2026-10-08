"""Fail-closed request classification and deterministic companion response."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import grp
import json
import math
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import struct
import time
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
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
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
    if not isinstance(role, str) or role not in {"system", "user", "assistant", "tool"}:
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
    if not isinstance(conversation, dict):
        return False, "companion_input_invalid"
    tool_mode = conversation.get("requested_operation") == "conversation_tools"
    expected = {"conversation_id", "machine_identity", "requested_operation", "observed_at"}
    expected |= {"messages", "tools"} if tool_mode else {"utterance"}
    if set(conversation) != expected:
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
    if conversation.get("requested_operation") not in ("conversation_only", "conversation_tools"):
        return False, "companion_operation_not_admitted"
    if tool_mode:
        if not isinstance(conversation['tools'], list):
            return False, "ollama_tools_invalid"
        chat_input = {"model":"qwen3:4b-instruct", "stream":False,
                      "messages":conversation["messages"]}
        if conversation['tools']:
            chat_input['tools'] = conversation['tools']
        admitted, reason = _classify_ollama_chat(chat_input)
        if not admitted:
            return False, reason
        # ADAPT the accepted HAOS adapter's complete tool-result correlation.
        pending, seen = set(), set()
        for message in conversation['messages']:
            if message['role']=='assistant' and message.get('tool_calls'):
                for call in message['tool_calls']:
                    call_id=call.get('id')
                    if not isinstance(call_id,str) or not call_id or call_id in seen:
                        return False, 'conversation_tool_call_id_invalid'
                    seen.add(call_id);pending.add(call_id)
            elif message['role']=='tool':
                call_id=message['tool_call_id']
                if call_id not in pending:
                    return False, 'conversation_tool_result_correlation_invalid'
                pending.remove(call_id)
        if pending:
            return False, 'conversation_tool_result_missing'
    elif (
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
    effects = request.get("effects")
    if (not isinstance(effects, dict)
            or set(effects) != {"playback", "device", "external_action"}
            or any(value is not False for value in effects.values())):
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
    personality_effects = personality.get("effects")
    if (not isinstance(personality_effects, dict)
            or set(personality_effects) != {"playback", "external_action"}
            or any(value is not False for value in personality_effects.values())):
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
    if not isinstance(request.get("action"), str) or request["action"] not in ALLOWED_ACTIONS:
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


def exchange_private_service(channel, payload, *, timeout_seconds, root=Path('/')):
    """Use only the existing fixed private Kernel service roads, once.

    Source: installed conversation/audit socket units; AF_UNIX SO_PEERCRED
    credentials are captured at listen(), so systemd's listener identity is
    root even though the receiving service runs as serein-stage1. Filesystem
    socket custody is checked separately. No discovery, start, retry or repair.
    The owning dispatch must supply a timeout within its remaining lease.
    """
    from .conversation_runtime import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES
    from .audit import MAX_EVENT_BYTES
    roads = {
        'CONVERSATION':('/run/serein/kernel/conversation.sock',0o660,MAX_REQUEST_BYTES,MAX_RESPONSE_BYTES,'serein-stage1'),
        'AUDIT':('/run/serein/stage1/audit.sock',0o600,MAX_EVENT_BYTES,4096,'serein-stage1'),
        # ADAPT sfos-public 0dca6bd7 / socket blob4cd03bc5: systemd-created,
        # root-owned 0660/serein-stage1 socket, not the old shared Gateway.
        # Consuming this road never creates/starts/adopts its absent listener.
        'HAOS_GATEWAY':('/run/serein/kernel/gateway-haos.sock',0o660,256*1024,64*1024,'root'),
    }
    if (not isinstance(channel,str) or channel not in roads
            or type(timeout_seconds) not in (int,float) or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 30):
        raise ValueError('private_service_configuration_denied')
    absolute, mode, maximum_request, maximum_response, owner = roads[channel]
    if not isinstance(payload,bytes) or not payload:
        raise ValueError('private_service_request_denied')
    frame=payload if payload.endswith(b'\n') else payload+b'\n'
    if len(frame)>maximum_request or frame.count(b'\n')!=1:
        raise ValueError('private_service_request_denied')
    root=Path(root)
    if not root.is_absolute() or '..' in root.parts:
        raise ValueError('private_service_root_denied')
    account=pwd.getpwnam('serein-stage1')
    group=grp.getgrnam('serein-stage1')
    handles=[]; parents=[]
    deadline=time.monotonic()+timeout_seconds
    def remaining():
        value=deadline-time.monotonic()
        if value<=0: raise TimeoutError('private_service_deadline')
        return value
    def identity(info):
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink)
    try:
        fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);handles.append(fd)
        parents.append(identity(os.fstat(fd)))
        parts=Path(absolute).parts[1:]
        for part in parts[:-1]:
            info=os.fstat(fd)
            if info.st_uid!=0 or stat.S_IMODE(info.st_mode)&0o022:
                raise ValueError('private_service_parent_custody_denied')
            fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            handles.append(fd)
            parents.append(identity(os.fstat(fd)))
        parent=os.fstat(fd)
        # The admitted Base owns this private Audit directory as stage1/0750.
        # Only this exact final directory has service custody; every ancestor
        # and the other roads remain root-owned and non-writable by peers.
        audit_parent=(parent.st_uid,parent.st_gid,stat.S_IMODE(parent.st_mode))
        if ((audit_parent!=(account.pw_uid,group.gr_gid,0o750)) if channel=='AUDIT'
                else (parent.st_uid!=0 or stat.S_IMODE(parent.st_mode)&0o022)):
            raise ValueError('private_service_parent_custody_denied')
        before=os.stat(parts[-1],dir_fd=fd,follow_symlinks=False)
        if (not stat.S_ISSOCK(before.st_mode) or before.st_nlink!=1
                or (before.st_uid,before.st_gid)!=((0 if owner=='root' else account.pw_uid),group.gr_gid)
                or stat.S_IMODE(before.st_mode)!=mode):
            raise ValueError('private_service_socket_custody_denied')
        def stable():
            current=root
            for part,opened,original in zip(('',*parts[:-1]),handles,parents):
                if part: current=current/part
                if identity(current.lstat())!=original or identity(os.fstat(opened))!=original:
                    raise ValueError('private_service_parent_changed')
            if identity(os.stat(parts[-1],dir_fd=fd,follow_symlinks=False))!=identity(before):
                raise ValueError('private_service_socket_changed')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            connection.settimeout(remaining())
            connection.connect(f'/proc/self/fd/{fd}/{parts[-1]}')
            _,uid,gid=struct.unpack('3i',connection.getsockopt(
                socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
            if (uid,gid)!=(0,0): raise ValueError('private_service_listener_identity_denied')
            stable()
            connection.settimeout(remaining());connection.sendall(frame)
            response=bytearray()
            while b'\n' not in response:
                connection.settimeout(remaining())
                block=connection.recv(min(16384,maximum_response+1-len(response)))
                if not block: raise ValueError('private_service_response_incomplete')
                response.extend(block)
                if len(response)>maximum_response: raise ValueError('private_service_response_size_denied')
            if not response.endswith(b'\n') or response.count(b'\n')!=1:
                raise ValueError('private_service_response_frame_denied')
            stable()
            return bytes(response)
    finally:
        for fd in reversed(handles): os.close(fd)


def record_terminal_event(response, *, root=Path('/')):
    """Existing audit API; an acknowledgement is not a domain witness."""
    from .authority_contract import canonical
    from .audit import decode_event, EXCHANGE_TIMEOUT_SECONDS
    from .conversation_runtime import _decode
    payload=canonical(response)
    decode_event(payload)
    raw=exchange_private_service('AUDIT',payload,timeout_seconds=EXCHANGE_TIMEOUT_SECONDS,root=root)
    if _decode(raw,4096)!={'status':'RECORDED'}:
        raise ValueError('gateway_audit_denied')


def handle_governed_companion(payload: bytes, *, client: str, route_request: dict,
                              context_reader, replay_store, runtime_call=None,
                              audit_call=record_terminal_event, clock) -> bytes:
    """Existing Stage-1 envelope through authenticated routing, not label authority.

    ADAPT gateway_runtime donor 4af8ea8b: preserve client isolation, private
    runtime envelope, terminal audit and response shape. Reuse current Authority
    and atomic Operations rather than its unbound replay socket. No listener,
    route registration, service startup, key access or default transport here.
    The caller must bind client and callbacks to their authenticated endpoints.
    """
    from .authority_contract import canonical
    from .conversation_runtime import _decode, call_expected
    from .kernel_operations import dispatch_once
    request_id = None
    current = clock()
    if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
        raise ValueError('gateway_clock_invalid')
    def denied(reason, status='DENIED'):
        return {'schema':'SereinStage1Response/v1', 'request_id':request_id,
                'status':status, 'reason':reason, 'timestamp':current.isoformat()}
    try:
        request = _decode(payload, 256 * 1024)
        request_id = request.get('request_id') if isinstance(request,dict) else None
        admitted, reason = classify_request(request, now=current)
        route_request = json.loads(canonical(route_request))
        if not admitted or request.get('action') != 'companion':
            response = denied(reason if not admitted else 'gateway_operation_not_admitted')
        elif (client not in ('HAOS','ANDROID','ESP32','INTERNAL')
                or route_request.get('caller') != client or route_request.get('plane') != 'COGNITIVE'
                or route_request.get('request_id') != request_id
                or route_request.get('conversation_id') != request['conversation']['conversation_id']):
            response = denied('gateway_client_correlation_denied')
        else:
            conversation = request['conversation']
            machine = conversation['machine_identity'].upper()
            if not (machine == client or machine.startswith(client + '_')):
                raise ValueError('gateway_client_identity_denied')
            # The entire validated conversation is the signed payload, including
            # tool declarations/history. Never flatten it into a text prompt.
            runtime_request = {'schema':'SereinStage1ConversationRuntimeRequest/v1',
                'request_id':request_id, **conversation}
            runtime_payload = canonical(runtime_request)
            if (route_request['authority_contract']['body']['scope'].get('payload_sha256')
                    != hashlib.sha256(runtime_payload).hexdigest()):
                raise ValueError('gateway_payload_binding_denied')
            if runtime_call is None:
                # Use the existing private runtime only inside the exact
                # signed contract's remaining lease; no URL or retry road.
                expires=datetime.fromisoformat(
                    route_request['authority_contract']['body']['expires_at'].replace('Z','+00:00'))
                runtime_call=lambda value:exchange_private_service('CONVERSATION',value,
                    timeout_seconds=(expires-clock()).total_seconds())
            routed = dispatch_once(route_request, runtime_payload, context_reader=context_reader,
                replay_store=replay_store, clock=clock,
                forward=lambda route, value:call_expected(value, runtime_call=runtime_call, clock=clock))
            if routed['result'] is None:
                response = denied('gateway_route_capacity_unavailable', 'UNAVAILABLE')
            else:
                result = json.loads(routed['result'])
                response = {'schema':'SereinStage1Response/v1','request_id':request_id,
                    'status':result['status'],'reason':reason if result['status']=='ANSWERED' else result['reason'],
                    'timestamp':result['completed_at']}
                if result['status'] == 'ANSWERED':
                    fields = (('message','continue_conversation','conversation_id','authority_effect','effects')
                        if conversation['requested_operation']=='conversation_tools' else
                        ('state','response','scope','conversation_id','authority_effect','effects'))
                    response['result'] = {field:result[field] for field in fields}
    except (UnicodeError, ValueError, TypeError, KeyError):
        response = denied('gateway_request_or_contract_denied')
    except Exception:
        response = denied('gateway_transaction_failed', 'UNAVAILABLE')
    encoded = canonical(response)
    try:
        audit_call(json.loads(encoded))
    except Exception:
        encoded = canonical(denied('gateway_audit_unavailable', 'UNAVAILABLE'))
    return encoded


def handle_installed_companion(payload: bytes, *, client, root, replay_store,
                               boundary, clock, audit_call=record_terminal_event) -> bytes:
    """Installed bounded HAOS policy -> one private result -> terminal Audit.

    The installed ingress owns authenticated client identity, replay lifetime
    and its real current-gate boundary. This is not an alternate generic grant
    producer and cannot execute tools or admit other clients/consequential actions.
    No service starts or Gateway readiness claims are made by this handler.
    """
    from .authority_contract import canonical
    from .conversation_runtime import _decode
    from .kernel_operations import dispatch_installed_conversation,OperationsDenied
    import base64
    current=clock();request_id=None;compute_evidence=None
    if not isinstance(current,datetime) or current.utcoffset() is None:
        raise ValueError('gateway_clock_invalid')
    def denied(reason,status='DENIED'):
        return {'schema':'SereinStage1Response/v1','request_id':request_id,
                'status':status,'reason':reason,'timestamp':current.isoformat()}
    try:
        request=_decode(payload,128*1024)
        request_id=request.get('request_id') if isinstance(request,dict) else None
        admitted,reason=classify_request(request,now=current)
        if not admitted or request.get('action')!='companion':
            response=denied('gateway_request_denied')
        else:
            dispatched=dispatch_installed_conversation(payload,authenticated_caller=client,
                root=root,replay_store=replay_store,boundary=boundary,clock=clock)
            result=_decode(dispatched['result'],256*1024)
            response={'schema':'SereinStage1Response/v1','request_id':request_id,
                'status':result['status'],'reason':reason if result['status']=='ANSWERED' else result['reason'],
                'timestamp':result['completed_at']}
            if result['status']=='ANSWERED':
                fields=(('message','continue_conversation','conversation_id','authority_effect','effects')
                    if request['conversation']['requested_operation']=='conversation_tools' else
                    ('state','response','scope','conversation_id','authority_effect','effects'))
                response['result']={key:result[key] for key in fields}
                # Preserve exact private runtime bytes before reducing the client
                # response. Audit already owns the private terminal-event road.
                # No replay key, request capability or public evidence field is
                # added; the independent reader must authenticate the retained
                # digest against the durable consumption, not trust this copy.
                compute_evidence={
                    'runtime_response_b64':base64.b64encode(dispatched['result']).decode('ascii'),
                    'runtime_response_sha256':dispatched['result_sha256'],
                    'replay_consumption_sha256':replay_store.contract.receipt_hash(dispatched['replay'][-1])}
    except OperationsDenied as exc:
        # Unknown-after-reservation evidence stays durable. Never retry the
        # private inference because its response or final witness failed.
        response=denied('gateway_transaction_unavailable','UNAVAILABLE') if hasattr(exc,'evidence') else denied('gateway_current_policy_denied')
    except (ValueError,TypeError,KeyError,UnicodeError):
        response=denied('gateway_request_or_policy_denied')
    except Exception:
        response=denied('gateway_transaction_unavailable','UNAVAILABLE')
    encoded=canonical(response)
    event=json.loads(encoded)
    if event['status']=='ANSWERED' and compute_evidence is not None:
        event['compute_evidence']=compute_evidence
    try:audit_call(event)
    except Exception:encoded=canonical(denied('gateway_audit_unavailable','UNAVAILABLE'))
    return encoded


def resolve_governed_companion_route(client, payload, *, context_reader, ump,
                                     issued_at, expires_at, signer, clock):
    """Compose an existing dispatch request only from exact governed policy.

    Internal Authority composition, not an ingress signing API: the owning
    Authority supplies signer, lease times, current context and UMP. Nothing
    in an external request grants a policy or changes those expectations.
    The result is still unconsumed and must pass point-of-use dispatch checks.
    """
    from uuid import NAMESPACE_URL, uuid5
    from .authority_contract import (canonical, issue, evaluate_dispatch,
        checked_registered_route, checked_dispatch_request, prepare_body,
        validate_dispatch_authorization)
    from .conversation_runtime import _decode, _validate

    current = clock()
    request = _decode(payload, 256 * 1024)
    admitted, _ = classify_request(request, now=current)
    if (not admitted or request.get('action') != 'companion'
            or client not in ('HAOS','ANDROID','ESP32','INTERNAL')):
        raise ValueError('gateway_resolver_request_denied')
    conversation = request['conversation']
    machine = conversation['machine_identity'].upper()
    if not (machine == client or machine.startswith(client + '_')):
        raise ValueError('gateway_resolver_client_denied')
    runtime = {'schema':'SereinStage1ConversationRuntimeRequest/v1',
               'request_id':request['request_id'], **conversation}
    _validate(runtime, now=current)
    runtime_payload = canonical(runtime)
    context = context_reader()
    # Snapshot every mutable input before asking the native signer to act.
    context = json.loads(canonical(context))
    ump = json.loads(canonical(ump))
    expected = context['expected']
    route = checked_registered_route(context['registered_route'],
        context['registered_route_sha256'], context['active_count'])
    correlation = {'route':route['route'], 'plane':'COGNITIVE', 'caller':client,
        'request_id':request['request_id'],
        'conversation_id':conversation['conversation_id'],
        'payload_sha256':hashlib.sha256(runtime_payload).hexdigest(),
        'ump_sha256':hashlib.sha256(canonical(ump)).hexdigest()}
    if (context['authenticated_caller'] != client or route['plane'] != 'COGNITIVE'
            or route.get('state') != 'ACTIVE' or route.get('posture') != 'ELIGIBLE'
            or hashlib.sha256(canonical(route)).hexdigest() != context['registered_route_sha256']
            or set(ump) != {'schema','state','claims','authority_effect'}
            or ump['schema'] != 'SEREIN/UMP/v1' or ump['state'] != 'KNOWN'
            or not isinstance(ump['claims'], list) or ump['authority_effect'] != 'NONE'
            or expected['action'] != 'kernel.route.dispatch.v1'
            or expected['intent'] != 'DISPATCH_KERNEL_COMPUTE'
            or expected['expected_result'] != 'ROUTE_DISPATCHED'
            or expected['object'] != route['route']
            or expected['boot_id'] != route['boot_id']
            or canonical(expected['source_generation']) != canonical(route['source_generation'])
            or context['ump_sha256'] != correlation['ump_sha256']
            or any(expected['scope'].get(name) != value for name,value in correlation.items())):
        raise ValueError('gateway_resolver_current_policy_denied')
    nonce = str(uuid5(NAMESPACE_URL, request['request_id']+':action'))
    unsigned = prepare_body(expected, action_nonce=nonce, issued_at=issued_at,
                            expires_at=expires_at, now=current)
    result = {'schema':'kernel.route.dispatch.v1/request', 'request_id':request['request_id'],
        'conversation_id':conversation['conversation_id'], 'route':route['route'],
        'plane':'COGNITIVE', 'caller':client, 'ump':ump,
        'authority_contract':{'body':unsigned,'signature':'0'*128}}
    # Exact future wire size/identity validation before the signer is touched.
    # The placeholder is never returned or treated as a signature.
    checked_dispatch_request(result)
    validate_dispatch_authorization(context['authorization'],expected=expected,
        authenticated_caller=client,now=current,contract_expires_at=expires_at)
    envelope = issue(expected, identity_records=context['identity_records'],
        installer_public=context['installer_public'], identity_checkpoint=context['identity_checkpoint'],
        action_nonce=nonce,
        issued_at=issued_at, expires_at=expires_at, now=current, signer=signer)
    result['authority_contract'] = envelope
    # Re-read actual governed state after signing. Never return an otherwise
    # valid signature against policy/identity/route state that changed meanwhile.
    fresh = context_reader()
    if canonical({k:v for k,v in fresh.items() if k != 'active_count'}) != canonical(
            {k:v for k,v in context.items() if k != 'active_count'}):
        raise ValueError('gateway_resolver_context_changed')
    evaluate_dispatch(result, **fresh, now=clock())
    return result


def _haos_tool_envelope(request, *, now):
    """Shared exact shape/identity/history validation; not authentication."""
    from uuid import UUID
    from .authority_contract import canonical
    request=json.loads(canonical(request))
    fields={'request_id','conversation_id','machine_identity','requested_operation',
            'observed_at','messages','tools'}
    if not isinstance(request,dict) or set(request)!=fields:
        raise ValueError('haos_tool_envelope_invalid')
    try:
        UUID(request['request_id'])
    except (ValueError,TypeError,AttributeError) as error:
        raise ValueError('haos_tool_request_id_invalid') from error
    machine=request['machine_identity']
    if (not isinstance(machine,str) or not (machine.upper()=='HAOS' or machine.upper().startswith('HAOS_'))
            or request['requested_operation']!='conversation_tools'):
        raise ValueError('haos_tool_identity_invalid')
    outer={'schema':'SereinStage1Request/v1','request_id':request['request_id'],
        'authority':'local-operator','action':'companion',
        'conversation':{k:v for k,v in request.items() if k!='request_id'}}
    admitted,reason=classify_request(outer,now=now)
    if not admitted:
        raise ValueError(reason)
    return outer


def prepare_haos_tool_round(request, *, now):
    """Adapt 4d512129's fresh internal round ID, not its Stage-2 pipeline.

    The authenticated Interface owner calls this after its own ingress checks.
    This pure envelope conversion grants no authority; the resulting companion
    request must still pass the existing signed Authority/Operations dispatch.
    HAOS keeps its external request ID across rounds. Every internal inference
    is a distinct replay-protected operation. No tool is executed here.
    """
    from uuid import uuid4
    outer=_haos_tool_envelope(request,now=now)
    outer['request_id']=str(uuid4())
    return outer


def map_haos_tool_round(request, internal, response, *, now):
    """Preserve the accepted HAOS envelope after a separately governed round."""
    from uuid import UUID
    from .conversation_runtime import _tool_message
    from .authority_contract import canonical
    request,internal,response=json.loads(canonical([request,internal,response]))
    external=_haos_tool_envelope(request,now=now)
    if (not isinstance(request,dict) or not isinstance(internal,dict)
            or not isinstance(response,dict)
            or set(response)!={'schema','request_id','status','reason','timestamp','result'}
            or set(request)!={'request_id','conversation_id','machine_identity','requested_operation',
                              'observed_at','messages','tools'}
            or set(internal)!={'schema','request_id','authority','action','conversation'}
            or internal['authority']!='local-operator'
            or internal.get('conversation')!=external['conversation']
            or internal.get('action')!='companion'
            or internal.get('schema')!='SereinStage1Request/v1'
            or internal.get('request_id')==request.get('request_id')
            or response.get('schema')!='SereinStage1Response/v1'
            or response.get('status')!='ANSWERED'
            or response.get('request_id')!=internal.get('request_id')):
        raise ValueError('haos_tool_round_correlation_denied')
    try:
        UUID(request['request_id'])
        internal_id=UUID(internal['request_id'])
        if internal_id.version!=4 or str(internal_id)!=internal['request_id']:
            raise ValueError('internal round ID is not a generated UUID4')
    except (ValueError,TypeError,AttributeError) as error:
        raise ValueError('haos_tool_round_correlation_denied') from error
    result=response.get('result')
    if (not isinstance(result,dict) or set(result)!={'message','continue_conversation',
            'conversation_id','authority_effect','effects'}
            or result['conversation_id']!=request.get('conversation_id')
            or result['authority_effect']!='NONE' or result['effects']!=[]
            or type(result['continue_conversation']) is not bool):
        raise ValueError('haos_tool_round_result_denied')
    message=_tool_message(result['message'],request)
    if result['continue_conversation']!=bool(message.get('tool_calls')):
        raise ValueError('haos_tool_round_continuation_denied')
    return json.loads(canonical({'status':'ANSWERED','request_id':request['request_id'],
        'conversation_id':request['conversation_id'],'message':message,
        'continue_conversation':result['continue_conversation'],
        'authority_effect':'NONE','effects':[]}))


def serve_governed_connection(connection, *, client: str, peer_uid: int, peer_gid: int,
                              route_resolver, context_reader, replay_store,
                              runtime_call=None, audit_call=record_terminal_event, clock,
                              installed_root=None, boundary=None,
                              http_credentials_directory=None) -> None:
    """One bounded private ingress exchange; never derive trust from its JSON.

    ADAPT donor gateway_runtime 4af8ea8b peer isolation and the existing
    conversation_runtime total-deadline framing. The owning service must bind
    its client/UID/GID and authenticated Authority/context/runtime/audit roads.
    There are deliberately no discovered endpoints, default identities, route
    registration, key reads, readiness claims or service activation here.
    A component test of this exchange is not production composition proof.
    """
    from .authority_contract import canonical
    from .conversation_runtime import _decode, REQUEST_TIMEOUT_SECONDS

    maximum = 256 * 1024
    installed_mode = installed_root is not None
    if ((installed_mode and (client != 'HAOS' or not callable(boundary)
            or any(value is not None for value in (route_resolver, context_reader, runtime_call))))
            or (not installed_mode and boundary is not None)):
        raise ValueError('gateway_dependency_configuration_denied')
    # Configuration errors never fall back to a less restricted client.
    if (client not in ('HAOS', 'ANDROID', 'ESP32', 'INTERNAL')
            or type(peer_uid) is not int or peer_uid < 0
            or type(peer_gid) is not int or peer_gid < 0):
        raise ValueError('gateway_peer_configuration_denied')

    def reject(reason):
        current = clock()
        if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
            raise ValueError('gateway_clock_invalid')
        value = {'schema':'SereinStage1Response/v1', 'request_id':None,
                 'status':'DENIED', 'reason':reason, 'timestamp':current.isoformat()}
        encoded = canonical(value)
        try:
            audit_call(json.loads(encoded))
        except Exception:
            value.update(status='UNAVAILABLE', reason='gateway_audit_unavailable')
            encoded = canonical(value)
        return encoded

    try:
        if (connection.family != socket.AF_UNIX
                or connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM):
            raise ValueError('gateway_client_isolation_denied')
        _, uid, gid = struct.unpack('3i', connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
        if (uid, gid) != (peer_uid, peer_gid):
            raise ValueError('gateway_client_isolation_denied')
    except (OSError, AttributeError, struct.error, ValueError):
        encoded = reject('gateway_client_isolation_denied')
    else:
        # ADAPT the existing public handler inside this already isolated owner.
        # Peek only after peer verification; leave the legacy newline frame
        # untouched. Never reconnect to our own single-threaded listener.
        if installed_mode:
            try:
                connection.settimeout(REQUEST_TIMEOUT_SECONDS)
                is_http = connection.recv(1, socket.MSG_PEEK) == b'P'
            except OSError:
                is_http = False
            if is_http:
                from .serein_https_gateway_adapter import serve_private_http
                serve_private_http(connection,
                    credentials_directory=http_credentials_directory,
                    gateway_call=lambda payload: handle_installed_companion(
                        payload, client=client, root=installed_root,
                        replay_store=replay_store, boundary=boundary,
                        audit_call=audit_call, clock=clock), clock=clock)
                return
        try:
            deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
            payload = bytearray()
            while b'\n' not in payload:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('gateway_request_deadline_denied')
                connection.settimeout(remaining)
                block = connection.recv(min(16384, maximum + 1 - len(payload)))
                if not block:
                    raise ValueError('gateway_request_frame_denied')
                payload.extend(block)
                if len(payload) > maximum:
                    raise ValueError('gateway_request_size_denied')
            if not payload.endswith(b'\n') or payload.count(b'\n') != 1:
                raise ValueError('gateway_request_frame_denied')
            payload = bytes(payload)
            request = _decode(payload, maximum)
            admitted, _ = classify_request(request, now=clock())
            if not admitted or request.get('action') != 'companion':
                raise ValueError('gateway_request_denied')
        except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
            encoded = reject('gateway_request_denied')
        else:
            if installed_mode:
                encoded = handle_installed_companion(payload, client=client,
                    root=installed_root, replay_store=replay_store, boundary=boundary,
                    audit_call=audit_call, clock=clock)
            else:
                encoded = _handle_generic_ingress(payload, client=client,
                    route_resolver=route_resolver, context_reader=context_reader,
                    replay_store=replay_store, runtime_call=runtime_call,
                    audit_call=audit_call, clock=clock, reject=reject)
    # One request per connection; the owning accept loop closes it. A vanished
    # peer must not crash that loop or cause a second dispatch/retry.
    try:
        connection.settimeout(REQUEST_TIMEOUT_SECONDS)
        connection.sendall(encoded)
    except OSError:
        pass


def _handle_generic_ingress(payload, *, client, route_resolver, context_reader,
                            replay_store, runtime_call, audit_call, clock, reject):
    # Existing signed-grant path remains separate from installed ordinary
    # conversation policy. Neither can silently fall back to the other.
    try:
        # Resolver sees immutable input plus the independently bound client.
        # Its result must still pass signed Authority checks.
        route = route_resolver(client, payload)
    except Exception:
        return reject('gateway_route_unavailable')
    return handle_governed_companion(payload, client=client,
        route_request=route, context_reader=context_reader,
        replay_store=replay_store, runtime_call=runtime_call,
        audit_call=audit_call, clock=clock)


def serve_governed_socket(server, *, client: str, peer_uid: int, peer_gid: int,
                          route_resolver, context_reader, replay_store,
                          runtime_call=None, audit_call=record_terminal_event, clock,
                          max_requests: int | None = None,
                          installed_root=None, boundary=None,
                          http_credentials_directory=None) -> None:
    """Serve an injected listener; this neither creates nor admits a service.

    Kernel remains the installation/admission unit. This transport constituent
    adds no authority or default signer and preserves the one-request exchange.
    The caller owns the listener; this loop owns each accepted connection.
    """
    if (client not in ('HAOS', 'ANDROID', 'ESP32', 'INTERNAL')
            or type(peer_uid) is not int or peer_uid < 0
            or type(peer_gid) is not int or peer_gid < 0):
        raise ValueError('gateway_peer_configuration_denied')
    if max_requests is not None and (type(max_requests) is not int or max_requests <= 0):
        raise ValueError('gateway_request_count_denied')
    installed_mode = installed_root is not None
    if (not callable(audit_call) or not callable(clock)
            or (installed_mode and (client != 'HAOS' or not callable(boundary)
                or any(value is not None for value in (route_resolver, context_reader, runtime_call))))
            or (not installed_mode and (boundary is not None or not callable(route_resolver)
                or not callable(context_reader)
                or (runtime_call is not None and not callable(runtime_call))))):
        raise ValueError('gateway_dependency_configuration_denied')
    try:
        listener_valid = (server.family == socket.AF_UNIX
            and server.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM
            and server.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1)
    except (OSError, AttributeError):
        listener_valid = False
    if not listener_valid:
        raise ValueError('gateway_listener_denied')
    handled = 0
    while max_requests is None or handled < max_requests:
        # Listener failure is a service failure: propagate, never busy-retry.
        connection, _ = server.accept()
        with connection:
            # The exchange contains expected client/transport rejections.
            # An escaping invariant/dependency failure closes this connection
            # and terminates the loop: never conceal it or retry dispatch.
            installed_arguments = ({'installed_root': installed_root, 'boundary': boundary,
                                   'http_credentials_directory': http_credentials_directory}
                                   if installed_mode else {})
            serve_governed_connection(connection, client=client,
                peer_uid=peer_uid, peer_gid=peer_gid,
                route_resolver=route_resolver, context_reader=context_reader,
                replay_store=replay_store, runtime_call=runtime_call,
                audit_call=audit_call, clock=clock, **installed_arguments)
        handled += 1


def serve_installed_haos(*, root=Path('/'), clock=None, max_requests=None):
    """Own the existing HAOS private ingress and installed replay lifetime.

    No listener creation, installation, admission or privilege
    transition. Outpost alone orders whole-domain startup. Readiness here is
    process readiness only; runtime rechecks the actual installed boundary.
    """
    from .authority_contract import read_consumer_installed_policy_evidence
    from .kernel_operations import installed_replay_owner, verify_installed_conversation_boundary
    from .supervision import inherited_systemd_socket, ready_and_watch
    root = Path(root)
    if not root.is_absolute() or '..' in root.parts:
        raise ValueError('gateway_root_denied')
    if clock is None:
        clock = lambda: datetime.now(timezone.utc)
    if not callable(clock) or (max_requests is not None
            and (type(max_requests) is not int or max_requests <= 0)):
        raise ValueError('gateway_dependency_configuration_denied')
    account = pwd.getpwnam('serein-stage1')
    if (os.geteuid(), os.getegid()) != (account.pw_uid, account.pw_gid):
        raise ValueError('gateway_owner_denied')
    def boundary(matched):
        return verify_installed_conversation_boundary(matched, root=root, clock=clock)
    def audit(response):
        return record_terminal_event(response, root=root)
    address = root/'run/serein/kernel/gateway-haos.sock'
    with installed_replay_owner(root=root,
            database_path=root/'var/lib/serein/kernel/replay/receipts.sqlite3', clock=clock) as store:
        with inherited_systemd_socket() as server:
            metadata = address.lstat()
            if (server.getsockname() != str(address) or not stat.S_ISSOCK(metadata.st_mode)
                    or (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode), metadata.st_nlink)
                        != (0, account.pw_gid, 0o660, 1)):
                raise ValueError('gateway_listener_custody_denied')
            boundary({'installed_policy': read_consumer_installed_policy_evidence(root=root)})
            ready_and_watch()
            serve_governed_socket(server, client='HAOS', peer_uid=account.pw_uid,
                peer_gid=account.pw_gid, route_resolver=None, context_reader=None,
                replay_store=store, audit_call=audit, clock=clock,
                max_requests=max_requests, installed_root=root, boundary=boundary,
                http_credentials_directory=os.environ.get('CREDENTIALS_DIRECTORY'))


def respond(request: Any, *, now: datetime | None = None, companion_infer=infer) -> dict[str, Any]:
    """Legacy shape/identity response; never a substitute for governed dispatch.

    The retained companion_infer argument is not execution authority. Only
    handle_governed_companion may compose the authenticated Companion road.
    """
    current = now or datetime.now(timezone.utc)
    admitted, reason = classify_request(request, now=current)
    timestamp = current.isoformat()
    request_id = request.get("request_id") if isinstance(request, dict) else None
    if admitted and (request['schema']==VOICE_REQUEST_SCHEMA
            or request.get('action') in {'companion','ollama_chat','ollama_list'}):
        admitted,reason=False,'governed_dispatch_required'
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
    if request["action"] == "health":
        # This legacy responder has no independent whole-domain witness.
        # Answering a request cannot admit Kernel or establish Stage 1.
        result = {"state": "UNPROVEN", "scope": "minimum-gateway-answering-seed"}
    else:
        result = {"product": "SFOS", "base_family": "debian", "profile": None}
    return {
        "schema": "SereinStage1Response/v1",
        "request_id": request_id,
        "status": "ANSWERED",
        "reason": reason,
        "timestamp": timestamp,
        "result": result,
    }
