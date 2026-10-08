"""Minimum private Stage-1 conversation runtime backed by loopback Ollama."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import hashlib
import socket
import time
from typing import Any

from .companion_provider import (CompanionUnavailable, infer_with_evidence,
    validate_compute_result, chat_with_evidence, MODEL, MAX_ANSWER_CHARS, MAX_RESPONSE_BYTES)
from .supervision import inherited_systemd_socket, ready_and_watch
from .domain_identity import canonical

REQUEST_SCHEMA = "SereinStage1ConversationRuntimeRequest/v1"
RESPONSE_SCHEMA = "SereinStage1ConversationRuntimeResponse/v2"
FIELDS = frozenset({
    "schema", "request_id", "conversation_id", "machine_identity",
    "requested_operation", "utterance", "observed_at",
})
MAX_REQUEST_BYTES = 128 * 1024  # Existing bounded HAOS chat-history contract.
MAX_TEXT_CHARS = 1024
MAX_AGE_SECONDS = 120
MAX_FUTURE_SKEW_SECONDS = 5
REQUEST_TIMEOUT_SECONDS = 2.0  # Existing bounded private exchange, not inference time.


def _decode(payload: bytes, maximum: int) -> object:
    if not isinstance(payload, bytes) or not payload or len(payload) > maximum:
        raise ValueError('conversation_runtime_payload_size_invalid')
    def pairs(items):
        result = {}
        for name, value in items:
            if name in result:
                raise ValueError('conversation_runtime_duplicate_field')
            result[name] = value
        return result
    def constant(value):
        raise ValueError('conversation_runtime_nonfinite_value')
    return json.loads(payload.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)


def _validate(value: object, *, now: datetime) -> dict[str, str]:
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError('conversation_runtime_clock_invalid')
    if not isinstance(value, dict) or value.get("schema") != REQUEST_SCHEMA:
        raise ValueError("conversation_runtime_envelope_invalid")
    tool_mode = value.get('requested_operation') == 'conversation_tools'
    fields = (FIELDS - {'utterance'}) | {'messages','tools'} if tool_mode else FIELDS
    if set(value) != fields:
        raise ValueError("conversation_runtime_envelope_invalid")
    for field, maximum in (
        ("request_id", 128), ("conversation_id", 256), ("machine_identity", 128),
        ("utterance", MAX_TEXT_CHARS),
    ):
        if field == 'utterance' and tool_mode:
            continue
        item = value.get(field)
        if not isinstance(item, str) or not item.strip() or len(item) > maximum or "\x00" in item:
            raise ValueError(f"conversation_runtime_{field}_invalid")
    if value.get("requested_operation") not in ("conversation_only", "conversation_tools"):
        raise ValueError("conversation_runtime_operation_not_admitted")
    if tool_mode:
        from .kernel import _classify_stage1_companion_request
        classified, reason = _classify_stage1_companion_request({
            'schema':'SereinStage1Request/v1','request_id':value['request_id'],
            'authority':'local-operator','action':'companion',
            'conversation':{k:v for k,v in value.items() if k not in ('schema','request_id')}},now=now)
        if not classified:
            raise ValueError(reason)
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


def invocation_binding(request):
    """Bind the complete validated request, not just its normalized words."""
    return {'request_id':request['request_id'],'conversation_id':request['conversation_id'],
            'runtime_request_sha256':hashlib.sha256(canonical(request)).hexdigest()}


def _tool_message(value, request):
    """ADAPT HAOS policy 7e6bf56a: recommendations, never tool execution."""
    from .companion_provider import _valid_tool_calls
    if (not isinstance(value,dict) or set(value)-{'role','content','tool_calls'}
            or value.get('role')!='assistant'):
        raise ValueError('conversation_tool_message_invalid')
    content=value.get('content');calls=value.get('tool_calls')
    if (content is not None and (not isinstance(content,str) or len(content)>MAX_ANSWER_CHARS
            or '\x00' in content)) or not _valid_tool_calls(calls):
        raise ValueError('conversation_tool_message_invalid')
    if calls is not None and (not calls or len(calls)>8):
        raise ValueError('conversation_tool_calls_invalid')
    if not content and not calls:
        raise ValueError('conversation_tool_message_empty')
    allowed={tool['function']['name'] for tool in request['tools']}
    seen={call['id'] for message in request['messages']
          for call in message.get('tool_calls',[])}
    total=0
    for call in calls or []:
        if (set(call)!={'id','function'} or set(call['function'])!={'name','arguments'}
                or not isinstance(call['id'],str) or not call['id']):
            raise ValueError('conversation_tool_call_invalid')
        if call['id'] in seen or call['function']['name'] not in allowed:
            raise ValueError('conversation_tool_call_correlation_invalid')
        seen.add(call['id'])
        total+=len(json.dumps(call['function']['arguments'],sort_keys=True,
            separators=(',',':'),ensure_ascii=False,allow_nan=False).encode())
        if total>32*1024:
            raise ValueError('conversation_tool_arguments_total_invalid')
    return json.loads(canonical(value))


def handle_payload(payload: bytes, *, now: datetime | None = None, inference=infer_with_evidence,
                   clock=None, chat_inference=chat_with_evidence) -> bytes:
    clock = clock or (lambda:datetime.now(timezone.utc))
    current = now if now is not None else clock()
    request_id: str | None = None
    conversation_id: str | None = None
    try:
        value = _validate(_decode(payload, MAX_REQUEST_BYTES), now=current)
        request_id = value["request_id"]
        conversation_id = value["conversation_id"]
        invocation=invocation_binding(value)
        response: dict[str, Any] = {
            "schema": RESPONSE_SCHEMA,
            "request_id": request_id,
            "conversation_id": conversation_id,
            "status": "ANSWERED",
            "completed_at": current.isoformat(),
            "authority_effect": "NONE",
            "effects": [],
        }
        if value['requested_operation']=='conversation_tools':
            # Exact provider settings from accepted adapter 314059cc/4d512129.
            provider_request={'model':MODEL,'messages':value['messages'],'tools':value['tools'],
                'stream':False,'keep_alive':'300s','options':{'num_ctx':8192},'think':False}
            # A callback cannot mutate the source request or its signed binding.
            observed=validate_compute_result(chat_inference(json.loads(canonical(provider_request)),
                invocation=dict(invocation)),chat_request=provider_request,invocation=invocation)
            message=_tool_message(observed['message'],value)
            response.update(message=message,continue_conversation=bool(message.get('tool_calls')),
                            invocation=invocation,compute_observation=observed['compute_observation'])
        else:
            utterance=" ".join(value['utterance'].split())
            observed=validate_compute_result(inference(utterance,invocation=dict(invocation)),
                utterance=utterance,invocation=invocation)
            response.update(state='READY',response=observed['answer'],
                compute_observation=observed['compute_observation'],scope='stage1-bounded-companion')
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
    # Explicit now retains the existing fixed-observation fixture contract.
    # The live path records completion after inference, never the start time.
    completed = current if now is not None else clock()
    if (not isinstance(completed, datetime) or completed.tzinfo is None
            or completed.utcoffset() is None or completed < current):
        raise ValueError('conversation_runtime_completion_clock_invalid')
    response['completed_at'] = completed.isoformat()
    encoded=(json.dumps(response,sort_keys=True,separators=(',',':'))+'\n').encode()
    if len(encoded)>MAX_RESPONSE_BYTES:
        # The provider's measured-result bound is not the complete wire bound.
        # Retain a bounded failure after this single inference; never truncate
        # a transcript/result, retry the model, or send an unreadable envelope.
        response={'schema':RESPONSE_SCHEMA,'request_id':request_id,
            'conversation_id':conversation_id,'status':'UNAVAILABLE',
            'reason':'conversation_runtime_response_too_large','completed_at':completed.isoformat(),
            'authority_effect':'NONE','effects':[]}
        encoded=(json.dumps(response,sort_keys=True,separators=(',',':'))+'\n').encode()
    return encoded


def call_expected(payload: bytes, *, runtime_call, clock) -> bytes:
    """Validate the existing private Companion return before routing it back.

    The bound caller owns transport/authentication and the Operations reservation.
    This performs no discovery, retry, signing, admission, or physical effect.
    Response correlation is not established by a schema name or transport alone.
    """
    request = _validate(_decode(payload, MAX_REQUEST_BYTES), now=clock())
    raw = runtime_call(payload)
    now = clock()
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError('conversation_runtime_clock_invalid')
    response = _decode(raw, MAX_RESPONSE_BYTES)
    common = {'schema','request_id','conversation_id','status','completed_at','authority_effect','effects'}
    if (not isinstance(response, dict) or response.get('schema') != RESPONSE_SCHEMA
            or response.get('request_id') != request['request_id']
            or response.get('conversation_id') != request['conversation_id']
            or response.get('authority_effect') != 'NONE' or response.get('effects') != []):
        raise ValueError('conversation_runtime_return_correlation_denied')
    status = response.get('status')
    observed=None
    if status == 'ANSWERED' and request['requested_operation']=='conversation_tools':
        if (set(response)!=common|{'message','continue_conversation','invocation','compute_observation'}
                or response['invocation']!=invocation_binding(request)
                or type(response['continue_conversation']) is not bool):
            raise ValueError('conversation_tool_return_correlation_denied')
        message=_tool_message(response['message'],request)
        if response['continue_conversation']!=bool(message.get('tool_calls')):
            raise ValueError('conversation_tool_continuation_denied')
        provider_request={'model':MODEL,'messages':request['messages'],'tools':request['tools'],
            'stream':False,'keep_alive':'300s','options':{'num_ctx':8192},'think':False}
        try:
            observed=validate_compute_result({'message':message,
                'compute_observation':response['compute_observation']},
                chat_request=provider_request,invocation=invocation_binding(request))['compute_observation']
        except (CompanionUnavailable,TypeError,ValueError) as exc:
            raise ValueError('conversation_runtime_compute_observation_denied') from exc
    elif status == 'ANSWERED':
        if (set(response) != common | {'state','response','scope','compute_observation'}
                or response['state'] != 'READY' or response['scope'] != 'stage1-bounded-companion'
                or not isinstance(response['response'], str) or not response['response'].strip()
                or len(response['response']) > MAX_ANSWER_CHARS or '\x00' in response['response']):
            raise ValueError('conversation_runtime_answer_contract_denied')
        try:
            observed=validate_compute_result({'answer':response['response'],
                'compute_observation':response['compute_observation']},
                utterance=' '.join(request['utterance'].split()),
                invocation=invocation_binding(request))['compute_observation']
        except (CompanionUnavailable,TypeError,ValueError) as exc:
            raise ValueError('conversation_runtime_compute_observation_denied') from exc
    elif status in ('DENIED','UNAVAILABLE'):
        if (set(response) != common | {'reason'} or not isinstance(response['reason'],str)
                or not response['reason'] or len(response['reason']) > MAX_TEXT_CHARS
                or '\x00' in response['reason']):
            raise ValueError('conversation_runtime_failure_contract_denied')
    else:
        raise ValueError('conversation_runtime_return_status_denied')
    if observed is not None:
        started=datetime.fromisoformat(observed['started_at'].replace('Z','+00:00'))
        finished=datetime.fromisoformat(observed['completed_at'].replace('Z','+00:00'))
        requested=datetime.fromisoformat(request['observed_at'].replace('Z','+00:00'))
        returned=datetime.fromisoformat(response['completed_at'].replace('Z','+00:00'))
        if returned.utcoffset() is None:
            raise ValueError('conversation_runtime_return_time_denied')
        if ((requested-started).total_seconds()>MAX_FUTURE_SKEW_SECONDS
                or (finished-returned).total_seconds()>MAX_FUTURE_SKEW_SECONDS
                or (finished-now).total_seconds()>MAX_FUTURE_SKEW_SECONDS
                or (now-finished).total_seconds()>MAX_AGE_SECONDS):
            raise ValueError('conversation_runtime_compute_time_denied')
    if not isinstance(response['completed_at'], str):
        raise ValueError('conversation_runtime_return_time_denied')
    completed = datetime.fromisoformat(response['completed_at'].replace('Z','+00:00'))
    observed = datetime.fromisoformat(request['observed_at'].replace('Z','+00:00'))
    if (completed.tzinfo is None or completed.utcoffset() is None
            or (completed-now).total_seconds() > MAX_FUTURE_SKEW_SECONDS
            or (observed-completed).total_seconds() > MAX_FUTURE_SKEW_SECONDS
            or (now-completed).total_seconds() > MAX_AGE_SECONDS):
        raise ValueError('conversation_runtime_return_time_denied')
    return raw


def serve_socket(server: socket.socket, *, max_requests: int | None = None) -> None:
    handled = 0
    while max_requests is None or handled < max_requests:
        connection, _ = server.accept()
        with connection:
            # Same total-deadline framing as Outpost's proven presentation road.
            # A stream recv is not a message; partial input cannot monopolize
            # this private endpoint or terminate service for the next caller.
            deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
            payload = b''
            try:
                while not payload.endswith(b'\n') and len(payload) <= MAX_REQUEST_BYTES:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('conversation_runtime_request_timeout')
                    connection.settimeout(remaining)
                    block = connection.recv(MAX_REQUEST_BYTES + 1 - len(payload))
                    if not block:
                        break
                    payload += block
                if not payload.endswith(b'\n') or len(payload) > MAX_REQUEST_BYTES:
                    raise ValueError('conversation_runtime_request_framing_invalid')
                response = handle_payload(payload)
                connection.settimeout(REQUEST_TIMEOUT_SECONDS)
                connection.sendall(response)
            except (OSError, ValueError):
                # Close this failed exchange; never retry its inference.
                pass
        handled += 1


def serve() -> None:
    with inherited_systemd_socket() as inherited:
        ready_and_watch()
        serve_socket(inherited)
