"""Bounded loopback inference provider for the Stage-1 companion."""

from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
import urllib.request
from typing import Callable
from .gpu_control import collect as collect_gpu, verify as verify_gpu, GPUControlDenied

ENDPOINT = "http://127.0.0.1:11434/api/generate"
CHAT_ENDPOINT = "http://127.0.0.1:11434/api/chat"
TAGS_ENDPOINT = "http://127.0.0.1:11434/api/tags"
RUNNING_ENDPOINT = "http://127.0.0.1:11434/api/ps"
MODEL = "qwen3:4b-instruct"
# Same offline model manifest pinned by install/offline_ollama_transaction.py.
# Ollama /api/tags returns bare lowercase SHA256, not a sha256: URI.
MODEL_DIGEST = "0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0"
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


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise CompanionUnavailable('companion_redirect_denied')


def _loopback_open(request, *, timeout):
    # Reuse Outpost's no-redirect method. Private inference never inherits
    # ambient proxy configuration or a globally installed alternate opener.
    if request.full_url not in {ENDPOINT, CHAT_ENDPOINT, TAGS_ENDPOINT, RUNNING_ENDPOINT}:
        raise CompanionUnavailable('companion_endpoint_denied')
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                       _RejectRedirect()).open(request, timeout=timeout)


def _request_json(endpoint: str, body: bytes | None, *, opener: Callable, timeout=90) -> dict:
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST" if body is not None else "GET",
        headers={"Content-Type": "application/json"},
    )
    try:
        with opener(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except Exception as error:
        raise CompanionUnavailable("companion_provider_unavailable") from error
    if not raw or len(raw) > MAX_RESPONSE_BYTES:
        raise CompanionUnavailable("companion_response_too_large")
    try:
        def pairs(items):
            value = {}
            for name, item in items:
                if name in value:
                    raise ValueError('duplicate provider field')
                value[name] = item
            return value
        def constant(value):
            raise ValueError('nonfinite provider field')
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeDecodeError, ValueError) as error:
        raise CompanionUnavailable("companion_response_invalid") from error
    if not isinstance(value, dict):
        raise CompanionUnavailable("companion_response_invalid")
    return value


def list_models(*, opener: Callable = _loopback_open) -> dict:
    """Return the loopback model list through the live Kernel."""
    value = _request_json(TAGS_ENDPOINT, None, opener=opener)
    models = value.get("models")
    if not isinstance(models, list):
        raise CompanionUnavailable("companion_response_invalid")
    admitted = [model for model in models if isinstance(model, dict) and model.get("model") == MODEL]
    if len(admitted) != 1 or admitted[0].get('digest') != MODEL_DIGEST:
        raise CompanionUnavailable("companion_model_unavailable")
    return {"models": admitted}


def running_model(*, opener: Callable = _loopback_open) -> dict:
    """Provider residency observation, never Kernel custody or admission."""
    value = _request_json(RUNNING_ENDPOINT, None, opener=opener)
    models = value.get('models')
    if not isinstance(models, list):
        raise CompanionUnavailable('companion_residency_invalid')
    selected = [row for row in models if isinstance(row,dict) and row.get('model') == MODEL]
    if (len(selected) != 1 or selected[0].get('digest') != MODEL_DIGEST
            or type(selected[0].get('size_vram')) is not int or selected[0]['size_vram'] <= 0):
        raise CompanionUnavailable('companion_gpu_residency_unproven')
    return selected[0]


def _gpu_facts(reader):
    try:
        value = reader()
        verify_gpu(value)
        if not isinstance(value.get('inventory'), dict):
            raise GPUControlDenied('GPU_INVENTORY_REQUIRED')
        # Preserve a canonical copy: provider callbacks must not be able to
        # mutate the earlier observation through a shared dictionary.
        return json.loads(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False))
    except (GPUControlDenied, OSError, ValueError, KeyError, TypeError) as error:
        raise CompanionUnavailable('companion_gpu_observation_unavailable') from error


def _gpu_observation(reader):
    value=_gpu_facts(reader)
    return value['boot_id'],value['gpu_inventory_sha256']


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


def chat(request: dict, *, opener: Callable = _loopback_open, _evidence=None) -> dict:
    """Run one bounded Ollama chat request, including HAOS Assist tool calls."""
    # Snapshot the exact input before calling the provider. Tool declarations
    # constrain recommendations only: HAOS still owns tool execution/authority.
    # ADAPT accepted Stage-1 policy.py 7e6bf56a: never return an undeclared tool.
    try:
        request = json.loads(json.dumps(request, allow_nan=False))
        tools = request.get("tools", [])
        if not isinstance(tools, list):
            raise ValueError("invalid tools")
        allowed_tools = set()
        for tool in tools:
            name = tool["function"]["name"]
            if (not isinstance(name, str) or not name or "\x00" in name
                    or len(name) > MAX_TOOL_NAME_CHARS or name in allowed_tools):
                raise ValueError("invalid tool name")
            allowed_tools.add(name)
    except (TypeError, ValueError, KeyError, AttributeError) as error:
        raise CompanionUnavailable("companion_request_invalid") from error
    upstream = {**request, "model": MODEL, "stream": False}
    # KEEP donor bef5d561's complete history. The pinned Ollama v0.33.3
    # Message schema supports tool_call_id; dropping it changes correlation
    # at the transport seam (DNAv1 / PRO-180). request is already detached.
    if upstream.get("keep_alive") == -1:
        upstream["keep_alive"] = BOUNDED_KEEP_ALIVE
    body = json.dumps(upstream, sort_keys=True, separators=(",", ":")).encode()
    tags_before = list_models(opener=opener)
    value = _request_json(CHAT_ENDPOINT, body, opener=opener)
    provider_digest = hashlib.sha256(json.dumps(value,sort_keys=True,
        separators=(',',':'),allow_nan=False).encode()).hexdigest()
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
    if any(call["function"]["name"] not in allowed_tools for call in tool_calls or []):
        raise CompanionUnavailable("companion_tool_not_declared")
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
    # Before/after tag observations bind the installed manifest at both sample
    # points. The upstream response has no signed digest: this is not an
    # inference attestation, GPU-custody witness or domain-admission result.
    tags_after = list_models(opener=opener)
    if _evidence is not None:
        _evidence.update(request_sha256=hashlib.sha256(body).hexdigest(),
            provider_response_canonical_sha256=provider_digest,
            model_tags_before=tags_before,model_tags_after=tags_after)
    return value


def _inference_body(utterance):
    return json.dumps({
        'model':MODEL,'prompt':f'{SYSTEM}\n\nUser request and governed context:\n{utterance}',
        'stream':False,'options':{'temperature':0},
    },sort_keys=True,separators=(',',':')).encode()


def _checked_invocation(value):
    if not isinstance(value,dict) or set(value)!={'request_id','conversation_id','runtime_request_sha256'}:
        raise CompanionUnavailable('companion_invocation_invalid')
    for field,maximum in (('request_id',128),('conversation_id',256)):
        item=value[field]
        if not isinstance(item,str) or not item.strip() or len(item)>maximum or '\x00' in item:
            raise CompanionUnavailable('companion_invocation_invalid')
    digest=value['runtime_request_sha256']
    if not isinstance(digest,str) or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):
        raise CompanionUnavailable('companion_invocation_invalid')
    return dict(value)


def _chat_body(request):
    """Exact historical HAOS provider recipe; never flatten history into text."""
    if (not isinstance(request,dict)
            or set(request)!={'model','messages','tools','stream','keep_alive','options','think'}
            or request['model']!=MODEL or request['stream'] is not False
            or request['keep_alive']!=BOUNDED_KEEP_ALIVE or request['think'] is not False
            or request['options']!={'num_ctx':8192}
            or not isinstance(request['messages'],list) or not request['messages']
            or not isinstance(request['tools'],list)):
        raise CompanionUnavailable('companion_chat_recipe_invalid')
    return json.dumps(request,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def validate_compute_result(value, *, utterance=None, invocation, chat_request=None):
    """Validate retained observations, without asserting control/admission."""
    try:
        invocation=_checked_invocation(invocation)
        encoded=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        if len(encoded)>MAX_RESPONSE_BYTES:raise ValueError('unbounded observation')
        value=json.loads(encoded)
        chat_mode=chat_request is not None
        result_key='message' if chat_mode else 'answer'
        digest_key='message_sha256' if chat_mode else 'answer_sha256'
        if not isinstance(value,dict) or set(value)!={result_key,'compute_observation'}:
            raise ValueError('compute result shape')
        answer=value[result_key];evidence=value['compute_observation']
        fields={'schema','state','model','model_digest','provider','started_at','completed_at',
            'request_sha256','provider_response_canonical_sha256',digest_key,'gpu_before',
            'gpu_after','model_tags_before','model_tags_after','model_residency_after',
            'alternate_provider_requested','alternate_model_requested','cpu_fallback_requested',
            'runtime_cpu_fallback','gpu_control','authority_effect','admission_effect','invocation'}
        if chat_mode:
            if (not isinstance(answer,dict) or answer.get('role')!='assistant'
                    or set(answer)-{'role','content','tool_calls'}
                    or not isinstance(answer.get('content'),str)
                    or len(answer['content'])>MAX_ANSWER_CHARS or '\x00' in answer['content']
                    or not _valid_tool_calls(answer.get('tool_calls'))
                    or not (answer['content'] or answer.get('tool_calls'))):
                raise ValueError('chat compute answer shape')
            answer_bytes=json.dumps(answer,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
            request_bytes=_chat_body(chat_request)
        else:
            if (not isinstance(answer,str) or not answer or answer!=' '.join(answer.split())
                    or len(answer)>MAX_ANSWER_CHARS or '\x00' in answer):
                raise ValueError('compute answer shape')
            answer_bytes=answer.encode();request_bytes=_inference_body(utterance)
        if (not isinstance(evidence,dict) or set(evidence)!=fields
                or evidence['schema']!=('SereinCompanionComputeObservation/v2' if chat_mode else 'SereinCompanionComputeObservation/v1')
                or evidence['invocation']!=invocation
                or evidence['state']!='OBSERVED_NOT_CONTROL_OR_ADMISSION'
                or evidence['model']!=MODEL or evidence['model_digest']!=MODEL_DIGEST
                or evidence['provider']!=(CHAT_ENDPOINT if chat_mode else ENDPOINT)
                or evidence['authority_effect']!='NONE' or evidence['admission_effect']!='NONE'
                or evidence['gpu_control']!='UNPROVEN' or evidence['runtime_cpu_fallback']!='UNPROVEN'
                or any(evidence[name] is not False for name in
                    ('alternate_provider_requested','alternate_model_requested','cpu_fallback_requested'))):
            raise ValueError('compute observation meaning')
        for name in ('request_sha256','provider_response_canonical_sha256',digest_key):
            digest=evidence[name]
            if not isinstance(digest,str) or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):
                raise ValueError('compute digest')
        if (evidence['request_sha256']!=hashlib.sha256(request_bytes).hexdigest()
                or evidence[digest_key]!=hashlib.sha256(answer_bytes).hexdigest()):
            raise ValueError('compute request/result correlation')
        started=datetime.fromisoformat(evidence['started_at'].replace('Z','+00:00'))
        completed=datetime.fromisoformat(evidence['completed_at'].replace('Z','+00:00'))
        if (started.tzinfo is None or started.utcoffset() is None
                or completed.tzinfo is None or completed.utcoffset() is None or completed<started):
            raise ValueError('compute chronology')
        gpu_fields={'schema','boot_id','device_count','driver_loaded','gpu_inventory_sha256',
                    'authority_effect','inventory'}
        for name in ('gpu_before','gpu_after'):
            if not isinstance(evidence[name],dict) or set(evidence[name])!=gpu_fields:
                raise ValueError('compute GPU observation shape')
            verify_gpu(evidence[name])
        if evidence['gpu_before']!=evidence['gpu_after']:
            raise ValueError('compute GPU changed')
        for name in ('model_tags_before','model_tags_after'):
            tags=evidence[name]
            if (not isinstance(tags,dict) or set(tags)!={'models'}
                    or not isinstance(tags['models'],list) or len(tags['models'])!=1
                    or not isinstance(tags['models'][0],dict)
                    or tags['models'][0].get('model')!=MODEL
                    or tags['models'][0].get('digest')!=MODEL_DIGEST):
                raise ValueError('compute model changed')
        residency=evidence['model_residency_after']
        if (not isinstance(residency,dict) or residency.get('model')!=MODEL
                or residency.get('digest')!=MODEL_DIGEST
                or type(residency.get('size_vram')) is not int or residency['size_vram']<=0):
            raise ValueError('compute residency unproven')
        return value
    except (GPUControlDenied,ValueError,TypeError,KeyError,AttributeError,RecursionError) as exc:
        raise CompanionUnavailable('companion_compute_observation_invalid') from exc


def infer_with_evidence(utterance: str, *, invocation, opener: Callable = _loopback_open,
                        gpu_reader: Callable = collect_gpu, clock=None) -> dict:
    invocation=_checked_invocation(invocation)
    value=_infer_observation(utterance,opener=opener,gpu_reader=gpu_reader,clock=clock)
    value['compute_observation']['invocation']=invocation
    return validate_compute_result(value,utterance=utterance,invocation=invocation)


def chat_with_evidence(request, *, invocation, opener: Callable = _loopback_open,
                       gpu_reader: Callable = collect_gpu, clock=None):
    """Same chat road, with measured provenance; no tool execution or admission."""
    invocation=_checked_invocation(invocation)
    request=json.loads(_chat_body(request))
    clock=clock or (lambda:datetime.now(timezone.utc))
    started=clock()
    if not isinstance(started,datetime) or started.utcoffset() is None:
        raise CompanionUnavailable('companion_observation_clock_invalid')
    before=_gpu_facts(gpu_reader);captured={}
    result=chat(request,opener=opener,_evidence=captured)
    residency=running_model(opener=opener);after=_gpu_facts(gpu_reader)
    completed=clock()
    if not isinstance(completed,datetime) or completed.utcoffset() is None or completed<started:
        raise CompanionUnavailable('companion_observation_clock_invalid')
    message=result['message']
    observation={**captured,'schema':'SereinCompanionComputeObservation/v2',
        'state':'OBSERVED_NOT_CONTROL_OR_ADMISSION','model':MODEL,'model_digest':MODEL_DIGEST,
        'provider':CHAT_ENDPOINT,'started_at':started.isoformat(),'completed_at':completed.isoformat(),
        'message_sha256':hashlib.sha256(json.dumps(message,sort_keys=True,
            separators=(',',':'),allow_nan=False).encode()).hexdigest(),
        'gpu_before':before,'gpu_after':after,'model_residency_after':residency,
        'alternate_provider_requested':False,'alternate_model_requested':False,
        'cpu_fallback_requested':False,'runtime_cpu_fallback':'UNPROVEN','gpu_control':'UNPROVEN',
        'authority_effect':'NONE','admission_effect':'NONE','invocation':invocation}
    return validate_compute_result({'message':message,'compute_observation':observation},
        invocation=invocation,chat_request=request)


def _infer_observation(utterance: str, *, opener: Callable,
                       gpu_reader: Callable, clock=None) -> dict:
    """Preserve measured provider facts; never convert them into GPU custody.

    Ollama's model/VRAM report proves residency, not per-token execution or
    exclusive ownership. No alternate model/provider or CPU fallback is
    requested here; runtime-internal placement remains explicitly unproven.
    Outpost still needs independent Host/control/readback acceptance.
    """
    clock=clock or (lambda:datetime.now(timezone.utc))
    started=clock()
    if (not isinstance(started,datetime) or started.tzinfo is None
            or started.utcoffset() is None):
        raise CompanionUnavailable('companion_observation_clock_invalid')
    body = _inference_body(utterance)
    before = _gpu_facts(gpu_reader)
    tags_before = list_models(opener=opener)
    result = _request_json(ENDPOINT, body, opener=opener, timeout=20)
    if not isinstance(result, dict) or result.get("model") != MODEL or result.get("done") is not True:
        raise CompanionUnavailable("companion_response_invalid")
    answer = result.get("response")
    if not isinstance(answer, str) or not answer.strip() or len(answer) > MAX_ANSWER_CHARS or "\x00" in answer:
        raise CompanionUnavailable("companion_answer_invalid")
    tags_after = list_models(opener=opener)
    residency = running_model(opener=opener)
    after = _gpu_facts(gpu_reader)
    if (after['boot_id'],after['gpu_inventory_sha256']) != (before['boot_id'],before['gpu_inventory_sha256']):
        raise CompanionUnavailable('companion_gpu_observation_changed')
    # Exact pinned model is resident on GPU in the same observed boot/device
    # interval. Ollama provides no per-token hardware attestation; do not turn
    # this bounded correlation into GPU ownership or Stage-1 admission.
    completed=clock()
    if (not isinstance(completed,datetime) or completed.tzinfo is None
            or completed.utcoffset() is None or completed<started):
        raise CompanionUnavailable('companion_observation_clock_invalid')
    answer=" ".join(answer.split())
    canonical=lambda value:json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    observation={'schema':'SereinCompanionComputeObservation/v1',
        'state':'OBSERVED_NOT_CONTROL_OR_ADMISSION','model':MODEL,'model_digest':MODEL_DIGEST,
        'provider':ENDPOINT,'started_at':started.isoformat(),'completed_at':completed.isoformat(),
        'request_sha256':hashlib.sha256(body).hexdigest(),
        'provider_response_canonical_sha256':hashlib.sha256(canonical(result)).hexdigest(),
        'answer_sha256':hashlib.sha256(answer.encode()).hexdigest(),
        'gpu_before':before,'gpu_after':after,'model_tags_before':tags_before,
        'model_tags_after':tags_after,'model_residency_after':residency,
        'alternate_provider_requested':False,'alternate_model_requested':False,
        'cpu_fallback_requested':False,'runtime_cpu_fallback':'UNPROVEN',
        'gpu_control':'UNPROVEN','authority_effect':'NONE','admission_effect':'NONE'}
    return {'answer':answer,'compute_observation':observation}


def infer(utterance: str, *, opener: Callable = _loopback_open,
          gpu_reader: Callable = collect_gpu) -> str:
    """Retain the current text API while the versioned evidence API is composed."""
    # Legacy text-only callers cannot emit an unbound v2 evidence response.
    return _infer_observation(utterance,opener=opener,gpu_reader=gpu_reader)['answer']
