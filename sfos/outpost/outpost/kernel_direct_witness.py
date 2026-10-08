"""Outpost's independent Authority-v2 observation; existing private socket only.

A trusted installation binding and public registry are explicit inputs from
the governed installer handoff, never supplied by the responding Kernel.
This initial-admission reader does not grant authority or start any service.
"""
from __future__ import annotations
from datetime import datetime, timezone
import copy
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import stat
import struct
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from install.transaction import strict_json, TransactionError
from install.kernel_first_install_runner import regular, current_host_gate, HOST_STATE
from install.public_generation_transaction import CANONICAL_AUTHORITY_SHA256

SOCKET = Path("/run/serein/stage1/kernel-authority-v1.sock")
OPERATIONS_SOCKET = Path('/run/serein/stage1/kernel-operations-v1.sock')
BOOT = Path("/proc/sys/kernel/random/boot_id")
ANCHOR = Path("/usr/share/serein/outpost/cognition-verification.pem")
PHASE_A_CHECKS = ("implementation-identity", "blueprint-policy-integrity", "frame-identity",
                  "contract-containment", "authority-admission-policy", "unknown-trust-safe-recovery")


class KernelWitnessError(ValueError):
    mode = "SAFE_RECOVERY"
    privileged_execution = False
    branch_advance = False


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def record_bytes(value):
    return canonical(value) + b"\n"


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def require(value, reason):
    if not value:
        raise KernelWitnessError(reason)


def compare_operations_response(raw, *, request, source, boot_id,
                                installed_evidence_sha256, observed_at):
    """Compare subject observation; transport authentication remains mandatory.

    Source and installed-evidence digest come from the verified installer, and
    the preceding Authority digest/nonce from Outpost, not this response.
    This consumer never imports subject code or promotes telemetry to Phase B.
    """
    try:
        require(isinstance(raw,bytes) and 0<len(raw)<=65536, 'KERNEL_OPERATIONS_SIZE_DENIED')
        value=strict_json(raw)
        source,request=copy.deepcopy((source,request))
        validate_expected_source(source)
        require(isinstance(installed_evidence_sha256,str)
                and re.fullmatch('[0-9a-f]{64}',installed_evidence_sha256)
                and isinstance(observed_at,datetime) and observed_at.utcoffset() is not None,
                'KERNEL_OPERATIONS_EXPECTATION_DENIED')
        require(isinstance(request,dict) and set(request)=={
                    'schema','branch','request_id','nonce','previous_evidence_digest'}
                and request['schema']=='SEREIN/KernelBranchWitnessRequest/v1'
                and request['branch']=='OPERATIONS'
                and isinstance(request['previous_evidence_digest'],str)
                and re.fullmatch('[0-9a-f]{64}',request['previous_evidence_digest'])
                and all(isinstance(request[key],str) and 0<len(request[key])<=128
                        and '\x00' not in request[key] for key in ('request_id','nonce')),
                'KERNEL_OPERATIONS_REQUEST_DENIED')
        require(isinstance(value,dict) and set(value)=={'schema','domain','branch','issuer',
                'verdict','issued_at','request_id','nonce','previous_evidence_digest',
                'source_commit','source_tree','canonical_manifest_digest','boot_id','facts',
                'facts_digest','uncertainty','authority_effect','evidence_digest'}
                and value['schema']=='SEREIN/KernelBranchDirectWitness/v1'
                and value['domain']=='KERNEL' and value['branch']=='OPERATIONS'
                and value['issuer']=='KERNEL_BRANCH_API' and value['verdict']=='UNKNOWN'
                and value['uncertainty']=='OPERATIONS_PHASE_B_UNPROVEN'
                and value['authority_effect']=='NONE' and value['boot_id']==boot_id
                and all(value[key]==source[key] for key in
                        ('source_commit','source_tree','canonical_manifest_digest'))
                and all(value[key]==request[key] for key in
                        ('request_id','nonce','previous_evidence_digest'))
                and value['evidence_digest']==digest({k:v for k,v in value.items() if k!='evidence_digest'}),
                'KERNEL_OPERATIONS_BINDING_DENIED')
        facts=value['facts']
        require(isinstance(facts,dict) and set(facts)=={'source_commit','source_tree',
                    'canonical_manifest_digest','boot_id','observation','audit','phase_b','authority_effect'}
                and all(facts[key]==value[key] for key in
                        ('source_commit','source_tree','canonical_manifest_digest','boot_id'))
                and facts['audit']=='ACK_CORRELATED_NOT_INDEPENDENT_LOG_PROOF'
                and facts['phase_b']=='UNPROVEN' and facts['authority_effect']=='NONE'
                and value['facts_digest']==digest(facts), 'KERNEL_OPERATIONS_FACTS_DENIED')
        event=facts['observation']
        event_fields={'schema','boot_id','sequence','observed_at',
                'monotonic_ns','bpm','cadence_state','heartbeat_scope','scheduler_state','queues',
                'queue_depth','leases','active_leases','recovery','event','authority_effect','unproven',
                'installed_evidence_sha256','queue_sha256','observation_sha256','scheduler_decision'}
        require(isinstance(event,dict) and set(event) in (event_fields,event_fields|{'replay_continuity'})
                and event['schema']=='SEREIN/KernelOperationsHeartbeat/v1'
                and event['boot_id']==boot_id
                and event['installed_evidence_sha256']==installed_evidence_sha256,
                'KERNEL_OPERATIONS_OBSERVATION_DENIED')
        if 'replay_continuity' in event:
            continuity=event['replay_continuity']
            counts=('chains','receipts','active_reservations','expired_reservations','consumed_chains')
            require(isinstance(continuity,dict) and set(continuity)==set(counts)|{'integrity','authority_effect','work_proof'}
                    and all(type(continuity[key]) is int and 0<=continuity[key]<4096 for key in counts)
                    and continuity['chains']<=continuity['receipts']<=3*continuity['chains']
                    and sum(continuity[key] for key in counts[2:])<=continuity['chains']
                    and continuity['active_reservations']==event['active_leases']
                    and continuity['integrity']==('AUTHENTICATED_REPLAY_HISTORY' if continuity['chains'] else 'EMPTY_NO_AUTHENTICATED_RECEIPTS')
                    and continuity['authority_effect']=='NONE' and continuity['work_proof'] is False,
                    'KERNEL_OPERATIONS_CONTINUITY_DENIED')
            # Expired reservations are retained evidence, not executable work.
            # Correlate their truthful count without granting recovery/admission.
        require(all(type(event[key]) is int and event[key]>=(1 if key=='sequence' else 0)
                    for key in ('sequence','monotonic_ns','queue_depth','active_leases'))
                and all(isinstance(event[key],str) and re.fullmatch('[0-9a-f]{64}',event[key])
                        for key in ('queue_sha256','observation_sha256')),
                'KERNEL_OPERATIONS_OBSERVATION_DENIED')
        bpm=event['bpm'];cadence=event['cadence_state']
        require(type(bpm) in (int,float) and 0<=bpm<=60_000_000_000 and math.isfinite(bpm)
                and ((cadence=='UNPROVEN' and bpm==0) or (cadence=='DEGRADED' and 0<bpm<60)
                     or (cadence=='OBSERVED' and bpm>=60))
                and event['heartbeat_scope']=='REPLAY_AND_QUEUE_OBSERVER_ONLY'
                and event['scheduler_state']=='QUEUE_SELECTION_OBSERVED_NOT_DISPATCH'
                and event['queues']=='PENDING_METADATA_OBSERVED'
                and event['leases']==event['recovery']=='UNKNOWN'
                and event['unproven']==['task_queues','lease_authenticity','recovery_controls','scheduler_decisions']
                and event['authority_effect']=='NONE'
                and event['event'] in ('BOOT_BOUND_START','HEARTBEAT','MISSED_HEARTBEAT')
                and event['scheduler_decision']==('IDLE_NO_PENDING_WORK' if event['queue_depth']==0
                                                 else 'HELD_REQUEST_MATERIAL_REQUIRED'),
                'KERNEL_OPERATIONS_OVERCLAIM_DENIED')
        issued=datetime.fromisoformat(value['issued_at'].replace('Z','+00:00'))
        collected=datetime.fromisoformat(event['observed_at'].replace('Z','+00:00'))
        require(all(stamp.utcoffset() is not None and 0<=(observed_at-stamp).total_seconds()<=30
                    for stamp in (issued,collected)) and collected<=issued,
                'KERNEL_OPERATIONS_STALE')
        return {'result':'OPERATIONS_OBSERVATION_CORRELATED','subject_evidence':value,
                'evidence_authentication':'SEPARATE_REQUIRED','phase_b':'UNPROVEN',
                'admission':'UNADMITTED','stage1':'NOT_READY','authority_effect':'NONE'}
    except KernelWitnessError:
        raise
    except (TransactionError,ValueError,TypeError,KeyError,AttributeError,OverflowError) as exc:
        raise KernelWitnessError('KERNEL_OPERATIONS_RESPONSE_DENIED') from exc


def compare_interface_response(raw, *, request, source, boot_id,
                               installed_evidence_sha256, observed_at):
    """Independently compare the existing private Interface denial probe.

    Transport and original predecessor must be bound by the owning observer.
    This narrow negative witness never proves complete Interface or compute.
    """
    try:
        require(isinstance(raw,bytes) and 0<len(raw)<=65536,'KERNEL_INTERFACE_SIZE_DENIED')
        value=strict_json(raw);source,request=copy.deepcopy((source,request))
        validate_expected_source(source)
        require(isinstance(installed_evidence_sha256,str)
                and re.fullmatch('[0-9a-f]{64}',installed_evidence_sha256)
                and isinstance(observed_at,datetime) and observed_at.utcoffset() is not None,
                'KERNEL_INTERFACE_EXPECTATION_DENIED')
        require(isinstance(request,dict) and set(request)=={'schema','branch','request_id','nonce','previous_evidence_digest'}
                and request['schema']=='SEREIN/KernelBranchWitnessRequest/v1' and request['branch']=='INTERFACE'
                and isinstance(request['previous_evidence_digest'],str)
                and re.fullmatch('[0-9a-f]{64}',request['previous_evidence_digest'])
                and all(isinstance(request[key],str) and 0<len(request[key])<=128
                    and '\x00' not in request[key] for key in ('request_id','nonce')),
                'KERNEL_INTERFACE_REQUEST_DENIED')
        require(set(value)=={'schema','domain','branch','issuer','verdict','issued_at',
                    'request_id','nonce','previous_evidence_digest','source_commit','source_tree',
                    'canonical_manifest_digest','boot_id','facts','facts_digest','uncertainty','authority_effect','evidence_digest'}
                and value['schema']=='SEREIN/KernelBranchDirectWitness/v1' and value['domain']=='KERNEL'
                and value['branch']=='INTERFACE' and value['issuer']=='KERNEL_BRANCH_API'
                and value['verdict']=='UNKNOWN' and value['uncertainty']=='INTERFACE_PHASE_C_UNPROVEN'
                and value['authority_effect']=='NONE' and value['boot_id']==boot_id
                and all(value[key]==source[key] for key in ('source_commit','source_tree','canonical_manifest_digest'))
                and all(value[key]==request[key] for key in ('request_id','nonce','previous_evidence_digest'))
                and value['evidence_digest']==digest({k:v for k,v in value.items() if k!='evidence_digest'}),
                'KERNEL_INTERFACE_BINDING_DENIED')
        facts=value['facts'];probe=facts['observation']
        require(set(facts)=={'source_commit','source_tree','canonical_manifest_digest','boot_id',
                    'observation','audit','phase_c','authority_effect','installed_evidence_sha256'}
                and all(facts[key]==value[key] for key in ('source_commit','source_tree','canonical_manifest_digest','boot_id'))
                and facts['installed_evidence_sha256']==installed_evidence_sha256
                and facts['audit']=='ACK_CORRELATED_NOT_INDEPENDENT_LOG_PROOF'
                and facts['phase_c']=='UNPROVEN' and facts['authority_effect']=='NONE'
                and value['facts_digest']==digest(facts),'KERNEL_INTERFACE_FACTS_DENIED')
        require(set(probe)=={'state','started_at','completed_at','request_sha256','response',
                    'response_sha256','audit','compute','authority_effect'}
                and probe['state']=='PRIVATE_INTERFACE_DENIAL_PROBE_ONLY'
                and probe['request_sha256']==hashlib.sha256(b'{}\n').hexdigest()
                and probe['audit']=='ACK_CORRELATED_NOT_INDEPENDENT_LOG_PROOF'
                and probe['compute']=='NOT_INVOKED' and probe['authority_effect']=='NONE',
                'KERNEL_INTERFACE_PROBE_DENIED')
        reply=probe['response']
        require(set(reply)=={'schema','request_id','status','reason','timestamp'}
                and reply['schema']=='SereinStage1Response/v1' and reply['request_id'] is None
                and reply['status']=='DENIED' and reply['reason']=='gateway_request_denied'
                and probe['response_sha256']==hashlib.sha256(record_bytes(reply)).hexdigest(),
                'KERNEL_INTERFACE_REJECTION_DENIED')
        stamps=[datetime.fromisoformat(stamp.replace('Z','+00:00')) for stamp in
                (probe['started_at'],reply['timestamp'],probe['completed_at'],value['issued_at'])]
        require(all(stamp.utcoffset() is not None and 0<=(observed_at-stamp).total_seconds()<=30 for stamp in stamps)
                and stamps==sorted(stamps) and (stamps[2]-stamps[0]).total_seconds()<=3,
                'KERNEL_INTERFACE_STALE')
        return {'result':'PRIVATE_INTERFACE_DENIAL_CORRELATED','subject_evidence':value,
                'evidence_authentication':'SEPARATE_REQUIRED','phase_c':'UNPROVEN',
                'admission':'UNADMITTED','stage1':'NOT_READY','authority_effect':'NONE'}
    except KernelWitnessError:
        raise
    except (TransactionError,ValueError,TypeError,KeyError,AttributeError,OverflowError) as exc:
        raise KernelWitnessError('KERNEL_INTERFACE_RESPONSE_DENIED') from exc


def compare_retained_compute_response(raw, *, query, source, installed_evidence_sha256,
                                      request, host_state, boot_id, observed_at,
                                      expected_provider_request_sha256, model, model_digest):
    """Compare the existing Operations private readback and retained bytes.

    The caller owns transport/installed unit identity. A response's hashes do
    not authenticate themselves; this pure comparison never claims they do.
    """
    import base64
    try:
        require(isinstance(raw,bytes) and 0<len(raw)<=65536,'KERNEL_COMPUTE_READBACK_SIZE_DENIED')
        value=strict_json(raw);query,source,request=copy.deepcopy((query,source,request))
        validate_expected_source(source)
        require(isinstance(query,dict) and set(query)=={'schema','branch','request_id','nonce',
                'previous_evidence_digest','compute_request_id'}
            and query['schema']=='SEREIN/KernelBranchWitnessRequest/v1' and query['branch']=='OPERATIONS'
            and query['compute_request_id']==request['request_id']
            and isinstance(query['previous_evidence_digest'],str)
            and re.fullmatch('[0-9a-f]{64}',query['previous_evidence_digest'])
            and all(isinstance(query[key],str) and 0<len(query[key])<=128 and '\x00' not in query[key]
                    for key in ('request_id','nonce','compute_request_id'))
            and isinstance(installed_evidence_sha256,str) and re.fullmatch('[0-9a-f]{64}',installed_evidence_sha256),
            'KERNEL_COMPUTE_READBACK_REQUEST_DENIED')
        require(set(value)=={'schema','domain','branch','issuer','verdict','issued_at',
                'request_id','nonce','previous_evidence_digest','source_commit','source_tree',
                'canonical_manifest_digest','boot_id','facts','facts_digest','uncertainty','authority_effect','evidence_digest'}
            and value['schema']=='SEREIN/KernelBranchDirectWitness/v1' and value['domain']=='KERNEL'
            and value['branch']=='OPERATIONS' and value['issuer']=='KERNEL_BRANCH_API'
            and value['verdict']=='UNKNOWN' and value['uncertainty']=='COMPUTE_DOMAIN_UNPROVEN'
            and value['authority_effect']=='NONE' and value['boot_id']==boot_id
            and all(value[key]==source[key] for key in ('source_commit','source_tree','canonical_manifest_digest'))
            and all(value[key]==query[key] for key in ('request_id','nonce','previous_evidence_digest'))
            and value['evidence_digest']==digest({k:v for k,v in value.items() if k!='evidence_digest'}),
            'KERNEL_COMPUTE_READBACK_BINDING_DENIED')
        facts=value['facts'];retained=facts['observation']
        require(set(facts)=={'source_commit','source_tree','canonical_manifest_digest','boot_id',
                'observation','audit','phase_b','authority_effect','installed_evidence_sha256'}
            and all(facts[key]==value[key] for key in ('source_commit','source_tree','canonical_manifest_digest','boot_id'))
            and facts['installed_evidence_sha256']==installed_evidence_sha256
            and facts['audit']=='RETAINED_BYTES_MATCH_AUTHENTICATED_REPLAY' and facts['phase_b']=='UNPROVEN'
            and facts['authority_effect']=='NONE' and value['facts_digest']==digest(facts),
            'KERNEL_COMPUTE_READBACK_FACTS_DENIED')
        require(set(retained)=={'state','observed_at','request_id','conversation_id','payload_sha256',
                'request_sha256','runtime_response_b64','runtime_response_sha256','replay_consumption_sha256',
                'authority_effect','admission_effect','stage1'}
            and retained['state']=='AUTHENTICATED_RETAINED_COMPUTE_ONLY'
            and retained['request_id']==request['request_id'] and retained['conversation_id']==request['conversation_id']
            and retained['payload_sha256']==hashlib.sha256(record_bytes(request)).hexdigest()
            and all(isinstance(retained[key],str) and re.fullmatch('[0-9a-f]{64}',retained[key])
                    for key in ('request_sha256','runtime_response_sha256','replay_consumption_sha256'))
            and retained['authority_effect']==retained['admission_effect']=='NONE' and retained['stage1']=='NOT_READY'
            and isinstance(retained['runtime_response_b64'],str) and len(retained['runtime_response_b64'])<=43692,
            'KERNEL_COMPUTE_RETAINED_BINDING_DENIED')
        runtime=base64.b64decode(retained['runtime_response_b64'],validate=True)
        require(base64.b64encode(runtime).decode('ascii')==retained['runtime_response_b64']
                and strict_json(runtime)['completed_at']==retained['observed_at'],
                'KERNEL_COMPUTE_RETAINED_ENCODING_DENIED')
        issued=datetime.fromisoformat(value['issued_at'].replace('Z','+00:00'))
        completed=datetime.fromisoformat(retained['observed_at'].replace('Z','+00:00'))
        require(observed_at.utcoffset() is not None and issued.utcoffset() is not None
                and completed.utcoffset() is not None and completed<=issued<=observed_at
                and (observed_at-issued).total_seconds()<=30,'KERNEL_COMPUTE_READBACK_STALE')
        result=compare_compute_response(runtime,request=request,host_state=host_state,boot_id=boot_id,
            observed_at=observed_at,expected_result_sha256=retained['runtime_response_sha256'],
            expected_provider_request_sha256=expected_provider_request_sha256,model=model,model_digest=model_digest)
        return {**result,'subject_evidence':value,'replay_consumption_sha256':retained['replay_consumption_sha256']}
    except KernelWitnessError:raise
    except (TransactionError,ValueError,TypeError,KeyError,AttributeError,OverflowError) as exc:
        raise KernelWitnessError('KERNEL_COMPUTE_READBACK_DENIED') from exc


def compare_public_conversation_response(raw, *, runtime_raw, expected_runtime_sha256, request,
                                         external_request=None):
    """Correlate existing public answer bytes; never authenticate their road.

    ADAPT the existing Kernel adapter's ordinary conversation envelope without
    importing subject code. The owner supplies runtime bytes already obtained
    through its independent retained-compute observer. This pure comparison
    cannot prove TLS, real HAOS rendering, GPU custody, or domain admission.
    """
    try:
        require(isinstance(raw, bytes) and 0 < len(raw) <= 65536
                and isinstance(runtime_raw, bytes) and 0 < len(runtime_raw) <= 32768
                and isinstance(expected_runtime_sha256, str)
                and re.fullmatch('[0-9a-f]{64}', expected_runtime_sha256)
                and hashlib.sha256(runtime_raw).hexdigest() == expected_runtime_sha256,
                'KERNEL_PUBLIC_RESPONSE_BYTES_DENIED')
        public = strict_json(raw); runtime = strict_json(runtime_raw)
        request = copy.deepcopy(request)
        chat=request['requested_operation']=='conversation_tools'
        require(request['requested_operation'] in ('conversation_only','conversation_tools')
                and runtime['schema'] == 'SereinStage1ConversationRuntimeResponse/v2'
                and runtime['status'] == 'ANSWERED'
                and runtime['authority_effect'] == 'NONE' and runtime['effects'] == []
                and runtime['request_id'] == request['request_id']
                and runtime['conversation_id'] == request['conversation_id'],
                'KERNEL_PUBLIC_RUNTIME_BINDING_DENIED')
        if chat:
            from uuid import UUID
            # This is an explicit independently captured input, never an ID or
            # original timestamp inferred from the response being inspected.
            require(isinstance(external_request,dict)
                    and set(external_request)==set(request)-{'schema'}
                    and canonical({k:v for k,v in external_request.items() if k!='request_id'})
                       ==canonical({k:v for k,v in request.items() if k not in ('schema','request_id')}),
                    'KERNEL_PUBLIC_ORIGINAL_REQUEST_REQUIRED')
            external_id=UUID(external_request['request_id']);internal_id=UUID(request['request_id'])
            require(str(external_id)==external_request['request_id']
                    and str(internal_id)==request['request_id'] and internal_id.version==4
                    and internal_id!=external_id,'KERNEL_PUBLIC_ROUND_ID_DENIED')
            message=runtime['message'];continuation=runtime['continue_conversation']
            require(isinstance(message,dict) and message.get('role')=='assistant'
                    and not set(message)-{'role','content','tool_calls'}
                    and isinstance(message.get('content'),str) and len(message['content'])<=4096
                    and '\x00' not in message['content'] and type(continuation) is bool
                    and continuation==bool(message.get('tool_calls')),
                    'KERNEL_PUBLIC_ANSWER_DENIED')
            public_id=external_request['request_id']
        else:
            require(external_request is None and runtime['state']=='READY'
                    and runtime['scope']=='stage1-bounded-companion','KERNEL_PUBLIC_RUNTIME_BINDING_DENIED')
            answer=runtime['response']
            require(isinstance(answer,str) and 0<len(answer)<=4096 and '\x00' not in answer
                    and answer==' '.join(answer.split()),'KERNEL_PUBLIC_ANSWER_DENIED')
            message={'role':'assistant','content':answer};continuation=False;public_id=request['request_id']
        expected = {'status': 'ANSWERED', 'request_id': public_id,
                    'conversation_id': request['conversation_id'],
                    'message':message,'continue_conversation':continuation,
                    'authority_effect':'NONE','effects':[]}
        # Canonical byte comparison distinguishes JSON false from numeric zero.
        require(canonical(public) == canonical(expected), 'KERNEL_PUBLIC_RESPONSE_MISMATCH')
        return {'result': 'PUBLIC_RESPONSE_BYTES_CORRELATED',
                'request_id': public_id, 'conversation_id': request['conversation_id'],
                'public_response_sha256': hashlib.sha256(raw).hexdigest(),
                'runtime_result_sha256': expected_runtime_sha256,
                'canonical_edge': 'UNPROVEN', 'haos_render': 'UNPROVEN',
                'evidence_authentication': 'SEPARATE_REQUIRED',
                'stage1': 'NOT_READY', 'authority_effect': 'NONE', 'admission_effect': 'NONE'}
    except KernelWitnessError:
        raise
    except (TransactionError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
        raise KernelWitnessError('KERNEL_PUBLIC_RESPONSE_DENIED') from exc


def validate_compute_inputs(*,request,expected_provider_request_sha256,model,model_digest):
    """Pure existing request grammar, shared by pre-effect owner and reader.

    This checks syntax only. It neither originates nor authenticates a request;
    currentness, source provenance and result correlation remain readback gates.
    """
    require(isinstance(request,dict),'KERNEL_COMPUTE_REQUEST_DENIED')
    chat=request.get('requested_operation')=='conversation_tools'
    fields={'schema','request_id','conversation_id','machine_identity','requested_operation','observed_at'}
    fields|={'messages','tools'} if chat else {'utterance'}
    require(set(request)==fields
            and request['schema']=='SereinStage1ConversationRuntimeRequest/v1'
            and request['requested_operation'] in ('conversation_only','conversation_tools'),
            'KERNEL_COMPUTE_REQUEST_DENIED')
    for name,maximum in (('request_id',128),('conversation_id',256),('machine_identity',128),('utterance',1024)):
        if chat and name=='utterance':continue
        require(isinstance(request[name],str) and request[name].strip()
                and len(request[name])<=maximum and '\x00' not in request[name],
                'KERNEL_COMPUTE_REQUEST_DENIED')
    if chat:
        require(isinstance(request['messages'],list) and 0<len(request['messages'])<=128
                and isinstance(request['tools'],list),'KERNEL_COMPUTE_CHAT_DENIED')
        allowed={'GetDateTime','GetLiveContext'};offered=set();pending=set();seen=set()
        for tool in request['tools']:
            require(isinstance(tool,dict) and set(tool)=={'type','function'}
                    and tool['type']=='function' and isinstance(tool['function'],dict),
                    'KERNEL_COMPUTE_CHAT_DENIED')
            name=tool['function'].get('name')
            require(isinstance(name,str) and name in allowed and name not in offered,
                    'KERNEL_COMPUTE_CHAT_SCOPE_DENIED');offered.add(name)
        for message in request['messages']:
            require(isinstance(message,dict) and message.get('role') in ('system','user','assistant','tool')
                    and not set(message)-{'role','content','tool_calls','tool_call_id'},
                    'KERNEL_COMPUTE_CHAT_DENIED')
            require(message.get('content') is None or isinstance(message['content'],str)
                    and '\x00' not in message['content'],'KERNEL_COMPUTE_CHAT_DENIED')
            calls=message.get('tool_calls',[])
            require(isinstance(calls,list) and len(calls)<=8,'KERNEL_COMPUTE_CHAT_DENIED')
            for call in calls:
                require(message['role']=='assistant' and isinstance(call,dict)
                        and set(call)=={'id','function'} and isinstance(call['id'],str)
                        and call['id'] and call['id'] not in seen
                        and isinstance(call['function'],dict)
                        and set(call['function'])=={'name','arguments'}
                        and call['function']['name'] in allowed
                        and isinstance(call['function']['arguments'],dict)
                        and len(canonical(call['function']['arguments']))<=16384,
                        'KERNEL_COMPUTE_CHAT_SCOPE_DENIED')
                seen.add(call['id']);pending.add(call['id'])
            if message['role']=='tool':
                require(message.get('tool_call_id') in pending,'KERNEL_COMPUTE_CHAT_CORRELATION_DENIED')
                pending.remove(message['tool_call_id'])
        require(not pending,'KERNEL_COMPUTE_CHAT_CORRELATION_DENIED')
    require(isinstance(model,str) and model and '\x00' not in model
            and isinstance(model_digest,str) and re.fullmatch('[0-9a-f]{64}',model_digest),
            'KERNEL_COMPUTE_MODEL_DENIED')
    require(isinstance(expected_provider_request_sha256,str)
            and re.fullmatch('[0-9a-f]{64}',expected_provider_request_sha256),
            'KERNEL_COMPUTE_FACTS_DIGEST_DENIED')
    try:
        require(isinstance(request['observed_at'],str)
                and datetime.fromisoformat(request['observed_at'].replace('Z','+00:00')).utcoffset() is not None,
                'KERNEL_COMPUTE_CHRONOLOGY_DENIED')
    except (ValueError,TypeError,OverflowError) as exc:
        raise KernelWitnessError('KERNEL_COMPUTE_CHRONOLOGY_DENIED') from exc
    require(len(record_bytes({'request':request,'expected_provider_request_sha256':
            expected_provider_request_sha256,'model':model,'model_digest':model_digest}))<=65536,
            'KERNEL_OBSERVER_INPUT_BOUND_DENIED')


def compare_compute_response(raw, *, request, host_state, boot_id, observed_at,
                             expected_result_sha256, expected_provider_request_sha256,
                             model, model_digest):
    """Independent semantic check, not authentication, GPU custody or admission.

    The owning observer must obtain the expected result digest from authenticated
    Operations evidence, the provider-request digest from the exact source-bound
    request recipe, and Host state from current_host_gate. These expectations
    must not be learned from this response. This comparison alone establishes
    none of their provenance. Never import/execute subject code.
    """
    from .host_vitality import validate_state
    try:
        require(isinstance(raw,bytes) and 0<len(raw)<=32768
                and re.fullmatch('[0-9a-f]{64}',expected_result_sha256)
                and hashlib.sha256(raw).hexdigest()==expected_result_sha256,
                'KERNEL_COMPUTE_RESULT_DIGEST_DENIED')
        value=strict_json(raw)
        request=copy.deepcopy(request);host=validate_state(copy.deepcopy(host_state),active=True)
        require(host['current_boot_id']==boot_id and host['classification'] in
                {'CURRENT_BOOT_STABLE','FIRST_BOOT_OBSERVED','RECOVERED_AFTER_BOOT_CHANGE'},
                'KERNEL_COMPUTE_HOST_DENIED')
        require(isinstance(observed_at,datetime) and observed_at.utcoffset() is not None,
                'KERNEL_COMPUTE_CLOCK_DENIED')
        validate_compute_inputs(request=request,expected_provider_request_sha256=expected_provider_request_sha256,
                                model=model,model_digest=model_digest)
        chat=request['requested_operation']=='conversation_tools'
        response_fields={'schema','request_id','conversation_id','status','compute_observation',
                         'completed_at','authority_effect','effects'}
        response_fields|={'message','continue_conversation','invocation'} if chat else {'state','response','scope'}
        require(isinstance(value,dict) and set(value)==response_fields
                and value['schema']=='SereinStage1ConversationRuntimeResponse/v2'
                and value['status']=='ANSWERED'
                and value['request_id']==request['request_id']
                and value['conversation_id']==request['conversation_id']
                and value['authority_effect']=='NONE' and value['effects']==[],
                'KERNEL_COMPUTE_RESPONSE_DENIED')
        facts=value['compute_observation']
        invocation={'request_id':request['request_id'],'conversation_id':request['conversation_id'],
                    'runtime_request_sha256':hashlib.sha256(record_bytes(request)).hexdigest()}
        digest_key='message_sha256' if chat else 'answer_sha256'
        if chat:
            answer=value['message']
            require(isinstance(answer,dict) and not set(answer)-{'role','content','tool_calls'}
                    and answer.get('role')=='assistant' and isinstance(answer.get('content'),str)
                    and len(answer['content'])<=4096 and '\x00' not in answer['content']
                    and value['invocation']==invocation and type(value['continue_conversation']) is bool,
                    'KERNEL_COMPUTE_ANSWER_DENIED')
            calls=answer.get('tool_calls',[])
            require(isinstance(calls,list) and len(calls)<=8 and (answer['content'] or calls)
                    and value['continue_conversation']==bool(calls),'KERNEL_COMPUTE_ANSWER_DENIED')
            offered={tool['function']['name'] for tool in request['tools']}
            seen={call['id'] for row in request['messages'] for call in row.get('tool_calls',[])}
            for call in calls:
                require(isinstance(call,dict) and set(call)=={'id','function'}
                        and isinstance(call['id'],str) and call['id'] and call['id'] not in seen
                        and isinstance(call['function'],dict) and set(call['function'])=={'name','arguments'}
                        and call['function']['name'] in offered and isinstance(call['function']['arguments'],dict)
                        and len(canonical(call['function']['arguments']))<=16384,
                        'KERNEL_COMPUTE_ANSWER_DENIED');seen.add(call['id'])
            require(sum(len(canonical(call['function']['arguments'])) for call in calls)<=32768,
                    'KERNEL_COMPUTE_ANSWER_DENIED')
            answer_bytes=canonical(answer)
        else:
            answer=value['response']
            require(value['state']=='READY' and value['scope']=='stage1-bounded-companion'
                    and isinstance(answer,str) and 0<len(answer)<=4096 and '\x00' not in answer
                    and answer==' '.join(answer.split()),'KERNEL_COMPUTE_ANSWER_DENIED')
            answer_bytes=answer.encode()
        fields={'schema','state','model','model_digest','provider','started_at','completed_at',
            'request_sha256','provider_response_canonical_sha256',digest_key,'gpu_before',
            'gpu_after','model_tags_before','model_tags_after','model_residency_after',
            'alternate_provider_requested','alternate_model_requested','cpu_fallback_requested',
            'runtime_cpu_fallback','gpu_control','authority_effect','admission_effect','invocation'}
        require(isinstance(facts,dict) and set(facts)==fields
                and facts['schema']==('SereinCompanionComputeObservation/v2' if chat else 'SereinCompanionComputeObservation/v1')
                and facts['state']=='OBSERVED_NOT_CONTROL_OR_ADMISSION'
                and facts['model']==model and facts['model_digest']==model_digest
                and facts['provider']==('http://127.0.0.1:11434/api/chat' if chat else 'http://127.0.0.1:11434/api/generate')
                and facts['invocation']==invocation
                and facts['authority_effect']==facts['admission_effect']=='NONE'
                and facts['gpu_control']==facts['runtime_cpu_fallback']=='UNPROVEN'
                and all(facts[name] is False for name in ('alternate_provider_requested',
                    'alternate_model_requested','cpu_fallback_requested')),
                'KERNEL_COMPUTE_FACTS_DENIED')
        require(isinstance(expected_provider_request_sha256,str)
                and re.fullmatch('[0-9a-f]{64}',expected_provider_request_sha256)
                and facts['request_sha256']==expected_provider_request_sha256
                and all(isinstance(facts[name],str) and re.fullmatch('[0-9a-f]{64}',facts[name])
                    for name in ('request_sha256','provider_response_canonical_sha256',digest_key))
                and facts[digest_key]==hashlib.sha256(answer_bytes).hexdigest(),
                'KERNEL_COMPUTE_FACTS_DIGEST_DENIED')
        times=[datetime.fromisoformat(item.replace('Z','+00:00')) for item in
               (request['observed_at'],facts['started_at'],facts['completed_at'],value['completed_at'])]
        require(all(item.utcoffset() is not None for item in times)
                and times[1]<=times[2] and all(-5<=(observed_at-item).total_seconds()<=120 for item in times)
                and (times[0]-times[1]).total_seconds()<=5
                and (times[2]-times[3]).total_seconds()<=5,
                'KERNEL_COMPUTE_CHRONOLOGY_DENIED')
        latest=host['latest'];gpu=facts['gpu_before']
        require(latest['boot_id']==boot_id and latest['gpu']['status']=='PASS'
                and latest['gpu']['pci_present'] is True and latest['gpu']['driver_loaded'] is True
                and 0<=observed_at.timestamp()-latest['observed_at']<=120,
                'KERNEL_COMPUTE_HOST_DENIED')
        require(isinstance(gpu,dict) and set(gpu)=={'schema','boot_id','device_count',
                'driver_loaded','gpu_inventory_sha256','authority_effect','inventory'}
                and gpu==facts['gpu_after'] and gpu['schema']=='SEREIN/KernelGPUControlWitness/v1'
                and gpu['boot_id']==boot_id and gpu['driver_loaded'] is True
                and gpu['authority_effect']=='NONE' and type(gpu['device_count']) is int
                and gpu['device_count']==latest['gpu']['device_count']>0,
                'KERNEL_COMPUTE_GPU_DENIED')
        inventory=gpu['inventory']
        require(isinstance(inventory,dict) and set(inventory)=={'pci_devices','nvidia_smi'}
                and all(isinstance(inventory[name],list) for name in inventory)
                and len(inventory['pci_devices'])==len(inventory['nvidia_smi'])==gpu['device_count']
                and gpu['gpu_inventory_sha256']==hashlib.sha256(record_bytes(inventory)).hexdigest(),
                'KERNEL_COMPUTE_GPU_INVENTORY_DENIED')
        def pci(text):
            match=re.fullmatch(r'([0-9a-fA-F]{4,8}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])',text)
            require(match is not None,'KERNEL_COMPUTE_GPU_PCI_DENIED')
            parts=tuple(int(part,16) for part in match.groups())
            require(parts[2]<=31,'KERNEL_COMPUTE_GPU_PCI_DENIED')
            return parts
        devices={pci(item) for item in inventory['pci_devices']};seen=set();uuids=set()
        for row in csv.reader(inventory['nvidia_smi'],skipinitialspace=True,strict=True):
            require(len(row)==4,'KERNEL_COMPUTE_GPU_ROW_DENIED')
            bus,uuid,name,driver=(item.strip() for item in row);bus=pci(bus)
            require(bus not in seen and uuid not in uuids and name and '\x00' not in ''.join(row)
                    and re.fullmatch(r'GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',uuid)
                    and re.fullmatch(r'[0-9]+(?:\.[0-9]+)+',driver),'KERNEL_COMPUTE_GPU_ROW_DENIED')
            seen.add(bus);uuids.add(uuid)
        require(seen==devices and len(devices)==gpu['device_count'],'KERNEL_COMPUTE_GPU_PCI_DENIED')
        for name in ('model_tags_before','model_tags_after'):
            tags=facts[name]
            require(isinstance(tags,dict) and set(tags)=={'models'} and isinstance(tags['models'],list)
                    and len(tags['models'])==1 and tags['models'][0]['model']==model
                    and tags['models'][0]['digest']==model_digest,'KERNEL_COMPUTE_MODEL_DENIED')
        resident=facts['model_residency_after']
        require(resident['model']==model and resident['digest']==model_digest
                and type(resident['size_vram']) is int and resident['size_vram']>0,
                'KERNEL_COMPUTE_RESIDENCY_DENIED')
        return {'result':'MEASURED_COMPUTE_CORRELATED','host_gpu_prerequisite':'MATCH',
                'host_projection_digest':host['projection_digest'],
                'runtime_result_sha256':expected_result_sha256,
                'runtime_request_sha256':facts['invocation']['runtime_request_sha256'],
                'gpu_control':'UNPROVEN','runtime_cpu_fallback':'UNPROVEN',
                'evidence_authentication':'SEPARATE_REQUIRED','stage1':'NOT_READY',
                'authority_effect':'NONE','admission_effect':'NONE'}
    except KernelWitnessError:
        raise
    except (ValueError,TypeError,KeyError,AttributeError,TransactionError,csv.Error) as exc:
        raise KernelWitnessError('KERNEL_COMPUTE_EVIDENCE_DENIED') from exc


def expected_identity(identity, anchor, source):
    """Verify birth registry signatures without confusing them with payload source.

    The installer-owned caller authenticates the optional public origin against
    its signed current plan/projection. Never derive that expectation from the
    subject registry. Current source/policy and possession checks stay separate.
    """
    try:
        require(hashlib.sha256(anchor).hexdigest() == CANONICAL_AUTHORITY_SHA256,
                "KERNEL_INSTALLER_ANCHOR_DENIED")
        require(isinstance(identity, dict) and set(identity) in (
                    {"binding", "registry"}, {"binding", "registry", "installation_origin"}),
                "KERNEL_EXPECTED_IDENTITY_DENIED")
        binding, registry = identity["binding"], identity["registry"]
        require(isinstance(binding, dict) and set(binding) == {
            "schema", "instance_id", "checkpoint", "registry_sha256", "private_sha256",
            "public_key", "transaction_context"} and binding["schema"] == "SereinKernelNativeIdentityMaterial/v1",
            "KERNEL_EXPECTED_IDENTITY_DENIED")
        require(isinstance(registry, dict) and set(registry) == {"schema", "records"}
                and registry["schema"] == "SereinDomainIdentityRegistry/v1"
                and hashlib.sha256(record_bytes(registry)).hexdigest() == binding["registry_sha256"],
                "KERNEL_EXPECTED_REGISTRY_DENIED")
        records = registry["records"]
        require(isinstance(records, list) and len(records) == 1
                and hashlib.sha256(record_bytes(records)).hexdigest() == binding["checkpoint"],
                "KERNEL_EXPECTED_CHECKPOINT_DENIED")
        record = records[0]
        require(isinstance(record, dict) and set(record) == {
            "body", "installer_signature", "domain_signature", "prior_key_signature"}
            and record["prior_key_signature"] is None, "KERNEL_EXPECTED_RECORD_DENIED")
        body = record["body"]
        require(re.fullmatch(r"[0-9a-f]{16}", binding["instance_id"])
                and all(re.fullmatch(r"[0-9a-f]{64}", binding[key]) for key in (
                    "checkpoint", "registry_sha256", "private_sha256", "public_key", "transaction_context")),
                "KERNEL_EXPECTED_IDENTITY_DENIED")
        birth_commit = source['source_commit']
        if 'installation_origin' in identity:
            origin = identity['installation_origin']
            require(isinstance(origin, dict) and set(origin) == {
                        'plan_sha256','source_generation','native_identity','host_identity_file','boot_id'}
                    and isinstance(origin['plan_sha256'],str)
                    and re.fullmatch(r'[0-9a-f]{64}',origin['plan_sha256'])
                    and origin['native_identity'] == {key:binding[key] for key in
                        ('instance_id','checkpoint','registry_sha256','transaction_context')}
                    and isinstance(origin['source_generation'],dict)
                    and set(origin['source_generation']) == {'parent','commit','tree'}
                    and all(isinstance(value,str) and re.fullmatch(r'[0-9a-f]{40}',value)
                            for value in origin['source_generation'].values())
                    and isinstance(origin['boot_id'],str)
                    and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',origin['boot_id']),
                    'KERNEL_EXPECTED_ORIGIN_DENIED')
            host = origin['host_identity_file']
            require(isinstance(host,dict) and set(host) == {
                        'target','state','bytes','sha256','mode','uid','gid','device','inode','nlink'}
                    and host['target']=='/etc/machine-id' and host['state']=='PRESENT_PRESERVED'
                    and host['mode'] in ('0444','0644')
                    and isinstance(host['sha256'],str) and re.fullmatch(r'[0-9a-f]{64}',host['sha256'])
                    and all(type(host[key]) is int and host[key]>=0 for key in
                            ('bytes','uid','gid','device','inode','nlink'))
                    and host['uid']==host['gid']==0 and host['nlink']==1,
                    'KERNEL_EXPECTED_ORIGIN_DENIED')
            birth_commit = origin['source_generation']['commit']
        expected = {"schema": "SereinDomainIdentityRecord/v1", "domain": "KERNEL",
                    "instance_id": binding["instance_id"], "operation": "INSTALL", "revision": 0,
                    "prior_record": None, "replaces_instance_id": None, "public_key": binding["public_key"],
                    "key_fingerprint": hashlib.sha256(bytes.fromhex(binding["public_key"])).hexdigest(),
                    "source_commit": birth_commit, "governance_receipt": binding["transaction_context"],
                    "authority_effect": "NONE", "admission_effect": "NONE"}
        require(body == expected and type(body["revision"]) is int, "KERNEL_EXPECTED_RECORD_DENIED")
        load_pem_public_key(anchor).verify(bytes.fromhex(record["installer_signature"]), record_bytes(body))
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(body["public_key"])).verify(
            bytes.fromhex(record["domain_signature"]), record_bytes(body))
    except KernelWitnessError:
        raise
    except Exception as exc:
        raise KernelWitnessError("KERNEL_EXPECTED_IDENTITY_CRYPTO_DENIED") from exc
    return body


def validate_expected_source(source):
    """Installer-owned public expectations, never learned from the subject."""
    require(isinstance(source,dict) and set(source)=={
        'source_commit','source_tree','canonical_manifest_digest','conversation_policy'}
        and all(isinstance(source[key],str) and re.fullmatch('[0-9a-f]{40}',source[key])
                for key in ('source_commit','source_tree'))
        and isinstance(source['canonical_manifest_digest'],str)
        and re.fullmatch('[0-9a-f]{64}',source['canonical_manifest_digest']),
        'KERNEL_EXPECTED_SOURCE_DENIED')
    policy=source['conversation_policy']
    require(isinstance(policy,dict) and set(policy)=={
        'path','source','sha256','plan_sha256','state','authority_effect','admission_effect'}
        and policy['path']=='/usr/lib/python3/dist-packages/serein_stage1/stage1-conversation-policy.v1.json'
        and policy['source']=='payload/serein_stage1/stage1-conversation-policy.v1.json'
        and all(isinstance(policy[key],str) and re.fullmatch('[0-9a-f]{64}',policy[key])
                for key in ('sha256','plan_sha256'))
        and policy['state']=='SIGNED_INSTALLED_POLICY_NOT_RUNTIME_ADMISSION'
        and policy['authority_effect']==policy['admission_effect']=='NONE',
        'KERNEL_EXPECTED_CONVERSATION_POLICY_DENIED')


def validate_authority_response(value, *, request, source, boot_id, observed_at, identity, anchor, host_machine_id):
    validate_expected_source(source)
    required = {"schema", "domain", "branch", "verdict", "issuer", "issued_at", "request_id", "nonce",
                "previous_evidence_digest", "source_commit", "source_tree", "canonical_manifest_digest",
                "boot_id", "facts_digest", "phase_a", "api_health", "uncertainty", "authority_effect",
                "native_identity_proof", "boot_decision", "frame_identity", "conversation_policy", "evidence_digest"}
    require(isinstance(value, dict) and set(value) == required, "KERNEL_RESPONSE_SHAPE_DENIED")
    require(all(isinstance(value[key], str) for key in required - {"phase_a", "native_identity_proof", "boot_decision", "frame_identity", "conversation_policy"}),
            "KERNEL_RESPONSE_SHAPE_DENIED")
    body = {key: item for key, item in value.items() if key != "evidence_digest"}
    require(value["schema"] == "SEREIN/KernelBranchDirectWitness/v2" and value["domain"] == "KERNEL"
            and value["branch"] == "AUTHORITY" and value["verdict"] in {"PASS", "FAIL", "UNKNOWN"}
            and value["issuer"] == "KERNEL_AUTHORITY_API" and value["boot_id"] == boot_id
            and value["previous_evidence_digest"] == request["previous_evidence_digest"] == "GENESIS"
            and value["request_id"] == request["request_id"] and value["nonce"] == request["nonce"]
            and all(value[key] == source[key] for key in source)
            and re.fullmatch(r"[0-9a-f]{64}", str(value["facts_digest"]))
            and value["authority_effect"] == "NONE" and value["evidence_digest"] == digest(body),
            "KERNEL_AUTHORITY_RESPONSE_DENIED")
    try:
        frame = value["frame_identity"]
        require(isinstance(host_machine_id, str) and re.fullmatch(r"[0-9a-f]{32}", host_machine_id)
                and host_machine_id != "0"*32 and isinstance(frame, dict)
                and set(frame) == {"machine_id", "boot_id", "host_projection_digest"}
                and frame["machine_id"] == host_machine_id and frame["boot_id"] == boot_id
                and isinstance(frame["host_projection_digest"], str)
                and re.fullmatch(r"[0-9a-f]{64}", frame["host_projection_digest"]),
                "KERNEL_FRAME_IDENTITY_DENIED")
        decision = value["boot_decision"]
        require(decision == {"schema": "SereinAuthorityBootDecision/v1",
                "mode": "PRIVATE_VALIDATION_ONLY", "allowed_effects": ["OBSERVE_AUTHORITY"],
                "privileged_execution": False, "branch_advance": False,
                "authority_effect": "NONE", "admission_effect": "NONE"}
                and decision["privileged_execution"] is False and decision["branch_advance"] is False,
                "KERNEL_BOOT_DECISION_DENIED")
        issued = datetime.fromisoformat(value["issued_at"].replace("Z", "+00:00"))
        require(issued.tzinfo is not None and 0 <= (observed_at-issued).total_seconds() <= 30,
                "KERNEL_AUTHORITY_STALE")
        checks = value["phase_a"]
        require(isinstance(checks, list) and len(checks) == len(PHASE_A_CHECKS)
                and all(isinstance(row, dict) and set(row) == {"name", "verdict"} and row["name"] == name
                        and row["verdict"] in {"PASS", "FAIL", "UNKNOWN"}
                        for row, name in zip(checks, PHASE_A_CHECKS)), "KERNEL_PHASE_A_SHAPE_DENIED")
        complete = value["api_health"] == "READY" and all(row["verdict"] == "PASS" for row in checks)
        verdict = "PASS" if complete else ("FAIL" if any(row["verdict"] == "FAIL" for row in checks) else "UNKNOWN")
        require(value["api_health"] in {"READY", "UNKNOWN", "DENIED"}
                and value["verdict"] == verdict
                and value["uncertainty"] == ("NONE" if complete else "PHASE_A_UNPROVEN"),
                "KERNEL_PHASE_A_VERDICT_DENIED")
        admitted = expected_identity(identity, anchor, source)
        native = value["native_identity_proof"]
        require(isinstance(native, dict) and set(native) == {
            "schema", "instance_id", "checkpoint", "key_fingerprint", "possession_signature"}
            and native["schema"] == "SereinNativeIdentityPossession/v1"
            and native["instance_id"] == admitted["instance_id"]
            and native["checkpoint"] == identity["binding"]["checkpoint"]
            and native["key_fingerprint"] == admitted["key_fingerprint"],
            "KERNEL_POSSESSION_BINDING_DENIED")
        unsigned = {**body, "native_identity_proof": {
            key: item for key, item in native.items() if key != "possession_signature"}}
        challenge = hashlib.sha256(canonical({"request": request, "witness": unsigned})).digest()
        envelope = {"domain": "KERNEL", "instance_id": native["instance_id"],
                    "checkpoint": native["checkpoint"], "challenge": challenge.hex()}
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(admitted["public_key"])).verify(
            bytes.fromhex(native["possession_signature"]), record_bytes(envelope))
    except KernelWitnessError:
        raise
    except Exception as exc:
        raise KernelWitnessError("KERNEL_AUTHORITY_PROOF_DENIED") from exc
    return value


def validate_authority_observation(raw, *, source, identity, request, boot_id,
                                   observed_at, anchor, host_machine_id):
    """Validate an existing observer result against installer-owned expectations.

    This authenticates the signed subject and checks the enclosing observation;
    its unkeyed digest does NOT authenticate the Outpost process. The caller must
    obtain the bytes from its trusted observer execution, not from Kernel or an
    arbitrary uploaded receipt. No admission or service effect is performed.
    """
    try:
        require(isinstance(raw, bytes) and 0 < len(raw) <= 131072,
                'KERNEL_OBSERVATION_SIZE_DENIED')
        value = strict_json(raw)
        source, identity, request = copy.deepcopy((source, identity, request))
        validate_expected_source(source)
        require(isinstance(request, dict) and set(request) == {
                    'schema', 'branch', 'request_id', 'nonce', 'previous_evidence_digest'}
                and request['schema'] == 'SEREIN/KernelBranchWitnessRequest/v1'
                and request['branch'] == 'AUTHORITY'
                and request['previous_evidence_digest'] == 'GENESIS'
                and all(isinstance(request[key], str) and 0 < len(request[key]) <= 128
                        for key in ('request_id', 'nonce')), 'KERNEL_REQUEST_DENIED')
        required = {'schema', 'issuer', 'subject_issuer', 'branch', 'boot_id', 'source',
                    'request', 'observed_at', 'subject_evidence', 'identity_possession',
                    'result', 'admission', 'stage1', 'authority_effect', 'observation_digest'}
        require(isinstance(value, dict) and set(value) == required,
                'KERNEL_OBSERVATION_SHAPE_DENIED')
        require(value['schema'] == 'SereinOutpostKernelAuthorityObservation/v2'
                and value['issuer'] == 'OUTPOST_DIRECT_WITNESS'
                and value['subject_issuer'] == 'KERNEL_AUTHORITY_API'
                and value['branch'] == 'AUTHORITY' and value['boot_id'] == boot_id
                and value['source'] == source and value['request'] == request
                and value['identity_possession'] == 'VERIFIED'
                and value['stage1'] == 'NOT_READY' and value['authority_effect'] == 'NONE'
                and value['observation_digest'] == digest({k: v for k, v in value.items()
                                                          if k != 'observation_digest'}),
                'KERNEL_OBSERVATION_BINDING_DENIED')
        require(isinstance(observed_at, datetime) and observed_at.utcoffset() is not None
                and isinstance(value['observed_at'], str), 'KERNEL_OBSERVATION_CLOCK_DENIED')
        stamp = datetime.fromisoformat(value['observed_at'].replace('Z', '+00:00'))
        require(stamp.utcoffset() is not None and 0 <= (observed_at-stamp).total_seconds() <= 30,
                'KERNEL_OBSERVATION_STALE')
        # Recheck at consumption time as well as the claimed observation time:
        # an old signed subject cannot be renewed by changing the wrapper.
        for clock in (stamp, observed_at):
            validate_authority_response(value['subject_evidence'], request=request, source=source,
                boot_id=boot_id, observed_at=clock, identity=identity, anchor=anchor,
                host_machine_id=host_machine_id)
        passed = value['subject_evidence']['verdict'] == 'PASS'
        require(value['result'] == ('AUTHORITY_PHASE_A_OBSERVED' if passed else 'AUTHORITY_IDENTITY_OBSERVED')
                and value['admission'] == ('INDEPENDENT_VALIDATION_PENDING' if passed else 'UNADMITTED'),
                'KERNEL_OBSERVATION_VERDICT_DENIED')
        return value
    except KernelWitnessError:
        raise
    except (TransactionError, ValueError, TypeError, KeyError) as exc:
        raise KernelWitnessError('KERNEL_OBSERVATION_DENIED') from exc


def observe_authority(*, source, identity, socket_path=SOCKET, boot_path=BOOT, anchor_path=ANCHOR, host_path=HOST_STATE, request=None):
    source, identity = copy.deepcopy(source), copy.deepcopy(identity)
    validate_expected_source(source)
    anchor = regular(Path(anchor_path))
    expected_identity(identity, anchor, source)
    account = pwd.getpwnam("serein-outpost")
    require(os.geteuid() == account.pw_uid, "OUTPOST_OBSERVER_IDENTITY_DENIED")
    path, boot_path = Path(socket_path), Path(boot_path)
    require(not path.is_symlink() and all(not parent.is_symlink() for parent in path.parents), "KERNEL_SOCKET_PATH_DENIED")
    info = path.lstat()
    require(stat.S_ISSOCK(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
            == (account.pw_uid, account.pw_gid, 0o600), "KERNEL_SOCKET_CUSTODY_DENIED")
    boot_id = boot_path.read_text(encoding="ascii").strip()
    require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot_id), "KERNEL_BOOT_IDENTITY_DENIED")
    host = current_host_gate(Path(host_path), boot_id)
    host_machine_id = host["latest"]["host"]["machine_id"]
    request = copy.deepcopy(request) if request is not None else {
        "schema": "SEREIN/KernelBranchWitnessRequest/v1", "branch": "AUTHORITY",
        "request_id": "kernel-authority-"+secrets.token_hex(16), "nonce": secrets.token_hex(32),
        "previous_evidence_digest": "GENESIS"}
    require(isinstance(request, dict) and set(request) == {"schema", "branch", "request_id", "nonce", "previous_evidence_digest"}
            and request["schema"] == "SEREIN/KernelBranchWitnessRequest/v1" and request["branch"] == "AUTHORITY"
            and request["previous_evidence_digest"] == "GENESIS"
            and all(isinstance(request[key], str) and 0 < len(request[key]) <= 128
                    for key in ("request_id", "nonce")), "KERNEL_REQUEST_DENIED")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            deadline = time.monotonic() + 3
            def remaining():
                seconds = deadline - time.monotonic()
                require(seconds > 0, 'KERNEL_RESPONSE_DEADLINE_DENIED')
                client.settimeout(seconds)
            remaining()
            client.connect(str(path))
            server_uid = struct.unpack("3i", client.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]
            require(server_uid == 0, "KERNEL_SERVER_IDENTITY_DENIED")
            after = path.lstat()
            require((info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid) ==
                    (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid), "KERNEL_SOCKET_CHANGED")
            remaining()
            client.sendall(canonical(request)+b"\n")
            raw = b""
            while not raw.endswith(b"\n") and len(raw) <= 65536:
                remaining()
                chunk = client.recv(min(4096, 65537-len(raw)))
                if not chunk:
                    break
                raw += chunk
    except OSError as exc:
        raise KernelWitnessError("KERNEL_TRANSPORT_UNAVAILABLE") from exc
    require(raw.endswith(b"\n") and len(raw) <= 65536, "KERNEL_RESPONSE_FRAMING_DENIED")
    try:
        value = strict_json(raw)
    except TransactionError as exc:
        raise KernelWitnessError("KERNEL_RESPONSE_JSON_DENIED") from exc
    observed = datetime.now(timezone.utc)
    validate_authority_response(value, request=request, source=source, boot_id=boot_id,
                                observed_at=observed, identity=identity, anchor=anchor,
                                host_machine_id=host_machine_id)
    require(boot_path.read_text(encoding="ascii").strip() == boot_id
            and regular(Path(anchor_path)) == anchor, "KERNEL_OBSERVATION_CHANGED")
    require(current_host_gate(Path(host_path), boot_id)["latest"]["host"]["machine_id"] == host_machine_id,
            "KERNEL_FRAME_IDENTITY_CHANGED")
    body = {"schema": "SereinOutpostKernelAuthorityObservation/v2", "issuer": "OUTPOST_DIRECT_WITNESS",
            "subject_issuer": "KERNEL_AUTHORITY_API", "branch": "AUTHORITY", "boot_id": boot_id,
            "source": source, "request": request, "observed_at": observed.isoformat(),
            "subject_evidence": value, "identity_possession": "VERIFIED",
            "result": "AUTHORITY_PHASE_A_OBSERVED" if value["verdict"] == "PASS" else "AUTHORITY_IDENTITY_OBSERVED",
            "admission": "INDEPENDENT_VALIDATION_PENDING" if value["verdict"] == "PASS" else "UNADMITTED",
            "stage1": "NOT_READY", "authority_effect": "NONE"}
    return {**body, "observation_digest": digest(body)}


def observe_operations(*, source, identity, installed_evidence_sha256,
                       authority_observation, socket_path=OPERATIONS_SOCKET,
                       boot_path=BOOT, anchor_path=ANCHOR, host_path=HOST_STATE,
                       interface_predecessor=None, compute_expectation=None):
    """Read the donor private API after verifying the actual Authority witness.

    Socket-activation peer credentials attest the root-created listener, not
    the service's UID or native key possession. Keep that distinction literal.
    The whole-domain owner must bind the exact unit/source before starting it.
    """
    source,identity=copy.deepcopy((source,identity))
    validate_expected_source(source)
    anchor=regular(Path(anchor_path))
    boot_path=Path(boot_path);boot_id=boot_path.read_text(encoding='ascii').strip()
    host=current_host_gate(Path(host_path),boot_id)
    require(isinstance(authority_observation,bytes), 'KERNEL_AUTHORITY_PREDECESSOR_DENIED')
    previous=strict_json(authority_observation)
    prior_request=previous.get('request') if isinstance(previous,dict) else None
    validate_authority_observation(authority_observation,source=source,identity=identity,
        request=prior_request,boot_id=boot_id,observed_at=datetime.now(timezone.utc),
        anchor=anchor,host_machine_id=host['latest']['host']['machine_id'])
    require(previous['result']=='AUTHORITY_PHASE_A_OBSERVED', 'KERNEL_AUTHORITY_PREDECESSOR_DENIED')
    require(interface_predecessor is None or (isinstance(interface_predecessor,str)
            and re.fullmatch('[0-9a-f]{64}',interface_predecessor)),
            'KERNEL_INTERFACE_PREDECESSOR_DENIED')
    compute=copy.deepcopy(compute_expectation)
    require(compute is None or (isinstance(compute,dict)
        and set(compute)=={'request','expected_provider_request_sha256','model','model_digest'}
        and isinstance(compute['request'],dict) and interface_predecessor is not None),
        'KERNEL_COMPUTE_EXPECTATION_DENIED')
    branch='INTERFACE' if interface_predecessor is not None and compute is None else 'OPERATIONS'
    request={'schema':'SEREIN/KernelBranchWitnessRequest/v1','branch':branch,
        'request_id':'kernel-operations-'+secrets.token_hex(16),'nonce':secrets.token_hex(32),
        'previous_evidence_digest':interface_predecessor if interface_predecessor is not None
                                   else previous['observation_digest']}
    if compute is not None:request['compute_request_id']=compute['request']['request_id']
    account=pwd.getpwnam('serein-outpost');path=Path(socket_path)
    require(os.geteuid()==account.pw_uid,'OUTPOST_OBSERVER_IDENTITY_DENIED')
    require(not path.is_symlink() and all(not p.is_symlink() for p in path.parents),
            'KERNEL_SOCKET_PATH_DENIED')
    info=path.lstat()
    def socket_identity(item):
        return (item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_gid)
    require(stat.S_ISSOCK(info.st_mode) and (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))
            ==(account.pw_uid,account.pw_gid,0o600), 'KERNEL_SOCKET_CUSTODY_DENIED')
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            deadline=time.monotonic()+3
            def remaining():
                seconds=deadline-time.monotonic()
                require(seconds>0,'KERNEL_RESPONSE_DEADLINE_DENIED')
                client.settimeout(seconds)
            remaining();client.connect(str(path))
            peer=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
            require(peer[1]==0,'KERNEL_SERVER_IDENTITY_DENIED')
            require(socket_identity(path.lstat())==socket_identity(info),'KERNEL_SOCKET_CHANGED')
            remaining();client.sendall(record_bytes(request))
            raw=b''
            while not raw.endswith(b'\n') and len(raw)<=65536:
                remaining();part=client.recv(min(4096,65537-len(raw)))
                if not part:break
                raw+=part
            remaining()
    except OSError as exc:
        raise KernelWitnessError('KERNEL_TRANSPORT_UNAVAILABLE') from exc
    require(raw.endswith(b'\n') and len(raw)<=65536,'KERNEL_RESPONSE_FRAMING_DENIED')
    now=datetime.now(timezone.utc)
    if compute is not None:
        result=compare_retained_compute_response(raw,query=request,source=source,boot_id=boot_id,
            installed_evidence_sha256=installed_evidence_sha256,observed_at=now,host_state=host,**compute)
    else:
        compare=compare_interface_response if branch=='INTERFACE' else compare_operations_response
        result=compare(raw,request=request,source=source,boot_id=boot_id,
            installed_evidence_sha256=installed_evidence_sha256,observed_at=now)
    require(socket_identity(path.lstat())==socket_identity(info)
            and boot_path.read_text(encoding='ascii').strip()==boot_id
            and regular(Path(anchor_path))==anchor,'KERNEL_OBSERVATION_CHANGED')
    final_host=current_host_gate(Path(host_path),boot_id)
    require(final_host['latest']['host']['machine_id']
            ==host['latest']['host']['machine_id'],'KERNEL_FRAME_IDENTITY_CHANGED')
    now=datetime.now(timezone.utc)
    if compute is not None:
        result=compare_retained_compute_response(raw,query=request,source=source,boot_id=boot_id,
            installed_evidence_sha256=installed_evidence_sha256,observed_at=now,
            host_state=final_host,**compute)
    validate_authority_observation(authority_observation,source=source,identity=identity,
        request=prior_request,boot_id=boot_id,observed_at=now,
        anchor=anchor,host_machine_id=host['latest']['host']['machine_id'])
    return {**result,'evidence_authentication':'ROOT_CREATED_PRIVATE_LISTENER',
            'native_identity_possession':'NOT_ESTABLISHED_BY_'+branch,
            'request':request,'observed_at':now.isoformat(),
            'subject_bytes_sha256':hashlib.sha256(raw).hexdigest()}


def main():
    """Existing observer entry; compute request content uses private stdin."""
    require(len(sys.argv) == 2, "KERNEL_EXPECTED_SOURCE_REQUIRED")
    try:
        raw=sys.stdin.buffer.read(65537) if sys.argv[1]=='-' else sys.argv[1].encode('utf-8')
        require(0<len(raw)<=65536,'KERNEL_EXPECTED_SOURCE_DENIED')
        envelope = strict_json(raw)
    except TransactionError as exc:
        raise KernelWitnessError("KERNEL_EXPECTED_SOURCE_DENIED") from exc
    require(isinstance(envelope, dict), "KERNEL_EXPECTED_SOURCE_DENIED")
    common={'source','identity','installed_evidence_sha256','authority_observation'}
    if set(envelope) in (common,common|{'interface_predecessor'},common|{'interface_predecessor','compute_expectation'}):
        require('compute_expectation' not in envelope or sys.argv[1]=='-', 'KERNEL_PRIVATE_COMPUTE_INPUT_REQUIRED')
        result=observe_operations(source=envelope['source'],identity=envelope['identity'],
            installed_evidence_sha256=envelope['installed_evidence_sha256'],
            authority_observation=record_bytes(envelope['authority_observation']),
            **{key:envelope[key] for key in ('interface_predecessor','compute_expectation') if key in envelope})
    else:
        require(set(envelope)=={'source','request','identity'}, 'KERNEL_EXPECTED_SOURCE_DENIED')
        result = observe_authority(source=envelope["source"], request=envelope["request"],
                                   identity=envelope["identity"])
    sys.stdout.buffer.write(canonical(result) + b"\n")


if __name__ == "__main__":
    main()
