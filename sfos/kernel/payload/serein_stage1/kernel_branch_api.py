"""Private Authority identity witness, adapted from canonical branch API v1.

Same AF_UNIX/peer boundary. Response v2 adds request/source/boot-bound native
key possession. An answered API or identity proof never implies Phase-A PASS.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
import pwd
import socket
import struct
import time

from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat
if __package__:
    from .authority_boot import collect_authority_facts, authority_boot_decision, AuthorityDenied, PHASE_A_CHECKS, strict_json, regular, NATIVE_REGISTRY
else:
    from authority_boot import collect_authority_facts, authority_boot_decision, AuthorityDenied, PHASE_A_CHECKS, strict_json, regular, NATIVE_REGISTRY

NATIVE_KEY = "/var/lib/serein/kernel/authority/domain-identity.pem"
SCHEMA = "SEREIN/KernelBranchDirectWitness/v2"


class BranchDenied(ValueError):
    # Errors cannot produce a signed healthy witness or advance a branch.
    mode = "SAFE_RECOVERY"
    privileged_execution = False
    branch_advance = False

    def __init__(self, message):
        super().__init__(message)
        self.decision = authority_boot_decision(None, requested_effect="OBSERVE_AUTHORITY")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def record_bytes(value):
    return canonical(value) + b"\n"


def require(value, reason):
    if not value:
        raise BranchDenied(reason)


def validate_request(request):
    require(isinstance(request, dict) and set(request) == {
        "schema", "branch", "request_id", "nonce", "previous_evidence_digest"}
        and request["schema"] == "SEREIN/KernelBranchWitnessRequest/v1"
        and request["branch"] == "AUTHORITY"
        and request["previous_evidence_digest"] == "GENESIS"
        and all(isinstance(request[key], str) and 0 < len(request[key]) <= 128
                for key in ("request_id", "nonce")), "REQUEST_SCHEMA_DENIED")


def answer(*args, **kwargs):
    raise BranchDenied("AUTHORITY_REQUIRES_VERIFIED_TRANSPORT")


def _answer(*args, **kwargs):
    raise BranchDenied("AUTHORITY_REQUIRES_VERIFIED_TRANSPORT")


def read_installed_operations_observation(*, root=Path('/')):
    """Existing installed/private observation reader, without a transport claim.

    Shared by the private witness endpoint and the owning conversation gate.
    Keep degraded/unknown observations intact; readers decide their own exact
    gate. This does not grant Authority, authenticate a caller or admit Kernel.
    """
    from .authority_contract import read_consumer_installed_policy_evidence,canonical as stored_bytes
    from .kernel_operations import _regular_bytes,_strict_json,_replay_progression
    from .audit import operations_event
    owner=pwd.getpwnam('serein-stage1')
    require((os.geteuid(),os.getegid())==(owner.pw_uid,owner.pw_gid),'OPERATIONS_OWNER_IDENTITY_DENIED')
    root=Path(root);installed=read_consumer_installed_policy_evidence(root=root)
    path=root/'var/lib/serein/kernel/replay/lifecycle-heartbeat.json'
    custody=(owner.pw_uid,owner.pw_gid,0o600)
    def snapshot():
        captured=_regular_bytes(path,custody=custody,include_fact=True)
        latest=_strict_json(captured[0])
        require(isinstance(latest,dict) and stored_bytes(latest)==captured[0],
                'OPERATIONS_OBSERVATION_ENCODING_DENIED')
        event=operations_event({key:value for key,value in latest.items() if key!='audit_observation'})
        require(latest['audit_observation']=={'state':'OBSERVATION_RECORDED_ONLY',
                    'event_sha256':hashlib.sha256(stored_bytes(event)).hexdigest(),'authority_effect':'NONE'}
                and event['boot_id']==installed['boot_id']
                and event['installed_evidence_sha256']==installed['evidence_sha256']
                and event['queue_sha256']==hashlib.sha256(stored_bytes(latest['queue_observation'])).hexdigest(),
                'OPERATIONS_OBSERVATION_BINDING_DENIED')
        return captured,event
    captured,event=snapshot()
    require(read_consumer_installed_policy_evidence(root=root)==installed,
            'OPERATIONS_INSTALLED_SOURCE_CHANGED')
    current,newer=snapshot()
    if current!=captured:
        # The owner atomically publishes while this reader verifies immutable
        # source. Accept only independently validated forward telemetry, never
        # source drift or an older healthy value over a new degraded one.
        require(newer['sequence']>event['sequence']
                and newer['monotonic_ns']>event['monotonic_ns']
                and datetime.fromisoformat(newer['observed_at'].replace('Z','+00:00'))
                    >=datetime.fromisoformat(event['observed_at'].replace('Z','+00:00'))
                and ('replay_continuity' in newer)==('replay_continuity' in event),
                'OPERATIONS_OBSERVATION_REGRESSED')
        if 'replay_continuity' in event:
            _replay_progression(event['replay_continuity'],newer['replay_continuity'])
    return installed,newer


def read_installed_interface_observation(*, root=Path('/'), deadline=None):
    """Use the existing private rejection road without invoking inference.

    A denied request is supporting Interface evidence, not an admitted route
    or complete Phase-C proof. The existing ingress records its rejection
    before replying; report that ACK correlation, not independent log proof.
    No new listener, credentials, runtime permission or service action.
    """
    from .authority_contract import read_consumer_installed_policy_evidence
    from .kernel_operations import verify_installed_conversation_boundary
    from .kernel import exchange_private_service
    if deadline is None:deadline=time.monotonic()+3
    def remaining():
        seconds=deadline-time.monotonic()
        require(0<seconds<=3,'INTERFACE_EXCHANGE_DEADLINE_DENIED')
        return seconds
    remaining()
    root=Path(root);owner=pwd.getpwnam('serein-stage1')
    require((os.geteuid(),os.getegid())==(owner.pw_uid,owner.pw_gid),
            'INTERFACE_OWNER_IDENTITY_DENIED')
    installed=read_consumer_installed_policy_evidence(root=root)
    clock=lambda:datetime.now(timezone.utc)
    def boundary():
        verify_installed_conversation_boundary({'installed_policy':installed},root=root,clock=clock)
        require(read_consumer_installed_policy_evidence(root=root)==installed,
                'INTERFACE_INSTALLED_SOURCE_CHANGED')
    boundary();started=clock()
    # Invalid shape has no request capability and cannot reserve or infer.
    payload=b'{}\n'
    raw=exchange_private_service('HAOS_GATEWAY',payload,timeout_seconds=min(2.0,remaining()),root=root)
    response=strict_json(raw)
    require(set(response)=={'schema','request_id','status','reason','timestamp'}
            and response['schema']=='SereinStage1Response/v1'
            and response['request_id'] is None and response['status']=='DENIED'
            and response['reason']=='gateway_request_denied',
            'INTERFACE_REJECTION_UNPROVEN')
    observed=datetime.fromisoformat(response['timestamp'].replace('Z','+00:00'))
    boundary();remaining();completed=clock()
    require(observed.utcoffset() is not None and started<=observed<=completed
            and 0<=(completed-started).total_seconds()<=3,
            'INTERFACE_OBSERVATION_STALE')
    return installed,{'state':'PRIVATE_INTERFACE_DENIAL_PROBE_ONLY',
        'started_at':started.isoformat(),'completed_at':completed.isoformat(),
        'request_sha256':hashlib.sha256(payload).hexdigest(),
        'response':response,'response_sha256':hashlib.sha256(raw).hexdigest(),
        'audit':'ACK_CORRELATED_NOT_INDEPENDENT_LOG_PROOF',
        'compute':'NOT_INVOKED','authority_effect':'NONE'}


def read_installed_compute_observation(request_id, *, root=Path('/')):
    """Existing private Audit + authenticated replay, without another dispatch.

    No request grant, replay key, or private signature material is exported.
    The independent reader still owns request, source and compute comparison.
    """
    import base64
    from .authority_contract import read_consumer_installed_policy_evidence
    from .kernel_operations import installed_replay_owner
    from .audit import read_recent_terminal
    root=Path(root);owner=pwd.getpwnam('serein-stage1')
    require((os.geteuid(),os.getegid())==(owner.pw_uid,owner.pw_gid),
            'COMPUTE_OWNER_IDENTITY_DENIED')
    installed=read_consumer_installed_policy_evidence(root=root)
    event=read_recent_terminal(root/'var/lib/serein/common/stage1-continuity/audit.jsonl',
                              request_id,custody=(owner.pw_uid,owner.pw_gid,0o600))
    require(event['status']=='ANSWERED','COMPUTE_TERMINAL_NOT_ANSWERED')
    retained=event.get('compute_evidence')
    require(isinstance(retained,dict) and set(retained)=={
        'runtime_response_b64','runtime_response_sha256','replay_consumption_sha256'},
        'COMPUTE_RETAINED_EVIDENCE_MISSING')
    require(isinstance(retained['runtime_response_b64'],str)
            and len(retained['runtime_response_b64'])<=43692,'COMPUTE_RETAINED_SIZE_DENIED')
    raw=base64.b64decode(retained['runtime_response_b64'],validate=True)
    require(0<len(raw)<=32768 and base64.b64encode(raw).decode('ascii')==retained['runtime_response_b64']
            and hashlib.sha256(raw).hexdigest()==retained['runtime_response_sha256'],
            'COMPUTE_RETAINED_DIGEST_DENIED')
    clock=lambda:datetime.now(timezone.utc)
    with installed_replay_owner(root=root,
            database_path=root/'var/lib/serein/kernel/replay/receipts.sqlite3',
            clock=clock,read_only=True) as store:
        evidence=store.dispatch_evidence(request_id,current_time=clock().isoformat().replace('+00:00','Z'))
        require(evidence is not None and evidence['outcome'] is not None
                and evidence['receipts'][-1]['body']['state']=='CONSUMED',
                'COMPUTE_AUTHENTICATED_OUTCOME_MISSING')
        binding=evidence['binding']['body']['binding']
        require(binding['schema']=='SereinStage1ConversationReplayBinding/v1'
                and binding['request_id']==request_id and binding['boot_id']==installed['boot_id']
                and binding['source_generation']=={'commit':installed['source_commit'],'tree':installed['source_tree']}
                and binding['canonical_manifest_digest']==installed['canonical_manifest_digest']
                and binding['policy_sha256']==installed['policy_sha256']
                and binding['plan_sha256']==installed['plan_sha256']
                and binding['kernel_instance']==installed['native_identity']['instance_id']
                and binding['identity_checkpoint']==installed['native_identity']['checkpoint']
                and binding['route']==installed['policy']['runtime_socket']
                and evidence['outcome']['body']['result_sha256']==retained['runtime_response_sha256']
                and store.contract.receipt_hash(evidence['receipts'][-1])==retained['replay_consumption_sha256'],
                'COMPUTE_AUTHENTICATED_BINDING_DENIED')
        runtime=strict_json(raw)
        observed=datetime.fromisoformat(runtime['completed_at'].replace('Z','+00:00'))
        consumed=datetime.fromisoformat(evidence['outcome']['body']['completed_at'].replace('Z','+00:00'))
        audited=datetime.fromisoformat(event['timestamp'].replace('Z','+00:00'))
        require(all(value.tzinfo is not None for value in (observed,consumed,audited))
                and audited<=observed<=consumed<=clock(), 'COMPUTE_RETAINED_TIME_DENIED')
    require(read_consumer_installed_policy_evidence(root=root)==installed,'COMPUTE_INSTALLED_SOURCE_CHANGED')
    require(0<=(clock()-observed).total_seconds()<=120,'COMPUTE_RETAINED_OBSERVATION_STALE')
    return installed,{'state':'AUTHENTICATED_RETAINED_COMPUTE_ONLY','observed_at':runtime['completed_at'],
        'request_id':request_id,'conversation_id':binding['conversation_id'],
        'payload_sha256':binding['payload_sha256'],'request_sha256':binding['request_sha256'],
        **retained,'authority_effect':'NONE','admission_effect':'NONE','stage1':'NOT_READY'}


def serve_operations(connection, *, root=Path('/')):
    """Donor Operations-v1 readback, not Authority signing or Phase-B admission.

    The existing stage1 owner reads its own private sampler record and public
    installed policy. No Outpost private files, runtime keys or health labels
    are borrowed. Outpost must independently compare these subject facts.
    """
    from .kernel_operations import _strict_json, OperationsDenied
    require(connection.family == socket.AF_UNIX, 'OPERATIONS_PRIVATE_TRANSPORT_REQUIRED')
    owner = pwd.getpwnam('serein-stage1')
    require((os.geteuid(), os.getegid()) == (owner.pw_uid, owner.pw_gid),
            'OPERATIONS_OWNER_IDENTITY_DENIED')
    peer = struct.unpack('3i', connection.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))[1]
    require(peer == pwd.getpwnam('serein-outpost').pw_uid, 'OUTPOST_PEER_IDENTITY_DENIED')
    deadline = time.monotonic() + 3
    def remaining():
        seconds = deadline - time.monotonic()
        require(seconds > 0, 'OPERATIONS_EXCHANGE_DEADLINE_DENIED')
        connection.settimeout(seconds)
    raw = b''
    try:
        while not raw.endswith(b'\n') and len(raw) <= 16384:
            remaining()
            part = connection.recv(min(4096, 16385-len(raw)))
            if not part:
                break
            raw += part
        require(raw.endswith(b'\n') and len(raw) <= 16384, 'REQUEST_FRAMING_DENIED')
        request = _strict_json(raw)
        fields={'schema','branch','request_id','nonce','previous_evidence_digest'}
        require(isinstance(request, dict) and set(request) in (fields,fields|{'compute_request_id'})
            and request['schema'] == 'SEREIN/KernelBranchWitnessRequest/v1'
            and request['branch'] in {'OPERATIONS','INTERFACE'}
            and isinstance(request['previous_evidence_digest'], str)
            and re.fullmatch('[0-9a-f]{64}', request['previous_evidence_digest'])
            and all(isinstance(request[key], str) and 0 < len(request[key]) <= 128
                    and '\x00' not in request[key] for key in ('request_id','nonce')),
            'REQUEST_SCHEMA_DENIED')
        compute='compute_request_id' in request
        require(not compute or (request['branch']=='OPERATIONS'
            and isinstance(request['compute_request_id'],str)
            and 0<len(request['compute_request_id'])<=128 and '\x00' not in request['compute_request_id']),
            'COMPUTE_REQUEST_SCHEMA_DENIED')
        if compute:
            installed,event=read_installed_compute_observation(request['compute_request_id'],root=root)
        elif request['branch']=='INTERFACE':
            installed,event=read_installed_interface_observation(root=root,deadline=deadline)
        else:
            installed,event=read_installed_operations_observation(root=root)
        # Preserve original collection time/sequence, including degraded or
        # old evidence. A new response timestamp never renews the observation.
        facts = {key:installed[key] for key in
                 ('source_commit','source_tree','canonical_manifest_digest','boot_id')}
        facts.update(observation=event, audit='ACK_CORRELATED_NOT_INDEPENDENT_LOG_PROOF',
                     phase_b='UNPROVEN', authority_effect='NONE')
        if compute:
            facts.update(audit='RETAINED_BYTES_MATCH_AUTHENTICATED_REPLAY',
                         installed_evidence_sha256=installed['evidence_sha256'])
        if request['branch']=='INTERFACE':
            facts.pop('phase_b')
            facts.update(phase_c='UNPROVEN',installed_evidence_sha256=installed['evidence_sha256'])
        response = {
            'schema':'SEREIN/KernelBranchDirectWitness/v1', 'domain':'KERNEL',
            'branch':request['branch'], 'issuer':'KERNEL_BRANCH_API', 'verdict':'UNKNOWN',
            'issued_at':datetime.now(timezone.utc).isoformat(),
            **{key:request[key] for key in ('request_id','nonce','previous_evidence_digest')},
            **{key:facts[key] for key in ('source_commit','source_tree','canonical_manifest_digest','boot_id')},
            'facts':facts, 'facts_digest':hashlib.sha256(canonical(facts)).hexdigest(),
            'uncertainty':'COMPUTE_DOMAIN_UNPROVEN' if compute else
                          'INTERFACE_PHASE_C_UNPROVEN' if request['branch']=='INTERFACE'
                          else 'OPERATIONS_PHASE_B_UNPROVEN', 'authority_effect':'NONE'}
        response['evidence_digest'] = hashlib.sha256(canonical(response)).hexdigest()
        remaining()
        connection.sendall(canonical(response)+b'\n')
        remaining()
        return response
    except BranchDenied:
        raise
    except (OSError, ValueError, TypeError, KeyError, OperationsDenied) as exc:
        raise BranchDenied('OPERATIONS_WITNESS_DENIED') from exc


def serve_authority(connection, *, root=Path("/")):
    """Get peer from the kernel, facts from installed source, key from custody."""
    require(connection.family == socket.AF_UNIX, "AUTHORITY_PRIVATE_TRANSPORT_REQUIRED")
    peer = struct.unpack("3i", connection.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]
    require(peer == pwd.getpwnam("serein-outpost").pw_uid, "OUTPOST_PEER_IDENTITY_DENIED")
    deadline = time.monotonic() + 3
    def remaining_response_time():
        remaining = deadline - time.monotonic()
        require(remaining > 0, "RESPONSE_DEADLINE_DENIED")
        return remaining
    raw = b""
    while not raw.endswith(b"\n") and len(raw) <= 16384:
        remaining = deadline - time.monotonic()
        require(remaining > 0, "REQUEST_DEADLINE_DENIED")
        connection.settimeout(remaining)
        chunk = connection.recv(min(4096, 16385-len(raw)))
        if not chunk:
            break
        raw += chunk
    require(raw.endswith(b"\n") and len(raw) <= 16384, "REQUEST_FRAMING_DENIED")
    try:
        request = strict_json(raw)
        validate_request(request)
        root = Path(root)
        facts = collect_authority_facts(root)
        remaining_response_time()
        decision = authority_boot_decision(facts, requested_effect="OBSERVE_AUTHORITY")
        require(decision == {
                    "schema": "SereinAuthorityBootDecision/v1",
                    "mode": "PRIVATE_VALIDATION_ONLY",
                    "allowed_effects": ["OBSERVE_AUTHORITY"],
                    "privileged_execution": False, "branch_advance": False,
                    "authority_effect": "NONE", "admission_effect": "NONE"}
                and decision["privileged_execution"] is False
                and decision["branch_advance"] is False,
                "AUTHORITY_SAFE_RECOVERY_REQUIRED")
        # Exercise the loaded decision function, without executing an effect:
        # unavailable trust and a forbidden admission request must both deny.
        for probe_facts, probe_effect in ((None, "OBSERVE_AUTHORITY"), (facts, "ADMIT")):
            denied = authority_boot_decision(probe_facts, requested_effect=probe_effect)
            require(denied == {
                        "schema": "SereinAuthorityBootDecision/v1",
                        "mode": "SAFE_RECOVERY", "allowed_effects": [],
                        "privileged_execution": False, "branch_advance": False,
                        "authority_effect": "NONE", "admission_effect": "NONE"}
                    and denied["privileged_execution"] is False
                    and denied["branch_advance"] is False,
                    "AUTHORITY_NEGATIVE_DECISION_DENIED")
        proof = facts["proof"]["native_identity"]
        require(proof["registry_integrity"] == "VERIFIED"
                and proof["authority_effect"] == proof["admission_effect"] == "NONE",
                "NATIVE_IDENTITY_UNPROVEN")
        registry_path = root / NATIVE_REGISTRY.lstrip("/")
        key_path = root / NATIVE_KEY.lstrip("/")
        registry_raw = regular(registry_path, root=root, expected_custody=(0, 0, 0o644))
        registry = strict_json(registry_raw)
        require(record_bytes(registry) == registry_raw
                and hashlib.sha256(record_bytes(registry["records"])).hexdigest() == proof["checkpoint"],
                "NATIVE_REGISTRY_CHANGED")
        body = registry["records"][-1]["body"]
        require(body["domain"] == "KERNEL" and body["instance_id"] == proof["instance_id"],
                "NATIVE_IDENTITY_CHANGED")
        private_raw = regular(key_path, root=root, expected_custody=(0, 0, 0o600))
        private = load_pem_private_key(private_raw, password=None)
        public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        require(public == body["public_key"], "NATIVE_KEY_MISMATCH")
        checks = facts["self_tests"]
        require(isinstance(checks, list) and len(checks) == len(PHASE_A_CHECKS)
                and all(isinstance(row, dict) and set(row) == {"name", "verdict"}
                        and row["name"] == name and row["verdict"] in {"PASS", "FAIL", "UNKNOWN"}
                        for row, name in zip(checks, PHASE_A_CHECKS)), "PHASE_A_SHAPE_DENIED")
        # This request has exercised the private transport, kernel peer check,
        # strict contract, loaded non-escalating policy and negative decisions. That
        # evidence belongs to this signed response, not the file collector.
        # Keep raw facts unchanged for the digest and final stability reread.
        checks = [dict(row) for row in checks]
        for row in checks:
            if row["name"] in {
                    "contract-containment", "authority-admission-policy",
                    "unknown-trust-safe-recovery"} and row["verdict"] == "UNKNOWN":
                row["verdict"] = "PASS"
        # The collector intentionally cannot prove a running API. Only this
        # authenticated request can complete that evidence, and only when all
        # six predicates passed. Never erase contrary or preasserted health.
        require(facts["api_health"] == "UNKNOWN", "AUTHORITY_API_HEALTH_DENIED")
        api_health = "READY" if all(row["verdict"] == "PASS" for row in checks) else "UNKNOWN"
        complete = api_health == "READY" and all(row["verdict"] == "PASS" for row in checks)
        verdict = "PASS" if complete else ("FAIL" if any(row["verdict"] == "FAIL" for row in checks) else "UNKNOWN")
        native = {"schema": "SereinNativeIdentityPossession/v1", "instance_id": proof["instance_id"],
                  "checkpoint": proof["checkpoint"], "key_fingerprint": hashlib.sha256(bytes.fromhex(public)).hexdigest()}
        response = {"schema": SCHEMA, "domain": "KERNEL", "branch": "AUTHORITY",
                    "verdict": verdict, "issuer": "KERNEL_AUTHORITY_API",
                    "issued_at": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
                    "request_id": request["request_id"], "nonce": request["nonce"],
                    "previous_evidence_digest": "GENESIS",
                    **{key: facts[key] for key in ("source_commit", "source_tree", "canonical_manifest_digest", "boot_id")},
                    "facts_digest": hashlib.sha256(canonical(facts)).hexdigest(),
                    "phase_a": checks, "api_health": api_health,
                    "uncertainty": "NONE" if complete else "PHASE_A_UNPROVEN",
                    "authority_effect": "NONE", "native_identity_proof": native,
                    "boot_decision": decision, "frame_identity": facts["proof"]["frame_identity"],
                    "conversation_policy": facts["proof"]["conversation_policy"]}
        # Sign the complete response meaning, not only the nonce: altering a
        # verdict, phase result, timestamp or source invalidates possession.
        remaining_response_time()
        challenge = hashlib.sha256(canonical({"request": request, "witness": response})).digest()
        envelope = {"domain": "KERNEL", "instance_id": proof["instance_id"],
                    "checkpoint": proof["checkpoint"], "challenge": challenge.hex()}
        signature = private.sign(record_bytes(envelope)).hex()
        require(collect_authority_facts(root) == facts, "AUTHORITY_FACTS_CHANGED")
        require(regular(registry_path, root=root, expected_custody=(0, 0, 0o644)) == registry_raw
                and regular(key_path, root=root, expected_custody=(0, 0, 0o600)) == private_raw,
                "NATIVE_IDENTITY_CHANGED")
        response["native_identity_proof"] = {**native, "possession_signature": signature}
        response["evidence_digest"] = hashlib.sha256(canonical(response)).hexdigest()
    except BranchDenied:
        raise
    except (AuthorityDenied, ValueError, KeyError, TypeError, OSError) as exc:
        raise BranchDenied("AUTHORITY_WITNESS_DENIED") from exc
    # Collection/signing do not reset the observer's existing three-second
    # exchange deadline. Never emit a late witness with a fresh-looking time.
    connection.settimeout(remaining_response_time())
    connection.sendall(canonical(response) + b"\n")
    remaining_response_time()
    return response
