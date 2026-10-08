"""Verify a route contract against independent current expectations.

ADAPT sfos-public 0dca6bd7 authority_contract.py body contract. Its unsigned
shape-only result is rejected as authority. Reuse installed native Kernel
identity verification. Pure issuance uses the owning Authority's injected
signer; this component reads no key, admits no route and performs no dispatch.
PRO-95/180: identity, policy, intent, scope, conditions and freshness are distinct.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import base64
import hashlib
import json
import re
from uuid import NAMESPACE_URL, uuid5

from .domain_identity import IdentityDenied, canonical, verify_lineage, verify_signature

SCHEMA = 'SEREIN/KernelAuthorityRouteContract/v1'
FIELDS = frozenset({'schema','action','object','intent','scope','conditions','policy_version',
    'policy_digest','issuer','subject','trust_identity','issued_at','expires_at','nonce',
    'expected_result','boot_id','source_generation','predecessor_evidence_digest','authority_effect'})
EXPECTED = FIELDS - {'schema','issuer','subject','issued_at','expires_at','nonce','authority_effect'}
HEX40 = re.compile(r'[0-9a-f]{40}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
INSTALLED_POLICY_EVIDENCE = '/var/lib/serein/kernel/authority/installed-policy-evidence.json'


class AuthorityDenied(ValueError):
    pass


def validate_stage1_conversation_policy(raw, *, expected_sha256):
    """Validate the closed installed-policy payload, not runtime admission.

    PRO-132/84e2d00d: ordinary conversation is not CP worker-lease accounting.
    The Outpost-signed plan must independently bind expected_sha256 and the
    fixed Authority-owned payload row. This parser alone grants nothing:
    current boot/native identity/gates, ingress, replay and runtime evidence
    remain point-of-use requirements. Generic signed dispatch is unchanged.
    """
    from .companion_provider import ENDPOINT, CHAT_ENDPOINT, MODEL, MODEL_DIGEST
    from .conversation_runtime import _decode
    try:
        if (type(raw) is not bytes or not isinstance(expected_sha256,str)
                or not HEX64.fullmatch(expected_sha256)
                or hashlib.sha256(raw).hexdigest()!=expected_sha256):
            raise ValueError('exact installed policy required')
        value=_decode(raw,8192)
        expected={'schema':'SereinStage1ConversationPolicy/v1','owner':'KERNEL_AUTHORITY',
            'default_decision':'DENY','caller':'HAOS','plane':'COGNITIVE',
            'requested_operation':'conversation_only','public_path':'/v1/voice/conversation',
            'gateway_socket':'/run/serein/kernel/gateway-haos.sock',
            'runtime_socket':'/run/serein/kernel/conversation.sock',
            'provider':ENDPOINT,'model':MODEL,'model_digest':MODEL_DIGEST,
            'tools':'DENY','external_actions':'DENY','alternate_routes':'DENY',
            'authority_effect':'NONE','admission_effect':'NONE','effects':[]}
        if value.get('schema')=='SereinStage1ConversationPolicy/v2':
            expected['schema']='SereinStage1ConversationPolicy/v2'
            # Exact historical HAOS informational scope, not arbitrary tools
            # advertised by an authenticated caller. HAOS alone executes its
            # official tools under its existing type/provenance checks.
            expected['readonly_chat']={'requested_operation':'conversation_tools',
                'provider':CHAT_ENDPOINT,'tools':['GetDateTime','GetLiveContext'],
                'tool_execution':'DENY','external_actions':'DENY'}
        if canonical(value)!=canonical(expected):
            raise ValueError('conversation policy widened or incomplete')
        return {'policy':value,'policy_sha256':expected_sha256,
                'state':'EXACT_POLICY_NOT_RUNTIME_ADMISSION',
                'authority_effect':'NONE','admission_effect':'NONE'}
    except (ValueError,TypeError,KeyError,UnicodeError,RecursionError) as exc:
        raise AuthorityDenied('STAGE1_CONVERSATION_POLICY_DENIED') from exc


def read_consumer_installed_policy_evidence(*, root):
    """Verify the installer's non-secret evidence; never read its private plan.

    This fixed read-only projection is usable by a non-root Kernel consumer.
    Its independent installer signature binds the checkpoint and installed
    hashes; it cannot grant dispatch, prove current Host health or admit a
    domain. Atomic publication belongs to the whole-domain installer only.
    """
    from pathlib import Path, PurePosixPath
    from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat
    from .authority_boot import regular, strict_json, ANCHOR, ANCHOR_SHA256, NATIVE_REGISTRY, BOOT
    try:
        root=Path(root)
        captured={}
        def read(name,mode=0o644):
            path=PurePosixPath(name)
            if not path.is_absolute() or '..' in path.parts:
                raise ValueError('invalid evidence path')
            location=root/name.lstrip('/')
            raw=regular(location,root=root,expected_custody=(0,0,mode))
            if name in captured and captured[name]!=(raw,mode):
                raise ValueError('evidence changed')
            captured[name]=(raw,mode)
            return raw
        anchor=read(ANCHOR)
        if hashlib.sha256(anchor).hexdigest()!=ANCHOR_SHA256:
            raise ValueError('wrong installer anchor')
        raw=read(INSTALLED_POLICY_EVIDENCE)
        document=strict_json(raw)
        if (not isinstance(document,dict) or set(document)!={'body','signature'}
                or canonical(document)!=raw):
            raise ValueError('noncanonical evidence envelope')
        body=document['body'];signature=document['signature']
        if not isinstance(signature,str) or not re.fullmatch(r'[A-Za-z0-9_-]{86}',signature):
            raise ValueError('invalid signature encoding')
        decoded=base64.b64decode(signature+'==',altchars=b'-_',validate=True)
        if base64.urlsafe_b64encode(decoded).decode().rstrip('=')!=signature:
            raise ValueError('noncanonical signature')
        public=load_pem_public_key(anchor)
        public.verify(decoded,canonical(body))
        fields={'schema','target','boot_id','source_generation','release_digest','plan_sha256','manifest_sha256',
            'source_receipt_sha256','source_inventory_digest','native_identity','host_identity_sha256','host_identity_file',
            'host_projection_digest','outpost_generation','conversation_policy','payload','state','authority_effect','admission_effect'}
        if (not isinstance(body,dict) or set(body)!=fields
                or body['schema']!='SereinKernelInstalledPolicyEvidence/v1'
                or body['target']!='VM4010' or body['state']!='MATERIAL_BINDING_ONLY'
                or body['authority_effect']!='NONE' or body['admission_effect']!='NONE'
                or not isinstance(body['boot_id'],str) or not BOOT.fullmatch(body['boot_id'])):
            raise ValueError('wrong evidence meaning')
        generation=body['source_generation']
        outpost=body['outpost_generation']
        if (not isinstance(outpost,dict) or set(outpost)!={'schema','generation','release_digest',
                'predecessor_receipt_sha256','inventory_digest','selector_digest'}
                or outpost['schema']!='SereinOutpostGenerationSelector/v1'
                or any(not isinstance(outpost[k],str) or not HEX64.fullmatch(outpost[k]) for k in
                    ('generation','predecessor_receipt_sha256','inventory_digest','selector_digest'))
                or outpost['release_digest']!='sha256:'+outpost['generation']
                or outpost['selector_digest']!=hashlib.sha256(json.dumps(
                    {k:v for k,v in outpost.items() if k!='selector_digest'},
                    sort_keys=True,separators=(',',':')).encode()).hexdigest()):
            raise ValueError('invalid installed Outpost generation binding')
        if (not isinstance(generation,dict) or set(generation)!={'parent','commit','tree'}
                or any(not isinstance(v,str) or not HEX40.fullmatch(v) for v in generation.values())
                or any(not isinstance(body[name],str) or not HEX64.fullmatch(body[name]) for name in
                    ('plan_sha256','source_receipt_sha256','host_identity_sha256','host_projection_digest','manifest_sha256'))
                or any(not isinstance(body[name],str) or not re.fullmatch(r'sha256:[0-9a-f]{64}',body[name])
                    for name in ('release_digest','source_inventory_digest'))):
            raise ValueError('unbound evidence source')
        def boot():
            return (root/'proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
        if boot()!=body['boot_id']:
            raise ValueError('wrong current boot')
        host_file=body['host_identity_file']
        if (not isinstance(host_file,dict) or set(host_file)!=
                {'target','state','bytes','sha256','mode','uid','gid','device','inode','nlink'}
                or host_file['target']!='/etc/machine-id' or host_file['state']!='PRESENT_PRESERVED'
                or not isinstance(host_file['mode'],str) or not re.fullmatch(r'[0-7]{4}',host_file['mode'])
                or int(host_file['mode'],8)&0o022):
            raise ValueError('unbound host identity file')
        machine_raw=read('/etc/machine-id',int(host_file['mode'],8))
        _,actual_host_file=regular(root/'etc/machine-id',root=root,
            expected_custody=(0,0,int(host_file['mode'],8)),include_fact=True)
        if actual_host_file!=host_file:
            raise ValueError('host identity file changed')
        machine=machine_raw.decode('ascii').strip()
        if (not re.fullmatch(r'[0-9a-f]{32}',machine) or machine=='0'*32
                or hashlib.sha256(machine.encode()).hexdigest()!=body['host_identity_sha256']):
            raise ValueError('wrong host identity')
        native=body['native_identity']
        if (not isinstance(native,dict) or set(native)!=
                {'instance_id','checkpoint','registry_sha256','transaction_context'}
                or not isinstance(native['instance_id'],str) or not re.fullmatch(r'[0-9a-f]{16}',native['instance_id'])
                or any(not isinstance(native[name],str) or not HEX64.fullmatch(native[name]) for name in
                    ('checkpoint','registry_sha256','transaction_context'))):
            raise ValueError('native evidence malformed')
        registry_raw=read(NATIVE_REGISTRY)
        registry=strict_json(registry_raw)
        if (hashlib.sha256(registry_raw).hexdigest()!=native['registry_sha256']
                or not isinstance(registry,dict) or set(registry)!={'schema','records'}
                or registry['schema']!='SereinDomainIdentityRegistry/v1'
                or canonical(registry)!=registry_raw):
            raise ValueError('native registry changed')
        identity=verify_lineage(registry['records'],
            installer_public=public.public_bytes(Encoding.Raw,PublicFormat.Raw).hex(),
            expected_checkpoint=native['checkpoint'],expected_domain='KERNEL')
        if (identity['instance_id']!=native['instance_id'] or len(registry['records'])!=1
                or registry['records'][0]['body']['source_commit']!=generation['commit']
                or registry['records'][0]['body']['governance_receipt']!=native['transaction_context']):
            raise ValueError('native source context changed')
        rows=body['payload'];seen=set();policies=[]
        prefixes=('/usr/lib/python3/dist-packages/serein_stage1/', '/usr/lib/serein/kernel/',
            '/usr/libexec/serein/', '/etc/systemd/system/serein-')
        if not isinstance(rows,list) or not 1<=len(rows)<=4096:
            raise ValueError('unbounded payload')
        for row in rows:
            if (not isinstance(row,dict) or set(row)!= {'branch','source','target','bytes','sha256','mode'}
                    or row['branch'] not in ('AUTHORITY','OPERATIONS','INTERFACE')
                    or not isinstance(row['target'],str) or not row['target'].startswith(prefixes)
                    or row['target'] in seen or PurePosixPath(row['target']).as_posix()!=row['target']
                    or '..' in PurePosixPath(row['target']).parts
                    or not isinstance(row['source'],str) or not row['source']
                    or PurePosixPath(row['source']).is_absolute() or '..' in PurePosixPath(row['source']).parts
                    or PurePosixPath(row['source']).as_posix()!=row['source'] or '\\' in row['source']
                    or type(row['bytes']) is not int or not 0<=row['bytes']<=16*1024*1024
                    or not isinstance(row['sha256'],str) or not HEX64.fullmatch(row['sha256'])
                    or row['mode'] not in ('0644','0755')):
                raise ValueError('invalid payload binding')
            seen.add(row['target'])
            installed=read(row['target'],int(row['mode'],8))
            if len(installed)!=row['bytes'] or hashlib.sha256(installed).hexdigest()!=row['sha256']:
                raise ValueError('installed payload drift')
            if row['source']=='payload/serein_stage1/stage1-conversation-policy.v1.json':policies.append(row)
        required=('__init__.py','kernel.py','serein_https_gateway_adapter.py','authority_contract.py','domain_identity.py',
            'authority_boot.py','kernel_branch_api.py','companion_provider.py','gpu_control.py','conversation_runtime.py','supervision.py',
            'kernel_operations.py','audit.py','outpost_evidence/__init__.py','outpost_evidence/host_vitality.py',
            'outpost_evidence/vitals_aggregation.py','outpost_evidence/vitals_edge.py')
        for name in required:
            expected_source='payload/serein_stage1/'+name
            expected_target='/usr/lib/python3/dist-packages/serein_stage1/'+name
            bound=[r for r in rows if r['source']==expected_source]
            if len(bound)!=1 or bound[0]['target']!=expected_target or bound[0]['mode']!='0644':
                raise ValueError('required consumer import closure missing')
        policy=body['conversation_policy']
        if (len(policies)!=1 or policies[0]!=policy
                or policy['branch']!='AUTHORITY' or policy['mode']!='0644'
                or policy['target']!='/usr/lib/python3/dist-packages/serein_stage1/stage1-conversation-policy.v1.json'):
            raise ValueError('required consumer closure missing')
        parsed=validate_stage1_conversation_policy(read(policy['target']),expected_sha256=policy['sha256'])
        for name,(previous,mode) in captured.items():
            if regular(root/name.lstrip('/'),root=root,expected_custody=(0,0,mode))!=previous:
                raise ValueError('evidence changed during read')
        if boot()!=body['boot_id']:
            raise ValueError('current boot changed')
        if regular(root/'etc/machine-id',root=root,
                expected_custody=(0,0,int(host_file['mode'],8)),include_fact=True)[1]!=host_file:
            raise ValueError('host identity file changed during read')
        return {**parsed,'evidence':body,'evidence_sha256':hashlib.sha256(raw).hexdigest(),
                'source_commit':generation['commit'],'source_tree':generation['tree'],
                'boot_id':body['boot_id'],'canonical_manifest_digest':body['manifest_sha256'],
                'plan_sha256':body['plan_sha256'],
                'native_identity':{**identity,'registry_integrity':'VERIFIED','private_key_possession':'UNKNOWN'},
                'authority_effect':'NONE','admission_effect':'NONE','dispatch_effect':'NONE'}
    except Exception as exc:
        raise AuthorityDenied('CONSUMER_INSTALLED_POLICY_EVIDENCE_DENIED') from exc


def read_installed_stage1_conversation_policy(*, root):
    """Read the existing signed install closure; no key, service or grant.

    The owning local Authority calls this in its existing read context. This
    function does not add a privileged starter or accept hashes from ingress.
    Native runtime/readiness and point-of-use replay are separate predicates.
    """
    from pathlib import Path
    from .authority_boot import (collect_authority_facts, regular,
        CONVERSATION_POLICY_FILE, MATERIAL, AuthorityDenied as ReadDenied)
    try:
        root=Path(root)
        facts=collect_authority_facts(root)
        binding=facts['proof']['conversation_policy']
        path=MATERIAL+CONVERSATION_POLICY_FILE
        if (binding['path']!=path or binding['source']!='payload/serein_stage1/'+CONVERSATION_POLICY_FILE
                or binding['state']!='SIGNED_INSTALLED_POLICY_NOT_RUNTIME_ADMISSION'
                or binding['authority_effect']!='NONE' or binding['admission_effect']!='NONE'):
            raise ValueError('fixed signed policy required')
        raw=regular(root/path.lstrip('/'),root=root,expected_custody=(0,0,0o644))
        policy=validate_stage1_conversation_policy(raw,expected_sha256=binding['sha256'])
        if collect_authority_facts(root)!=facts:
            raise ValueError('installed policy context changed')
        return {**policy,'source_commit':facts['source_commit'],'source_tree':facts['source_tree'],
            'boot_id':facts['boot_id'],'canonical_manifest_digest':facts['canonical_manifest_digest'],
            'plan_sha256':binding['plan_sha256'],'native_identity':facts['proof']['native_identity'],
            'frame_identity':facts['proof']['frame_identity']}
    except (ReadDenied,OSError,ValueError,TypeError,KeyError,UnicodeError,RecursionError) as exc:
        raise AuthorityDenied('INSTALLED_STAGE1_CONVERSATION_POLICY_DENIED') from exc


def match_installed_stage1_conversation(payload, *, authenticated_caller, root, now):
    """Match only the installed policy's request scope, never admit/dispatch.

    Caller identity is supplied by the authenticated ingress owner, not JSON.
    Tools/history cannot be stripped or relabeled to match ordinary speech.
    The result still needs current constituent evidence and durable replay at
    the actual private forward; it is not a replacement for generic dispatch.
    """
    from .kernel import classify_request
    from .conversation_runtime import _decode, _validate
    try:
        if authenticated_caller!='HAOS':
            raise ValueError('authenticated HAOS owner required')
        request=_decode(payload,128*1024)
        admitted,_=classify_request(request,now=now)
        if not admitted or request.get('action')!='companion':
            raise ValueError('bounded conversation required')
        conversation=request['conversation']
        machine=conversation['machine_identity'].upper()
        if not (machine=='HAOS' or machine.startswith('HAOS_')):
            raise ValueError('client mismatch')
        runtime={'schema':'SereinStage1ConversationRuntimeRequest/v1',
                 'request_id':request['request_id'],**conversation}
        _validate(runtime,now=now)
        # Replay uses the same strict external request identifier as the
        # existing dispatch road; do not trim or generate a replacement ID.
        request_id=request['request_id']
        if (request_id!=request_id.strip() or any(ord(c)<32 or ord(c)>126 for c in request_id)):
            raise ValueError('invalid replay identity')
        # Consumer reads only the installer's separately signed non-secret
        # evidence. Private plan/source receipt/witness remain root-only.
        policy=read_consumer_installed_policy_evidence(root=root)
        operation=conversation['requested_operation']
        if operation=='conversation_tools':
            scope=policy['policy'].get('readonly_chat')
            if not scope or scope['requested_operation']!=operation:
                raise ValueError('installed informational chat scope required')
            allowed=set(scope['tools'])
            offered={tool['function']['name'] for tool in conversation['tools']}
            historical={call['function']['name'] for message in conversation['messages']
                        for call in message.get('tool_calls',[])}
            if not offered<=allowed or not historical<=allowed:
                raise ValueError('consequential or unknown tools denied')
        elif operation!=policy['policy']['requested_operation']:
            raise ValueError('installed conversation scope required')
        requested=datetime.fromisoformat(conversation['observed_at'].replace('Z','+00:00'))
        observed=requested.astimezone(timezone.utc).isoformat().replace('+00:00','Z')
        # This records actual installed-policy scope, never a generic signed
        # dispatch contract or worker lease. Operations still owns reservation.
        replay_binding={'schema':'SereinStage1ConversationReplayBinding/v1',
            'request_id':request_id,'conversation_id':conversation['conversation_id'],
            'request_sha256':hashlib.sha256(canonical(request)).hexdigest(),
            'payload_sha256':hashlib.sha256(canonical(runtime)).hexdigest(),
            'caller':authenticated_caller,'requested_operation':operation,
            'route':policy['policy']['runtime_socket'],
            'policy_sha256':policy['policy_sha256'],'plan_sha256':policy['plan_sha256'],
            'canonical_manifest_digest':policy['canonical_manifest_digest'],
            'boot_id':policy['boot_id'],
            'source_generation':{'commit':policy['source_commit'],'tree':policy['source_tree']},
            'kernel_instance':policy['native_identity']['instance_id'],
            'identity_checkpoint':policy['native_identity']['checkpoint'],
            'observed_at':observed,'authority_effect':'NONE','admission_effect':'NONE'}
        from .conversation_runtime import MAX_AGE_SECONDS
        replay_expires=(requested+timedelta(seconds=MAX_AGE_SECONDS)).astimezone(
            timezone.utc).isoformat().replace('+00:00','Z')
        return {'request_id':request_id,'conversation_id':conversation['conversation_id'],
            'request_sha256':hashlib.sha256(canonical(request)).hexdigest(),
            'runtime_request':runtime,'runtime_request_sha256':hashlib.sha256(canonical(runtime)).hexdigest(),
            'installed_policy':policy,'state':'SCOPE_MATCHED_PENDING_CURRENT_GATES_AND_REPLAY',
            'replay_binding':replay_binding,'replay_expires_at':replay_expires,
            'authority_effect':'NONE','admission_effect':'NONE','dispatch_effect':'NONE'}
    except (ValueError,TypeError,KeyError,AttributeError,UnicodeError,RecursionError) as exc:
        raise AuthorityDenied('STAGE1_CONVERSATION_SCOPE_DENIED') from exc


def validate_dispatch_authorization(authorization, *, expected, authenticated_caller,
                                    now, contract_expires_at):
    """Check an independently current PRO-95/97 registry projection, read-only.

    This is an internal normalized record, not a public registry API or a grant
    writer. The owning Authority supplies its current record digest and freshly
    evaluated condition facts independently of ingress. A digest learned from
    the same untrusted record is NOT current authorization. No renewal, usage
    counter mutation, policy discovery or discretionary matching occurs here.
    """
    try:
        if (not isinstance(authorization, dict)
                or set(authorization) != {'record','record_sha256','condition_facts'}):
            raise ValueError('current authorization required')
        captured = json.loads(canonical(authorization))
        record = captured['record']
        fields = {'authorization_id','subject','target','action','scope','exclusions',
            'conditions','risk','policy_version','policy_digest','approval_source',
            'approved_at','issued_at','expires_at','renewal_policy','revoked_at',
            'superseded_by','evidence','provenance','execution_count','renewal_count',
            'success_count','failure_count','last_used_at'}
        if not isinstance(record, dict) or set(record) != fields:
            raise ValueError('complete registry record required')
        raw = canonical(record)
        if (len(raw) > 16384 or not isinstance(captured['record_sha256'],str)
                or not HEX64.fullmatch(captured['record_sha256'])
                or hashlib.sha256(raw).hexdigest() != captured['record_sha256']):
            raise ValueError('registry currentness mismatch')
        for name in ('authorization_id','subject','target','action','risk',
                     'policy_version','approval_source','provenance','renewal_policy'):
            value = record[name]
            if (not isinstance(value,str) or not value or value != value.strip()
                    or value == 'UNKNOWN' or any(ord(c)<32 for c in value)):
                raise ValueError('unknown authorization field')
        if record['revoked_at'] is not None or record['superseded_by'] is not None:
            raise ValueError('authorization withdrawn')
        for name in ('conditions','exclusions','evidence'):
            value = record[name]
            if (not isinstance(value,list) or (name != 'exclusions' and not value)
                    or any(not isinstance(v,str) or not v or v != v.strip()
                           or v == 'UNKNOWN' or any(ord(c)<32 for c in v) for v in value)
                    or len(set(value)) != len(value)):
                raise ValueError('authorization references invalid')
        facts = captured['condition_facts']
        if (not isinstance(facts,dict) or set(facts) != set(record['conditions'])
                or any(value is not True for value in facts.values())):
            raise ValueError('authorization conditions unproven')
        for name in ('execution_count','renewal_count','success_count','failure_count'):
            if type(record[name]) is not int or record[name] < 0:
                raise ValueError('invalid registry counters')
        if record['success_count'] + record['failure_count'] > record['execution_count']:
            raise ValueError('inconsistent registry counters')
        def instant(value):
            if not isinstance(value,str):
                raise ValueError('lease instant required')
            parsed = datetime.fromisoformat(value.replace('Z','+00:00'))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError('aware lease instant required')
            return parsed
        approved, issued, expires = (instant(record[name]) for name in
                                     ('approved_at','issued_at','expires_at'))
        deadline = instant(contract_expires_at)
        if (not isinstance(now,datetime) or now.tzinfo is None or now.utcoffset() is None
                or not approved <= issued <= now < deadline <= expires
                or not 0 < (expires-issued).total_seconds() <= 86400):
            raise ValueError('authorization lease stale or exceeded')
        if record['last_used_at'] is not None and not (
                approved <= instant(record['last_used_at']) <= now):
            raise ValueError('registry usage instant invalid')
        scope = expected['scope']
        permitted = record['scope']
        if (not isinstance(permitted,dict) or not {'route','plane','caller'} <= set(permitted)
                or not isinstance(scope,dict)
                or any(name not in scope or canonical(scope[name]) != canonical(value)
                       for name,value in permitted.items())
                or record['subject'] != authenticated_caller
                or record['target'] != expected['object'] or record['action'] != expected['action']
                or record['policy_version'] != expected['policy_version']
                or record['policy_digest'] != expected['policy_digest']
                or not isinstance(record['policy_digest'],str)
                or not HEX64.fullmatch(record['policy_digest'])
                or canonical(record['conditions']) != canonical(expected['conditions'])
                or scope.get('authorization_id') != record['authorization_id']
                or scope.get('authorization_sha256') != captured['record_sha256']
                or scope.get('authorization_expires_at') != record['expires_at']
                or scope.get('risk') != record['risk']
                or canonical(scope.get('exclusions')) != canonical(record['exclusions'])):
            raise ValueError('authorization does not match exact current intent')
        return {'authorization_id':record['authorization_id'],
                'record_sha256':captured['record_sha256'], 'expires_at':record['expires_at'],
                'authority_effect':'NONE','admission_effect':'NONE'}
    except (ValueError,TypeError,KeyError,AttributeError,OverflowError,RecursionError) as exc:
        raise AuthorityDenied('CURRENT_AUTHORIZATION_DENIED') from exc


def _checked_body(body, expected, now):
    """Shared pre-sign/post-sign checks; expected is independently governed."""
    if (not isinstance(body,dict) or set(body)!=FIELDS
            or not isinstance(expected,dict) or set(expected)!=EXPECTED):
        raise ValueError('closed contract fields required')
    raw=canonical(body)
    if len(raw)>16384:
        raise ValueError('contract unbounded')
    body=json.loads(raw)
    if (body['schema']!=SCHEMA or body['issuer']!='KERNEL_AUTHORITY'
            or body['subject']!='KERNEL' or body['authority_effect']!='NONE'):
        raise ValueError('contract identity')
    if canonical({name:body[name] for name in EXPECTED})!=canonical(expected):
        raise ValueError('current contract expectations differ')
    for name in ('action','object','intent','policy_version','trust_identity',
                 'expected_result','boot_id','nonce'):
        if not isinstance(body[name],str) or not body[name] or body[name]=='UNKNOWN' or '\x00' in body[name]:
            raise ValueError('unknown contract field')
    for name in ('policy_digest','predecessor_evidence_digest'):
        if not isinstance(body[name],str) or not HEX64.fullmatch(body[name]):
            raise ValueError('contract digest')
    generation=body['source_generation']
    if (not isinstance(generation,dict) or set(generation)!={'commit','tree'}
            or any(not isinstance(value,str) or not HEX40.fullmatch(value) for value in generation.values())):
        raise ValueError('contract generation')
    if (not isinstance(body['scope'],dict) or body['scope'].get('route')!=body['object']
            or not isinstance(body['conditions'],list) or not body['conditions']
            or any(not isinstance(item,str) or not item or item=='UNKNOWN' for item in body['conditions'])):
        raise ValueError('contract conditions')
    issued=datetime.fromisoformat(body['issued_at'].replace('Z','+00:00'))
    expires=datetime.fromisoformat(body['expires_at'].replace('Z','+00:00'))
    if (not isinstance(now,datetime) or now.tzinfo is None or issued.tzinfo is None
            or expires.tzinfo is None or not issued<=now<expires
            or not 0<(expires-issued).total_seconds()<=30):
        raise ValueError('contract freshness')
    return body


def prepare_body(expected, *, action_nonce, issued_at, expires_at, now):
    """Unsigned typed bytes only; never an authority envelope or admission."""
    if not isinstance(expected,dict) or set(expected)!=EXPECTED:
        raise ValueError('current expectations required')
    snapshot=json.loads(canonical(expected))
    body={**snapshot,'schema':SCHEMA,'issuer':'KERNEL_AUTHORITY',
          'subject':'KERNEL','authority_effect':'NONE','nonce':action_nonce,
          'issued_at':issued_at,'expires_at':expires_at}
    return _checked_body(body,snapshot,now)


def issue(expected, *, identity_records, installer_public, identity_checkpoint,
          action_nonce, issued_at, expires_at, now, signer):
    """Sign only independently supplied current policy; no policy discovery.

    PRO-95/180: caller owns authenticated current expectations and replay nonce.
    These must never come from ingress or be inferred from identity. This pure
    operation selects no path, reads no key, registers no route, consumes no
    replay state and admits no domain. The owning Authority supplies its signer.
    A signed contract still requires validate/evaluate_dispatch at point of use.
    """
    try:
        body=prepare_body(expected,action_nonce=action_nonce,issued_at=issued_at,
                          expires_at=expires_at,now=now)
        identity=verify_lineage(identity_records,installer_public=installer_public,
            expected_checkpoint=identity_checkpoint,expected_domain='KERNEL')
        raw=canonical(body)
        signature=signer(raw)
        if not isinstance(signature,bytes) or len(signature)!=64:
            raise ValueError('invalid signer output')
        verify_signature(identity['public_key'],signature.hex(),raw)
        envelope={'body':body,'signature':signature.hex()}
        # Reread supplied lineage/expectations after the callback: a mutation
        # during signing must not publish a stale or substituted envelope.
        validate(envelope,identity_records=identity_records,installer_public=installer_public,
            identity_checkpoint=identity_checkpoint,expected=expected,now=now)
        return envelope
    except (IdentityDenied,ValueError,TypeError,KeyError,AttributeError,OverflowError,OSError) as exc:
        raise AuthorityDenied('AUTHORITY_ISSUANCE_DENIED') from exc


def validate(envelope, *, identity_records, installer_public, identity_checkpoint,
             expected, now):
    """Authenticate exact current intent; caller still owns replay/admission.

    expected and identity_checkpoint MUST come from the governed current local
    policy/registry, never be copied from the incoming contract. Every expected
    field is required, so omitting a scope/policy comparison cannot mean ALLOW.
    Calling this function creates no route, lease, nonce or domain admission.
    """
    if (not isinstance(envelope, dict) or set(envelope) != {'body','signature'}
            or not isinstance(envelope.get('body'), dict) or set(envelope['body']) != FIELDS):
        raise AuthorityDenied('AUTHORITY_SIGNED_ENVELOPE_REQUIRED')
    if not isinstance(expected, dict) or set(expected) != EXPECTED:
        raise AuthorityDenied('AUTHORITY_CURRENT_EXPECTATIONS_REQUIRED')
    try:
        raw = canonical(envelope['body'])
        if len(raw) > 16384:
            raise ValueError('contract unbounded')
        identity = verify_lineage(identity_records, installer_public=installer_public,
            expected_checkpoint=identity_checkpoint, expected_domain='KERNEL')
        verify_signature(identity['public_key'], envelope['signature'], raw)
        body = _checked_body(json.loads(raw), expected, now)
    except (IdentityDenied, ValueError, TypeError, KeyError, AttributeError, OverflowError) as exc:
        raise AuthorityDenied('AUTHORITY_CONTRACT_DENIED') from exc
    return {'contract':body,'contract_sha256':hashlib.sha256(raw).hexdigest(),
            'kernel_instance':identity['instance_id'],'identity_checkpoint':identity_checkpoint,
            'verified_at':now.astimezone(timezone.utc).isoformat(),
            'state':'AUTHENTICATED_CURRENT_CONTRACT_NOT_ROUTE_ADMISSION',
            'replay_state':'UNCONSUMED_REQUIRES_ATOMIC_CAS','authority_effect':'NONE',
            'admission_effect':'NONE','dispatch_effect':'NONE'}


def project_dispatch_expectations(template, request_binding, *, ump_sha256):
    """Bind request correlation to an exact admitted policy, never add rights.

    The installed policy remains stable across requests. Only these four
    correlation fields vary; caller/route/intent/authorization/risk/conditions
    and all other policy fields are preserved byte-for-byte in meaning.
    """
    try:
        runtime_fields = {'request_id','conversation_id','payload_sha256','ump_sha256'}
        if (not isinstance(template,dict) or set(template) != EXPECTED
                or not isinstance(template['scope'],dict)
                or runtime_fields & set(template['scope'])
                or not isinstance(request_binding,dict)
                or set(request_binding) != runtime_fields - {'ump_sha256'}):
            raise ValueError('closed policy/request projection required')
        value=json.loads(canonical(template))
        binding=json.loads(canonical(request_binding))
        request_id=binding['request_id']; conversation_id=binding['conversation_id']
        if (not isinstance(request_id,str) or not request_id or len(request_id)>128
                or request_id != request_id.strip()
                or any(ord(c)<32 or ord(c)>126 for c in request_id)
                or not isinstance(conversation_id,str) or not conversation_id.strip()
                or len(conversation_id)>256 or '\x00' in conversation_id
                or not isinstance(binding['payload_sha256'],str)
                or not HEX64.fullmatch(binding['payload_sha256'])
                or not isinstance(ump_sha256,str) or not HEX64.fullmatch(ump_sha256)):
            raise ValueError('request correlation invalid')
        value['scope'].update(binding,ump_sha256=ump_sha256)
        return value
    except (ValueError,TypeError,KeyError,RecursionError) as exc:
        raise AuthorityDenied('POLICY_REQUEST_PROJECTION_DENIED') from exc


def read_installed_dispatch_context(*, root, bindings, authenticated_caller,
                                    active_count, installer_public,
                                    identity_checkpoint, source_generation,
                                    current_boot, condition_facts, request_binding):
    """Read exact governed local material for the existing dispatch evaluator.

    The owning Authority must independently supply current bindings, trust
    anchor/checkpoint and source/boot. They must NEVER come from ingress JSON
    or be calculated by accepting whatever files happen to be present. This
    reader creates no file, policy, route, authority, identity or admission.
    Bindings are explicit (absolute path, SHA256) pairs; no new installed path
    or public API is introduced. Reuse Authority's descriptor/custody reader.
    The caller must reread current governance before every invocation; these
    bytes alone cannot prove that an authorization remains unrevoked.
    """
    from pathlib import Path
    from .authority_boot import regular, strict_json, AuthorityDenied as ReadDenied
    try:
        names = {'registered_route', 'expected', 'ump', 'identity_registry', 'authorization'}
        if (not isinstance(bindings, dict) or set(bindings) != names
                or authenticated_caller not in ('OUTPOST','HAOS','ANDROID','ESP32','INTERNAL')
                or type(active_count) is not int or active_count < 0
                or not isinstance(source_generation, dict)
                or set(source_generation) != {'commit','tree'}
                or any(not isinstance(value, str) or not HEX40.fullmatch(value)
                       for value in source_generation.values())
                or not isinstance(current_boot, str)
                or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', current_boot)):
            raise ValueError('current local bindings required')
        root = Path(root)
        captured = {}
        pinned = {}
        for name in sorted(names):
            pair = bindings[name]
            if (not isinstance(pair, tuple) or len(pair) != 2
                    or not isinstance(pair[0], str) or not pair[0].startswith('/')
                    or not isinstance(pair[1], str) or not HEX64.fullmatch(pair[1])):
                raise ValueError('exact path/hash pair required')
            path = Path(pair[0])
            if '..' in path.parts or path == Path('/'):
                raise ValueError('invalid material path')
            pinned[name] = pair
        if len({pair[0] for pair in pinned.values()}) != len(names):
            raise ValueError('aliased material paths')
        def read_boot():
            # Same exact host-owned proc identity used by Authority collection.
            return (root/'proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
        if read_boot() != current_boot:
            raise ValueError('current boot changed')
        values = {}
        for name, (path, digest) in pinned.items():
            raw, fact = regular(root/path.lstrip('/'), root=root, include_fact=True)
            if len(raw) > 128 * 1024 or hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError('governed material changed')
            value = strict_json(raw)
            if canonical(value) != raw:
                raise ValueError('noncanonical material')
            captured[name] = (raw, fact)
            values[name] = value
        registry = values['identity_registry']
        if (set(registry) != {'schema','records'}
                or registry['schema'] != 'SereinDomainIdentityRegistry/v1'):
            raise ValueError('native registry required')
        verify_lineage(registry['records'], installer_public=installer_public,
            expected_checkpoint=identity_checkpoint, expected_domain='KERNEL')
        expected = project_dispatch_expectations(values['expected'],request_binding,
                                                  ump_sha256=pinned['ump'][1])
        route = values['registered_route']
        ump = values['ump']
        if (set(expected) != EXPECTED
                or expected['boot_id'] != current_boot or route.get('boot_id') != current_boot
                or canonical(expected['source_generation']) != canonical(source_generation)
                or canonical(route.get('source_generation')) != canonical(source_generation)
                or expected['scope'].get('caller') != authenticated_caller
                or expected['scope'].get('route') != route.get('route')
                or set(ump) != {'schema','state','claims','authority_effect'}
                or ump['schema'] != 'SEREIN/UMP/v1' or ump['state'] != 'KNOWN'
                or not isinstance(ump['claims'], list) or ump['authority_effect'] != 'NONE'
                or expected['scope'].get('ump_sha256') != pinned['ump'][1]):
            raise ValueError('independent local context mismatch')
        for name, (path, _) in pinned.items():
            if regular(root/path.lstrip('/'), root=root, include_fact=True) != captured[name]:
                raise ValueError('material changed during context read')
        if read_boot() != current_boot or bindings != pinned:
            raise ValueError('context bindings changed')
        return {'registered_route':route,
                'registered_route_sha256':pinned['registered_route'][1],
                'authenticated_caller':authenticated_caller, 'active_count':active_count,
                'ump_sha256':pinned['ump'][1], 'identity_records':registry['records'],
                'installer_public':installer_public, 'identity_checkpoint':identity_checkpoint,
                'expected':expected,
                'authorization':{'record':values['authorization'],
                    'record_sha256':pinned['authorization'][1],
                    'condition_facts':json.loads(canonical(condition_facts))}}
    except (ReadDenied, IdentityDenied, OSError, UnicodeError, ValueError, TypeError,
            KeyError, AttributeError, RecursionError) as exc:
        raise AuthorityDenied('INSTALLED_DISPATCH_CONTEXT_DENIED') from exc


def checked_dispatch_request(request):
    """Shared exact wire shape/identity limits; no signature verification."""
    fields = {'schema','request_id','conversation_id','route','plane',
              'caller','ump','authority_contract'}
    if (not isinstance(request,dict) or set(request)!=fields
            or request.get('schema')!='kernel.route.dispatch.v1/request'):
        raise ValueError('route request shape')
    raw=canonical(request)
    if len(raw)>32768:
        raise ValueError('unbounded dispatch')
    request=json.loads(raw)
    for field in ('request_id','conversation_id','route','caller'):
        if (not isinstance(request[field],str) or not request[field]
                or len(request[field])>256 or '\x00' in request[field]):
            raise ValueError('request identity')
    request_id=request['request_id']
    if (len(request_id)>128 or request_id!=request_id.strip()
            or any(ord(char)<0x20 or ord(char)>0x7e for char in request_id)):
        raise ValueError('replay request identity')
    return request


def checked_registered_route(registered_route, registered_route_sha256, active_count):
    """Shared pre-sign/dispatch prerequisites; not authentication or admission."""
    route_raw = canonical(registered_route)
    if (len(route_raw) > 32768 or not isinstance(registered_route_sha256, str)
            or not HEX64.fullmatch(registered_route_sha256)
            or hashlib.sha256(route_raw).hexdigest() != registered_route_sha256):
        raise ValueError('registered route changed')
    route = json.loads(route_raw)
    fields = {'schema', 'route', 'owner', 'plane', 'version', 'posture',
              'qos', 'failover', 'source_generation', 'registration_authority_sha256',
              'authority_contract', 'state', 'boot_id', 'authority_effect'}
    if (not isinstance(route, dict) or set(route) != fields
            or route['schema'] != 'SEREIN/KernelRouteRecord/v1'
            or route['state'] != 'ACTIVE' or route['posture'] != 'ELIGIBLE'
            or route['authority_effect'] != 'NONE'
            or not isinstance(route['route'],str) or not route['route'].endswith('.v1')
            or not isinstance(route['owner'],str) or not route['owner']
            or not isinstance(route['version'],str) or not route['version']):
        raise ValueError('route not eligible')
    qos = route['qos']
    if (not isinstance(qos, dict) or set(qos) != {'priority','capacity','backpressure'}
            or type(qos['capacity']) is not int or qos['capacity'] < 1
            or qos['backpressure'] not in ('REJECT', 'QUEUE')
            or type(active_count) is not int or active_count < 0):
        raise ValueError('capacity evidence invalid')
    return route


def evaluate_dispatch(request, *, registered_route, registered_route_sha256,
                      authenticated_caller, active_count, ump_sha256, identity_records,
                      installer_public, identity_checkpoint, expected, authorization, now):
    """Evaluate the existing PRO-180 dispatch envelope, without forwarding.

    Adapt the donor Router.dispatch policy seam, not its unauthenticated route
    storage or server. The route and its independently admitted digest, caller,
    capacity, independently verified UMP digest and expected policy must be supplied by trusted local state, never
    by the ingress packet. Correlation belongs in the signed scope (PRO-180),
    so an otherwise valid contract cannot be transplanted to another request.
    A positive result still requires atomic replay consumption and the actual
    destination dispatch/readback; this function does neither and admits none.
    """
    fields = {'schema', 'request_id', 'conversation_id', 'route', 'plane',
              'caller', 'ump', 'authority_contract'}
    if (not isinstance(request, dict) or set(request) != fields
            or request.get('schema') != 'kernel.route.dispatch.v1/request'):
        raise AuthorityDenied('ROUTE_REQUEST_DENIED')
    try:
        # Snapshot all input before validation; return no caller-owned aliases.
        request = checked_dispatch_request(request)
        raw = canonical(request)
        route = checked_registered_route(registered_route, registered_route_sha256, active_count)
        request_id = request['request_id']
        planes = {'ADMIN': {'OUTPOST'},
                  'COGNITIVE': {'HAOS', 'ANDROID', 'ESP32', 'INTERNAL'},
                  'RECOVERY': {'OUTPOST'}}
        if (not isinstance(request['plane'], str) or request['plane'] not in planes
                or request['caller'] not in planes[request['plane']]
                or request['caller'] != authenticated_caller
                or request['route'] != route['route'] or request['plane'] != route['plane']
                or not route['route'].endswith('.v1')
                or not isinstance(route['owner'], str) or not route['owner']
                or not isinstance(route['version'], str) or not route['version']):
            raise ValueError('route or authenticated caller mismatch')
        ump = request['ump']
        if (not isinstance(ump, dict) or set(ump) != {'schema','state','claims','authority_effect'}
                or ump['schema'] != 'SEREIN/UMP/v1' or ump['state'] != 'KNOWN'
                or not isinstance(ump['claims'], list) or ump['authority_effect'] != 'NONE'):
            raise ValueError('UMP unavailable or contrary')
        if (not isinstance(ump_sha256, str) or not HEX64.fullmatch(ump_sha256)
                or hashlib.sha256(canonical(ump)).hexdigest() != ump_sha256):
            raise ValueError('UMP independent evidence mismatch')
        qos = route['qos']
        validate_dispatch_authorization(authorization,expected=expected,
            authenticated_caller=authenticated_caller,now=now,
            contract_expires_at=request['authority_contract']['body']['expires_at'])
        verified = validate(request['authority_contract'], identity_records=identity_records,
            installer_public=installer_public, identity_checkpoint=identity_checkpoint,
            expected=expected, now=now)
        contract = verified['contract']
        scope = contract['scope']
        # Reuse the recorded replay-store donor's exact UUID5 mapping. The
        # signed Authority nonce is the same nonce persisted by Operations.
        replay_identity = {'run_id':str(uuid5(NAMESPACE_URL, f'{request_id}:run')),
                           'action_nonce':str(uuid5(NAMESPACE_URL, f'{request_id}:action'))}
        correlation = {'route':request['route'], 'plane':request['plane'],
                       'caller':request['caller'], 'request_id':request['request_id'],
                       'conversation_id':request['conversation_id'], 'ump_sha256':ump_sha256}
        if (contract['action'] != 'kernel.route.dispatch.v1'
                or contract['intent'] != 'DISPATCH_KERNEL_COMPUTE'
                or contract['expected_result'] != 'ROUTE_DISPATCHED'
                or contract['object'] != route['route']
                or contract['nonce'] != replay_identity['action_nonce']
                or contract['boot_id'] != route['boot_id']
                or canonical(contract['source_generation']) != canonical(route['source_generation'])
                or any(scope.get(name) != value for name,value in correlation.items())):
            raise ValueError('current dispatch contract mismatch')
    except (AuthorityDenied, ValueError, TypeError, KeyError, AttributeError, OverflowError) as exc:
        raise AuthorityDenied('ROUTE_DISPATCH_POLICY_DENIED') from exc
    full = active_count >= qos['capacity']
    disposition = ('QUEUE_REQUIRES_REVALIDATION' if qos['backpressure'] == 'QUEUE'
                   else 'DENY_BACKPRESSURE') if full else 'VALIDATED_PENDING_REPLAY'
    return {'schema':'kernel.route.policy.evaluate.v1/response',
            'request_id':request['request_id'], 'conversation_id':request['conversation_id'],
            'route':route['route'], 'owner':route['owner'], 'plane':route['plane'],
            'registered_route_sha256':registered_route_sha256,
            'request_sha256':hashlib.sha256(raw).hexdigest(),
            'contract_sha256':verified['contract_sha256'],
            'kernel_instance':verified['kernel_instance'],
            'identity_checkpoint':identity_checkpoint, 'verified_at':verified['verified_at'],
            'replay_identity':replay_identity,
            'disposition':disposition, 'replay_state':'UNCONSUMED_REQUIRES_ATOMIC_CAS',
            'authority_effect':'NONE', 'admission_effect':'NONE', 'dispatch_effect':'NONE',
            'queue_effect':'NONE'}
