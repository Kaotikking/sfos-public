"""Read-only source-integrity evidence supporting PRO-142 Phase A.

Uses the existing Outpost signed-source receipt and installed material. A new
Seed is candidate material, not permission. The independent Outpost admission
path must still validate the result before Operations can advance.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import pwd
import re
import stat
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives.serialization import load_pem_public_key

PHASE_A_CHECKS = (
    "implementation-identity", "blueprint-policy-integrity", "frame-identity",
    "contract-containment", "authority-admission-policy", "unknown-trust-safe-recovery",
)
STATE = "/var/lib/serein-outpost/kernel"
ANCHOR = "/usr/share/serein/outpost/cognition-verification.pem"
# Same preserved public trust anchor already pinned by the installed Outpost.
ANCHOR_SHA256 = "1f7533bbd5e2645f52a0d7e17502166f079a76c8c1fd31c8feaa0fc057a48652"
SEED_SHA256 = "4f1ce883e175dd7df04086c6a6c48ef00bd98df45700222ec2c85498291c98ef"
POLICY_SHA256 = "c0aad8ace45e05915622f68a8d8585b7d89869c6f66a6ba4497a75245da0c665"
DICTIONARY_SHA256 = "af63410c75f83d0737d4d5ff2cd225879e2b2732bdefe29a3ea9113605dac438"
DICTIONARY_FILE = "engineering-dictionary.v3.md"
BLUEPRINT_FILE = "kernel-api-blueprint.pro180.md"
CONVERSATION_POLICY_FILE = "stage1-conversation-policy.v1.json"
BLUEPRINT_SHA256 = "460fd7a1a3126e7745a8548fa4ae7ba2e10b11d8e7992cf9e9f2b1b61276c623"
MATERIAL = "/usr/lib/python3/dist-packages/serein_stage1/"
AUTHORITY_LAUNCHER = "/usr/libexec/serein/serein-kernel-branch-api"
AUTHORITY_UNITS = frozenset(
    "/etc/systemd/system/serein-kernel-authority-api." + suffix
    for suffix in ("service", "socket"))
NATIVE_REGISTRY = "/var/lib/serein/kernel/authority/domain-identity.json"
LIMIT = 16 * 1024 * 1024
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
BOOT = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")


class AuthorityDenied(ValueError):
    pass


def require(value, reason):
    if not value:
        raise AuthorityDenied(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "AUTHORITY_DUPLICATE_KEY_DENIED")
            result[key] = value
        return result
    def invalid_constant(value):
        raise AuthorityDenied("AUTHORITY_NONFINITE_DENIED")
    try:
        result = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (ValueError, UnicodeError) as exc:
        raise AuthorityDenied("AUTHORITY_JSON_DENIED") from exc
    require(isinstance(result, dict), "AUTHORITY_JSON_OBJECT_REQUIRED")
    return result


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)


def directory_custody(info, relative):
    # The installed Outpost owns this one existing parent. Kernel state below
    # it is root-private; do not change the parent's established ownership.
    allowed = info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o022
    if relative == "var/lib/serein-outpost" and not allowed:
        owner = pwd.getpwnam("serein-outpost")
        allowed = (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (owner.pw_uid, owner.pw_gid, 0o750)
    require(stat.S_ISDIR(info.st_mode) and allowed, "AUTHORITY_DIRECTORY_CUSTODY_DENIED")


def regular(path, *, root=Path("/"), expected_custody=None, include_fact=False):
    """Descriptor-bound, root-owned immutable input; no symlink/permission repair."""
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "AUTHORITY_PATH_DENIED")
    root = Path(root)
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise AuthorityDenied("AUTHORITY_PATH_DENIED") from exc
    handles = []
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(fd)
        handles.append((fd, None, None, directory_identity(info)))
        directory_custody(info, "")
        walked = []
        for part in relative.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            info = os.fstat(child)
            handles.append((child, fd, part, directory_identity(info)))
            walked.append(part)
            directory_custody(info, "/".join(walked))
            fd = child
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(file_fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid == 0
                    and before.st_nlink == 1 and not stat.S_IMODE(before.st_mode) & 0o022
                    and before.st_size <= LIMIT, "AUTHORITY_CUSTODY_DENIED")
            require(expected_custody is None or
                    (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) == expected_custody,
                    "AUTHORITY_INSTALLED_CUSTODY_DENIED")
            # Size is already bounded; one extra byte detects growth without
            # requesting a maximum-size buffer for every small input.
            read_bound = before.st_size + 1
            raw = stream.read(read_bound)
            if include_fact:
                stream.seek(0)
                require(stream.read(read_bound) == raw, "AUTHORITY_INPUT_CHANGED")
            after = os.fstat(stream.fileno())
            named = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
            require(len(raw) == before.st_size and fingerprint(before) == fingerprint(after)
                    == fingerprint(named), "AUTHORITY_INPUT_CHANGED")
        for child, parent, name, captured in handles:
            opened = os.fstat(child)
            named = os.stat(root, follow_symlinks=False) if parent is None else os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(directory_identity(opened) == directory_identity(named) == captured,
                    "AUTHORITY_PARENT_CHANGED")
        if include_fact:
            return raw, {"target": "/" + relative.as_posix(), "state": "PRESENT_PRESERVED",
                         "bytes": len(raw), "sha256": sha(raw), "mode": format(stat.S_IMODE(before.st_mode), "04o"),
                         "uid": before.st_uid, "gid": before.st_gid, "device": before.st_dev,
                         "inode": before.st_ino, "nlink": before.st_nlink}
        return raw
    except OSError as exc:
        raise AuthorityDenied("AUTHORITY_INPUT_UNAVAILABLE") from exc
    finally:
        for fd, _, _, _ in reversed(handles):
            os.close(fd)


def trust_disposition(trust):
    # This bootstrap proof grants no privileged route, even for known identity.
    return "PRIVATE_VALIDATION_ONLY" if trust == "VERIFIED" else "SAFE_RECOVERY"


def verify_host_identity(root, plan, witness):
    """Read signed handoff plus Host file; never access Outpost private Host state."""
    identity = plan.get("host_identity")
    require(isinstance(identity, dict) and set(identity) == {"machine_id", "file"}
            and identity == witness.get("host_identity")
            and isinstance(identity["machine_id"], str)
            and re.fullmatch(r"[0-9a-f]{32}", identity["machine_id"])
            and identity["machine_id"] != "0"*32
            and isinstance(plan.get("host_projection_digest"), str)
            and HEX64.fullmatch(plan["host_projection_digest"])
            and plan["host_projection_digest"] == witness.get("host_projection_digest"),
            "AUTHORITY_HOST_BINDING_DENIED")
    raw, fact = regular(Path(root)/"etc/machine-id", root=Path(root), include_fact=True)
    try:
        actual = raw.decode("ascii").strip()
    except UnicodeError as exc:
        raise AuthorityDenied("AUTHORITY_FRAME_IDENTITY_DENIED") from exc
    require(actual == identity["machine_id"] and fact == identity["file"],
            "AUTHORITY_HOST_IDENTITY_CHANGED")
    return {"machine_id": actual, "boot_id": plan["current_boot_id"],
            "host_projection_digest": plan["host_projection_digest"]}


def authority_boot_decision(facts, *, requested_effect):
    """Apply loaded bootstrap trust to observation only, never admission.

    Called with internally collected facts by the private API. A caller label
    such as VERIFIED is not facts. Collector failure supplies None. Even exact
    identity evidence grants no branch advancement or privileged execution.
    """
    verified = False
    try:
        native = facts["proof"]["native_identity"]
        frame = facts["proof"]["frame_identity"]
        verified = (
            facts["source_integrity"] == "VERIFIED"
            and facts["proof"]["identity"] == "KERNEL"
            and facts["proof"]["policy"] == "DEFAULT_DENY"
            and facts["proof"]["containment"] == "PRIVATE_ONLY"
            and facts["proof"]["self_admission"] is False
            and all(HEX40.fullmatch(facts[key]) for key in ("source_commit", "source_tree"))
            and HEX64.fullmatch(facts["canonical_manifest_digest"]) is not None
            and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", facts["boot_id"]) is not None
            and native["registry_integrity"] == "VERIFIED"
            and native["authority_effect"] == native["admission_effect"] == "NONE"
            and frame["boot_id"] == facts["boot_id"]
            and re.fullmatch(r"[0-9a-f]{32}", frame["machine_id"]) is not None
            and frame["machine_id"] != "0"*32
            and HEX64.fullmatch(frame["host_projection_digest"]) is not None
            and requested_effect == "OBSERVE_AUTHORITY"
        )
    except (KeyError, TypeError, AttributeError):
        pass
    mode = trust_disposition("VERIFIED" if verified else "UNKNOWN")
    return {"schema": "SereinAuthorityBootDecision/v1", "mode": mode,
            "allowed_effects": ["OBSERVE_AUTHORITY"] if verified else [],
            "privileged_execution": False, "branch_advance": False,
            "authority_effect": "NONE", "admission_effect": "NONE"}


def verify_material(seed_raw, policy_raw, dictionary_raw, blueprint_raw):
    require(sha(seed_raw) == SEED_SHA256 and sha(policy_raw) == POLICY_SHA256,
            "AUTHORITY_CONSTITUTION_BINDING_DENIED")
    seed, policy = strict_json(seed_raw), strict_json(policy_raw)
    reference = seed.get("semantic_reference")
    require(isinstance(dictionary_raw, bytes) and sha(dictionary_raw) == DICTIONARY_SHA256
            and isinstance(reference, dict)
            and set(reference) == {"document_id", "title", "version", "source_revision",
                                   "source_serialization", "payload", "sha256"}
            and reference["document_id"] == "4b81537c-eaa7-43da-8d41-cf0421de24ad"
            and reference["version"] == 3
            and reference["source_revision"] == "2026-08-13T19:27:55.492Z"
            and reference["source_serialization"] == "UTF-8 Linear document content plus terminal LF"
            and reference["payload"] == DICTIONARY_FILE
            and reference["sha256"] == DICTIONARY_SHA256,
            "AUTHORITY_DICTIONARY_BINDING_DENIED")
    # This preserves the canonical source document. It does not turn prose
    # into executable policy, permissions, or a domain admission decision.
    require(type(blueprint_raw) is bytes and sha(blueprint_raw) == BLUEPRINT_SHA256
            and policy.get("blueprint_reference") == {
                "issue_id": "8d0407f6-ff86-4d14-ab5a-cf3d578cd0b6",
                "identifier": "PRO-180",
                "title": "SereinNet Kernel Domain API Blueprint — PRO-178 Conformance Consolidation",
                "source_revision": "2026-09-04T21:12:23.438Z",
                "source_serialization": "UTF-8 Linear issue description plus terminal LF",
                "payload": BLUEPRINT_FILE,
                "sha256": BLUEPRINT_SHA256},
            "AUTHORITY_BLUEPRINT_BINDING_DENIED")
    require(seed.get("identity") == policy.get("identity") == "KERNEL"
            and seed.get("status") == "CANDIDATE_UNADMITTED"
            and policy.get("branch") == "AUTHORITY"
            and policy.get("phase_a") == list(PHASE_A_CHECKS)
            and policy.get("branch_order") == ["AUTHORITY", "OPERATIONS", "INTERFACE"]
            and policy.get("default_decision") == "DENY"
            and policy.get("cross_domain_access") == "API_ONLY"
            and policy.get("private_state_access") == "DENY"
            and policy.get("self_admission") is False
            and policy.get("unknown_trust") == "SAFE_RECOVERY"
            and policy.get("route_admission") == "INDEPENDENT_CURRENT_AUTHORITY_REQUIRED"
            and all(obj.get(key) == "NONE" for obj in (seed, policy)
                    for key in ("authority_effect", "admission_effect")),
            "AUTHORITY_POLICY_DENIED")
    require(all(trust_disposition(value) == "SAFE_RECOVERY"
                for value in (None, "UNKNOWN", "INVALID", "STALE", "CONFLICT", "")),
            "AUTHORITY_UNSAFE_UNKNOWN_TRUST")
    return seed, policy


def verify_native_binding(plan, registry_raw, anchor, witness, *, identity_source):
    """Read-only public identity integrity, not private-key possession/admission."""
    require(sha(anchor) == ANCHOR_SHA256, "AUTHORITY_TRUST_ANCHOR_DENIED")
    try:
        signature = plan["signature"]
        load_pem_public_key(anchor).verify(
            base64.b64decode(signature + "=" * (-len(signature) % 4), altchars=b"-_", validate=True),
            canonical({k: v for k, v in plan.items() if k != "signature"}))
        require(plan.get("schema") == "SereinPublicKernelFirstInstallPlan/v1"
                and plan.get("target_vm_id") == witness["target"] == "VM4010"
                and plan.get("current_boot_id") == witness["boot_id"]
                and plan.get("authority_sha256") == sha(anchor)
                and all(plan.get(key) == witness[key] for key in (
                    "source_commit", "source_tree", "archive_sha256", "release_digest",
                    "source_receipt_sha256", "rollback_selector")),
                "AUTHORITY_NATIVE_PLAN_BINDING_DENIED")
        # Execute only the exact signed identity primitive, never package
        # __init__ or an ambient module that may import downstream runtime.
        rows = [row for row in plan["payload"]
                if row["source"] == "payload/serein_stage1/domain_identity.py"]
        require(len(rows) == 1 and rows[0]["branch"] == "AUTHORITY"
                and type(identity_source) is bytes and len(identity_source) == rows[0]["bytes"]
                and sha(identity_source) == rows[0]["sha256"], "AUTHORITY_NATIVE_SOURCE_DENIED")
        import types
        identity_module = types.ModuleType("_serein_verified_native_identity")
        exec(compile(identity_source, "verified-domain-identity.py", "exec"), identity_module.__dict__)
        binding = plan["native_identity"]
        require(isinstance(binding, dict) and set(binding) == {
            "schema", "instance_id", "checkpoint", "registry_sha256", "private_sha256",
            "public_key", "transaction_context"}
            and binding["schema"] == "SereinKernelNativeIdentityMaterial/v1"
            and witness.get("native_identity") == binding
            and sha(registry_raw) == binding["registry_sha256"],
            "AUTHORITY_NATIVE_REGISTRY_BINDING_DENIED")
        registry = strict_json(registry_raw)
        require(set(registry) == {"schema", "records"}
                and registry["schema"] == "SereinDomainIdentityRegistry/v1"
                and canonical(registry) == registry_raw,
                "AUTHORITY_NATIVE_REGISTRY_DENIED")
        reserved = plan["reserved_domain_ids"]
        require(isinstance(reserved, list) and all(
            isinstance(value, str) and re.fullmatch(r"[0-9a-f]{16}", value) for value in reserved)
            and reserved == sorted(set(reserved)), "AUTHORITY_NATIVE_RESERVED_DENIED")
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        public = load_pem_public_key(anchor).public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        verified = identity_module.verify_lineage(
            registry["records"], installer_public=public,
            expected_checkpoint=binding["checkpoint"], expected_domain="KERNEL",
            reserved_ids=set(reserved))
        context = sha(canonical({k: v for k, v in plan.items()
                                 if k not in {"signature", "native_identity"}}))
        require(len(registry["records"]) == 1
                and registry["records"][0]["body"]["source_commit"] == plan["source_commit"]
                and registry["records"][0]["body"]["governance_receipt"] == context
                and binding["transaction_context"] == context
                and verified["instance_id"] == binding["instance_id"]
                and verified["public_key"] == binding["public_key"],
                "AUTHORITY_NATIVE_CONTEXT_DENIED")
    except AuthorityDenied:
        raise
    except Exception as exc:
        raise AuthorityDenied("AUTHORITY_NATIVE_IDENTITY_DENIED") from exc
    return {"domain": "KERNEL", "instance_id": verified["instance_id"],
            "checkpoint": verified["checkpoint"], "registry_integrity": "VERIFIED",
            "private_key_possession": "UNKNOWN", "authority_effect": "NONE",
            "admission_effect": "NONE"}


def _construction_material(read_bytes, rooted, receipt, anchor, boot, manifest_raw):
    """Read existing signed preterminal installation material, not readiness.

    The root-owned request is only a locator. Exact plan signature, source,
    boot and signed installed-policy projection establish the binding. No new
    record, selector, grant or terminal witness is created by this reader.
    """
    request_raw=read_bytes(rooted(STATE+'/install-request.json'),expected_custody=(0,0,0o600))
    request=strict_json(request_raw)
    fields={'schema','target_vm_id','repository','source_parent','source_commit','source_tree',
            'archive_sha256','rollback_selector','reserved_domain_ids'}
    require(isinstance(request,dict) and request.get('schema') in
            ('SereinOutpostKernelInstallRequest/v1','SereinOutpostKernelInstallRequest/v2'),
            'AUTHORITY_CONSTRUCTION_REQUEST_DENIED')
    if request['schema'].endswith('/v2'):fields.add('offline_companion')
    if 'recovered_predecessor' in request:fields.add('recovered_predecessor')
    require(set(request)==fields and request['target_vm_id']=='VM4010'
            and request['repository']==receipt['repository']
            and all(request.get(k)==receipt[k] for k in
                ('source_parent','source_commit','source_tree','archive_sha256')),
            'AUTHORITY_CONSTRUCTION_REQUEST_DENIED')
    if 'offline_companion' in request:
        offline=request['offline_companion']
        require(isinstance(offline,dict) and set(offline)==
                {'bundle_root','expected_before','rollback_selector','request_id'},
                'AUTHORITY_CONSTRUCTION_REQUEST_DENIED')
        location=offline['bundle_root'];expected=offline['expected_before']
        require(isinstance(location,str) and location.startswith('/') and location!='/'
                and '\\' not in location and '\x00' not in location
                and str(PurePosixPath(location))==location and '..' not in PurePosixPath(location).parts
                and isinstance(offline['request_id'],str)
                and re.fullmatch(r'[A-Za-z0-9_-]{8,128}',offline['request_id'])
                and isinstance(offline['rollback_selector'],str)
                and re.fullmatch(r'/var/lib/serein/rollback/offline-ollama-\d{8}T\d{6}Z-[0-9a-f]{12}',offline['rollback_selector'])
                and offline['rollback_selector']!=request['rollback_selector']
                and isinstance(expected,dict) and set(expected)==
                    {'schema','unit','files','runtime_objects','directories','immutable_inputs'}
                and expected['schema']=='SereinOfflineOllamaExpectedBefore/v2'
                and isinstance(expected['unit'],dict)
                and all(isinstance(expected[k],list) for k in
                    ('files','runtime_objects','directories','immutable_inputs')),
                'AUTHORITY_CONSTRUCTION_REQUEST_DENIED')
    selector=request['rollback_selector']
    require(isinstance(selector,str) and re.fullmatch(
        r'/var/lib/serein/rollback/kernel-first-install-\d{8}T\d{6}Z-[0-9a-f]{12}',selector),
        'AUTHORITY_NATIVE_PLAN_PATH_DENIED')
    raw=read_bytes(rooted(selector+'/plan.json'),expected_custody=(0,0,0o600))
    plan=strict_json(raw)
    require(isinstance(plan,dict) and canonical(plan)==raw,'AUTHORITY_NATIVE_PLAN_BYTES_DENIED')
    try:
        signature=plan['signature']
        load_pem_public_key(anchor).verify(base64.b64decode(
            signature+'='*(-len(signature)%4),altchars=b'-_',validate=True),
            canonical({k:v for k,v in plan.items() if k!='signature'}))
    except Exception as exc:
        raise AuthorityDenied('AUTHORITY_CONSTRUCTION_SIGNATURE_DENIED') from exc
    require(plan.get('schema')=='SereinPublicKernelFirstInstallPlan/v1'
            and plan.get('target_vm_id')=='VM4010' and plan.get('current_boot_id')==boot
            and plan.get('authority_sha256')==sha(anchor)
            and plan.get('rollback_selector')==selector
            and plan.get('reserved_domain_ids')==request['reserved_domain_ids']
            and all(plan.get(k)==receipt[k] for k in
                ('source_parent','source_commit','source_tree','archive_sha256','release_digest'))
            and plan.get('source_receipt_sha256')==sha(canonical(receipt))
            and plan.get('source_inventory_digest')==receipt['inventory_digest'],
            'AUTHORITY_CONSTRUCTION_PLAN_DENIED')
    if 'recovered_predecessor' in request:
        previous=plan.get('recovered_predecessor')
        require(isinstance(previous,dict) and
                {k:v for k,v in previous.items() if k!='reserved_domain_id'}==request['recovered_predecessor']
                and previous.get('reserved_domain_id') in plan['reserved_domain_ids'],
                'AUTHORITY_RECOVERED_BINDING_DENIED')
        historical=read_bytes(rooted(STATE+'/kernel-install-witness.json'),expected_custody=(0,0,0o600))
        archived=read_bytes(rooted(selector+'/predecessor-witness.json'),expected_custody=(0,0,0o600))
        require(historical==archived and sha(historical)==previous.get('witness_sha256'),
                'AUTHORITY_RECOVERED_WITNESS_DENIED')
        previous_selector=previous.get('rollback_selector')
        require(isinstance(previous_selector,str) and previous_selector!=selector and re.fullmatch(
            r'/var/lib/serein/rollback/kernel-first-install-\d{8}T\d{6}Z-[0-9a-f]{12}',previous_selector),
            'AUTHORITY_RECOVERED_BINDING_DENIED')
        for filename,field in (('plan.json','plan_sha256'),('receipt.json','receipt_sha256'),
                               ('phase-journal.json','journal_sha256')):
            require(sha(read_bytes(rooted(previous_selector+'/'+filename),expected_custody=(0,0,0o600)))==previous.get(field),
                    'AUTHORITY_RECOVERED_HISTORY_CHANGED')
    # Same exact public projection placed by kernel_first_install.install.
    projection_raw=read_bytes(rooted('/var/lib/serein/kernel/authority/installed-policy-evidence.json'),
                              expected_custody=(0,0,0o644))
    projection=strict_json(projection_raw)
    rows=plan['payload'];native=plan['native_identity']
    policies=[r for r in rows if r['source']=='payload/serein_stage1/'+CONVERSATION_POLICY_FILE]
    require(len(policies)==1,'AUTHORITY_CONSTRUCTION_POLICY_DENIED')
    expected={'schema':'SereinKernelInstalledPolicyEvidence/v1','target':'VM4010','boot_id':boot,
        'source_generation':{'parent':plan['source_parent'],'commit':plan['source_commit'],'tree':plan['source_tree']},
        'release_digest':plan['release_digest'],'plan_sha256':sha(raw),'manifest_sha256':sha(manifest_raw),
        'source_receipt_sha256':plan['source_receipt_sha256'],'source_inventory_digest':plan['source_inventory_digest'],
        'native_identity':{k:native[k] for k in ('instance_id','checkpoint','registry_sha256','transaction_context')},
        'host_identity_sha256':sha(plan['host_identity']['machine_id'].encode('ascii')),
        'host_identity_file':plan['host_identity']['file'],'host_projection_digest':plan['host_projection_digest'],
        'outpost_generation':plan['outpost_generation'],'conversation_policy':policies[0],
        'payload':sorted(rows,key=lambda r:('AUTHORITY','OPERATIONS','INTERFACE').index(r['branch'])),
        'state':'MATERIAL_BINDING_ONLY','authority_effect':'NONE','admission_effect':'NONE'}
    require(isinstance(projection,dict) and set(projection)=={'body','signature'}
            and canonical(projection)==projection_raw and projection['body']==expected,
            'AUTHORITY_CONSTRUCTION_PROJECTION_DENIED')
    try:
        signature=projection['signature']
        load_pem_public_key(anchor).verify(base64.b64decode(
            signature+'='*(-len(signature)%4),altchars=b'-_',validate=True),canonical(expected))
    except Exception as exc:
        raise AuthorityDenied('AUTHORITY_CONSTRUCTION_PROJECTION_SIGNATURE_DENIED') from exc
    binding={'target':'VM4010','boot_id':boot,**{k:plan[k] for k in
        ('source_commit','source_tree','archive_sha256','release_digest','source_receipt_sha256',
         'rollback_selector','native_identity','host_identity','host_projection_digest')}}
    return plan,raw,binding


def collect_authority_facts(root=Path("/")):
    root = Path(root)
    def rooted(name):
        path = PurePosixPath(name)
        require(path.is_absolute() and ".." not in path.parts, "AUTHORITY_PATH_DENIED")
        return root.joinpath(*path.parts[1:])
    def read(name):
        return strict_json(read_bytes(rooted(name)))
    captured = {}
    captured_custody = {}
    def read_bytes(path, expected_custody=None):
        if expected_custody is not None:
            prior_custody = captured_custody.setdefault(path, expected_custody)
            require(prior_custody == expected_custody, "AUTHORITY_INSTALLED_CUSTODY_DENIED")
        raw = regular(path, root=root, expected_custody=captured_custody.get(path))
        previous = captured.setdefault(path, raw)
        require(previous == raw, "AUTHORITY_INPUT_CHANGED")
        return raw
    def current_boot():
        try:
            boot = rooted("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as exc:
            raise AuthorityDenied("AUTHORITY_BOOT_UNAVAILABLE") from exc
        require(BOOT.fullmatch(boot), "AUTHORITY_BOOT_DENIED")
        return boot

    boot = current_boot()

    anchor = read_bytes(rooted(ANCHOR))
    require(sha(anchor) == ANCHOR_SHA256, "AUTHORITY_TRUST_ANCHOR_DENIED")
    receipt = read(STATE + "/source-receipt.json")
    required = {"schema", "repository", "ref", "source_parent", "source_commit", "source_tree",
                "archive_sha256", "release_digest", "inventory_digest", "signature"}
    require(set(receipt) == required
            and receipt["schema"] == "SereinOutpostKernelSourceReceipt/v1"
            and receipt["repository"] == "Kaotikking/sfos-public"
            and receipt["ref"] == "refs/heads/main"
            and all(HEX40.fullmatch(str(receipt[k])) for k in ("source_parent", "source_commit", "source_tree"))
            and HEX64.fullmatch(str(receipt["archive_sha256"])), "AUTHORITY_SOURCE_BINDING_DENIED")
    try:
        signature = receipt["signature"]
        load_pem_public_key(anchor).verify(
            base64.b64decode(signature + "=" * (-len(signature) % 4), altchars=b"-_", validate=True),
            canonical({k: v for k, v in receipt.items() if k != "signature"}))
    except Exception as exc:
        raise AuthorityDenied("AUTHORITY_SOURCE_SIGNATURE_DENIED") from exc
    source = rooted(STATE + "/source/sfos/kernel")
    def source_inventory():
        items = []
        for path in sorted(source.rglob("*")):
            require(not path.is_symlink(), "AUTHORITY_SOURCE_SYMLINK_DENIED")
            if path.is_dir():
                directory_custody(path.stat(), path.relative_to(root).as_posix())
                continue
            raw = read_bytes(path)
            items.append({"path": path.relative_to(source).as_posix(), "bytes": len(raw), "sha256": sha(raw)})
        return items
    inventory = source_inventory()
    require(inventory and receipt["inventory_digest"] == "sha256:" + sha(canonical(inventory)),
            "AUTHORITY_SOURCE_INVENTORY_DENIED")
    manifest = strict_json(read_bytes(source / "release-manifest.json"))
    require(manifest.get("self_digest") == receipt["release_digest"]
            == "sha256:" + sha(canonical({k: v for k, v in manifest.items() if k != "self_digest"})),
            "AUTHORITY_RELEASE_DENIED")
    layout = strict_json(read_bytes(source / "install-layout.json"))
    roots = layout.get("payload_roots")
    rows = manifest.get("payload")
    require(isinstance(roots, dict) and isinstance(rows, list) and rows, "AUTHORITY_PAYLOAD_DENIED")
    require(manifest.get("payload_digest") == "sha256:" + sha(canonical(rows)), "AUTHORITY_PAYLOAD_DENIED")
    targets = set()
    for row in rows:
        require(isinstance(row, list) and len(row) == 4, "AUTHORITY_PAYLOAD_DENIED")
        relative, size, digest, mode = row
        require(isinstance(relative, str) and not PurePosixPath(relative).is_absolute()
                and ".." not in PurePosixPath(relative).parts, "AUTHORITY_PAYLOAD_DENIED")
        prefixes = [prefix for prefix in roots if relative.startswith(prefix + "/")]
        require(len(prefixes) == 1, "AUTHORITY_LAYOUT_DENIED")
        prefix = prefixes[0]
        target = roots[prefix].rstrip("/") + "/" + relative[len(prefix) + 1:]
        require(target not in targets and type(size) is int and size >= 0
                and HEX64.fullmatch(str(digest)) and mode in ("0644", "0755"), "AUTHORITY_PAYLOAD_DENIED")
        require(target != AUTHORITY_LAUNCHER or mode == "0755", "AUTHORITY_LAUNCHER_MODE_DENIED")
        require(target not in AUTHORITY_UNITS or mode == "0644", "AUTHORITY_UNIT_MODE_DENIED")
        require(target != MATERIAL + BLUEPRINT_FILE or mode == "0644", "AUTHORITY_BLUEPRINT_MODE_DENIED")
        raw = read_bytes(rooted(target), expected_custody=(0, 0, int(mode, 8)))
        require(len(raw) == size and sha(raw) == digest, "AUTHORITY_INSTALLED_BYTES_DENIED")
        targets.add(target)
    require(({MATERIAL + name for name in ("kernel-seed.v1.json", "authority-proof-contract.v1.json",
                                          "authority_boot.py", "authority_contract.py", "domain_identity.py", "kernel_branch_api.py", DICTIONARY_FILE, BLUEPRINT_FILE,
                                          CONVERSATION_POLICY_FILE)}
             | {AUTHORITY_LAUNCHER} | AUTHORITY_UNITS) <= targets,
            "AUTHORITY_REQUIRED_MATERIAL_MISSING")
    seed, policy = verify_material(read_bytes(rooted(MATERIAL + "kernel-seed.v1.json")),
                                   read_bytes(rooted(MATERIAL + "authority-proof-contract.v1.json")),
                                   read_bytes(rooted(MATERIAL + DICTIONARY_FILE)),
                                   read_bytes(rooted(MATERIAL + BLUEPRINT_FILE)))
    machine = read_bytes(rooted("/etc/machine-id")).decode("ascii").strip()
    require(re.fullmatch(r"[0-9a-f]{32}", machine), "AUTHORITY_FRAME_IDENTITY_DENIED")
    witness_path=rooted(STATE+'/kernel-install-witness.json')
    had_witness=os.path.lexists(witness_path)
    historical_witness=read_bytes(witness_path,expected_custody=(0,0,0o600)) if had_witness else None
    terminal_record=strict_json(historical_witness) if had_witness else None
    terminal_current=(had_witness and all(terminal_record.get(k)==receipt[k]
        for k in ('source_commit','source_tree','archive_sha256','release_digest')))
    # Same source is not the same transaction: a recovered reinstall may
    # retain those four fields while its signed plan/native identity changes.
    # This selects a verifier path only; both paths still authenticate the
    # exact plan/identity below. A terminal needs no transient request.
    projection_path=rooted('/var/lib/serein/kernel/authority/installed-policy-evidence.json')
    if terminal_current and os.path.lexists(projection_path):
        terminal_selector=terminal_record.get('rollback_selector')
        require(isinstance(terminal_selector,str) and re.fullmatch(
            r'/var/lib/serein/rollback/kernel-first-install-\d{8}T\d{6}Z-[0-9a-f]{12}',terminal_selector),
            'AUTHORITY_NATIVE_PLAN_PATH_DENIED')
        projection=strict_json(read_bytes(projection_path,expected_custody=(0,0,0o644)))
        terminal_current=(isinstance(projection,dict) and isinstance(projection.get('body'),dict)
            and projection['body'].get('plan_sha256')==sha(read_bytes(
                rooted(terminal_selector+'/plan.json'),expected_custody=(0,0,0o600))))
    current_request=read(STATE+'/install-request.json') if had_witness and not terminal_current else None
    recovered=(isinstance(current_request,dict) and isinstance(current_request.get('recovered_predecessor'),dict)
               and current_request['recovered_predecessor'].get('witness_sha256')==sha(historical_witness)) if had_witness else False
    if not had_witness or recovered:
        plan,plan_raw,witness=_construction_material(read_bytes,rooted,receipt,anchor,boot,
            read_bytes(source/'release-manifest.json'))
    else:
        witness = read(STATE + "/kernel-install-witness.json")
        inactive = (witness.get('schema') == 'SereinOutpostKernelInstallWitness/v1'
                    and witness.get('install_status') == 'INSTALLED_INACTIVE'
                    and witness.get('admission') == 'INDEPENDENT_AUDIT_PENDING')
        construction = False
        if witness.get('schema') == 'SereinOutpostKernelInstallWitness/v2':
            observations = witness.get('observations')
            expected_results = {'authority': 'AUTHORITY_PHASE_A_OBSERVED',
                'operations': 'OPERATIONS_MINIMUM_OBSERVED',
                'interface': 'PRIVATE_INTERFACE_DENIAL_CORRELATED'}
            # A complete installed construction can await its first real HAOS
            # acceptance round. Missing measurements are not readiness and
            # cannot be mixed with a claimed public or partial compute result.
            pending = (isinstance(observations,dict)
                and all(observations.get(name) is None for name in ('compute','gpu','public_response')))
            measured = (isinstance(observations,dict)
                and isinstance(observations.get('compute'),dict)
                and observations['compute'].get('result')=='MEASURED_COMPUTE_CORRELATED'
                and isinstance(observations.get('gpu'),dict)
                and observations['gpu'].get('result')=='RUNTIME_GPU_PROCESS_OBSERVED')
            construction = (witness.get('install_status') == 'CONSTRUCTION_OBSERVED'
                and witness.get('admission') == 'UNADMITTED'
                and witness.get('admission_effect') == 'NONE'
                and witness.get('public_acceptance') == 'UNPROVEN'
                and witness.get('temporal_scope') == 'HISTORICAL_CONSTRUCTION_OBSERVATION'
                and isinstance(observations, dict)
                and set(observations) == set(expected_results) | {'compute','gpu','public_response'}
                and (pending or measured)
                and all(isinstance(observations[name], dict)
                        and observations[name].get('result') == result
                        for name, result in expected_results.items())
                and witness.get('observations_sha256') == sha(canonical(observations)))
        # Construction observations authenticate no current service/admission
        # predicate. The exact signed source/native/Host and request-time checks
        # below remain mandatory; v1 is never reinterpreted as active proof.
        require((inactive or construction)
            and witness.get("witness_digest") == sha(canonical({k: v for k, v in witness.items() if k != "witness_digest"}))
            and witness.get("target") == "VM4010" and witness.get("boot_id") == boot
            and witness.get("stage1") == "NOT_READY" and witness.get("authority_effect") == "NONE"
            and all(witness.get(k) == receipt[k] for k in ("source_commit", "source_tree", "archive_sha256", "release_digest"))
            and witness.get("source_receipt_sha256") == sha(canonical(receipt)),
                "AUTHORITY_INSTALL_WITNESS_DENIED")
        selector = witness.get("rollback_selector")
        require(isinstance(selector, str) and re.fullmatch(
        r"/var/lib/serein/rollback/kernel-first-install-\d{8}T\d{6}Z-[0-9a-f]{12}", selector),
            "AUTHORITY_NATIVE_PLAN_PATH_DENIED")
        plan_raw = read_bytes(rooted(selector + "/plan.json"), expected_custody=(0, 0, 0o600))
        plan = strict_json(plan_raw)
        require(canonical(plan) == plan_raw, "AUTHORITY_NATIVE_PLAN_BYTES_DENIED")
    native_identity = verify_native_binding(
        plan, read_bytes(rooted(NATIVE_REGISTRY), expected_custody=(0, 0, 0o644)), anchor, witness,
        identity_source=read_bytes(rooted(MATERIAL + "domain_identity.py"), expected_custody=(0, 0, 0o644)))
    # The signature/native-context checks above authenticate this exact plan.
    # Binding a public policy is source evidence, not a runtime grant. Its
    # closed conversation semantics and current conditions are checked at use.
    conversation_path = MATERIAL + CONVERSATION_POLICY_FILE
    conversation_source = "payload/serein_stage1/" + CONVERSATION_POLICY_FILE
    conversation_raw = read_bytes(rooted(conversation_path), expected_custody=(0, 0, 0o644))
    conversation_rows = [row for row in plan["payload"]
                         if isinstance(row, dict) and (row.get("source") == conversation_source
                                                      or row.get("target") == conversation_path)]
    require(len(conversation_rows) == 1 and conversation_rows[0] == {
        "branch": "AUTHORITY", "source": conversation_source, "target": conversation_path,
        "bytes": len(conversation_raw), "sha256": sha(conversation_raw), "mode": "0644"},
        "AUTHORITY_CONVERSATION_POLICY_BINDING_DENIED")
    require(read_bytes(source / conversation_source) == conversation_raw,
            "AUTHORITY_CONVERSATION_POLICY_SOURCE_DENIED")
    conversation_policy = {"path": conversation_path, "source": conversation_source,
                           "sha256": sha(conversation_raw), "plan_sha256": sha(plan_raw),
                           "state": "SIGNED_INSTALLED_POLICY_NOT_RUNTIME_ADMISSION",
                           "authority_effect": "NONE", "admission_effect": "NONE"}
    frame_identity = verify_host_identity(root, plan, witness)
    for path, expected in captured.items():
        require(regular(path, root=root, expected_custody=captured_custody.get(path)) == expected,
                "AUTHORITY_INPUT_CHANGED")
    # Rechecking captured files alone cannot detect new unmanifested source.
    require(source_inventory() == inventory, "AUTHORITY_SOURCE_INVENTORY_CHANGED")
    require(current_boot() == boot, "AUTHORITY_BOOT_CHANGED")
    require(os.path.lexists(witness_path)==had_witness,'AUTHORITY_INPUT_CHANGED')
    require(verify_host_identity(root, plan, witness) == frame_identity, "AUTHORITY_HOST_IDENTITY_CHANGED")
    return {"source_commit": receipt["source_commit"], "source_tree": receipt["source_tree"],
            "canonical_manifest_digest": sha(captured[source / "release-manifest.json"]),
            "boot_id": boot, "api_health": "UNKNOWN", "source_integrity": "VERIFIED",
            # Only these three predicates have completed above: authenticated
            # source/installed identity, pinned Blueprint/policy, and signed
            # current-boot Host/frame binding, including stability rechecks.
            # None proves API health, runtime containment or admission.
            "self_tests": [{"name": name, "verdict": "PASS" if name in {
                "implementation-identity", "blueprint-policy-integrity", "frame-identity"
            } else "UNKNOWN"} for name in PHASE_A_CHECKS],
            "proof": {"identity": seed["identity"], "policy": "DEFAULT_" + policy["default_decision"],
                      "containment": "PRIVATE_ONLY", "self_admission": policy["self_admission"],
                      "native_identity": native_identity, "frame_identity": frame_identity,
                      "conversation_policy": conversation_policy}}
