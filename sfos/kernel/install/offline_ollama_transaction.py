#!/usr/bin/env python3
"""Fail-closed installation of an already-present Ollama runtime/model bundle.

This transaction never resolves a URL and never invokes ``ollama pull``.  Its
only source is a caller-supplied directory whose complete byte denominator is
bound by ``bundle-manifest.json``.
"""
from __future__ import annotations

import hashlib
import csv
import base64
import json
import os
import re
import shutil
import stat
import tarfile
import tempfile
import subprocess
import shlex
from pathlib import Path, PurePosixPath
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

class TransactionError(RuntimeError):
    pass


# Native llama.cpp d222767 (Ollama f96e7aa / 0.33.2): --fit-target is
# a device-memory margin, not a layer count, model or context override.
# This is an unadmitted candidate constituent. Only the enclosing complete
# Kernel transaction may install it; a rendered configuration is not proof
# of placement, latency, GPU ownership, or Stage 1.
NATIVE_ALLOCATION_ENVIRONMENT = {'LLAMA_ARG_FIT_TARGET': '512'}
NATIVE_ALLOCATION_TARGET = '/etc/systemd/system/ollama.service.d/serein-allocation.conf'
NATIVE_ALLOCATION_RUNTIME = {
    'binary_sha256': '20cca6e293efd5bbed05b26abba891df7dec75ac3edc640caa5f60eed95c6292',
    'binary_bytes': 39348080,
    'model_root': '/var/lib/ollama/models',
}
NATIVE_ALLOCATION_SCHEMA = 'SereinNativeAllocationPlan/v1'
NATIVE_ALLOCATION_RECEIPT = 'SereinNativeAllocationReceipt/v1'
NATIVE_ALLOCATION_WARMUP = ('/usr/libexec/serein/serein-ollama-warmup', 1634,
    '4a8971d72739c161d2f082a67814ad3646065a3a77011fd978311ffdf98cc89e')


def native_allocation_configuration(environment):
    """Render the one candidate delta; never accept caller-supplied settings."""
    if (type(environment) is not dict
            or environment != NATIVE_ALLOCATION_ENVIRONMENT
            or any(type(key) is not str or type(value) is not str
                   for key, value in environment.items())):
        raise TransactionError('NATIVE_ALLOCATION_CONFIGURATION_DENIED')
    return b'[Service]\nEnvironment="LLAMA_ARG_FIT_TARGET=512"\n'


def native_worker_policy(arguments, environment, material):
    """Effective native options derived from the pinned d222767 parser/defaults.

    This is configuration evidence, not measured KV allocation or performance.
    Never infer a loaded layer count or a safe numeric margin from this result.
    """
    aliases={'-c':'context','--ctx-size':'context','-np':'parallel','--parallel':'parallel',
        '-ctk':'key','--cache-type-k':'key','-ctv':'value','--cache-type-v':'value',
        '-m':'model','--model':'model','-fitt':'fit_target','--fit-target':'fit_target',
        '-fit':'fit','--fit':'fit','-ngl':'layers','--n-gpu-layers':'layers','--gpu-layers':'layers'}
    if (type(arguments) is not list or not arguments or any(type(a) is not str for a in arguments)
            or type(environment) is not dict or environment.get('LLAMA_ARG_FIT_TARGET')!='512'):
        raise TransactionError('NATIVE_ALLOCATION_CHILD_POLICY_DENIED')
    # The pinned Ollama launcher emits these fixed non-allocation options.
    # Unknown options are not evidence of preserved context/model semantics.
    fixed_options={'--host':'127.0.0.1','--log-verbosity':'4',
        '--flash-attn':'auto','-b':'512','-ub':'512','--keep':'4'}
    switches={'--no-webui','--offline','--no-log-prefix',
        '--no-log-timestamps','--context-shift'}
    selected={};seen=set();index=1
    while index<len(arguments):
        token=arguments[index];name,sep,value=token.partition('=')
        if name in seen:
            raise TransactionError('NATIVE_ALLOCATION_CHILD_POLICY_DENIED')
        seen.add(name)
        if name in switches:
            if sep:raise TransactionError('NATIVE_ALLOCATION_CHILD_POLICY_DENIED')
        elif name in aliases or name in fixed_options or name=='--port':
            if not sep:
                index+=1
                if index>=len(arguments):raise TransactionError('NATIVE_ALLOCATION_CHILD_POLICY_DENIED')
                value=arguments[index]
            if name in aliases:
                field=aliases[name]
                if field in selected:raise TransactionError('NATIVE_ALLOCATION_CHILD_POLICY_DENIED')
                selected[field]=value
            elif name=='--port':
                if not value.isdecimal() or not 1<=int(value)<=65535:
                    raise TransactionError('NATIVE_ALLOCATION_CHILD_POLICY_DENIED')
            elif value!=fixed_options[name]:
                raise TransactionError('NATIVE_ALLOCATION_CHILD_POLICY_DENIED')
        else:
            raise TransactionError('NATIVE_ALLOCATION_CHILD_POLICY_DENIED')
        index+=1
    # Exact current model payload identified by installed readback, not a
    # substituted smaller model. The signed material list must contain it.
    model='/var/lib/ollama/models/blobs/sha256-85e4a5b7b8ef0e48af0e8658f5aaab9c2324c76c1641493f4d1e25fce54b18b9'
    expected={'context':'8192','parallel':'1','key':'f16','value':'f16','model':model,
        'fit_target':'512','fit':'on'}
    effective={'key':'f16','value':'f16','fit':'on','fit_target':environment['LLAMA_ARG_FIT_TARGET'],**selected}
    env_fields={'LLAMA_ARG_CTX_SIZE':'8192','LLAMA_ARG_CACHE_TYPE_K':'f16',
        'LLAMA_ARG_CACHE_TYPE_V':'f16','LLAMA_ARG_FIT':'on','OLLAMA_KV_CACHE_TYPE':'f16',
        'LLAMA_ARG_N_PARALLEL':'1','LLAMA_ARG_MODEL':model,'LLAMA_ARG_FIT_TARGET':'512'}
    if (effective!=expected or set(environment)-set(env_fields)
            or any(name in environment and environment[name]!=value for name,value in env_fields.items())
            or not any(row['path']==model and row['role']=='model' and row['type']=='regular'
                       and row['sha256']==model.rsplit('-',1)[1] for row in material)):
        raise TransactionError('NATIVE_ALLOCATION_CHILD_POLICY_DENIED')
    return {'result':'PINNED_NATIVE_CONFIGURATION_OBSERVED','context':8192,'parallel':1,
        'key':'f16','value':'f16','fit_target_mib':512,'model_path':model,
        'defaults_source':'llama.cpp/d222767c7a6516559a3f49e7721b6c6b1acc87b4/common/common.h',
        'placement':'UNPROVEN','performance':'UNPROVEN','stage1':'NOT_READY'}


def native_allocation_transition(before, after, *, restoring=False):
    """Verify a declared restart without erasing the original process tuple.

    Inputs are observations captured by the transaction, not caller authority.
    Complete material custody/bytes and boot remain identical; only the process
    incarnation and this one native setting may change. In restoration mode
    ``before`` is the retained original and ``after`` the observed restoration;
    restoring bytes must not be misreported as restoring the original PID.
    This pure comparison does not read/write files, restart, or admit anything.
    """
    try:
        before = json.loads(canonical(before)); after = json.loads(canonical(after))
        fields = {'runtime', 'environment', 'material', 'model', 'required_context', 'required_kv_cache'}
        runtime_fields = {'boot_id', 'pid', 'start_time', 'binary_sha256', 'binary_bytes', 'model_root'}
        if type(restoring) is not bool or set(before) != fields or set(after) != fields:
            raise ValueError('SHAPE')
        for value in (before, after):
            runtime = value['runtime']
            if (type(runtime) is not dict or set(runtime) != runtime_fields
                    or not isinstance(runtime['boot_id'], str)
                    or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', runtime['boot_id'])
                    or type(runtime['pid']) is not int or runtime['pid'] <= 0
                    or not isinstance(runtime['start_time'], str)
                    or not runtime['start_time'].isdecimal()
                    or any(runtime[key] != expected for key, expected in NATIVE_ALLOCATION_RUNTIME.items())
                    or type(runtime['binary_bytes']) is not int
                    or value['model'] != PINNED_MODEL
                    or type(value['required_context']) is not int or value['required_context'] != 8192
                    or value['required_kv_cache'] != {'key': 'f16', 'value': 'f16'}):
                raise ValueError('RUNTIME')
            environment = value['environment']
            if (type(environment) is not dict
                    or any(type(key) is not str or type(item) is not str
                           or not key or '\x00' in key + item for key, item in environment.items())):
                raise ValueError('ENVIRONMENT')
            # Exact byte inventory is supplied by the source-bound collector.
            # Require both runtime and model closure, not just the main binary.
            material = value['material']
            if type(material) is not list or not material:
                raise ValueError('MATERIAL')
            seen = set(); roles = set()
            for row in material:
                if (type(row) is not dict
                        or set(row) != {'path', 'role', 'type', 'sha256', 'bytes', 'uid', 'gid', 'mode'}
                        or row['role'] not in {'runtime', 'model'}
                        or row['type'] not in {'regular', 'symlink', 'directory'}
                        or type(row['path']) is not str or not row['path'].startswith('/')
                        or str(PurePosixPath(row['path'])) != row['path']
                        or '..' in PurePosixPath(row['path']).parts or '\\' in row['path']
                        or row['path'] in seen
                        or type(row['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}', row['sha256'])
                        or any(type(row[key]) is not int or row[key] < 0 for key in ('bytes', 'uid', 'gid', 'mode'))
                        or row['mode'] > 0o7777):
                    raise ValueError('MATERIAL_ROW')
                seen.add(row['path']); roles.add(row['role'])
            if roles != {'runtime', 'model'}:
                raise ValueError('MATERIAL_CLOSURE')
        old = before['runtime']; new = after['runtime']
        if (any(old[key] != new[key] for key in runtime_fields - {'pid', 'start_time'})
                or (not (restoring and old == new)
                    and int(new['start_time']) <= int(old['start_time']))
                or before['material'] != after['material']):
            raise ValueError('PRESERVATION')
        expected_environment = dict(before['environment'])
        if not restoring:
            expected_environment.update(NATIVE_ALLOCATION_ENVIRONMENT)
        if after['environment'] != expected_environment:
            raise ValueError('ENVIRONMENT_DELTA')
        return {'result': 'RESTORED_RUNTIME_OBSERVED' if restoring else 'NATIVE_ALLOCATION_TRANSITION_OBSERVED',
                'before': before, 'after': after, 'stage1': 'NOT_READY',
                'placement': 'UNPROVEN', 'performance': 'UNPROVEN',
                'authority_effect': 'NONE', 'admission_effect': 'NONE'}
    except (ValueError, TypeError, KeyError, OverflowError) as exc:
        raise TransactionError('NATIVE_ALLOCATION_TRANSITION_DENIED') from exc


# ADAPT only the used primitives from public0dca6bd7 transaction.py,
# blob66d515d49880a3d5a7a568cc899cd4cc692dcb4f. The old ambient import
# referred to an absent Kernel sibling and an incompatible current Outpost
# module. Do not copy the donor's account creation, reload or key machinery.
def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def under(root, absolute):
    root = Path(root)
    if not isinstance(absolute, str):
        raise TransactionError('TARGET_PATH_DENIED')
    pure = PurePosixPath(absolute)
    if (not root.is_absolute() or not pure.is_absolute() or str(pure) != absolute
            or '..' in pure.parts or '\\' in absolute):
        raise TransactionError('TARGET_PATH_DENIED')
    path = root / absolute.lstrip('/')
    if path == root or root not in path.parents:
        raise TransactionError('TARGET_PATH_DENIED')
    return path


def nofollow_ancestors(root, path, allow_missing=True):
    current = Path(root)
    try:
        parts = Path(path).relative_to(current).parts
    except ValueError as exc:
        raise TransactionError('TARGET_PATH_DENIED') from exc
    if '..' in parts:
        raise TransactionError('TARGET_PATH_DENIED')
    if current.is_symlink():
        raise TransactionError('ROOT_SYMLINK_DENIED')
    for part in parts:
        current = current / part
        if os.path.lexists(current) and current.is_symlink():
            raise TransactionError('PATH_SYMLINK_DENIED:' + str(current))
        if not os.path.lexists(current) and not allow_missing:
            raise TransactionError('PATH_MISSING:' + str(current))


class RealAdapter:
    """Existing offline installer's substrate reader; no account/reload methods."""
    def __init__(self, unit_names=()):
        self.root = Path('/')
        self.unit_state = {name:self.read_unit(name) for name in unit_names}

    def boundary(self):
        pass

    def directory_metadata(self, path):
        info = Path(path).lstat()
        return {'mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid}

    file_metadata = directory_metadata

    def read_unit(self, name):
        if name != 'ollama.service':
            raise TransactionError('OFFLINE_UNIT_DENIED')
        # systemd v257 systemctl-is-{enabled,active}.c: state and exit status
        # are one observation. Empty/error output is never stopped prestate.
        allowed = {
            'is-enabled': {0: {'enabled', 'enabled-runtime', 'static', 'alias',
                               'indirect', 'generated'},
                           1: {'disabled', 'masked', 'masked-runtime', 'linked',
                               'linked-runtime', 'transient', 'bad'},
                           4: {'not-found'}},
            'is-active': {0: {'active', 'reloading', 'refreshing'},
                          3: {'inactive', 'failed', 'activating', 'deactivating',
                              'maintenance'},
                          4: {'inactive'}},
        }
        result = {}
        for operation, field in (('is-enabled', 'enabled'), ('is-active', 'active')):
            try:
                observed = subprocess.run(['systemctl', operation, name], text=True,
                                          capture_output=True, check=False, timeout=30)
            except (OSError, subprocess.SubprocessError) as exc:
                raise TransactionError('OFFLINE_UNIT_STATUS_UNAVAILABLE') from exc
            state = observed.stdout.strip()
            if (observed.stderr.strip()
                    or state not in allowed[operation].get(observed.returncode, set())):
                raise TransactionError('OFFLINE_UNIT_STATUS_INVALID:' + operation)
            result[field] = state
        return result


BUNDLE_SCHEMA = "SereinOfflineOllamaBundle/v2"
PLAN_SCHEMA = "SereinOfflineOllamaInstallPlan/v2"
RECEIPT_SCHEMA = "SereinOfflineOllamaInstallReceipt/v2"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PINNED_ARCHIVE={"source":"ollama-linux-amd64-v0.33.3.tar","sha256":"9088b9e666c0db7e4eafa8ac110a4f114af15595e4bcda2a3b0dba2afb376604","bytes":2262201344,
                "member":"bin/ollama","member_sha256":"7deaad14177b824d8fcff7136d4418c0111d2db35fa872a5071fa8db5b8db527","member_bytes":39521328}
ORIGINAL_ARCHIVE_PROVENANCE={"url":"https://github.com/ollama/ollama/releases/download/v0.33.3/ollama-linux-amd64.tar.zst",
    "sha256":"c13cea8f3389db4145f8a6cb88d1747242a48639d7c13e3bda7c1ebdc6eebb2f","bytes":1433825108}
ARCHIVE_DENOMINATOR_SOURCE="ollama-linux-amd64-v0.33.3.archive-denominator.json"
ARCHIVE_DENOMINATOR_SHA256="d71bf196f13cfd7481a7af57bde34df56d7d4ae94f3e3c86b3c7fa87aed4da2c"
PINNED_MODEL={"name":"qwen3:4b-instruct","digest":"sha256:0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0"}
PINNED_MODEL_FILES={
 "0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0":859,
 "0914c7781e001948488d937994217538375b4fd8c1466c5e7a625221abd3ea7a":119,
 "85e4a5b7b8ef0e48af0e8658f5aaab9c2324c76c1641493f4d1e25fce54b18b9":2497280480,
 "b72accf9724e93698c57cbd3b1af2d3341b3d05ec2089d86d273d97964853cd2":487,
 "d18a5cc71b84bc4af394a31116bd3932b42241de70c77d2b76d69a314ec8aa12":11338,
 "eade0a07cac7712787bbce23d12f9306adb4781d873d1df6e16f7840fa37afec":1379,
}
SELECTOR = re.compile(
    r"/var/lib/serein/rollback/offline-ollama-\d{8}T\d{6}Z-[0-9a-f]{12}\Z")
IMMUTABLE_TARGETS = frozenset({
    "/etc/serein-outpost/readonly.token", "/etc/serein-outpost/admission.token",
    "/etc/serein-outpost/cognition-signing.pem",
    "/usr/share/serein/outpost/cognition-verification.pem",
})
MODEL_DIRECTORIES = (
    "/usr/share/ollama", "/usr/share/ollama/.ollama",
    "/usr/share/ollama/.ollama/models", "/usr/share/ollama/.ollama/models/blobs",
    "/usr/share/ollama/.ollama/models/manifests",
    "/usr/share/ollama/.ollama/models/manifests/registry.ollama.ai",
    "/usr/share/ollama/.ollama/models/manifests/registry.ollama.ai/library",
    "/usr/share/ollama/.ollama/models/manifests/registry.ollama.ai/library/qwen3",
)


def _restorable_unit(state):
    # Preserve every observed state, but this transaction can restore only
    # these four pairs. Never collapse masked/runtime/failed/unknown to stopped.
    if (not isinstance(state, dict) or set(state) != {'enabled', 'active'}
            or state['enabled'] not in ('enabled', 'disabled')
            or state['active'] not in ('active', 'inactive')):
        raise TransactionError('OFFLINE_UNIT_PRESTATE_NOT_RESTORABLE')


class OfflineOllamaRealAdapter(RealAdapter):
    """Production effects; the only HTTP roads are provider-owned loopback URLs."""
    def __init__(self):
        super().__init__(["ollama.service"])
        self.boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    def stop_unit(self,name):
        if name!="ollama.service": raise TransactionError("OFFLINE_UNIT_DENIED")
        subprocess.run(["systemctl","stop",name],check=True)
    def start_unit(self,name):
        if name!="ollama.service": raise TransactionError("OFFLINE_UNIT_DENIED")
        subprocess.run(["systemctl","start",name],check=True)
    def reload_native_allocation(self):
        subprocess.run(['systemctl','daemon-reload'],check=True,timeout=30)
    def read_native_allocation_definition(self):
        result=subprocess.run(['systemctl','show','ollama.service',
            '--property=FragmentPath,DropInPaths,NeedDaemonReload,Environment,EnvironmentFiles'],
            capture_output=True,text=True,check=True,timeout=10)
        rows=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
        if (set(rows)!={'FragmentPath','DropInPaths','NeedDaemonReload','Environment','EnvironmentFiles'}
                or result.stderr.strip() or rows['NeedDaemonReload'] not in {'yes','no'}):
            raise TransactionError('NATIVE_ALLOCATION_DEFINITION_DENIED')
        environment={}
        for pair in shlex.split(rows['Environment']):
            name,sep,value=pair.partition('=')
            if not sep or not re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',name) or name in environment:
                raise TransactionError('NATIVE_ALLOCATION_DEFINITION_ENVIRONMENT_DENIED')
            environment[name]=value
        return {'fragment':rows['FragmentPath'],'dropins':rows['DropInPaths'].split(),
            'need_reload':rows['NeedDaemonReload'],'environment':environment,
            'environment_files':rows['EnvironmentFiles']}
    def preload_native_allocation(self):
        # Same source-bound empty-prompt preload as complete Kernel residency.
        # It supplies no synthetic answer and changes no model or context.
        name, size, expected = NATIVE_ALLOCATION_WARMUP
        path = under(self.root, name); nofollow_ancestors(self.root, path, allow_missing=False)
        raw,before,identity = _native_file_read(self, path, limit=1634)
        if (before['sha256'] != expected or before['bytes'] != size
                or before['uid'] != 0 or before['gid'] != 0 or before['mode'] != 0o755):
            raise TransactionError('NATIVE_ALLOCATION_WARMUP_SOURCE_DENIED')
        # Execute the exact captured and pinned Python bytes. A pathname swap
        # after verification cannot choose a different root program.
        subprocess.run(['/usr/bin/python3','-B','-c',raw.decode('utf-8')],
                       check=True,timeout=1860,capture_output=True)
        if _native_file_read(self,path,limit=1634)!=(raw,before,identity):
            raise TransactionError('NATIVE_ALLOCATION_WARMUP_SOURCE_CHANGED')
    def restore_unit(self,name,state):
        if name!="ollama.service": raise TransactionError("OFFLINE_UNIT_DENIED")
        _restorable_unit(state)
        subprocess.run(["systemctl","enable" if state["enabled"]=="enabled" else "disable",name],check=True)
        subprocess.run(["systemctl","start" if state["active"]=="active" else "stop",name],check=True)
    def ollama_tags(self):
        from serein_stage1.companion_provider import list_models
        return list_models()["models"]
    def _runtime_pid(self):
        observed=subprocess.run(['systemctl','show','ollama.service','--property=MainPID','--value'],
                                capture_output=True,text=True,check=False,timeout=10)
        value=observed.stdout.strip()
        if observed.returncode or observed.stderr.strip() or not re.fullmatch(r'[1-9][0-9]*',value):
            raise TransactionError('OFFLINE_RUNTIME_PROCESS_UNAVAILABLE')
        return int(value)
    def native_runtime_stopped(self):
        result=subprocess.run(['systemctl','show','ollama.service','--property=MainPID','--value'],
            capture_output=True,text=True,check=True,timeout=10)
        if result.stdout.strip()!='0' or result.stderr.strip():return False
        group=self.root/'sys/fs/cgroup/system.slice/ollama.service'
        nofollow_ancestors(self.root,group)
        if not os.path.lexists(group):return True
        if group.is_symlink() or not group.is_dir():return False
        paths=[group,*sorted(path for path in group.rglob('*') if path.is_dir())]
        for path in paths:
            nofollow_ancestors(self.root,path,allow_missing=False)
            procs=path/'cgroup.procs'
            if procs.is_symlink() or procs.read_text().strip():return False
        return paths==[group,*sorted(path for path in group.rglob('*') if path.is_dir())]
    def observe_native_material(self):
        return self.observe_native_allocation(material_only=True)['material']
    def observe_native_allocation(self, *, material_only=False):
        """Capture the existing runtime's material without running inference.

        The source-bound owner must compare this with the signed plan. This
        read alone grants no restart/configuration or admission authority.
        Environment selection covers native inference/model/device controls;
        service invocation IDs are intentionally not runtime configuration.
        """
        before = None if material_only else self.observe_runtime()
        try:
            if not material_only and any(before[key] != value for key, value in NATIVE_ALLOCATION_RUNTIME.items()):
                raise ValueError('RUNTIME_IMAGE')
            proc = None if material_only else self.root/'proc'/str(before['pid'])
            def environment():
                if material_only:return {}
                with (proc/'environ').open('rb') as stream: raw = stream.read(1048577)
                if len(raw) > 1048576: raise ValueError('ENVIRONMENT_SIZE')
                selected = {}
                for pair in raw.split(b'\0'):
                    key, separator, value = pair.partition(b'=')
                    if separator and (key.startswith((b'OLLAMA_', b'LLAMA_ARG_', b'GGML_'))
                                      or key in {b'HOME', b'CUDA_VISIBLE_DEVICES', b'LD_LIBRARY_PATH'}):
                        name = key.decode('utf-8')
                        if name in selected: raise ValueError('ENVIRONMENT_DUPLICATE')
                        selected[name] = value.decode('utf-8')
                return selected
            selected = environment()
            if selected.get('OLLAMA_KV_CACHE_TYPE', 'f16') != 'f16':
                raise ValueError('KV_CACHE')
            if any(name in selected for name in ('LLAMA_ARG_CTX_SIZE', 'LLAMA_ARG_N_GPU_LAYERS',
                   'LLAMA_ARG_CACHE_TYPE_K', 'LLAMA_ARG_CACHE_TYPE_V')):
                raise ValueError('UNBOUND_OVERRIDE')
            models = self.root/'var/lib/ollama/models'
            manifest = models/'manifests/registry.ollama.ai/library/qwen3/4b-instruct'
            nofollow_ancestors(self.root, manifest, allow_missing=False)
            with manifest.open('rb') as stream:
                manifest_raw = stream.read(PINNED_MODEL_FILES[PINNED_MODEL['digest'].removeprefix('sha256:')] + 1)
            manifest_digest = hashlib.sha256(manifest_raw).hexdigest()
            if (manifest_digest != PINNED_MODEL['digest'].removeprefix('sha256:')
                    or len(manifest_raw) != PINNED_MODEL_FILES[manifest_digest]):
                raise ValueError('MODEL_MANIFEST')
            document = json.loads(manifest_raw)
            descriptors = [document['config'], *document['layers']]
            model_paths = [manifest]
            model_hashes = {manifest: manifest_digest}
            for row in descriptors:
                identity = row['digest']
                if (not re.fullmatch('sha256:[0-9a-f]{64}', identity)
                        or type(row['size']) is not int
                        or PINNED_MODEL_FILES.get(identity.removeprefix('sha256:')) != row['size']):
                    raise ValueError('MODEL_BLOB')
                path = models/'blobs'/identity.replace(':', '-')
                model_paths.append(path); model_hashes[path] = identity.removeprefix('sha256:')
            if (len(set(model_paths)) != len(model_paths)
                    or {PINNED_MODEL['digest'].removeprefix('sha256:'),
                        *(row['digest'].removeprefix('sha256:') for row in descriptors)} != set(PINNED_MODEL_FILES)):
                raise ValueError('MODEL_CLOSURE')
            runtime = self.root/'usr/lib/ollama'
            nofollow_ancestors(self.root, runtime, allow_missing=False)
            def runtime_paths():
                return [self.root/'usr/bin/ollama', runtime, *sorted(runtime.rglob('*'))]
            runtime_files = runtime_paths()
            material = []; identities = []
            for role, paths in (('runtime', runtime_files), ('model', model_paths)):
                for path in paths:
                    nofollow_ancestors(self.root, path.parent, allow_missing=False)
                    initial = path.lstat()
                    if stat.S_ISREG(initial.st_mode):
                        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                        with os.fdopen(fd, 'rb') as stream:
                            captured = os.fstat(stream.fileno()); value = hashlib.sha256(); size = 0
                            while chunk := stream.read(8*1024*1024):
                                value.update(chunk); size += len(chunk)
                            final = os.fstat(stream.fileno())
                        kind = 'regular'; digest_value = value.hexdigest()
                    elif role == 'runtime' and stat.S_ISLNK(initial.st_mode):
                        raw = os.readlink(path).encode('utf-8')
                        resolved = path.resolve(strict=True)
                        if resolved not in runtime_files or not resolved.is_file():
                            raise ValueError('RUNTIME_LINK_OUTSIDE_MATERIAL')
                        captured = final = initial; kind = 'symlink'
                        size = len(raw); digest_value = hashlib.sha256(raw).hexdigest()
                    elif role == 'runtime' and stat.S_ISDIR(initial.st_mode):
                        captured = final = initial; kind = 'directory'
                        size = 0; digest_value = hashlib.sha256(b'').hexdigest()
                    else: raise ValueError('MATERIAL_TYPE')
                    identity = lambda info: (info.st_dev, info.st_ino, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns, info.st_mode, info.st_uid, info.st_gid)
                    if not identity(initial) == identity(captured) == identity(final) == identity(path.lstat()):
                        raise ValueError('MATERIAL_CHANGED')
                    identities.append((path, identity(initial)))
                    if role == 'model' and (digest_value != model_hashes[path]
                            or PINNED_MODEL_FILES.get(digest_value) != size):
                        raise ValueError('MODEL_BYTES')
                    material.append({'path': '/'+path.relative_to(self.root).as_posix(),
                        'role': role, 'type': kind, 'sha256': digest_value, 'bytes': size,
                        'uid': initial.st_uid, 'gid': initial.st_gid, 'mode': stat.S_IMODE(initial.st_mode)})
            if (runtime_paths() != runtime_files
                    or (not material_only and self.observe_runtime() != before) or environment() != selected
                    or any(identity(path.lstat()) != expected for path, expected in identities)):
                raise ValueError('RUNTIME_CHANGED')
            return {'runtime': before, 'environment': selected, 'material': material,
                'model': dict(PINNED_MODEL), 'required_context': 8192,
                'required_kv_cache': {'key': 'f16', 'value': 'f16'}}
        except (OSError, ValueError, KeyError, TypeError, UnicodeError, RuntimeError) as exc:
            raise TransactionError('NATIVE_ALLOCATION_OBSERVATION_DENIED') from exc
    def observe_runtime(self, *, expected=None):
        """Read the actual service process, never execute a candidate binary.

        Reuses the proven PVE readback primitives: systemd MainPID, proc exe,
        process start time and only the model-path environment fields. This
        is identity evidence, not proof of library/GPU custody or admission.
        The owning transaction may supply its exact preserved-runtime prestate.
        This does not select the optional replacement recipe, change a runtime,
        or establish the provenance/authority of that caller-owned expectation.
        """
        try:
            if expected is not None:
                expected=json.loads(canonical(expected))
                if (not isinstance(expected,dict) or set(expected)!={'boot_id','pid','start_time',
                        'binary_sha256','binary_bytes','model_root'}
                        or expected['boot_id']!=self.boot_id
                        or type(expected['pid']) is not int or expected['pid']<=0
                        or type(expected['binary_bytes']) is not int
                        or not 0<expected['binary_bytes']<=64*1024*1024
                        or not isinstance(expected['start_time'],str) or not expected['start_time'].isdecimal()
                        or not isinstance(expected['binary_sha256'],str)
                        or not re.fullmatch('[0-9a-f]{64}',expected['binary_sha256'])
                        or not isinstance(expected['model_root'],str)
                        or not expected['model_root'].startswith('/')
                        or str(PurePosixPath(expected['model_root']))!=expected['model_root']
                        or '..' in PurePosixPath(expected['model_root']).parts):
                    raise ValueError('PRESERVED_RUNTIME_EXPECTATION')
            boot_path=self.root/'proc/sys/kernel/random/boot_id'
            boot=boot_path.read_text().strip();pid=self._runtime_pid()
            proc=self.root/'proc'/str(pid)
            def start_time():
                value=(proc/'stat').read_text()
                if not value.startswith(str(pid)+' ('):raise ValueError('PID')
                result=value.rsplit(') ',1)[1].split()[19]
                if not result.isdecimal():raise ValueError('START_TIME')
                return result
            def model_root():
                with (proc/'environ').open('rb') as stream:raw=stream.read(1048577)
                if len(raw)>1048576:raise ValueError('ENVIRONMENT_SIZE')
                selected={}
                for pair in raw.split(b'\0'):
                    key,separator,value=pair.partition(b'=')
                    if separator and key in {b'OLLAMA_MODELS',b'HOME'}:
                        if key in selected:raise ValueError('ENVIRONMENT_DUPLICATE')
                        selected[key]=value.decode('utf-8')
                value=selected.get(b'OLLAMA_MODELS')
                if value is None:
                    home=selected.get(b'HOME')
                    if not home:raise ValueError('MODEL_ROOT_UNKNOWN')
                    value=home+'/.ollama/models'
                if not value.startswith('/') or str(PurePosixPath(value))!=value or '..' in PurePosixPath(value).parts:
                    raise ValueError('MODEL_ROOT')
                return value
            started=start_time();models=model_root()
            # proc/<pid>/exe is intentionally dereferenced: Linux exposes the
            # executing inode here, including an unlinked old executable.
            with (proc/'exe').open('rb') as stream:
                before=os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_size>64*1024*1024:
                    raise ValueError('EXECUTABLE_SIZE_OR_TYPE')
                value=hashlib.sha256();size=0
                while chunk:=stream.read(1048576):
                    size+=len(chunk)
                    if size>64*1024*1024:raise ValueError('EXECUTABLE_SIZE')
                    value.update(chunk)
                after=os.fstat(stream.fileno())
            identity=lambda info:(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
            if (identity(before)!=identity(after) or identity(after)!=identity((proc/'exe').stat())
                    or size!=before.st_size or started!=start_time() or models!=model_root()
                    or pid!=self._runtime_pid() or boot!=boot_path.read_text().strip()):
                raise ValueError('PROCESS_CHANGED')
            observed={'boot_id':boot,'pid':pid,'start_time':started,
                    'binary_sha256':value.hexdigest(),'binary_bytes':size,'model_root':models}
            if expected is not None and observed!=expected:
                raise ValueError('PRESERVED_RUNTIME_CHANGED')
            return observed
        except (OSError,ValueError,TypeError,IndexError,subprocess.SubprocessError) as exc:
            raise TransactionError('OFFLINE_RUNTIME_PROCESS_UNAVAILABLE') from exc
    def companion_inference(self,model):
        from serein_stage1.companion_provider import MODEL,infer
        from serein_stage1.gpu_control import collect
        if model!=MODEL: raise TransactionError("OFFLINE_MODEL_IDENTITY_DENIED")
        before=self.observe_runtime()
        if (before['boot_id']!=self.boot_id or before['binary_sha256']!=PINNED_ARCHIVE['member_sha256']
                or before['binary_bytes']!=PINNED_ARCHIVE['member_bytes']
                or before['model_root']!=MODEL_DIRECTORIES[2]):
            raise TransactionError('OFFLINE_RUNTIME_PROCESS_MISMATCH')
        gpu=collect()
        answer=infer("Reply with one short factual sentence: two plus two equals four.")
        binding=self.observe_gpu_binding(gpu)
        if canonical(collect())!=canonical(gpu):
            raise TransactionError('OFFLINE_GPU_RUNTIME_INVENTORY_CHANGED')
        if self.observe_runtime()!=before:raise TransactionError('OFFLINE_RUNTIME_PROCESS_CHANGED')
        return {"model":MODEL,"answer":answer,"gpu_runtime_binding":binding}

    def observe_gpu_binding(self, gpu, *, gpu_module=None):
        """Bind active GPU workers to this runtime, without exclusive custody.

        ADAPT PRO142 Primus recovery V3 df217ffc: actual runtime/device binding,
        not a claim based on device presence. Ollama's GPU worker can be a child
        of its manager. NVIDIA's documented compute-app query supplies PID/UUID;
        Linux's fixed service cgroup binds that worker back to the runtime.
        This is read-only evidence for the enclosing complete Kernel verifier.
        """
        if gpu_module is None:
            from serein_stage1 import gpu_control as gpu_module
        verify, GPUControlDenied = gpu_module.verify, gpu_module.GPUControlDenied
        try:
            gpu=json.loads(canonical(gpu))
            verify(gpu)
            inventory=gpu['inventory']
            uuids={row[1].strip() for row in csv.reader(inventory['nvidia_smi'],strict=True)}
            before=self.observe_runtime()
            if before['boot_id']!=gpu['boot_id'] or before['boot_id']!=self.boot_id:
                raise ValueError('BOOT')
            group='0::/system.slice/ollama.service'

            def process(pid):
                proc=self.root/'proc'/str(pid)
                cgroup=(proc/'cgroup').read_text().strip()
                if cgroup!=group:raise ValueError('SERVICE_CGROUP')
                fields=(proc/'stat').read_text()
                if not fields.startswith(str(pid)+' ('):raise ValueError('PID')
                started=fields.rsplit(') ',1)[1].split()[19]
                if not started.isdecimal():raise ValueError('START_TIME')
                with (proc/'exe').open('rb') as stream:
                    original=os.fstat(stream.fileno())
                    if not stat.S_ISREG(original.st_mode) or not 0<original.st_size<=64*1024*1024:
                        raise ValueError('EXECUTABLE_SIZE')
                    value=hashlib.sha256();size=0
                    while chunk:=stream.read(1048576):
                        size+=len(chunk)
                        if size>64*1024*1024:raise ValueError('EXECUTABLE_SIZE')
                        value.update(chunk)
                    final=os.fstat(stream.fileno())
                identity=lambda info:(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
                if identity(original)!=identity(final) or identity(final)!=identity((proc/'exe').stat()):
                    raise ValueError('EXECUTABLE_CHANGED')
                return {'pid':pid,'start_time':started,'cgroup':cgroup,
                        'binary_sha256':value.hexdigest(),'binary_bytes':size}

            manager=process(before['pid'])
            if any(manager[name]!=before[name] for name in ('start_time','binary_sha256','binary_bytes')):
                raise ValueError('MANAGER_CHANGED')
            def memberships():
                observed=subprocess.run(['nvidia-smi','--query-compute-apps=pid,gpu_uuid',
                    '--format=csv,noheader,nounits'],capture_output=True,text=True,check=False,timeout=10)
                if observed.returncode or observed.stderr.strip() or len(observed.stdout)>65536:
                    raise ValueError('GPU_QUERY')
                seen=set()
                for row in csv.reader(observed.stdout.splitlines(),skipinitialspace=True,strict=True):
                    if len(row)!=2:raise ValueError('GPU_QUERY_ROW')
                    pid,uuid=(item.strip() for item in row)
                    if not re.fullmatch(r'[1-9][0-9]{0,9}',pid) or uuid not in uuids:
                        raise ValueError('GPU_QUERY_IDENTITY')
                    key=(int(pid),uuid)
                    if key in seen:raise ValueError('GPU_QUERY_DUPLICATE')
                    seen.add(key)
                return seen
            workers=[]
            for pid,uuid in sorted(memberships()):
                # Other workloads may legitimately share a Host GPU. They do
                # not prove or disprove this exact runtime's GPU binding.
                proc=self.root/'proc'/str(pid)
                if (proc/'cgroup').read_text().strip()!=group:continue
                workers.append({**process(pid),'gpu_uuid':uuid})
            if not workers:raise ValueError('RUNTIME_GPU_WORKER_ABSENT')
            # Bracket each captured process identity with GPU membership;
            # never join an old GPU PID to a newly reused, non-GPU process.
            if not {(row['pid'],row['gpu_uuid']) for row in workers}<=memberships():
                raise ValueError('GPU_WORKER_MEMBERSHIP_CHANGED')
            for worker in workers:
                if process(worker['pid'])!={k:v for k,v in worker.items() if k!='gpu_uuid'}:
                    raise ValueError('GPU_WORKER_CHANGED')
            if process(before['pid'])!=manager or self.observe_runtime()!=before:
                raise ValueError('MANAGER_CHANGED')
            return {'state':'RUNTIME_GPU_PROCESS_OBSERVED','runtime':before,
                    'gpu':gpu,
                    'gpu_inventory_sha256':gpu['gpu_inventory_sha256'],
                    'workers':sorted(workers,key=lambda item:(item['pid'],item['gpu_uuid'])),
                    'authority_effect':'NONE','admission_effect':'NONE'}
        except (GPUControlDenied,OSError,ValueError,KeyError,IndexError,TypeError,csv.Error,
                subprocess.SubprocessError) as exc:
            raise TransactionError('OFFLINE_GPU_RUNTIME_BINDING_UNPROVEN') from exc

    def observe_native_worker_policy(self, binding, plan):
        rows=[]
        for worker in binding['workers']:
            proc=self.root/'proc'/str(worker['pid'])
            def read():
                state=(proc/'stat').read_text()
                if not state.startswith(str(worker['pid'])+' ('):
                    raise TransactionError('NATIVE_ALLOCATION_CHILD_CHANGED')
                if (state.rsplit(') ',1)[1].split()[19]!=worker['start_time']
                        or (proc/'cgroup').read_text().strip()!=worker['cgroup']):
                    raise TransactionError('NATIVE_ALLOCATION_CHILD_CHANGED')
                def bounded(name):
                    with (proc/name).open('rb') as stream:raw=stream.read(1048577)
                    if len(raw)>1048576:raise TransactionError('NATIVE_ALLOCATION_CHILD_SIZE_DENIED')
                    return raw
                return bounded('cmdline'),bounded('environ')
            args_raw,env_raw=read();environment={}
            for pair in env_raw.split(b'\0'):
                name,sep,value=pair.partition(b'=')
                if sep and name.startswith((b'LLAMA_ARG_',b'OLLAMA_KV_CACHE_TYPE')):
                    key=name.decode('utf-8')
                    if key in environment:raise TransactionError('NATIVE_ALLOCATION_CHILD_ENVIRONMENT_DUPLICATE')
                    environment[key]=value.decode('utf-8')
            policy=native_worker_policy(args_raw.decode('utf-8').rstrip('\0').split('\0'),
                environment,plan['runtime_prestate']['material'])
            if read()!=(args_raw,env_raw):raise TransactionError('NATIVE_ALLOCATION_CHILD_CHANGED')
            rows.append({'pid':worker['pid'],'start_time':worker['start_time'],'policy':policy})
        if not rows:raise TransactionError('NATIVE_ALLOCATION_CHILD_ABSENT')
        return rows


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def verify_gpu_runtime_recipe(binding, plan, *, gpu_module=None):
    """Compare measured executing images with the exact signed runtime recipe.

    Does not authorize inference, establish exclusive custody, or admit Kernel.
    The enclosing install has already verified plan signature and file parity.
    """
    if gpu_module is None:
        from serein_stage1 import gpu_control as gpu_module
    verify, GPUControlDenied = gpu_module.verify, gpu_module.GPUControlDenied
    try:
        value=json.loads(canonical(binding))
        if (set(value)!={'state','runtime','gpu','gpu_inventory_sha256','workers',
                         'authority_effect','admission_effect'}
                or value['state']!='RUNTIME_GPU_PROCESS_OBSERVED'
                or value['authority_effect']!='NONE' or value['admission_effect']!='NONE'):
            raise ValueError('MEANING')
        gpu=value['gpu'];verify(gpu)
        if (set(gpu)!={'schema','boot_id','device_count','driver_loaded',
                'gpu_inventory_sha256','authority_effect','inventory'}
                or gpu['boot_id']!=plan['boot_id']
                or value['gpu_inventory_sha256']!=gpu['gpu_inventory_sha256']):
            raise ValueError('GPU_SOURCE')
        runtime=value['runtime']
        native=plan.get('schema')==NATIVE_ALLOCATION_SCHEMA
        expected_runtime=plan['runtime_prestate']['runtime'] if native else {
            'binary_sha256':plan['runtime_archive']['member_sha256'],
            'binary_bytes':plan['runtime_archive']['member_bytes'],'model_root':MODEL_DIRECTORIES[2]}
        if (set(runtime)!={'boot_id','pid','start_time','binary_sha256','binary_bytes','model_root'}
                or runtime['boot_id']!=plan['boot_id']
                or type(runtime['pid']) is not int or runtime['pid']<=0
                or not isinstance(runtime['start_time'],str) or not runtime['start_time'].isdecimal()
                or any(runtime[key]!=expected_runtime[key] for key in ('binary_sha256','binary_bytes','model_root'))):
            raise ValueError('RUNTIME_SOURCE')
        material=([row for row in plan['runtime_prestate']['material'] if row['role']=='runtime']
                  if native else plan['runtime_objects'])
        images={(row['sha256'],row['bytes']) for row in material
                if row['type']=='regular' and row['mode']&0o111}
        if (runtime['binary_sha256'],runtime['binary_bytes']) not in images:
            raise ValueError('MANAGER_RECIPE')
        uuids={row[1].strip() for row in csv.reader(gpu['inventory']['nvidia_smi'],strict=True)}
        workers=value['workers'];seen=set()
        if not isinstance(workers,list) or not 0<len(workers)<=256:raise ValueError('WORKERS')
        for row in workers:
            if (not isinstance(row,dict) or set(row)!={'pid','start_time','cgroup',
                    'binary_sha256','binary_bytes','gpu_uuid'}
                    or type(row['pid']) is not int or row['pid']<=0
                    or not isinstance(row['start_time'],str) or not row['start_time'].isdecimal()
                    or row['cgroup']!='0::/system.slice/ollama.service'
                    or row['gpu_uuid'] not in uuids
                    or type(row['binary_bytes']) is not int
                    or (row['binary_sha256'],row['binary_bytes']) not in images
                    or (row['pid'],row['gpu_uuid']) in seen):
                raise ValueError('WORKER_RECIPE')
            seen.add((row['pid'],row['gpu_uuid']))
        return value
    except (GPUControlDenied,ValueError,KeyError,IndexError,TypeError,csv.Error) as exc:
        raise TransactionError('OFFLINE_GPU_RUNTIME_RECIPE_DENIED') from exc


def file_digest(path: Path) -> tuple[str, int]:
    value=hashlib.sha256(); size=0
    with path.open("rb") as stream:
        while chunk:=stream.read(8*1024*1024):
            value.update(chunk); size+=len(chunk)
    return value.hexdigest(),size


def receipt_digest(value: dict) -> str:
    return digest(canonical({k: v for k, v in value.items() if k != "receipt_digest"}))


def _fsync_dir(path: Path) -> None:
    if hasattr(os, "O_DIRECTORY"):
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)


def _set_dir_metadata(adapter,path,mode):
    os.chmod(path,mode)
    if not isinstance(adapter, RealAdapter):
        adapter.directory_metadata_overrides["/"+path.relative_to(adapter.root).as_posix()]={"mode":mode,"uid":0,"gid":0}


def _immutable_inventory(adapter, declared=None):
    result=[]
    supplied={} if declared is None else {r.get("target"):r for r in declared if isinstance(r,dict)}
    if declared is not None and (len(supplied)!=len(declared) or set(supplied)!=IMMUTABLE_TARGETS):
        raise TransactionError("OFFLINE_IMMUTABLE_DENOMINATOR_DENIED")
    for target in sorted(IMMUTABLE_TARGETS):
        path=_target(adapter.root,target)
        if path.is_symlink() or not path.is_file(): raise TransactionError("OFFLINE_IMMUTABLE_PATH_DENIED:"+target)
        row={"target":target,**_metadata(adapter,path)}
        if declared is not None and row!=supplied[target]: raise TransactionError("OFFLINE_IMMUTABLE_DRIFT:"+target)
        result.append(row)
    return result


def _safe_relative(value: object) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise TransactionError("OFFLINE_BUNDLE_SOURCE_PATH_DENIED")
    pure = PurePosixPath(value)
    if pure.is_absolute() or str(pure) != value or any(p in {"", ".", ".."} for p in pure.parts):
        raise TransactionError("OFFLINE_BUNDLE_SOURCE_PATH_DENIED")
    return Path(*pure.parts)


def _runtime_target(member: str) -> str:
    if member == "bin/ollama": return "/usr/local/bin/ollama"
    if member == "lib/ollama": return "/usr/local/lib/ollama"
    if member.startswith("lib/ollama/"):
        pure=PurePosixPath(member)
        if any(part in {"", ".", ".."} for part in pure.parts):
            raise TransactionError("OFFLINE_RUNTIME_MEMBER_PATH_DENIED")
        return "/usr/local/"+member
    raise TransactionError("OFFLINE_RUNTIME_MEMBER_PATH_DENIED")


def load_archive_denominator(root: Path, archive: dict) -> list[dict]:
    path=root/ARCHIVE_DENOMINATOR_SOURCE
    if path.is_symlink() or not path.is_file():
        raise TransactionError("OFFLINE_RUNTIME_DENOMINATOR_PATH_DENIED")
    raw=path.read_bytes()
    if digest(raw)!=ARCHIVE_DENOMINATOR_SHA256:
        raise TransactionError("OFFLINE_RUNTIME_DENOMINATOR_HASH_DENIED")
    try: value=json.loads(raw)
    except (UnicodeError,json.JSONDecodeError) as exc:
        raise TransactionError("OFFLINE_RUNTIME_DENOMINATOR_INVALID") from exc
    expected_safety={"accepted_types":["regular","directory","symlink"],"absolute_paths":0,
        "traversal_paths":0,"device_or_special_members":0,"unsafe_links":0}
    if (not isinstance(value,dict) or set(value)!={"schema","source","safety","member_count","members"}
            or value.get("schema")!="sfos.archive-denominator.v1"
            or value.get("source")!={"filename":"ollama-linux-amd64-v0.33.3.tar.zst",
                "size":ORIGINAL_ARCHIVE_PROVENANCE["bytes"],"sha256":ORIGINAL_ARCHIVE_PROVENANCE["sha256"]}
            or value.get("safety")!=expected_safety or value.get("member_count")!=65
            or not isinstance(value.get("members"),list) or len(value["members"])!=65):
        raise TransactionError("OFFLINE_RUNTIME_DENOMINATOR_INVALID")
    seen=set()
    for row in value["members"]:
        if (not isinstance(row,dict) or set(row)!={"type","path","size","link_target","sha256"}
                or row["type"] not in {"regular","directory","symlink"}
                or row["path"] in seen or _runtime_target(row["path"]) is None):
            raise TransactionError("OFFLINE_RUNTIME_DENOMINATOR_INVALID")
        if row["type"]=="regular" and (not SHA256.fullmatch(str(row["sha256"])) or row["size"]<0):
            raise TransactionError("OFFLINE_RUNTIME_DENOMINATOR_INVALID")
        if row["type"]=="directory" and (row["size"]!=0 or row["sha256"] is not None or row["link_target"] is not None):
            raise TransactionError("OFFLINE_RUNTIME_DENOMINATOR_INVALID")
        if row["type"]=="symlink":
            link=row["link_target"]
            if (not isinstance(link,str) or not link or PurePosixPath(link).is_absolute()
                    or ".." in PurePosixPath(link).parts or row["sha256"] is not None):
                raise TransactionError("OFFLINE_RUNTIME_DENOMINATOR_INVALID")
        seen.add(row["path"])
    binary=next((row for row in value["members"] if row["path"]=="bin/ollama"),None)
    if binary!={"type":"regular","path":"bin/ollama","size":archive["member_bytes"],
            "link_target":None,"sha256":archive["member_sha256"]}:
        raise TransactionError("OFFLINE_RUNTIME_BINARY_BINDING_DENIED")
    return value["members"]


def _runtime_candidate(row: dict) -> dict:
    mode=0o755 if row["type"]=="directory" or row["path"]=="bin/ollama" else (0o777 if row["type"]=="symlink" else 0o644)
    return {"target":_runtime_target(row["path"]),"type":row["type"],"sha256":row["sha256"],
            "bytes":row["size"],"link_target":row["link_target"],"mode":mode,"uid":0,"gid":0}


def _object_metadata(adapter, path: Path) -> dict:
    info=path.lstat()
    if path.is_dir() and not path.is_symlink(): base=adapter.directory_metadata(path)
    elif path.is_file() and not path.is_symlink(): base=adapter.file_metadata(path)
    else: base={"mode":stat.S_IMODE(info.st_mode),"uid":getattr(info,"st_uid",0),"gid":getattr(info,"st_gid",0)}
    if path.is_symlink(): return {"type":"symlink","link_target":os.readlink(path),**base}
    if path.is_dir(): return {"type":"directory",**base}
    if path.is_file():
        value,size=file_digest(path); return {"type":"regular","sha256":value,"bytes":size,**base}
    raise TransactionError("OFFLINE_RUNTIME_TARGET_TYPE_DENIED")


def _validate_runtime_prestate(adapter, rows: list[dict], supplied: list[dict]) -> list[dict]:
    declared={r.get("target"):r.get("observed") for r in supplied if isinstance(r,dict) and set(r)=={"target","observed"}}
    targets={r["target"] for r in rows}
    if len(declared)!=len(supplied) or set(declared)!=targets: raise TransactionError("OFFLINE_RUNTIME_PRESTATE_DENIED")
    # The entire governed runtime tree is denominated; unknown residue is denied.
    lib=_target(adapter.root,"/usr/local/lib/ollama")
    if os.path.lexists(lib):
        found={"/usr/local/lib/ollama"}
        if not lib.is_symlink() and lib.is_dir():
            found|={"/"+p.relative_to(adapter.root).as_posix() for p in lib.rglob("*")}
        expected={t for t in targets if t.startswith("/usr/local/lib/ollama")}
        if found-expected: raise TransactionError("OFFLINE_RUNTIME_FOREIGN_RESIDUE_DENIED")
    result=[]
    for row in rows:
        path=_target(adapter.root,row["target"]); observed=_object_metadata(adapter,path) if os.path.lexists(path) else None
        if observed!=declared[row["target"]]: raise TransactionError("OFFLINE_RUNTIME_PRESTATE_DRIFT:"+row["target"])
        result.append({**row,"before":observed})
    return result


def _target(root: Path, value: object) -> Path:
    if not isinstance(value, str) or not value.startswith("/") or "\\" in value:
        raise TransactionError("OFFLINE_BUNDLE_TARGET_PATH_DENIED")
    pure = PurePosixPath(value)
    if str(pure) != value or any(p in {".", ".."} for p in pure.parts):
        raise TransactionError("OFFLINE_BUNDLE_TARGET_PATH_DENIED")
    return under(root, value)


def _metadata(adapter, path: Path) -> dict:
    info = path.lstat()
    return {"sha256": digest(path.read_bytes()), "bytes": info.st_size,
            "mode": stat.S_IMODE(info.st_mode), "uid": adapter.file_metadata(path)["uid"],
            "gid": adapter.file_metadata(path)["gid"]}


def _directory_metadata(adapter,path):
    return adapter.directory_metadata(path)


def _atomic_write(adapter, target: Path, raw: bytes, row: dict) -> None:
    nofollow_ancestors(adapter.root, target)
    if not target.parent.is_dir() or target.parent.is_symlink():
        raise TransactionError("OFFLINE_TARGET_PARENT_DENIED:" + row["target"])
    adapter.boundary()
    fd, temporary = tempfile.mkstemp(prefix=".serein-offline-ollama-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = -1; stream.write(raw); stream.flush()
            mode = int(row["mode"], 8) if isinstance(row["mode"], str) else row["mode"]
            if hasattr(os,"fchmod"): os.fchmod(stream.fileno(), mode)
            else: os.chmod(temporary,mode)
            if isinstance(adapter, RealAdapter):
                if not hasattr(os,"fchown"): raise TransactionError("OFFLINE_ATOMIC_CUSTODY_UNSUPPORTED")
                os.fchown(stream.fileno(), row["uid"], row["gid"])
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        _fsync_dir(target.parent)
        if not isinstance(adapter, RealAdapter):
            adapter.file_metadata_overrides["/" + target.relative_to(adapter.root).as_posix()] = {
                "mode": mode, "uid": row["uid"], "gid": row["gid"]}
    finally:
        if fd != -1: os.close(fd)
        if os.path.exists(temporary): os.unlink(temporary)


def _guard(adapter, plan: dict) -> None:
    if getattr(adapter,"boot_id",None)!=plan["boot_id"]: raise TransactionError("OFFLINE_PLAN_BOOT_DENIED")
    _immutable_inventory(adapter,plan["immutable_inputs"])


def _remove_staged_tree(adapter, staging: Path, selector: Path) -> None:
    if not os.path.lexists(staging): return
    try: staging.resolve(strict=False).relative_to(selector.resolve())
    except ValueError as exc: raise TransactionError("OFFLINE_STAGING_CONTAINMENT_DENIED") from exc
    if staging.is_symlink() or not staging.is_dir(): raise TransactionError("OFFLINE_STAGING_TYPE_DENIED")
    for child in sorted(staging.rglob("*"),key=lambda p:len(p.parts),reverse=True):
        adapter.boundary()
        if child.is_symlink() or child.is_file(): child.unlink()
        elif child.is_dir(): child.rmdir()
        else: raise TransactionError("OFFLINE_STAGING_TYPE_DENIED")
        _fsync_dir(child.parent)
    adapter.boundary();staging.rmdir();_fsync_dir(staging.parent)


def _verify_runtime_objects(adapter, rows: list[dict]) -> None:
    for row in rows:
        target=_target(adapter.root,row["target"])
        observed=_object_metadata(adapter,target) if os.path.lexists(target) else None
        expected={k:row[k] for k in ("type","sha256","bytes","link_target","mode","uid","gid") if row.get(k) is not None or k not in {"sha256","link_target"}}
        comparable={k:v for k,v in expected.items() if k in observed} if observed else None
        if observed is None or comparable!=observed: raise TransactionError("OFFLINE_RUNTIME_POSTSTATE_DENIED:"+row["target"])


def _verify_restored_prestate(adapter, receipt: dict) -> None:
    for row in receipt["files"]:
        target=_target(adapter.root,row["target"])
        if os.path.lexists(target) and (target.is_symlink() or not target.is_file()):
            raise TransactionError("OFFLINE_ROLLBACK_COMPLETED_DRIFT:"+row["target"])
        observed=_metadata(adapter,target) if os.path.lexists(target) and target.is_file() and not target.is_symlink() else None
        if observed!=row["before"]: raise TransactionError("OFFLINE_ROLLBACK_COMPLETED_DRIFT:"+row["target"])
    for row in receipt["runtime_objects"]:
        target=_target(adapter.root,row["target"])
        observed=_object_metadata(adapter,target) if os.path.lexists(target) else None
        if observed!=row["before"]: raise TransactionError("OFFLINE_ROLLBACK_COMPLETED_DRIFT:"+row["target"])
    for row in receipt["directories"]:
        target=_target(adapter.root,row["target"])
        if os.path.lexists(target) and (target.is_symlink() or not target.is_dir()):
            raise TransactionError("OFFLINE_ROLLBACK_COMPLETED_DRIFT:"+row["target"])
        observed=_directory_metadata(adapter,target) if os.path.lexists(target) and target.is_dir() and not target.is_symlink() else None
        if observed!=row["before"]: raise TransactionError("OFFLINE_ROLLBACK_COMPLETED_DRIFT:"+row["target"])


def load_bundle(bundle_root: Path) -> tuple[dict, list[dict]]:
    root = bundle_root.resolve(strict=True)
    manifest_path = root / "bundle-manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise TransactionError("OFFLINE_BUNDLE_MANIFEST_DENIED")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    required = {"schema", "delivery_actor", "executor", "target", "method", "network", "model", "runtime_archive", "files"}
    if (not isinstance(manifest, dict) or set(manifest) != required
            or manifest.get("schema") != BUNDLE_SCHEMA or manifest.get("delivery_actor") != "SFOS_PROXY"
            or manifest.get("executor") != "OUTPOST" or manifest.get("target") != "VM4010"
            or manifest.get("method") != "PVE_REST_QGA"
            or manifest.get("network") != "PROHIBIT_FETCH_AND_PULL"
            or not isinstance(manifest.get("files"), list)):
        raise TransactionError("OFFLINE_BUNDLE_SCHEMA_DENIED")
    model = manifest["model"]
    if (not isinstance(model, dict) or set(model) != {"name", "digest"}
            or model.get("name") != "qwen3:4b-instruct"
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(model.get("digest")))):
        raise TransactionError("OFFLINE_MODEL_IDENTITY_DENIED")
    archive = manifest["runtime_archive"]
    if (not isinstance(archive, dict) or set(archive) != {"source", "sha256", "bytes", "member", "member_sha256", "member_bytes", "target", "mode", "uid", "gid", "original_zst", "denominator", "format"}
            or archive.get("target") != "/usr/local/bin/ollama" or archive.get("mode") != "0755"
            or archive.get("uid") != 0 or archive.get("gid") != 0 or archive.get("format") != "tar"
            or archive.get("original_zst") != ORIGINAL_ARCHIVE_PROVENANCE
            or archive.get("denominator") != {"source":ARCHIVE_DENOMINATOR_SOURCE,"sha256":ARCHIVE_DENOMINATOR_SHA256}
            or not SHA256.fullmatch(str(archive.get("member_sha256")))):
        raise TransactionError("OFFLINE_RUNTIME_ARCHIVE_SCHEMA_DENIED")
    if any(archive.get(k)!=v for k,v in PINNED_ARCHIVE.items()):
        raise TransactionError("OFFLINE_RUNTIME_PIN_DENIED")
    if model!=PINNED_MODEL: raise TransactionError("OFFLINE_MODEL_PIN_DENIED")
    rows, seen = [], set()
    for row in manifest["files"]:
        if (not isinstance(row, dict) or set(row) != {"source", "target", "sha256", "bytes", "mode", "uid", "gid"}
                or row["target"] in seen or not SHA256.fullmatch(str(row["sha256"]))
                or not isinstance(row["bytes"], int) or row["bytes"] < 0):
            raise TransactionError("OFFLINE_BUNDLE_FILE_SCHEMA_DENIED")
        source = root / _safe_relative(row["source"])
        try: source.resolve(strict=True).relative_to(root)
        except ValueError as exc: raise TransactionError("OFFLINE_BUNDLE_SOURCE_CONTAINMENT_DENIED") from exc
        if source.is_symlink() or not source.is_file(): raise TransactionError("OFFLINE_BUNDLE_SOURCE_TYPE_DENIED")
        raw = source.read_bytes()
        if len(raw) != row["bytes"] or digest(raw) != row["sha256"]:
            raise TransactionError("OFFLINE_BUNDLE_SOURCE_HASH_DENIED:" + row["source"])
        target = str(row["target"])
        allowed_manifest = target == "/usr/share/ollama/.ollama/models/manifests/registry.ollama.ai/library/qwen3/4b-instruct"
        allowed_blob = re.fullmatch(r"/usr/share/ollama/\.ollama/models/blobs/sha256-[0-9a-f]{64}", target) is not None
        if not (allowed_manifest or allowed_blob): raise TransactionError("OFFLINE_MODEL_TARGET_DENIED")
        if allowed_blob and target.rsplit("sha256-",1)[1] != row["sha256"]:
            raise TransactionError("OFFLINE_MODEL_BLOB_NAME_HASH_DENIED")
        seen.add(target); rows.append({**row, "source_path": str(source)})
    manifests = [r for r in rows if "/manifests/" in r["target"]]
    blobs = [r for r in rows if "/blobs/" in r["target"]]
    if len(rows) != 6 or len(manifests) != 1 or len(blobs) != 5:
        raise TransactionError("OFFLINE_MODEL_DENOMINATOR_DENIED")
    observed_pins={r["sha256"]:r["bytes"] for r in rows}
    if observed_pins!=PINNED_MODEL_FILES: raise TransactionError("OFFLINE_MODEL_PIN_DENIED")
    if manifests[0]["sha256"] != model["digest"].removeprefix("sha256:"):
        raise TransactionError("OFFLINE_MODEL_DIGEST_BINDING_DENIED")
    archive_source = root / _safe_relative(archive["source"])
    observed_hash,observed_size=file_digest(archive_source)
    if observed_size != archive["bytes"] or observed_hash != archive["sha256"]:
        raise TransactionError("OFFLINE_RUNTIME_ARCHIVE_HASH_DENIED")
    denominator=load_archive_denominator(root,archive)
    rows.extend({**_runtime_candidate(r),"source":archive["source"]+"#"+r["path"],
                 "source_path":str(archive_source),"member":r["path"]} for r in denominator)
    return manifest, rows


def stage_runtime(bundle_root: Path, manifest: dict, staging: Path) -> dict[str,Path]:
    """Manually stage the exact plain-tar denominator; extraction APIs are forbidden."""
    archive=manifest["runtime_archive"]
    expected=load_archive_denominator(bundle_root.resolve(strict=True),archive)
    staging.mkdir(mode=0o700); materialized={}
    try:
        with tarfile.open(bundle_root/_safe_relative(archive["source"]),"r:") as tar:
            for wanted in expected:
                member=tar.next()
                if member is None or member.name!=wanted["path"]:
                    raise TransactionError("OFFLINE_RUNTIME_ARCHIVE_ORDER_DENIED")
                kind="directory" if member.isdir() else "symlink" if member.issym() else "regular" if member.isfile() else "special"
                if (kind!=wanted["type"] or member.size!=wanted["size"]
                        or (member.linkname if member.issym() else None)!=wanted["link_target"]):
                    raise TransactionError("OFFLINE_RUNTIME_ARCHIVE_ROW_DENIED:"+wanted["path"])
                target=staging/Path(*PurePosixPath(wanted["path"]).parts)
                target.parent.mkdir(parents=True,exist_ok=True)
                if kind=="directory": target.mkdir(exist_ok=True)
                elif kind=="symlink": os.symlink(member.linkname,target)
                else:
                    stream=tar.extractfile(member)
                    if stream is None: raise TransactionError("OFFLINE_RUNTIME_ARCHIVE_ROW_DENIED:"+wanted["path"])
                    value=hashlib.sha256();size=0
                    with target.open("xb") as output:
                        while chunk:=stream.read(8*1024*1024): output.write(chunk);value.update(chunk);size+=len(chunk)
                    if size!=wanted["size"] or value.hexdigest()!=wanted["sha256"]:
                        raise TransactionError("OFFLINE_RUNTIME_MEMBER_HASH_DENIED:"+wanted["path"])
                materialized[wanted["path"]]=target
            if tar.next() is not None: raise TransactionError("OFFLINE_RUNTIME_ARCHIVE_EXTRA_MEMBER_DENIED")
    except (tarfile.TarError,OSError) as exc:
        raise TransactionError("OFFLINE_RUNTIME_ARCHIVE_INVALID") from exc
    if set(materialized)!={r["path"] for r in expected}: raise TransactionError("OFFLINE_RUNTIME_STAGING_DENOMINATOR_DENIED")
    return materialized


def classify(adapter, bundle_root: Path, expected_before: dict, rollback_selector: str, *,
             boot_id: str, source_generation: dict, request_id: str) -> dict:
    manifest, rows = load_bundle(bundle_root)
    if not SELECTOR.fullmatch(str(rollback_selector)):
        raise TransactionError("OFFLINE_ROLLBACK_SELECTOR_DENIED")
    if (not re.fullmatch(r"[0-9a-f-]{36}", boot_id)
            or not isinstance(source_generation, dict)
            or set(source_generation) != {"commit", "tree"}
            or any(not re.fullmatch(r"[0-9a-f]{40}", str(v)) for v in source_generation.values())
            or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", request_id)):
        raise TransactionError("OFFLINE_PLAN_LINEAGE_DENIED")
    if (not isinstance(expected_before, dict) or set(expected_before) != {"schema", "unit", "files", "runtime_objects", "directories", "immutable_inputs"}
            or expected_before["schema"] != "SereinOfflineOllamaExpectedBefore/v2"
            or expected_before["unit"] != adapter.read_unit("ollama.service")):
        raise TransactionError("OFFLINE_EXPECTED_BEFORE_DENIED")
    _restorable_unit(expected_before['unit'])
    supplied = {r.get("target"): r.get("observed") for r in expected_before["files"]
                if isinstance(r, dict) and set(r) == {"target", "observed"}}
    if len(supplied) != len(expected_before["files"]): raise TransactionError("OFFLINE_EXPECTED_BEFORE_DENIED")
    planned = []
    model_source_rows=[r for r in rows if "member" not in r]
    runtime_source_rows=[r for r in rows if "member" in r]
    for row in model_source_rows:
        target = _target(adapter.root, row["target"])
        observed = None
        if os.path.lexists(target):
            if target.is_symlink() or not target.is_file(): raise TransactionError("OFFLINE_TARGET_TYPE_DENIED")
            observed = _metadata(adapter, target)
        if row["target"] not in supplied or supplied[row["target"]] != observed:
            raise TransactionError("OFFLINE_EXPECTED_BEFORE_DRIFT:" + row["target"])
        planned.append({k: v for k, v in row.items() if k not in {"source_path", "payload"}} | {"before": observed})
    if set(supplied) != {r["target"] for r in planned}: raise TransactionError("OFFLINE_EXPECTED_BEFORE_EXTRA_TARGET")
    runtime_candidates=[{k:v for k,v in r.items() if k not in {"source_path","source","member"}} for r in runtime_source_rows]
    runtime_planned=_validate_runtime_prestate(adapter,runtime_candidates,expected_before["runtime_objects"])
    declared_dirs={r.get("target"):r.get("observed") for r in expected_before["directories"]
                   if isinstance(r,dict) and set(r)=={"target","observed"}}
    if len(declared_dirs)!=len(MODEL_DIRECTORIES) or set(declared_dirs)!=set(MODEL_DIRECTORIES):
        raise TransactionError("OFFLINE_DIRECTORY_DENOMINATOR_DENIED")
    model_rows=[r for r in planned if r["target"].startswith("/usr/share/ollama/")]
    ownership={(r["uid"],r["gid"]) for r in model_rows}
    if len(ownership)!=1: raise TransactionError("OFFLINE_MODEL_CUSTODY_DENIED")
    uid,gid=next(iter(ownership));directories=[]
    for target in MODEL_DIRECTORIES:
        path=_target(adapter.root,target);observed=None
        if os.path.lexists(path):
            if path.is_symlink() or not path.is_dir(): raise TransactionError("OFFLINE_DIRECTORY_TYPE_DENIED:"+target)
            observed=_directory_metadata(adapter,path)
        expected=declared_dirs[target]
        if observed!=expected: raise TransactionError("OFFLINE_DIRECTORY_PRESTATE_DRIFT:"+target)
        candidate={"mode":0o755,"uid":uid,"gid":gid}
        if observed is not None and observed!=candidate: raise TransactionError("OFFLINE_DIRECTORY_CUSTODY_DENIED:"+target)
        directories.append({"target":target,"before":observed,"candidate":candidate,
                            "introduced":observed is None})
    body = {"schema": PLAN_SCHEMA, "target": "VM4010", "method": "PVE_REST_QGA",
            "delivery_actor": "SFOS_PROXY", "executor": "OUTPOST",
            "network": "PROHIBIT_FETCH_AND_PULL", "model": manifest["model"],
            "runtime_archive": manifest["runtime_archive"], "rollback_selector": rollback_selector,
            "boot_id": boot_id, "source_generation": source_generation, "request_id": request_id,
            "unit_prestate": expected_before["unit"], "directories":directories,
            "immutable_inputs":_immutable_inventory(adapter,expected_before["immutable_inputs"]),
            "runtime_objects":runtime_planned,"files": planned}
    return {**body, "plan_sha256": digest(canonical(body)), "signature_algorithm":"Ed25519",
            "signing_key_id":"outpost-cognition-v1", "signature":None}


def signing_payload(plan: dict) -> bytes:
    return canonical({k:v for k,v in plan.items() if k != "signature"})


def _verify_signature(adapter, plan: dict) -> None:
    if plan.get("signature_algorithm") != "Ed25519" or plan.get("signing_key_id") != "outpost-cognition-v1":
        raise TransactionError("OFFLINE_PLAN_AUTHORITY_DENIED")
    anchor = _target(adapter.root, "/usr/share/serein/outpost/cognition-verification.pem")
    try:
        public = serialization.load_pem_public_key(anchor.read_bytes())
        signature = base64.urlsafe_b64decode(str(plan["signature"]) + "=" * (-len(str(plan["signature"])) % 4))
        if not isinstance(public, Ed25519PublicKey): raise ValueError("wrong key")
        public.verify(signature, signing_payload(plan))
    except Exception as exc: raise TransactionError("OFFLINE_PLAN_SIGNATURE_DENIED") from exc


def native_allocation_prestate(adapter):
    """The observed no-drop-in denominator; no generalized service editor."""
    unit = _target(adapter.root, '/etc/systemd/system/ollama.service')
    config = _target(adapter.root, NATIVE_ALLOCATION_TARGET)
    nofollow_ancestors(adapter.root, unit, allow_missing=False)
    nofollow_ancestors(adapter.root, config)
    definition=adapter.read_native_allocation_definition()
    if (set(definition)!={'fragment','dropins','need_reload','environment','environment_files'}
            or definition['fragment']!='/etc/systemd/system/ollama.service' or definition['dropins']
            or definition['need_reload']!='no' or definition['environment_files']
            or type(definition['environment']) is not dict
            or 'LLAMA_ARG_FIT_TARGET' in definition['environment']
            or not unit.is_file() or os.path.lexists(config.parent)
            or adapter.read_unit('ollama.service') != {'active':'active','enabled':'enabled'}):
        raise TransactionError('NATIVE_ALLOCATION_PRESTATE_DENIED')
    _, metadata, identity = _native_file_read(adapter, unit)
    if metadata['uid'] != 0 or metadata['gid'] != 0 or metadata['mode'] != 0o600:
        raise TransactionError('NATIVE_ALLOCATION_UNIT_CUSTODY_DENIED')
    return {'unit':metadata, 'unit_identity':identity, 'definition':definition,
            'state':{'active':'active','enabled':'enabled'}, 'dropin_directory':None}


def prepare_native_allocation(adapter, *, source_generation, request_id, rollback_selector):
    """Read-only preparation consumed only by the complete Outpost owner."""
    if (type(source_generation) is not dict or set(source_generation) != {'commit','tree'}
            or any(type(value) is not str or not re.fullmatch('[0-9a-f]{40}',value)
                   for value in source_generation.values())
            or type(request_id) is not str or not re.fullmatch('[A-Za-z0-9_-]{1,128}',request_id)
            or type(rollback_selector) is not str or not SELECTOR.fullmatch(rollback_selector)):
        raise TransactionError('NATIVE_ALLOCATION_INPUT_DENIED')
    adapter.boundary()
    unit = native_allocation_prestate(adapter)
    observed = adapter.observe_native_allocation()
    native_allocation_transition(observed,observed,restoring=True)
    if observed['runtime']['boot_id'] != adapter.boot_id:
        raise TransactionError('NATIVE_ALLOCATION_BOOT_DENIED')
    if 'LLAMA_ARG_FIT_TARGET' in observed['environment']:
        raise TransactionError('NATIVE_ALLOCATION_PREEXISTING_OVERRIDE_DENIED')
    immutable = _immutable_inventory(adapter)
    if native_allocation_prestate(adapter) != unit:
        raise TransactionError('NATIVE_ALLOCATION_PRESTATE_CHANGED')
    body = {'schema':NATIVE_ALLOCATION_SCHEMA, 'actor':'OUTPOST',
        'scope':'RUNTIME_DEPENDENCY_ONLY', 'boot_id':adapter.boot_id,
        'source_generation':dict(source_generation), 'request_id':request_id,
        'rollback_selector':rollback_selector, 'unit_prestate':unit,
        'runtime_prestate':observed, 'immutable_inputs':immutable,
        'environment':dict(NATIVE_ALLOCATION_ENVIRONMENT),
        'config_sha256':digest(native_allocation_configuration(NATIVE_ALLOCATION_ENVIRONMENT))}
    return {**body, 'plan_sha256':digest(canonical(body)), 'signature_algorithm':'Ed25519',
            'signing_key_id':'outpost-cognition-v1', 'signature':None}


def _native_allocation_unit_guard(adapter, plan):
    unit = _target(adapter.root, '/etc/systemd/system/ollama.service')
    nofollow_ancestors(adapter.root,unit,allow_missing=False)
    definition=adapter.read_native_allocation_definition()
    normalized=dict(definition)
    if normalized.get('need_reload') not in {'yes','no'}:
        raise TransactionError('NATIVE_ALLOCATION_UNIT_CHANGED')
    normalized['need_reload']='no'
    _, metadata, identity = _native_file_read(adapter,unit)
    if (metadata != plan['unit_prestate']['unit']
            or identity != plan['unit_prestate']['unit_identity']
            or definition.get('fragment')!='/etc/systemd/system/ollama.service'
            or normalized not in (_native_expected_definition(plan,installed=False),
                                  _native_expected_definition(plan,installed=True))):
        raise TransactionError('NATIVE_ALLOCATION_UNIT_CHANGED')
    _guard(adapter,plan); adapter.boundary()


def _native_expected_definition(plan, *, installed):
    value=json.loads(canonical(plan['unit_prestate']['definition']))
    if installed:
        value['dropins']=[NATIVE_ALLOCATION_TARGET]
        value['environment'].update(NATIVE_ALLOCATION_ENVIRONMENT)
    return value


def _native_allocation_record(adapter, selector, receipt):
    receipt['receipt_digest'] = receipt_digest(receipt)
    _atomic_write(adapter,selector/'receipt.json',canonical(receipt),
        {'target':'receipt.json','mode':'0600','uid':0,'gid':0})


def _native_file_read(adapter, path, *, limit=2097152):
    """One bounded, no-follow inode observation for transaction control files."""
    nofollow_ancestors(adapter.root,path,allow_missing=False)
    parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    fd=-1
    def identity(info):
        return {'device':info.st_dev,'inode':info.st_ino}
    def fingerprint(info):
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
                info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    try:
        parent_before=os.fstat(parent)
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>limit:
            raise TransactionError('NATIVE_ALLOCATION_CONTROL_FILE_DENIED')
        raw=bytearray()
        while len(raw)<=limit:
            chunk=os.read(fd,min(65536,limit+1-len(raw)))
            if not chunk:break
            raw.extend(chunk)
        if (len(raw)!=before.st_size or len(raw)>limit
                or fingerprint(os.fstat(fd))!=fingerprint(before)
                or fingerprint(os.stat(path.name,dir_fd=parent,follow_symlinks=False))!=fingerprint(before)
                or fingerprint(os.fstat(parent))!=fingerprint(parent_before)
                or fingerprint(path.parent.lstat())!=fingerprint(parent_before)):
            raise TransactionError('NATIVE_ALLOCATION_CONTROL_FILE_CHANGED')
        return bytes(raw),{'sha256':digest(raw),'bytes':len(raw),
            'mode':stat.S_IMODE(before.st_mode),'uid':before.st_uid,'gid':before.st_gid},identity(before)
    finally:
        if fd!=-1:os.close(fd)
        os.close(parent)


def _native_directory_identity(path):
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=(0,0,0o755):
        raise TransactionError('NATIVE_ALLOCATION_DIRECTORY_CUSTODY_DENIED')
    return {'device':info.st_dev,'inode':info.st_ino}


def _native_create_configuration(adapter, path, raw, receipt, selector):
    # Same create-only hard-link publication and write-ahead inode ownership
    # already used by kernel_first_install.atomic. Never replace a live file.
    parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    name='.serein-allocation-'+os.urandom(16).hex();fd=-1
    def guard():
        info=os.fstat(parent)
        if (_native_directory_identity(path.parent)!=receipt['directory_identity']
                or {'device':info.st_dev,'inode':info.st_ino}!=receipt['directory_identity']):
            raise TransactionError('NATIVE_ALLOCATION_DIRECTORY_CHANGED')
        _native_allocation_unit_guard(adapter,receipt['plan'])
    try:
        guard()
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        with os.fdopen(fd,'wb') as stream:
            fd=-1;stream.write(raw);stream.flush()
            os.fchmod(stream.fileno(),0o644);os.fchown(stream.fileno(),0,0);os.fsync(stream.fileno())
            info=os.fstat(stream.fileno())
        receipt['config_identity']={'device':info.st_dev,'inode':info.st_ino}
        _native_allocation_record(adapter,selector,receipt)
        guard()
        try:os.link(name,path.name,src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
        except FileExistsError:raise TransactionError('NATIVE_ALLOCATION_CONFIG_COLLISION') from None
        os.fsync(parent);guard()
    finally:
        if fd!=-1:os.close(fd)
        try:os.unlink(name,dir_fd=parent);os.fsync(parent)
        except FileNotFoundError:pass
        os.close(parent)


def _native_owned_configuration(adapter, receipt):
    path=_target(adapter.root,NATIVE_ALLOCATION_TARGET);plan=receipt['plan']
    nofollow_ancestors(adapter.root,path)
    directory=receipt['directory_identity'];file_identity=receipt['config_identity']
    if os.path.lexists(path.parent):
        if directory is None or _native_directory_identity(path.parent)!=directory:
            raise TransactionError('NATIVE_ALLOCATION_FOREIGN_DIRECTORY_DENIED')
        if set(p.name for p in path.parent.iterdir())-({path.name} if os.path.lexists(path) else set()):
            raise TransactionError('NATIVE_ALLOCATION_FOREIGN_DIRECTORY_CONTENT_DENIED')
    elif directory is not None:
        raise TransactionError('NATIVE_ALLOCATION_OWNED_DIRECTORY_MISSING')
    if os.path.lexists(path):
        _,metadata,identity=_native_file_read(adapter,path)
        expected={'sha256':plan['config_sha256'],
            'bytes':len(native_allocation_configuration(plan['environment'])), 'mode':0o644,'uid':0,'gid':0}
        if file_identity is None or identity!=file_identity or metadata!=expected:
            raise TransactionError('NATIVE_ALLOCATION_FOREIGN_CONFIG_DENIED')
    elif file_identity is not None:
        # A durable create intent can precede the link, but absence after an
        # observed installation is foreign drift, not permission to recover.
        if receipt['phase'] not in {'CONFIG_REQUESTED'}:
            raise TransactionError('NATIVE_ALLOCATION_OWNED_CONFIG_MISSING')
    return path


def install_native_allocation(adapter, plan, selector):
    """Internal constituent, not a CLI or independent Kernel installation.

    The complete Outpost-owned Kernel lifecycle must hold the generation lock,
    quiesce consumers and retain this constituent's compensation until final
    generation publication. Its dependency receipt cannot admit Stage 1.
    """
    plan = json.loads(canonical(plan))
    _verify_signature(adapter,plan)
    original = prepare_native_allocation(adapter, source_generation=plan['source_generation'],
        request_id=plan['request_id'],rollback_selector=plan['rollback_selector'])
    if {**plan,'signature':None} != original:
        raise TransactionError('NATIVE_ALLOCATION_PLAN_CHANGED')
    selector = Path(selector)
    if selector != _target(adapter.root,plan['rollback_selector']) or os.path.lexists(selector):
        raise TransactionError('NATIVE_ALLOCATION_SELECTOR_DENIED')
    nofollow_ancestors(adapter.root,selector)
    _native_allocation_unit_guard(adapter,plan)
    selector.mkdir(mode=0o700);_set_dir_metadata(adapter,selector,0o700);_fsync_dir(selector.parent)
    receipt = {'schema':NATIVE_ALLOCATION_RECEIPT, 'actor':'OUTPOST',
        'selector':str(selector), 'plan':plan, 'plan_sha256':plan['plan_sha256'],
        'scope':'RUNTIME_DEPENDENCY_ONLY', 'phase':'PREPARED',
        'acceptance':None, 'restoration':None, 'rollback_complete':False,
        'directory_identity':None,'config_identity':None,'runtime_after':None}
    _native_allocation_record(adapter,selector,receipt)
    config = _target(adapter.root,NATIVE_ALLOCATION_TARGET)
    try:
        _native_allocation_unit_guard(adapter,plan)
        if adapter.observe_native_allocation() != plan['runtime_prestate']:
            raise TransactionError('NATIVE_ALLOCATION_RUNTIME_CHANGED')
        receipt['phase']='STOP_REQUESTED';_native_allocation_record(adapter,selector,receipt)
        adapter.stop_unit('ollama.service');_native_allocation_unit_guard(adapter,plan)
        if (adapter.read_unit('ollama.service') != {'active':'inactive','enabled':'enabled'}
                or not adapter.native_runtime_stopped()):
            raise TransactionError('NATIVE_ALLOCATION_STOP_UNPROVEN')
        if os.path.lexists(config.parent): raise TransactionError('NATIVE_ALLOCATION_DIRECTORY_RACE')
        receipt['phase']='CONFIG_REQUESTED';_native_allocation_record(adapter,selector,receipt)
        config.parent.mkdir(mode=0o755);_set_dir_metadata(adapter,config.parent,0o755)
        _fsync_dir(config.parent.parent)
        receipt['directory_identity']=_native_directory_identity(config.parent)
        _native_allocation_record(adapter,selector,receipt)
        _native_create_configuration(adapter,config,native_allocation_configuration(plan['environment']),receipt,selector)
        adapter.reload_native_allocation();_native_allocation_unit_guard(adapter,plan)
        receipt['phase']='START_REQUESTED';_native_allocation_record(adapter,selector,receipt)
        adapter.start_unit('ollama.service')
        observed=adapter.observe_native_allocation()
        native_allocation_transition(plan['runtime_prestate'],observed)
        receipt['runtime_after']=observed;_native_allocation_record(adapter,selector,receipt)
        adapter.preload_native_allocation()
        _native_allocation_unit_guard(adapter,plan)
        observed=adapter.observe_native_allocation()
        if observed!=receipt['runtime_after']:
            raise TransactionError('NATIVE_ALLOCATION_SUCCESSOR_CHANGED')
        transition=native_allocation_transition(plan['runtime_prestate'],observed)
        if adapter.read_unit('ollama.service') != plan['unit_prestate']['state']:
            raise TransactionError('NATIVE_ALLOCATION_START_UNPROVEN')
        if adapter.read_native_allocation_definition()!=_native_expected_definition(plan,installed=True):
            raise TransactionError('NATIVE_ALLOCATION_EFFECTIVE_CONFIG_UNPROVEN')
        expected={'sha256':plan['config_sha256'],
            'bytes':len(native_allocation_configuration(plan['environment'])),
            'mode':0o644,'uid':0,'gid':0}
        _native_owned_configuration(adapter,receipt)
        if _native_file_read(adapter,config)[1] != expected:
            raise TransactionError('NATIVE_ALLOCATION_CONFIG_CHANGED')
        receipt.update(phase='DEPENDENCY_OBSERVED',acceptance=transition)
        _native_allocation_record(adapter,selector,receipt)
        _native_allocation_unit_guard(adapter,plan)
        _native_owned_configuration(adapter,receipt)
        return receipt
    except BaseException:
        # The whole owner independently verifies this evidence before it may
        # recover the enclosing generation. Never report restoration on trust.
        # A failed read/guard before STOP_REQUESTED owns no runtime effect.
        # Do not "compensate" it by restarting the untouched predecessor.
        if receipt['phase']!='PREPARED':
            if hasattr(adapter,'fail_after'):adapter.fail_after=None
            rollback_native_allocation(adapter,selector)
        raise


def _native_allocation_receipt(adapter, selector):
    selector=Path(selector);nofollow_ancestors(adapter.root,selector,allow_missing=False)
    raw,metadata,_=_native_file_read(adapter,selector/'receipt.json')
    receipt=json.loads(raw)
    fields={'schema','actor','selector','plan','plan_sha256','scope','phase','acceptance',
        'restoration','rollback_complete','directory_identity','config_identity','runtime_after','receipt_digest'}
    if type(receipt) is not dict or set(receipt)!=fields:
        raise TransactionError('NATIVE_ALLOCATION_RESTORATION_RECEIPT_DENIED')
    plan=receipt['plan']
    plan_fields={'schema','actor','scope','boot_id','source_generation','request_id',
        'rollback_selector','unit_prestate','runtime_prestate','immutable_inputs','environment',
        'config_sha256','plan_sha256','signature_algorithm','signing_key_id','signature'}
    if type(plan) is not dict or set(plan)!=plan_fields:
        raise TransactionError('NATIVE_ALLOCATION_PLAN_SHAPE_DENIED')
    body={k:v for k,v in plan.items() if k not in {'plan_sha256','signature_algorithm','signing_key_id','signature'}}
    if (plan['schema']!=NATIVE_ALLOCATION_SCHEMA or plan['actor']!='OUTPOST'
            or plan['scope']!='RUNTIME_DEPENDENCY_ONLY'
            or plan['plan_sha256']!=digest(canonical(body))
            or plan['config_sha256']!=digest(native_allocation_configuration(plan['environment']))
            or receipt.get('schema')!=NATIVE_ALLOCATION_RECEIPT
            or receipt['actor']!='OUTPOST' or receipt['scope']!='RUNTIME_DEPENDENCY_ONLY'
            or receipt['phase'] not in {'PREPARED','STOP_REQUESTED','CONFIG_REQUESTED','START_REQUESTED',
                'DEPENDENCY_OBSERVED','RESTORE_REQUESTED','RESTORED'}
            or type(receipt['rollback_complete']) is not bool
            or receipt['rollback_complete']!=(receipt['phase']=='RESTORED')
            or receipt['plan_sha256']!=plan['plan_sha256']
            or receipt.get('selector')!=str(selector)
            or receipt.get('receipt_digest')!=receipt_digest(receipt)
            or selector!=_target(adapter.root,plan['rollback_selector'])
            or not SELECTOR.fullmatch(plan['rollback_selector'])
            or adapter.directory_metadata(selector)!={'mode':0o700,'uid':0,'gid':0}
            or {k:metadata[k] for k in ('mode','uid','gid')}!={'mode':0o600,'uid':0,'gid':0}):
        raise TransactionError('NATIVE_ALLOCATION_RESTORATION_RECEIPT_DENIED')
    for name in ('directory_identity','config_identity'):
        value=receipt[name]
        if value is not None and (type(value) is not dict or set(value)!={'device','inode'}
                or any(type(v) is not int or v<0 for v in value.values())):
            raise TransactionError('NATIVE_ALLOCATION_OWNERSHIP_DENIED')
    _verify_signature(adapter,plan);_native_allocation_unit_guard(adapter,plan)
    if _native_file_read(adapter,selector/'receipt.json')[0]!=raw:
        raise TransactionError('NATIVE_ALLOCATION_RECEIPT_CHANGED')
    return receipt


def rollback_native_allocation(adapter, selector):
    selector=Path(selector);receipt=_native_allocation_receipt(adapter,selector);plan=receipt['plan']
    if receipt['rollback_complete']:
        if native_allocation_prestate(adapter)!=plan['unit_prestate']:
            raise TransactionError('NATIVE_ALLOCATION_RESTORED_UNIT_DENIED')
        observed=adapter.observe_native_allocation()
        if observed!=receipt['restoration']['after']:
            raise TransactionError('NATIVE_ALLOCATION_RESTORED_RUNTIME_CHANGED')
        native_allocation_transition(plan['runtime_prestate'],observed,restoring=True)
        return receipt
    # Establish exact ownership before any stop/remove/restart. A failed
    # predicate is evidence; it never grants control over foreign state.
    config=_native_owned_configuration(adapter,receipt)
    state=adapter.read_unit('ollama.service')
    if state=={'active':'active','enabled':'enabled'}:
        observed=adapter.observe_native_allocation()
        expected=receipt['runtime_after'] or plan['runtime_prestate']
        if observed!=expected:
            raise TransactionError('NATIVE_ALLOCATION_FOREIGN_RUNTIME_DENIED')
        if receipt['phase'] in {'PREPARED','STOP_REQUESTED'} and receipt['directory_identity'] is None:
            if native_allocation_prestate(adapter)!=plan['unit_prestate']:
                raise TransactionError('NATIVE_ALLOCATION_RESTORED_UNIT_DENIED')
            restored=native_allocation_transition(plan['runtime_prestate'],observed,restoring=True)
            receipt.update(phase='RESTORED',restoration=restored,rollback_complete=True)
            _native_allocation_record(adapter,selector,receipt)
            return receipt
    elif state=={'active':'inactive','enabled':'enabled'}:
        if receipt['phase']=='PREPARED' or not adapter.native_runtime_stopped():
            raise TransactionError('NATIVE_ALLOCATION_STOP_OWNERSHIP_DENIED')
    else:
        raise TransactionError('NATIVE_ALLOCATION_SERVICE_OWNERSHIP_DENIED')
    if adapter.observe_native_material()!=plan['runtime_prestate']['material']:
        raise TransactionError('NATIVE_ALLOCATION_FOREIGN_MATERIAL_DENIED')
    _native_owned_configuration(adapter,receipt);_native_allocation_unit_guard(adapter,plan)
    receipt['phase']='RESTORE_REQUESTED';_native_allocation_record(adapter,selector,receipt)
    if state['active']=='active':adapter.stop_unit('ollama.service')
    if adapter.read_unit('ollama.service')!={'active':'inactive','enabled':'enabled'} or not adapter.native_runtime_stopped():
        raise TransactionError('NATIVE_ALLOCATION_STOP_UNPROVEN')
    _native_allocation_unit_guard(adapter,plan);_native_owned_configuration(adapter,receipt)
    if os.path.lexists(config):
        config.unlink();_fsync_dir(config.parent)
    if os.path.lexists(config.parent):
        if _native_directory_identity(config.parent)!=receipt['directory_identity']:
            raise TransactionError('NATIVE_ALLOCATION_FOREIGN_DIRECTORY_DENIED')
        config.parent.rmdir();_fsync_dir(config.parent.parent)
    adapter.reload_native_allocation();_native_allocation_unit_guard(adapter,plan)
    adapter.start_unit('ollama.service');adapter.preload_native_allocation()
    _native_allocation_unit_guard(adapter,plan)
    if native_allocation_prestate(adapter)!=plan['unit_prestate']:
        raise TransactionError('NATIVE_ALLOCATION_RESTORED_UNIT_DENIED')
    restored=native_allocation_transition(plan['runtime_prestate'],adapter.observe_native_allocation(),restoring=True)
    receipt.update(phase='RESTORED',restoration=restored,rollback_complete=True)
    _native_allocation_record(adapter,selector,receipt)
    _native_allocation_unit_guard(adapter,plan)
    return receipt


def verify_installed_native_allocation(adapter, selector, *, expected_plan_sha256):
    """Read-only constituent acceptance; never a Stage-1 or whole-owner PASS."""
    selector=Path(selector);receipt=_native_allocation_receipt(adapter,selector)
    plan=receipt['plan']
    if (plan['plan_sha256']!=expected_plan_sha256 or receipt['phase']!='DEPENDENCY_OBSERVED'
            or receipt['rollback_complete'] or receipt['restoration'] is not None):
        raise TransactionError('NATIVE_ALLOCATION_INSTALLED_RECEIPT_DENIED')
    _native_owned_configuration(adapter,receipt)
    if (adapter.read_unit('ollama.service')!=plan['unit_prestate']['state']
            or adapter.read_native_allocation_definition()!=_native_expected_definition(plan,installed=True)):
        raise TransactionError('NATIVE_ALLOCATION_INSTALLED_DEFINITION_DENIED')
    observed=adapter.observe_native_allocation()
    transition=native_allocation_transition(plan['runtime_prestate'],observed)
    if observed!=receipt['runtime_after'] or transition!=receipt['acceptance']:
        raise TransactionError('NATIVE_ALLOCATION_INSTALLED_RUNTIME_CHANGED')
    if _native_allocation_receipt(adapter,selector)!=receipt:
        raise TransactionError('NATIVE_ALLOCATION_RECEIPT_CHANGED')
    _native_owned_configuration(adapter,receipt)
    return {'result':'NATIVE_ALLOCATION_INSTALLED_OBSERVED','plan_sha256':expected_plan_sha256,
        'runtime':observed,'stage1':'NOT_READY','scope':'RUNTIME_DEPENDENCY_ONLY'}


def verify_completed_native_allocation_rollback(adapter, selector, *, expected_plan_sha256):
    """Verify captured restoration without invoking any recovery effect."""
    selector=Path(selector);receipt=_native_allocation_receipt(adapter,selector);plan=receipt['plan']
    if (plan['plan_sha256']!=expected_plan_sha256 or receipt['phase']!='RESTORED'
            or receipt['rollback_complete'] is not True
            or native_allocation_prestate(adapter)!=plan['unit_prestate']):
        raise TransactionError('NATIVE_ALLOCATION_RESTORATION_UNPROVEN')
    observed=adapter.observe_native_allocation()
    transition=native_allocation_transition(plan['runtime_prestate'],observed,restoring=True)
    if transition!=receipt['restoration']:
        raise TransactionError('NATIVE_ALLOCATION_RESTORATION_CHANGED')
    if _native_allocation_receipt(adapter,selector)!=receipt:
        raise TransactionError('NATIVE_ALLOCATION_RECEIPT_CHANGED')
    return {'result':'NATIVE_ALLOCATION_RESTORATION_OBSERVED','plan_sha256':expected_plan_sha256,
        'runtime':observed,'stage1':'NOT_READY','scope':'RUNTIME_DEPENDENCY_ONLY'}


def install(adapter, bundle_root: Path, plan: dict, selector: Path) -> dict:
    body = {k: v for k, v in plan.items() if k not in {"plan_sha256","signature_algorithm","signing_key_id","signature"}}
    if plan.get("schema") != PLAN_SCHEMA or plan.get("plan_sha256") != digest(canonical(body)):
        raise TransactionError("OFFLINE_PLAN_INTEGRITY_DENIED")
    _verify_signature(adapter,plan)
    _restorable_unit(plan.get('unit_prestate'))
    if getattr(adapter,"boot_id",None) != plan["boot_id"]: raise TransactionError("OFFLINE_PLAN_BOOT_DENIED")
    declared = _target(adapter.root, plan["rollback_selector"])
    if selector.resolve() != declared.resolve(): raise TransactionError("OFFLINE_SELECTOR_PLAN_MISMATCH")
    manifest, source_rows = load_bundle(bundle_root)
    if manifest["model"] != plan["model"] or manifest["runtime_archive"] != plan["runtime_archive"]:
        raise TransactionError("OFFLINE_BUNDLE_PLAN_DRIFT")
    by_target = {r["target"]: r for r in source_rows}
    planned_targets={r["target"] for r in plan["files"]}|{r["target"] for r in plan["runtime_objects"]}
    if set(by_target) != planned_targets: raise TransactionError("OFFLINE_BUNDLE_PLAN_DRIFT")
    if os.path.lexists(selector): raise TransactionError("OFFLINE_SELECTOR_COLLISION_DENIED")
    records = []
    try:
        _guard(adapter,plan)
        if adapter.read_unit("ollama.service")!=plan["unit_prestate"]: raise TransactionError("OFFLINE_UNIT_PRESTATE_DRIFT")
        adapter.boundary(); selector.mkdir(mode=0o700);_set_dir_metadata(adapter,selector,0o700);_fsync_dir(selector.parent)
        backups = selector / "prestate"; adapter.boundary(); backups.mkdir(mode=0o700);_set_dir_metadata(adapter,backups,0o700);_fsync_dir(selector)
        runtime_records=[]
        receipt = {"schema": RECEIPT_SCHEMA, "actor": "OUTPOST", "selector": str(selector), "plan_sha256": plan["plan_sha256"],
                   "model": plan["model"], "boot_id":plan["boot_id"],"request_id":plan["request_id"],
                   "source_generation":plan["source_generation"],"authority_effect":"NONE",
                   "scope":"RUNTIME_DEPENDENCY_ONLY", "unit_prestate": plan["unit_prestate"],
                   "immutable_inputs":plan["immutable_inputs"], "directories":plan["directories"],
                   "runtime_objects":runtime_records,"files": records,
                   "acceptance": None, "rollback_complete": False}
        for index, row in enumerate(plan["files"]):
            target = _target(adapter.root, row["target"]); current = None
            if os.path.lexists(target):
                if target.is_symlink() or not target.is_file() or _metadata(adapter, target) != row["before"]:
                    raise TransactionError("OFFLINE_INSTALL_PRESTATE_DRIFT:" + row["target"])
                current = target.read_bytes(); backup = backups / f"{index:04d}.bin"
                _atomic_write(adapter,backup,current,{"target":row["target"],"mode":"0600","uid":0,"gid":0})
            records.append({"target": row["target"], "before": row["before"],
                            "backup": None if current is None else f"prestate/{index:04d}.bin", "after": row["sha256"]})
        for index,row in enumerate(plan["runtime_objects"],start=len(plan["files"])):
            target=_target(adapter.root,row["target"]); backup=None
            if row["before"] is not None and row["before"]["type"]=="regular":
                backup=f"prestate/{index:04d}.bin";_atomic_write(adapter,selector/backup,target.read_bytes(),
                    {"target":row["target"],"mode":"0600","uid":0,"gid":0})
            elif row["before"] is not None and row["before"]["type"]=="symlink":
                backup=f"prestate/{index:04d}.link";_atomic_write(adapter,selector/backup,row["before"]["link_target"].encode(),
                    {"target":row["target"],"mode":"0600","uid":0,"gid":0})
            runtime_records.append({"target":row["target"],"before":row["before"],"backup":backup,
                "after":{k:row[k] for k in ("type","sha256","bytes","link_target","mode","uid","gid")}})
        receipt["receipt_digest"] = receipt_digest(receipt)
        _atomic_write(adapter,selector / "receipt.json",canonical(receipt),{"target":"receipt.json","mode":"0600","uid":0,"gid":0});_fsync_dir(selector)
        _guard(adapter,plan)
        for row in plan["directories"]:
            if row["introduced"]:
                path=_target(adapter.root,row["target"])
                if not path.parent.is_dir(): raise TransactionError("OFFLINE_DIRECTORY_PARENT_DENIED:"+row["target"])
                adapter.boundary();path.mkdir(mode=row["candidate"]["mode"]);_set_dir_metadata(adapter,path,row["candidate"]["mode"])
                if isinstance(adapter,RealAdapter): os.chown(path,row["candidate"]["uid"],row["candidate"]["gid"])
                _fsync_dir(path.parent)
        _guard(adapter,plan);adapter.stop_unit("ollama.service");_guard(adapter,plan)
        staging=selector/"staged-runtime"
        staged=stage_runtime(bundle_root,manifest,staging)
        for row in sorted(plan["runtime_objects"],key=lambda r:(r["type"]!="directory",r["target"])):
            _guard(adapter,plan)
            target=_target(adapter.root,row["target"]); source=staged[by_target[row["target"]]["member"]]
            if row["type"]=="directory":
                if not target.exists(): adapter.boundary();target.mkdir(mode=row["mode"]);_fsync_dir(target.parent)
            elif row["type"]=="symlink":
                if os.path.lexists(target): adapter.boundary();target.unlink()
                adapter.boundary();os.symlink(row["link_target"],target);_fsync_dir(target.parent)
            else:
                _atomic_write(adapter,target,source.read_bytes(),row)
        for row in plan["files"]:
            _guard(adapter,plan)
            source_row = by_target[row["target"]]
            raw = source_row.get("payload")
            if raw is None: raw = Path(source_row["source_path"]).read_bytes()
            _atomic_write(adapter, _target(adapter.root, row["target"]), raw, row)
        _verify_runtime_objects(adapter,plan["runtime_objects"])
        _guard(adapter,plan);adapter.start_unit("ollama.service");_guard(adapter,plan)
        _remove_staged_tree(adapter,staging,selector)
        tags = adapter.ollama_tags()
        witness = adapter.companion_inference(plan["model"]["name"])
        _guard(adapter,plan)
        admitted=[row for row in tags if isinstance(row,dict)
                  and row.get("model")==plan["model"]["name"]
                  and row.get("digest")==plan["model"]["digest"].removeprefix("sha256:")]
        if len(admitted)!=1 or witness.get("model") != plan["model"]["name"] or not witness.get("answer"):
            raise TransactionError("OFFLINE_RUNTIME_ACCEPTANCE_DENIED")
        gpu_binding=verify_gpu_runtime_recipe(witness.get('gpu_runtime_binding'),plan)
        receipt["acceptance"] = {"boot_id":plan["boot_id"],"request_id":plan["request_id"],
            "source_generation":plan["source_generation"],"installed_files":
            [{"target":r["target"],"sha256":r["sha256"]} for r in plan["files"]],
            "tags": tags,"model_digest":plan["model"]["digest"],
            "companion_answer_sha256":digest(witness["answer"].encode()),
            "gpu_runtime_binding":gpu_binding,
            "scope":"RUNTIME_DEPENDENCY_ONLY"}
        receipt["receipt_digest"] = receipt_digest(receipt)
        _atomic_write(adapter,selector / "receipt.json",canonical(receipt),{"target":"receipt.json","mode":"0600","uid":0,"gid":0});_fsync_dir(selector)
        return receipt
    except Exception:
        # Failure injection represents the interrupted forward operation, not a
        # permanently broken storage device; compensation must get its own
        # complete boundary sequence.
        if hasattr(adapter, "fail_after"): adapter.fail_after = None
        if selector.exists() and (selector / "receipt.json").exists(): rollback(adapter, selector)
        elif selector.exists(): shutil.rmtree(selector)
        raise


def _read_rollback_receipt(adapter, selector: Path) -> dict:
    try:
        logical="/"+selector.resolve(strict=False).relative_to(adapter.root.resolve()).as_posix()
    except (ValueError,OSError) as exc:
        raise TransactionError("OFFLINE_ROLLBACK_SELECTOR_DENIED") from exc
    if not SELECTOR.fullmatch(logical) or selector.is_symlink() or not selector.is_dir():
        raise TransactionError("OFFLINE_ROLLBACK_SELECTOR_DENIED")
    nofollow_ancestors(adapter.root,selector)
    receipt_path = selector / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if (receipt.get("schema") != RECEIPT_SCHEMA or receipt.get("selector") != str(selector)
            or receipt.get("receipt_digest") != receipt_digest(receipt)
            or receipt.get("rollback_complete") not in {False,True}):
        raise TransactionError("OFFLINE_RECEIPT_INTEGRITY_DENIED")
    if adapter.directory_metadata(selector)!={"mode":0o700,"uid":0,"gid":0} or adapter.file_metadata(receipt_path)!={"mode":0o600,"uid":0,"gid":0}:
        raise TransactionError("OFFLINE_ROLLBACK_CUSTODY_DENIED")
    if getattr(adapter,"boot_id",None)!=receipt["boot_id"]: raise TransactionError("OFFLINE_ROLLBACK_BOOT_DENIED")
    _immutable_inventory(adapter,receipt["immutable_inputs"])
    return receipt


def verify_completed_rollback(adapter, selector: Path, *, expected_plan_sha256: str) -> dict:
    """Confirm restoration read-only; never retry an incomplete compensation."""
    adapter.boundary()
    receipt=_read_rollback_receipt(adapter,selector)
    if receipt['rollback_complete'] is not True or receipt.get('plan_sha256')!=expected_plan_sha256:
        raise TransactionError('OFFLINE_RESTORATION_UNPROVEN')
    if adapter.read_unit('ollama.service')!=receipt['unit_prestate']:
        raise TransactionError('OFFLINE_ROLLBACK_UNIT_DRIFT')
    _verify_restored_prestate(adapter,receipt)
    adapter.boundary()
    if _read_rollback_receipt(adapter,selector)!=receipt:
        raise TransactionError('OFFLINE_RESTORATION_EVIDENCE_CHANGED')
    if adapter.read_unit('ollama.service')!=receipt['unit_prestate']:
        raise TransactionError('OFFLINE_ROLLBACK_UNIT_DRIFT')
    _verify_restored_prestate(adapter,receipt)
    return receipt


def rollback(adapter, selector: Path) -> dict:
    receipt=_read_rollback_receipt(adapter,selector)
    receipt_path=selector/'receipt.json'
    if receipt["rollback_complete"]:
        if adapter.read_unit("ollama.service")!=receipt["unit_prestate"]: raise TransactionError("OFFLINE_ROLLBACK_UNIT_DRIFT")
        _verify_restored_prestate(adapter,receipt)
        return receipt
    adapter.stop_unit("ollama.service")
    staged=selector/"staged-runtime"
    _remove_staged_tree(adapter,staged,selector)
    for row in reversed(receipt["files"]):
        target = _target(adapter.root, row["target"])
        if row["before"] is None and not os.path.lexists(target):
            continue
        if row["before"] is not None and target.is_file() and _metadata(adapter, target) == row["before"]:
            continue
        if target.is_symlink() or not target.is_file() or digest(target.read_bytes()) != row["after"]:
            raise TransactionError("OFFLINE_ROLLBACK_CURRENT_HASH_DENIED:" + row["target"])
        if row["backup"] is None:
            adapter.boundary(); target.unlink()
        else:
            backup = selector / row["backup"]
            if digest(backup.read_bytes()) != row["before"]["sha256"]: raise TransactionError("OFFLINE_ROLLBACK_BACKUP_DENIED")
            restore = {"target": row["target"], **row["before"]}
            _atomic_write(adapter, target, backup.read_bytes(), restore)
    for row in reversed(receipt["runtime_objects"]):
        target=_target(adapter.root,row["target"]); before=row["before"]
        current=_object_metadata(adapter,target) if os.path.lexists(target) else None
        after={k:v for k,v in row["after"].items() if v is not None or k not in {"sha256","link_target"}}
        if before is not None and current==before: continue
        comparable={k:v for k,v in row["after"].items() if k in current} if current else None
        if current is None or comparable!=current: raise TransactionError("OFFLINE_ROLLBACK_RUNTIME_DRIFT:"+row["target"])
        if before is None:
            adapter.boundary(); target.rmdir() if target.is_dir() and not target.is_symlink() else target.unlink();_fsync_dir(target.parent)
        elif before["type"]=="regular":
            backup=selector/row["backup"]
            if file_digest(backup)[0]!=before["sha256"]: raise TransactionError("OFFLINE_ROLLBACK_BACKUP_DENIED")
            _atomic_write(adapter,target,backup.read_bytes(),{"target":row["target"],**before})
        elif before["type"]=="symlink":
            adapter.boundary();target.unlink();os.symlink(before["link_target"],target);_fsync_dir(target.parent)
        else:
            os.chmod(target,before["mode"])
    adapter.restore_unit("ollama.service", receipt["unit_prestate"])
    if adapter.read_unit("ollama.service")!=receipt["unit_prestate"]: raise TransactionError("OFFLINE_ROLLBACK_UNIT_RESTORE_DENIED")
    for row in reversed(receipt["directories"]):
        if row["introduced"]:
            path=_target(adapter.root,row["target"])
            if path.exists():
                if any(path.iterdir()): raise TransactionError("OFFLINE_ROLLBACK_DIRECTORY_RESIDUE:"+row["target"])
                adapter.boundary();path.rmdir();_fsync_dir(path.parent)
    _immutable_inventory(adapter,receipt["immutable_inputs"])
    if getattr(adapter,"boot_id",None)!=receipt["boot_id"]: raise TransactionError("OFFLINE_ROLLBACK_BOOT_DENIED")
    receipt["rollback_complete"] = True
    receipt["receipt_digest"] = receipt_digest(receipt)
    _atomic_write(adapter,receipt_path,canonical(receipt),{"target":"receipt.json","mode":"0600","uid":0,"gid":0});_fsync_dir(selector)
    return receipt
