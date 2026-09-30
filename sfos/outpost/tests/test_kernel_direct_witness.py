"""Private Authority-v2 source proof only; never admission or service activation."""
import importlib
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import shutil
import signal
import sys
import tempfile
import threading
import time
import traceback
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption

from outpost import kernel_direct_witness as witness
from outpost.host_vitality import HostVitalityStore,digest as host_digest
from tests.test_host_vitality import observation

_CONSTITUTION_PATH=(Path(__file__).resolve().parents[2]/
                    'kernel/tests/test_constitution_binding.py')
_CONSTITUTION_SPEC=importlib.util.spec_from_file_location(
    'kernel_direct_witness_constitution_fixture',_CONSTITUTION_PATH)
constitution=importlib.util.module_from_spec(_CONSTITUTION_SPEC)
_CONSTITUTION_SPEC.loader.exec_module(constitution)
source_inventory_fixture=constitution.source_inventory_fixture
authority=constitution.authority
PAYLOAD=constitution.PAYLOAD


REQUEST={"schema":"SEREIN/KernelBranchWitnessRequest/v1","branch":"AUTHORITY",
         "request_id":"kernel-authority-test-request","nonce":"11"*32,
         "previous_evidence_digest":"GENESIS"}


@pytest.fixture
def direct_fixture(source_inventory_fixture,monkeypatch):
    root,_,_,native=source_inventory_fixture
    monkeypatch.syspath_prepend(str(PAYLOAD.parent))
    producer=importlib.import_module('serein_stage1.kernel_branch_api')
    # Reuse the already-loaded exact fixture collector whose synthetic anchor
    # hash is explicitly bound; no subject result is stubbed.
    monkeypatch.setattr(producer,'collect_authority_facts',authority.collect_authority_facts)
    uid,gid=os.geteuid(),os.getegid()
    account=SimpleNamespace(pw_uid=uid,pw_gid=gid)
    monkeypatch.setattr(producer,'pwd',SimpleNamespace(getpwnam=lambda name:account))
    monkeypatch.setattr(witness,'pwd',SimpleNamespace(getpwnam=lambda name:account))
    anchor=root/witness.ANCHOR.as_posix().lstrip('/')
    monkeypatch.setattr(witness,'CANONICAL_AUTHORITY_SHA256',witness.hashlib.sha256(anchor.read_bytes()).hexdigest())
    key_path=root/producer.NATIVE_KEY.lstrip('/')
    key_path.parent.mkdir(parents=True,exist_ok=True)
    key_path.write_bytes(native['private']);key_path.chmod(0o600)
    socket_dir=Path(tempfile.mkdtemp(prefix='kw-',dir='/tmp'))
    socket_path=socket_dir/'s'
    boot_path=root/'proc/sys/kernel/random/boot_id'
    boot_id=boot_path.read_text().strip()
    host_observation=observation();host_observation['boot_id']=boot_id
    host_observation['host']['machine_id']='e'*32
    host_observation['evidence_digest']=host_digest(
        {key:value for key,value in host_observation.items() if key!='evidence_digest'})
    host_path=root/'var/lib/serein-outpost/direct-host/state.json'
    HostVitalityStore(host_path.parent).record(host_observation)
    facts=authority.collect_authority_facts(root)
    source={key:facts[key] for key in ('source_commit','source_tree','canonical_manifest_digest')}
    identity={'binding':native['binding'],'registry':json.loads(native['registry'])}
    yield root,producer,source,identity,socket_path,boot_path,anchor,host_path,key_path
    shutil.rmtree(socket_dir)


def roundtrip(fixture,request=REQUEST,server_errors=None):
    root,producer,source,identity,socket_path,boot_path,anchor,host_path,_=fixture
    errors=[] if server_errors is None else server_errors
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path));os.chmod(socket_path,0o600);listener.listen(1);listener.settimeout(4)
        def serve():
            try:
                connection,_=listener.accept()
                with connection:producer.serve_authority(connection,root=root)
            except Exception as exc:errors.append(exc)
        thread=threading.Thread(target=serve);thread.start()
        try:
            observed=witness.observe_authority(
                source=source,identity=identity,socket_path=socket_path,
                boot_path=boot_path,anchor_path=anchor,host_path=host_path,request=request)
        finally:
            thread.join(timeout=5)
    return observed,errors


def test_real_private_roundtrip_proves_possession_but_remains_unadmitted(direct_fixture):
    observed,errors=roundtrip(direct_fixture)
    assert not errors
    subject=observed['subject_evidence']
    assert subject['verdict']=='UNKNOWN' and subject['api_health']=='UNKNOWN'
    assert subject['phase_a']==[
        {'name':name,'verdict':'PASS' if index<3 else 'UNKNOWN'}
        for index,name in enumerate(authority.PHASE_A_CHECKS)]
    assert observed['identity_possession']=='VERIFIED'
    assert observed['result']=='AUTHORITY_IDENTITY_OBSERVED'
    assert observed['admission']=='UNADMITTED' and observed['stage1']=='NOT_READY'
    assert observed['authority_effect']=='NONE'


@pytest.mark.parametrize('fault',(None,'artifact','plan','boot','key'))
def test_exact_launcher_fd3_dispatch_with_synthetic_root_trust_account_adapters(
        direct_fixture,fault):
    """Exercise exact launcher/fd3 with labelled root, trust and account adapters."""
    root,producer,source,identity,socket_path,boot_path,anchor,host_path,key_path=direct_fixture
    launcher=root/'usr/libexec/serein/serein-kernel-branch-api'
    installed_package=root/'usr/lib/python3/dist-packages/serein_stage1'
    installed_api=installed_package/'kernel_branch_api.py'
    assert launcher.read_bytes()==(PAYLOAD.parent/'bin/serein-kernel-branch-api').read_bytes()
    assert installed_api.read_bytes()==(PAYLOAD/'kernel_branch_api.py').read_bytes()
    assert (installed_package/'authority_boot.py').read_bytes()==(PAYLOAD/'authority_boot.py').read_bytes()
    if fault=='artifact':
        artifact=installed_package/'authority-proof-contract.v1.json'
        artifact.write_bytes(artifact.read_bytes()+b' ')
    elif fault=='plan':
        installed_witness=json.loads(
            (root/'var/lib/serein-outpost/kernel/kernel-install-witness.json').read_bytes())
        plan=root/installed_witness['rollback_selector'].lstrip('/')/'plan.json'
        plan.write_bytes(plan.read_bytes()+b' ')
    elif fault=='key':
        key_path.write_bytes(Ed25519PrivateKey.generate().private_bytes(
            Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
        key_path.chmod(0o600)
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    listener.bind(str(socket_path));os.chmod(socket_path,0o600);listener.listen(1)
    child_read,child_write=os.pipe()
    child=os.fork()
    if child==0:
        try:
            os.close(child_read)
            os.dup2(listener.fileno(),3)
            os.set_inheritable(3,True)
            os.set_inheritable(child_write,True)
            adapter=r'''import os,runpy,socket,stat,sys,time,traceback
from pathlib import Path
from types import SimpleNamespace
launcher=Path(sys.argv[1]);installed=Path(sys.argv[2]);source=Path(sys.argv[3])
root=Path(sys.argv[4]);endpoint=sys.argv[5];anchor_sha=sys.argv[6]
uid=int(sys.argv[7]);gid=int(sys.argv[8]);ready_fd=int(sys.argv[9])
boot_file=Path(sys.argv[10]);fault=sys.argv[11]
timings=[]
def report(kind,value,tb):
 detail=''.join(traceback.format_exception(kind,value,tb))+f'\ntimings={timings!r}\n'
 try:os.write(ready_fd,b'E'+detail.encode())
 except OSError:pass
sys.excepthook=report
assert sys.flags.isolated==1 and sys.flags.no_user_site==1
assert launcher.read_bytes()==(source.parent/'bin/serein-kernel-branch-api').read_bytes()
for name in ('kernel_branch_api.py','authority_boot.py'):
 assert (installed/name).read_bytes()==(source/name).read_bytes()
fd3=os.fstat(3);probe=socket.fromfd(3,socket.AF_UNIX,socket.SOCK_STREAM)
try:fd3_name=probe.getsockname()
finally:probe.close()
assert stat.S_ISSOCK(fd3.st_mode) and fd3_name==endpoint
# Test-only adapters: synthetic root, synthetic trust anchor and synthetic
# account.  The exact installed producer module and launcher remain in use.
sys.path.insert(0,str(installed))
import authority_boot
authority_boot.ANCHOR_SHA256=anchor_sha
import kernel_branch_api
account=SimpleNamespace(pw_uid=uid,pw_gid=gid)
kernel_branch_api.pwd=SimpleNamespace(getpwnam=lambda name:account)
collect=kernel_branch_api.collect_authority_facts
def timed_collect(selected_root):
 started=time.monotonic()
 try:return collect(selected_root)
 finally:
  timings.append(('collect_authority_facts',time.monotonic()-started))
kernel_branch_api.collect_authority_facts=timed_collect
subject=kernel_branch_api.serve_authority
def timed_subject(connection):
 started=time.monotonic()
 try:
  if fault=='boot':
   boot_file.write_text('aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\n')
  return subject(connection,root=root)
 finally:timings.append(('serve_authority',time.monotonic()-started))
kernel_branch_api.serve_authority=timed_subject
sys.argv=[str(launcher),'--branch','AUTHORITY']
os.write(ready_fd,b'R')
runpy.run_path(str(launcher),run_name='__main__')
os.write(ready_fd,b'D'+repr(timings).encode())
'''
            argv=[sys.executable,'-I','-B','-c',adapter,str(launcher),str(installed_package),
                  str(PAYLOAD),str(root),str(socket_path),
                  witness.hashlib.sha256(anchor.read_bytes()).hexdigest(),
                  str(os.geteuid()),str(os.getegid()),str(child_write),
                  str(boot_path),fault or 'none']
            os.execv(sys.executable,argv)
        except BaseException:
            try:os.write(child_write,b'E'+traceback.format_exc().encode())
            except OSError:pass
            os._exit(97)
        os._exit(0)
    os.close(child_write)
    status=None
    try:
        ready,_,_=select.select([child_read],[],[],3)
        assert ready
        marker=os.read(child_read,1)
        if marker==b'E':
            _,status=os.waitpid(child,0);child=None
            detail=os.read(child_read,65536).decode(errors='replace')
            pytest.fail(f'pre-launch child failure: {detail}; exit={os.waitstatus_to_exitcode(status)}')
        assert marker==b'R'
        def finish_child(pid):
            nonlocal child
            deadline=time.monotonic()+3
            output=b''
            while time.monotonic()<deadline:
                readable,_,_=select.select([child_read],[],[],0.05)
                if readable:
                    chunk=os.read(child_read,65536)
                    if chunk:output+=chunk
                waited,wait_status=os.waitpid(pid,os.WNOHANG)
                if waited:
                    return wait_status,output.decode(errors='replace')
            os.kill(pid,signal.SIGKILL)
            _,wait_status=os.waitpid(pid,0)
            child=None
            pytest.fail(f'child completion timeout; diagnostics={output.decode(errors="replace")}; '
                        f'exit={os.waitstatus_to_exitcode(wait_status)}')
        # Only the child-owned fd3 remains, so child failure closes the endpoint
        # immediately instead of making the consumer wait on the parent copy.
        listener.close()
        try:
            observed=witness.observe_authority(
                source=source,identity=identity,socket_path=socket_path,
                boot_path=boot_path,anchor_path=anchor,host_path=host_path,request=REQUEST)
        except Exception as exc:
            status,detail=finish_child(child);child=None
            if fault is None:
                pytest.fail(f'consumer={exc!r}; child={detail}; exit={os.waitstatus_to_exitcode(status)}')
            assert os.waitstatus_to_exitcode(status)!=0
            assert 'Traceback' in detail and 'BranchDenied' in detail
            assert 'native_identity_proof' not in detail and 'possession_signature' not in detail
            return
        status,detail=finish_child(child);child=None
    finally:
        os.close(child_read)
        listener.close()
        if child is not None:
            waited,_=os.waitpid(child,os.WNOHANG)
            if waited==0:
                os.kill(child,signal.SIGKILL);os.waitpid(child,0)
    assert os.waitstatus_to_exitcode(status)==0
    assert fault is None
    assert observed['identity_possession']=='VERIFIED'
    assert observed['subject_evidence']['verdict']=='UNKNOWN'
    assert observed['admission']=='UNADMITTED' and observed['stage1']=='NOT_READY'
    assert observed['authority_effect']=='NONE'


def test_answer_helpers_cannot_bypass_verified_transport(direct_fixture):
    _,producer,*_=direct_fixture
    with pytest.raises(producer.BranchDenied,match='VERIFIED_TRANSPORT'):producer.answer({})
    with pytest.raises(producer.BranchDenied,match='VERIFIED_TRANSPORT'):producer._answer({})


def test_actual_wrong_peer_identity_is_denied(direct_fixture,monkeypatch):
    _,producer,*_=direct_fixture
    wrong=SimpleNamespace(pw_uid=os.geteuid()+1,pw_gid=os.getegid())
    monkeypatch.setattr(producer,'pwd',SimpleNamespace(getpwnam=lambda name:wrong))
    errors=[]
    with pytest.raises(witness.KernelWitnessError,match='(RESPONSE_FRAMING|TRANSPORT_UNAVAILABLE)') as caught:
        roundtrip(direct_fixture,server_errors=errors)
    assert errors and 'OUTPOST_PEER_IDENTITY_DENIED' in str(errors[0])
    assert caught.value.mode == 'SAFE_RECOVERY'
    assert caught.value.privileged_execution is caught.value.branch_advance is False


@pytest.mark.parametrize('stage', ('connect', 'peer', 'send', 'receive'))
def test_transport_os_errors_remain_safe_recovery(direct_fixture, monkeypatch, stage):
    _,_,source,identity,socket_path,boot_path,anchor,host_path,_=direct_fixture
    failure=OSError('synthetic transport interruption')

    class InterruptedClient:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def settimeout(self, seconds): assert seconds == 3
        def connect(self, address):
            if stage == 'connect': raise failure
        def getsockopt(self, *args):
            if stage == 'peer': raise failure
            return witness.struct.pack('3i', os.getpid(), 0, 0)
        def sendall(self, data):
            if stage == 'send': raise failure
        def recv(self, size):
            assert stage == 'receive'
            raise failure

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path));os.chmod(socket_path,0o600);listener.listen(1)
        monkeypatch.setattr(witness, 'socket', SimpleNamespace(
            socket=lambda *args: InterruptedClient(), AF_UNIX=socket.AF_UNIX,
            SOCK_STREAM=socket.SOCK_STREAM, SOL_SOCKET=socket.SOL_SOCKET,
            SO_PEERCRED=socket.SO_PEERCRED))
        with pytest.raises(witness.KernelWitnessError, match='KERNEL_TRANSPORT_UNAVAILABLE') as caught:
            witness.observe_authority(source=source, identity=identity, socket_path=socket_path,
                boot_path=boot_path, anchor_path=anchor, host_path=host_path, request=REQUEST)
    assert caught.value.__cause__ is failure
    assert caught.value.mode == 'SAFE_RECOVERY'
    assert caught.value.privileged_execution is caught.value.branch_advance is False


@pytest.mark.parametrize('field',('verdict','nonce','boot_id','source_commit','issued_at',
                                  'possession_signature','instance_id','checkpoint','boot_decision',
                                  'frame_identity'))
def test_altered_complete_response_meaning_is_denied(direct_fixture,field):
    observed,errors=roundtrip(direct_fixture);assert not errors
    value=observed['subject_evidence'];root,_,source,identity,_,boot_path,anchor,_,_=direct_fixture
    if field in {'possession_signature','instance_id','checkpoint'}:
        value['native_identity_proof'][field]='0'*(128 if field=='possession_signature' else 16 if field=='instance_id' else 64)
    elif field=='verdict':value[field]='PASS'
    elif field=='nonce':value[field]='22'*32
    elif field=='boot_id':value[field]='aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
    elif field=='source_commit':value[field]='f'*40
    elif field=='boot_decision':
        value[field]['mode']='SAFE_RECOVERY';value[field]['allowed_effects']=[]
    elif field=='frame_identity':value[field]['machine_id']='a'*32
    else:value[field]='2000-01-01T00:00:00Z'
    body={key:item for key,item in value.items() if key!='evidence_digest'}
    value['evidence_digest']=witness.digest(body)
    with pytest.raises(witness.KernelWitnessError):
        witness.validate_authority_response(
            value,request=REQUEST,source=source,boot_id=boot_path.read_text().strip(),
            observed_at=witness.datetime.now(witness.timezone.utc),identity=identity,
            anchor=anchor.read_bytes(),host_machine_id='e'*32)


@pytest.mark.parametrize('fault',('wrong-key','custody','symlink'))
def test_native_private_key_faults_fail_closed(direct_fixture,fault):
    *_,key_path=direct_fixture
    if fault=='wrong-key':
        other=Ed25519PrivateKey.generate().private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption())
        key_path.write_bytes(other);key_path.chmod(0o600)
    elif fault=='custody':key_path.chmod(0o644)
    else:
        saved=key_path.with_name('foreign.pem');saved.write_bytes(key_path.read_bytes());saved.chmod(0o600)
        key_path.unlink();key_path.symlink_to(saved)
    errors=[]
    with pytest.raises(witness.KernelWitnessError,match='RESPONSE_FRAMING'):
        roundtrip(direct_fixture,server_errors=errors)
    expected='NATIVE_KEY_MISMATCH' if fault=='wrong-key' else 'AUTHORITY_WITNESS_DENIED'
    assert errors and expected in str(errors[0])


@pytest.mark.parametrize('fault',('bad-facts','collector-error'))
def test_producer_safe_recovery_failure_emits_no_signed_response(
        direct_fixture,monkeypatch,fault):
    _,producer,*_=direct_fixture
    if fault=='bad-facts':monkeypatch.setattr(producer,'collect_authority_facts',lambda root:'VERIFIED')
    else:
        def failed(root):raise authority.AuthorityDenied('COLLECTOR_FAILED')
        monkeypatch.setattr(producer,'collect_authority_facts',failed)
    server,client=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        client.sendall(producer.canonical(REQUEST)+b'\n')
        with pytest.raises(producer.BranchDenied) as caught:
            producer.serve_authority(server,root=direct_fixture[0])
        assert caught.value.mode=='SAFE_RECOVERY'
        assert caught.value.privileged_execution is caught.value.branch_advance is False
        assert caught.value.decision=={
            'schema':'SereinAuthorityBootDecision/v1','mode':'SAFE_RECOVERY',
            'allowed_effects':[],'privileged_execution':False,'branch_advance':False,
            'authority_effect':'NONE','admission_effect':'NONE'}
        server.close();client.settimeout(1)
        assert client.recv(65536)==b''
    finally:
        server.close();client.close()

