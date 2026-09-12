import hashlib,importlib.util,json,sys
from pathlib import Path
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import base64
from sfos.kernel.install.kernel_first_install import Denied,ROOTS,install,rollback,sha
import sfos.kernel.install.kernel_first_install as transaction
from sfos.kernel.payload.serein_stage1 import audit,cognitive_gateway,commission_runner,companion_provider,compute_dispatch,conversation_runtime,core_attachments,domain1_runner,gateway_runtime,gpu_control,haos_https_adapter,independent_audit,kernel_router,offline_companion,stage1_witness
from datetime import datetime,timezone
BOOT="11111111-2222-3333-8444-555555555555"
IDENTITIES={"serein-outpost":{"user":"serein-outpost","group":"serein-outpost","uid":991,"gid":991,"primary_gid":991,"members":[]},"serein-stage1":{"user":"serein-stage1","group":"serein-stage1","uid":992,"gid":992,"primary_gid":992,"members":[]}}
AUDIT={"schema":"SEREIN/IndependentRouteAudit/v1","route":"kernel.companion.generate.v1","status":"PASS","verdict":"PASS — SECURITY ROUTE INDEPENDENTLY VERIFIED","auditor":"INDEPENDENT_VALIDATOR","selected_by":"OPERATOR","boot_id":BOOT,"source_generation":{"commit":"e"*40,"tree":"9"*40},"issued_at":"1970-01-01T00:01:30Z","expires_at":"1970-01-01T00:02:00Z","nonce":"audit-default","evidence_sha256":"a"*64,"signature":"injected-verifier"}
def authority(action,caller,nonce):
 route="kernel.companion.generate.v1"
 if action=="kernel.route.register.v1":intent="COMMISSION_KERNEL_ROUTE";scope={"route":route,"plane":"COGNITIVE","owner":"KERNEL"};conditions=["INDEPENDENT_AUDIT_PASS","UMP_KNOWN","ROUTE_UNIQUE"];expected="ROUTE_REGISTERED"
 elif action=="kernel.route.dispatch.v1":intent="DISPATCH_KERNEL_COMPUTE";scope={"route":route,"plane":"COGNITIVE","caller":caller};conditions=["ROUTE_ACTIVE","UMP_KNOWN","CAPACITY_ENFORCED"];expected="ROUTE_DISPATCHED"
 else:intent="stage1_companion_compute";scope={"route":route};conditions=["OFFLINE_GPU_ONLY"];expected="CORRELATED_COMPANION_RESPONSE"
 return {"schema":"SEREIN/KernelAuthorityRouteContract/v1","action":action,"object":route,"intent":intent,"scope":scope,"conditions":conditions,"policy_version":kernel_router.POLICY_VERSION,"policy_digest":kernel_router.POLICY_DIGEST,"issuer":"KERNEL_AUTHORITY","subject":"KERNEL","trust_identity":caller,"issued_at":"1970-01-01T00:01:30Z","expires_at":"1970-01-01T00:01:50Z","nonce":nonce,"expected_result":expected,"boot_id":BOOT,"source_generation":{"commit":"e"*40,"tree":"9"*40},"predecessor_evidence_digest":"b"*64,"authority_effect":"NONE"}
def lookup(user,group):return dict(IDENTITIES[user])
@pytest.fixture(autouse=True)
def identities(monkeypatch):monkeypatch.setattr(transaction,"system_identity",lookup)
def fixture(tmp):
 root=tmp/"root";source=tmp/"source";(root/"proc/sys/kernel/random").mkdir(parents=True);(root/"proc/sys/kernel/random/boot_id").write_text(BOOT);(root/"var/lib/serein/rollback").mkdir(parents=True)
 rows=[]
 for branch,name in (("AUTHORITY","authority.py"),("OPERATIONS","operations.py"),("INTERFACE","interface.py")):
  path=source/name;path.parent.mkdir(parents=True,exist_ok=True);data=(branch+"\n").encode();path.write_bytes(data);rows.append({"branch":branch,"source":name,"target":f"/usr/lib/serein/kernel/{name}","bytes":len(data),"sha256":sha(data),"mode":"0644"})
 declared=[[r["source"],r["bytes"],r["sha256"],r["mode"]] for r in rows];manifest={"schema":"SereinPortableKernelRelease/v1","payload":declared,"payload_digest":"sha256:"+sha((json.dumps(declared,sort_keys=True,separators=(",",":"))+"\n").encode()),"install_denominator_digest":"sha256:"+sha((json.dumps(rows,sort_keys=True,separators=(",",":"))+"\n").encode())};manifest["self_digest"]="sha256:"+sha((json.dumps(manifest,sort_keys=True,separators=(",",":"))+"\n").encode());(source/"release-manifest.json").write_text(json.dumps(manifest))
 private=Ed25519PrivateKey.generate();public=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo);anchor=root/"usr/share/serein/outpost/cognition-verification.pem";anchor.parent.mkdir(parents=True);anchor.write_bytes(public)
 plan={"schema":"SereinPublicKernelFirstInstallPlan/v1","target_vm_id":"VM4010","source_parent":"9"*40,"source_commit":"a"*40,"source_tree":"b"*40,"release_digest":manifest["self_digest"],"current_boot_id":BOOT,"outpost_identity":IDENTITIES["serein-outpost"],"replay_identity":IDENTITIES["serein-stage1"],"payload":rows,"rollback_selector":"/var/lib/serein/rollback/kernel-first-install-20260910T120000Z-abcdef123456","authority_sha256":sha(public),"archive_sha256":"c"*64,"source_receipt_sha256":"d"*64,"source_inventory_digest":"sha256:"+"e"*64};plan["signature"]=base64.urlsafe_b64encode(private.sign((json.dumps(plan,sort_keys=True,separators=(",",":"))+"\n").encode())).decode().rstrip("=");return root,source,plan
def test_authority_operations_interface_inactive(tmp_path):
 root,source,plan=fixture(tmp_path);result=install(root,source,plan,random_bytes=lambda n:b"k"*n);assert result=={"status":"INSTALLED_INACTIVE","branch_order":["AUTHORITY","OPERATIONS","INTERFACE"],"receipt":plan["rollback_selector"]+"/receipt.json","secret_exported":False}
 key=root/"var/lib/serein/kernel/authority/replay.key";assert key.read_bytes()==b"k"*32 and key.stat().st_mode&0o777==0o600 and (key.stat().st_uid,key.stat().st_gid)==(992,992)
 descriptor=json.loads((root/"var/lib/serein/kernel/authority/replay-descriptor.json").read_text());assert descriptor["body"]["trusted_key_fingerprint"]==hashlib.sha256(b"k"*32).hexdigest() and descriptor["body"]["authority_effect"]=="NONE"
 assert "k"*32 not in (root/"etc/serein/kernel/replay-peer.env").read_text()
def test_signed_rollback_removes_exact_first_install(tmp_path):
 root,source,plan=fixture(tmp_path);install(root,source,plan,random_bytes=lambda n:b"x"*n);receipt=root/plan["rollback_selector"].lstrip("/")/"receipt.json";assert rollback(root,receipt)["status"]=="ROLLBACK_COMPLETE";assert not (root/"var/lib/serein/kernel/authority/replay.key").exists()
def test_rollback_denies_live_file_drift(tmp_path):
 root,source,plan=fixture(tmp_path);install(root,source,plan,random_bytes=lambda n:b"x"*n);path=root/"usr/lib/serein/kernel/interface.py";path.write_text("drift\n")
 with pytest.raises(Denied,match="FILE_CAS"):rollback(root,root/plan["rollback_selector"].lstrip("/")/"receipt.json")
 assert path.read_text()=="drift\n"
def test_rollback_resumes_after_interrupted_unlink_and_without_replay_key(tmp_path):
 root,source,plan=fixture(tmp_path);install(root,source,plan,random_bytes=lambda n:b"x"*n);receipt=root/plan["rollback_selector"].lstrip("/")/"receipt.json";counter={"value":0}
 def boundary():
  counter["value"]+=1
  if counter["value"]==3:raise Denied("INTERRUPTED")
 with pytest.raises(Denied,match="INTERRUPTED"):rollback(root,receipt,boundary)
 (root/"var/lib/serein/kernel/authority/replay.key").unlink(missing_ok=True)
 assert rollback(root,receipt)["status"]=="ROLLBACK_COMPLETE"
 assert rollback(root,receipt)["status"]=="ROLLBACK_COMPLETE"
 journal=json.loads((receipt.parent/"phase-journal.json").read_text());assert journal["state"]=="ROLLBACK_COMPLETE"
@pytest.mark.parametrize("failure_boundary",[1,2,3])
def test_setup_interruption_restores_absent_selector_and_retry(tmp_path,failure_boundary):
 root,source,plan=fixture(tmp_path);counter={"value":0}
 def boundary():
  counter["value"]+=1
  if counter["value"]==failure_boundary:raise Denied("SETUP_INTERRUPTED")
 with pytest.raises(Denied,match="SETUP_INTERRUPTED"):install(root,source,plan,boundary,lambda n:b"s"*n)
 selector=root/plan["rollback_selector"].lstrip("/");assert not selector.exists()
 assert install(root,source,plan,random_bytes=lambda n:b"s"*n)["status"]=="INSTALLED_INACTIVE"
def test_tamper_collision_and_environment_specific_target_deny(tmp_path):
 root,source,plan=fixture(tmp_path);(source/"authority.py").write_text("tamper")
 with pytest.raises(Denied,match="SOURCE_HASH"):install(root,source,plan)
 root,source,plan=fixture(tmp_path/"target");plan["payload"][0]["target"]="/etc/haproxy/haos.cfg"
 with pytest.raises(Denied,match="PLAN_SIGNATURE"):install(root,source,plan)
 root,source,plan=fixture(tmp_path/"collision");p=root/"usr/lib/serein/kernel/authority.py";p.parent.mkdir(parents=True);p.write_text("foreign")
 with pytest.raises(Denied,match="COLLISION"):install(root,source,plan)
 assert p.read_text()=="foreign"
def test_midflight_failure_compensates(tmp_path):
 root,source,plan=fixture(tmp_path);count={"n":0}
 def boundary():
  count["n"]+=1
  if count["n"]==5:raise Denied("INJECTED")
 with pytest.raises(Denied,match="INJECTED"):install(root,source,plan,boundary,lambda n:b"z"*n)
 assert not (root/"var/lib/serein/kernel/authority/replay.key").exists()
def test_public_kernel_manifest_is_exhaustive_and_environment_neutral():
 root=Path(__file__).parents[1];manifest=json.loads((root/"release-manifest.json").read_text());declared={row[0]:(row[1],row[2]) for row in manifest["payload"]};actual={}
 for path in (root/"payload").rglob("*"):
  if path.is_file():data=path.read_bytes();actual[path.relative_to(root).as_posix()]=(len(data),sha(data))
 assert declared==actual and manifest["branch_order"]==["AUTHORITY","OPERATIONS","INTERFACE"] and manifest["secret_archive_entries"]==[]
 joined=b"".join(path.read_bytes() for path in (root/"payload").rglob("*") if path.is_file()).lower()
 # PRO-120 requires generic isolated HAOS and Android function identities in
 # the public Kernel contract.  What must remain absent is client-specific
 # implementation, private routing, credentials, model-pull code, and target
 # addresses.
 assert all(term not in joined for term in (b"haproxy",b"ollama pull",b"https://",b"192.168.",b"authorization:",b"api_key",b"token="))
 assert b"http://" not in joined.replace(b"http://127.0.0.1:11434",b"")
def test_operations_dependency_closure_is_kernel_owned_and_complete():
 root=Path(__file__).parents[1];payload=root/"payload";heartbeat=(payload/"systemd/serein-kernel-operations-heartbeat.service").read_text();replay=(payload/"systemd/serein-kernel-replay-store.service").read_text();runner=(payload/"bin/serein-kernel-operations-heartbeat").read_text();branch=(payload/"serein_stage1/kernel_branch_api.py").read_text()
 assert "Requires=serein-kernel-replay-store.service serein-observation-audit.socket" in heartbeat
 assert "/var/lib/serein/kernel" in heartbeat+replay+runner+branch and "/run/serein/kernel/replay-store.sock" in replay+branch
 assert "/var/lib/serein/stage2" not in heartbeat+replay+runner+branch and "serein-stage2-replay" not in heartbeat+replay
 required={"runtime/persistent_replay_store.py","runtime/replay_store.py","serein_stage1/audit.py","bin/serein-observation-audit","systemd/serein-observation-audit.service","systemd/serein-observation-audit.socket","systemd/serein-kernel-replay-store.service"}
 assert all((payload/name).is_file() for name in required)
def test_every_manifest_target_is_inside_an_exact_allowed_family(tmp_path):
 _,_,_,rows=actual_payload_fixture(tmp_path)
 assert all(any(row["target"].startswith(prefix) for prefix in ROOTS) for row in rows)
def test_complete_domain_one_sequence_and_outpost_only_stage1_witness():
 root=Path(__file__).parents[1];manifest=json.loads((root/"release-manifest.json").read_text());layout=json.loads((root/"install-layout.json").read_text());expected=["AUTHORITY","OPERATIONS","INTERFACE","GPU_CONTROL","OFFLINE_COMPANION","COGNITIVE_GATEWAY","OUTPOST_STAGE1_WITNESS"]
 assert manifest["stage1_order"]==layout["stage1_order"]==expected and manifest["activation"]=="OUTPOST_ONLY_AFTER_INACTIVE_PROOF"
 assert manifest["later_core_attachments"]==list(core_attachments.CORE_ORDER)
def test_gpu_companion_gateway_and_later_attachments_are_bounded():
 gpu=gpu_control.verify({"schema":"SEREIN/KernelGPUControlWitness/v1","boot_id":BOOT,"device_count":1,"driver_loaded":True,"gpu_inventory_sha256":"a"*64,"authority_effect":"NONE"});assert gpu["status"]=="READY" and gpu["owner"]=="KERNEL"
 response=offline_companion.request({"schema":"SEREIN/KernelCompanionRequest/v1","conversation_id":"c1","prompt":"hello","model_digest":"sha256:model","network_policy":"OFFLINE_ONLY"},lambda prompt,digest:"local answer");assert response["answer"]=="local answer" and response["network_effect"]=="NONE"
 calls={name:[] for name in cognitive_gateway.CLIENTS};handlers={name:(lambda packet,n=name:(calls[n].append(packet) or {"status":"OK"})) for name in cognitive_gateway.CLIENTS};gateway=cognitive_gateway.Gateway(handlers)
 for client in cognitive_gateway.CLIENTS:assert gateway.call(client,{"client":client,"request_id":client})["isolation"]=="PER_CLIENT_FUNCTION"
 assert all(len(calls[name])==1 and calls[name][0]["client"]==name for name in calls)
 assert all(row["state"]=="INERT" and row["activation"]=="OUTPOST_ONLY" and row["admission_state"]=="UNADMITTED" and row["blueprint"]=="REQUIRED_UNLOADED" for row in core_attachments.contracts())
 with pytest.raises(cognitive_gateway.GatewayDenied):gateway.call("HAOS",{"client":"ANDROID"})

def test_runnable_companion_surface_correlates_and_contains_client_failure():
 now=datetime(2026,9,10,tzinfo=timezone.utc)
 def packet(client,request):return json.dumps({"schema":"SereinStage1ConversationRuntimeRequest/v1","request_id":request,"conversation_id":"stage1-stable","machine_identity":client+"_TEST","requested_operation":"conversation_only","utterance":"hello","observed_at":now.isoformat()}).encode()
 failed=json.loads(conversation_runtime.handle_payload(packet("HAOS","failed"),now=now,inference=lambda _:(_ for _ in ()).throw(conversation_runtime.CompanionUnavailable("isolated"))))
 passed=json.loads(conversation_runtime.handle_payload(packet("ANDROID","passed"),now=now,inference=lambda _:"local answer"))
 assert failed["status"]=="UNAVAILABLE" and failed["request_id"]=="failed"
 assert passed["status"]=="ANSWERED" and passed["request_id"]=="passed" and passed["conversation_id"]=="stage1-stable" and passed["authority_effect"]=="NONE"
 root=Path(__file__).parents[1]/"payload";service=(root/"systemd/serein-conversation-runtime.service").read_text();socket_unit=(root/"systemd/serein-conversation-runtime.socket").read_text()
 assert "User=serein-stage1" in service and "ExecStart=/usr/libexec/serein/serein-conversation-runtime" in service and "RestrictAddressFamilies=AF_UNIX" in service
 assert "ListenStream=/run/serein/kernel/conversation.sock" in socket_unit and "SocketGroup=serein-stage1" in socket_unit

def test_gateway_clients_have_distinct_process_and_socket_boundaries():
 payload=Path(__file__).parents[1]/"payload";template=(payload/"systemd/serein-kernel-client-gateway@.service").read_text()
 assert "ExecStart=/usr/libexec/serein/serein-kernel-client-gateway %i" in template and "User=serein-stage1" in template
 seen=set()
 for client in ("haos","android","esp32","internal"):
  unit=(payload/f"systemd/serein-kernel-client-gateway-{client}.socket").read_text();endpoint=f"/run/serein/kernel/gateway-{client}.sock"
  assert f"Service=serein-kernel-client-gateway@{client}.service" in unit and endpoint in unit and endpoint not in seen;seen.add(endpoint)
 assert len(seen)==4

def test_outpost_owned_stage1_join_requires_every_kernel_surface():
 correlation={"request_id":"r1","conversation_id":"stage1-stable"};gateways={client:{"client":client,"process_isolation":"DEDICATED",**correlation} for client in stage1_witness.CLIENTS}
 packet={"schema":"SEREIN/OutpostKernelStage1Witness/v1","boot_id":BOOT,"branch_order":["AUTHORITY","OPERATIONS","INTERFACE"],"gpu":{"status":"READY"},"companion":{"status":"ANSWERED",**correlation},"gateways":gateways,"attachments":core_attachments.contracts(),"observer":"OUTPOST","authority_effect":"NONE"}
 assert stage1_witness.verify(packet)["status"]=="STAGE1_READY"
 broken=json.loads(json.dumps(packet));broken["gateways"].pop("ESP32")
 with pytest.raises(stage1_witness.Stage1Denied,match="GATEWAY"):stage1_witness.verify(broken)

def test_offline_model_transaction_is_exactly_bound_and_contains_no_payload_blob():
 root=Path(__file__).parents[1];manifest=json.loads((root/"release-manifest.json").read_text());layout=json.loads((root/"install-layout.json").read_text());rows=manifest["installer_files"]
 assert [row[0] for row in rows]==["install/kernel_first_install.py","install/offline_ollama_transaction.py"]
 for relative,size,digest,mode in rows:
  data=(root/relative).read_bytes();assert (size,digest,mode)==(len(data),hashlib.sha256(data).hexdigest(),"0755")
 source=(root/rows[1][0]).read_bytes();assert len(source)==rows[1][1] and sha(source)==rows[1][2]
 contract=layout["offline_model_transaction"];assert contract["executor"]=="OUTPOST_ONLY" and contract["network"]=="PROHIBIT_FETCH_AND_PULL" and contract["blobs_in_public_archive"] is False
 assert contract["runtime_archive_sha256"]=="9088b9e666c0db7e4eafa8ac110a4f114af15595e4bcda2a3b0dba2afb376604"
 assert contract["model_digest"]=="sha256:0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0"
 assert b"ollama pull" in source and b"never invokes" in source and not any(p.stat().st_size>50_000_000 for p in root.rglob("*") if p.is_file())

def actual_payload_fixture(tmp_path):
 root=tmp_path/"root";source=Path(__file__).parents[1];(root/"proc/sys/kernel/random").mkdir(parents=True);(root/"proc/sys/kernel/random/boot_id").write_text(BOOT);(root/"var/lib/serein/rollback").mkdir(parents=True)
 manifest=json.loads((source/"release-manifest.json").read_text());layout=json.loads((source/"install-layout.json").read_text());rows=[]
 for relative,size,digest,mode in manifest["payload"]:
  prefix=next(prefix for prefix in layout["payload_roots"] if relative==prefix or relative.startswith(prefix+"/"));suffix=relative[len(prefix):].lstrip("/");destination=layout["payload_roots"][prefix].rstrip("/")+"/"+suffix
  name=Path(relative).name
  branch="INTERFACE" if "interface" in name else ("OPERATIONS" if "operations" in name else "AUTHORITY")
  rows.append({"branch":branch,"source":relative,"target":destination,"bytes":size,"sha256":digest,"mode":mode})
 rows.sort(key=lambda row:(["AUTHORITY","OPERATIONS","INTERFACE"].index(row["branch"]),row["target"]))
 private=Ed25519PrivateKey.generate();public=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo);anchor=root/"usr/share/serein/outpost/cognition-verification.pem";anchor.parent.mkdir(parents=True);anchor.write_bytes(public)
 plan={"schema":"SereinPublicKernelFirstInstallPlan/v1","target_vm_id":"VM4010","source_parent":"9"*40,"source_commit":"a"*40,"source_tree":"b"*40,"release_digest":manifest["self_digest"],"current_boot_id":BOOT,"outpost_identity":IDENTITIES["serein-outpost"],"replay_identity":IDENTITIES["serein-stage1"],"payload":rows,"rollback_selector":"/var/lib/serein/rollback/kernel-first-install-20260910T130000Z-fedcba654321","authority_sha256":sha(public),"archive_sha256":"c"*64,"source_receipt_sha256":"d"*64,"source_inventory_digest":"sha256:"+"e"*64};plan["signature"]=base64.urlsafe_b64encode(private.sign((json.dumps(plan,sort_keys=True,separators=(",",":"))+"\n").encode())).decode().rstrip("=")
 return root,source,plan,rows

def test_actual_public_payload_installs_verifies_runtime_and_rolls_back(tmp_path):
 root,source,plan,rows=actual_payload_fixture(tmp_path);result=install(root,source,plan,random_bytes=lambda n:b"q"*n);assert result["status"]=="INSTALLED_INACTIVE"
 for row in rows:
  path=root/row["target"].lstrip("/");assert sha(path.read_bytes())==row["sha256"] and path.stat().st_mode&0o777==int(row["mode"],8)
 descriptor=json.loads((root/"var/lib/serein/kernel/authority/replay-descriptor.json").read_text());runtime=source/"payload/runtime/replay_store.py";spec=importlib.util.spec_from_file_location("portable_replay_contract",runtime);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);body=descriptor["body"]
 assert module.verify_descriptor(descriptor,key=b"q"*32,expected_store_id=body["store_id"],expected_backend_identity="SEREIN_KERNEL_REPLAY",expected_issuer="KERNEL_AUTHORITY",expected_observer="OUTPOST",expected_key_fingerprint=hashlib.sha256(b"q"*32).hexdigest(),expected_key_receipt=body["trusted_key_receipt"],expected_target={"vm_id":"VM4010","boot_id":BOOT},expected_generation={"parent":"9"*40,"commit":"a"*40,"tree":"b"*40})==body
 assert (root/"etc/serein/kernel/replay-peer.env").read_text()=="SEREIN_OUTPOST_UID=991\nSEREIN_OUTPOST_GID=991\nSEREIN_GATEWAY_UID=992\nSEREIN_GATEWAY_GID=992\n"
 replay_unit=(root/"etc/systemd/system/serein-kernel-replay-store.service").read_text();assert "/usr/lib/serein/kernel/persistent_replay_store.py" in replay_unit and "/var/lib/serein/kernel" in replay_unit
 assert not any((root/"etc/systemd/system").glob("*.wants"))
 receipt=root/plan["rollback_selector"].lstrip("/")/"receipt.json";assert rollback(root,receipt)["status"]=="ROLLBACK_COMPLETE"
 assert all(not (root/row["target"].lstrip("/")).exists() for row in rows) and not (root/"var/lib/serein/kernel/authority/replay.key").exists()

@pytest.mark.parametrize("failure_boundary",range(1,len(json.loads((Path(__file__).parents[1]/"release-manifest.json").read_text())["payload"])+5))
def test_actual_payload_every_install_boundary_compensates(tmp_path,failure_boundary):
 root,source,plan,rows=actual_payload_fixture(tmp_path);counter={"value":0}
 def boundary():
  counter["value"]+=1
  if counter["value"]==failure_boundary:raise Denied("INJECTED")
 with pytest.raises(Denied,match="INJECTED"):install(root,source,plan,boundary,lambda n:b"z"*n)
 assert all(not (root/row["target"].lstrip("/")).exists() for row in rows)
 assert not (root/"var/lib/serein/kernel/authority/replay.key").exists()
def test_ancestor_symlink_and_receipt_tamper_fail_closed(tmp_path):
 root,source,plan=fixture(tmp_path);outside=tmp_path/"outside";outside.mkdir();(root/"usr/lib").symlink_to(outside,target_is_directory=True)
 with pytest.raises(Denied,match="ANCESTOR_CUSTODY"):install(root,source,plan)
 assert not any(outside.iterdir())
 root,source,plan=fixture(tmp_path/"receipt");install(root,source,plan,random_bytes=lambda n:b"r"*n);receipt=root/plan["rollback_selector"].lstrip("/")/"receipt.json";value=json.loads(receipt.read_text());value["replacements"][0]["target"]="/etc/passwd";receipt.write_text(json.dumps(value))
 with pytest.raises(Denied,match="RECEIPT_(DIGEST|TARGET)"):rollback(root,receipt)
 assert (root/"var/lib/serein/kernel/authority/replay.key").exists()

def test_gpu_collector_is_live_read_only_and_current_boot_bound(tmp_path):
 root=tmp_path;device=root/"sys/bus/pci/devices/0000:01:00.0";device.mkdir(parents=True);(device/"vendor").write_text("0x10de\n");(device/"class").write_text("0x030000\n")
 (root/"proc/sys/kernel/random").mkdir(parents=True);(root/"proc/sys/kernel/random/boot_id").write_text(BOOT);(root/"proc/modules").write_text("nvidia 1 0 - Live 0x0\n")
 class Result:returncode=0;stdout="00000000:01:00.0, GPU-1, NVIDIA, 580.1\n"
 result=gpu_control.collect(root,lambda *args,**kwargs:Result());assert result["boot_id"]==BOOT and result["device_count"]==1 and result["inventory"]["nvidia_smi"]

def test_gateway_peer_credential_fails_closed(monkeypatch):
 class Peer:
  def getsockopt(self,*_):return __import__("struct").pack("3i",1,991,991)
 monkeypatch.setenv("SEREIN_OUTPOST_UID","991");monkeypatch.setenv("SEREIN_OUTPOST_GID","991");assert gateway_runtime._peer_allowed(Peer(),"ANDROID") is True
 monkeypatch.setenv("SEREIN_OUTPOST_UID","992");assert gateway_runtime._peer_allowed(Peer(),"ANDROID") is False
 monkeypatch.setenv("SEREIN_GATEWAY_UID","991");monkeypatch.setenv("SEREIN_GATEWAY_GID","991");assert gateway_runtime._peer_allowed(Peer(),"HAOS") is True
 monkeypatch.setenv("SEREIN_GATEWAY_GID","992");assert gateway_runtime._peer_allowed(Peer(),"HAOS") is False

def test_haos_socket_custody_matches_dedicated_stage1_edge():
 unit=(Path(__file__).parents[1]/"payload/systemd/serein-kernel-client-gateway-haos.socket").read_text()
 assert "SocketMode=0660" in unit and "SocketGroup=serein-stage1" in unit and "SocketGroup=serein-outpost" not in unit

def test_provider_binds_exact_offline_model_and_bounded_keepalive():
 class Response:
  def __enter__(self):return self
  def __exit__(self,*_):return False
  def read(self,_):return json.dumps({"model":"qwen3:4b-instruct","done":True,"response":"ready"}).encode()
 seen=[]
 def opener(request,timeout):seen.append((request.full_url,json.loads(request.data),timeout));return Response()
 assert companion_provider.infer("status",opener=opener)=="ready"
 assert seen[0][0]=="http://127.0.0.1:11434/api/generate" and seen[0][1]["model"]=="qwen3:4b-instruct"

def test_gateway_exact_envelope_replay_precedes_compute_and_consumes_after_answer():
 now=datetime(2026,9,10,tzinfo=timezone.utc);calls=[];state="ABSENT"
 def replay(request_id,operation,**kwargs):
  nonlocal state
  calls.append(operation)
  if operation=="WITNESS":return {"ok":True,"state":state,"chain_id":"a"*64,"receipt_sha256":None}
  if operation=="RESERVE":state="RESERVED";return {"ok":True,"state":state,"chain_id":"a"*64,"receipt_sha256":"b"*64}
  state="CONSUMED";return {"ok":True,"state":state,"chain_id":"a"*64,"receipt_sha256":"c"*64}
 def runtime(payload):
  value=json.loads(payload);return json.dumps({"schema":"SereinStage1ConversationRuntimeResponse/v1","request_id":value["request_id"],"conversation_id":value["conversation_id"],"status":"ANSWERED","state":"READY","response":"ready","scope":"stage1-bounded-companion","completed_at":now.isoformat(),"authority_effect":"NONE","effects":[]}).encode()
 packet={"schema":"SereinStage1Request/v1","request_id":"r-provider","authority":"local-operator","action":"companion","conversation":{"conversation_id":"c-provider","machine_identity":"HAOS_VM5011","requested_operation":"conversation_only","utterance":"status","observed_at":now.isoformat()}}
 result=json.loads(gateway_runtime.handle_client_payload(json.dumps(packet).encode(),"HAOS",runtime_call=runtime,replay_call=replay,audit_call=lambda _:None,now=now))
 assert result["status"]=="ANSWERED" and calls==["WITNESS","RESERVE","CONSUME"] and state=="CONSUMED"

def test_gateway_terminal_audit_records_answer_and_fails_closed_when_unavailable():
 now=datetime(2026,9,10,tzinfo=timezone.utc);packet={"schema":"SereinStage1Request/v1","request_id":"r-audit","authority":"local-operator","action":"companion","conversation":{"conversation_id":"c-audit","machine_identity":"HAOS","requested_operation":"conversation_only","utterance":"hello","observed_at":now.isoformat()}}
 state={"value":"ABSENT"}
 def replay(_,operation,**kwargs):
  if operation=="WITNESS":return {"ok":True,"state":state["value"],"chain_id":"a"*64,"receipt_sha256":None}
  state["value"]="RESERVED" if operation=="RESERVE" else "CONSUMED";return {"ok":True,"state":state["value"],"chain_id":"a"*64,"receipt_sha256":"b"*64}
 runtime=lambda _:json.dumps({"status":"ANSWERED","completed_at":now.isoformat(),"state":"READY","response":"answer","scope":"stage1-bounded-companion","conversation_id":"c-audit","authority_effect":"NONE","effects":[],"compute_receipt":{"status":"ANSWERED"}}).encode()
 events=[];answered=json.loads(gateway_runtime.handle_client_payload(json.dumps(packet).encode(),"HAOS",runtime_call=runtime,replay_call=replay,audit_call=events.append,now=now));assert answered["status"]=="ANSWERED" and events==[answered]
 state["value"]="ABSENT";unavailable=json.loads(gateway_runtime.handle_client_payload(json.dumps(packet).encode(),"HAOS",runtime_call=runtime,replay_call=replay,audit_call=lambda _:(_ for _ in ()).throw(OSError("audit-down")),now=now));assert unavailable["status"]=="UNAVAILABLE" and unavailable["reason"]=="gateway_audit_unavailable"

@pytest.mark.parametrize("status",["ANSWERED","DENIED","UNAVAILABLE"])
def test_audit_admits_only_exact_terminal_gateway_shapes(status):
 event={"schema":"SereinStage1Response/v1","request_id":"r-audit","status":status,"reason":"terminal","timestamp":"2026-09-11T00:00:00+00:00"}
 if status=="ANSWERED":event["result"]={"conversation_id":"c-audit"}
 assert audit.decode_event((json.dumps(event)+"\n").encode())==event
 with pytest.raises(ValueError,match="shape"):audit.decode_event((json.dumps({**event,"extra":"denied"})+"\n").encode())

def test_production_independent_audit_verifier_binds_signer_route_boot_source_and_expiry(tmp_path):
 private=Ed25519PrivateKey.generate();public=tmp_path/"auditor.pem";public.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo));public.chmod(0o600)
 generation={"commit":"e"*40,"tree":"9"*40};body={"schema":"SEREIN/IndependentRouteAudit/v1","route":"kernel.companion.generate.v1","status":"PASS","verdict":"PASS — SECURITY ROUTE INDEPENDENTLY VERIFIED","auditor":"OPERATOR_SELECTED_CODEX","selected_by":"OPERATOR","boot_id":BOOT,"source_generation":generation,"issued_at":"1970-01-01T00:01:30Z","expires_at":"1970-01-01T00:02:00Z","nonce":"audit-1","evidence_sha256":"a"*64};receipt={**body,"signature":base64.urlsafe_b64encode(private.sign(independent_audit.canonical(body))).decode().rstrip("=")};verify=independent_audit.verifier(public)
 now=datetime.fromtimestamp(100,timezone.utc);assert verify(receipt,route=body["route"],boot_id=BOOT,source_generation=generation,now=now) is True
 for changed in ({**receipt,"route":"wrong.v1"},{**receipt,"boot_id":"wrong"},{**receipt,"source_generation":{"commit":"d"*40,"tree":"9"*40}},{**receipt,"signature":"tampered"}):
  with pytest.raises(independent_audit.AuditDenied):verify(changed,route=body["route"],boot_id=BOOT,source_generation=generation,now=now)
 with pytest.raises(independent_audit.AuditDenied,match="FRESHNESS"):verify(receipt,route=body["route"],boot_id=BOOT,source_generation=generation,now=datetime.fromtimestamp(121,timezone.utc))
 service=(Path(__file__).parents[1]/"payload/systemd/serein-kernel-router.service").read_text();assert "LoadCredential=independent-route-audit.pem:" in service

def test_stage1_witness_is_signed_durable_and_current_boot_only(tmp_path):
 key=tmp_path/"key";key.write_bytes(b"k"*32);boot=tmp_path/"boot";boot.write_text(BOOT);state=tmp_path/"state.json";correlation={"request_id":"r1","conversation_id":"stage1-stable"}
 packet={"schema":"SEREIN/OutpostKernelStage1Witness/v1","boot_id":BOOT,"branch_order":["AUTHORITY","OPERATIONS","INTERFACE"],"gpu":{"status":"READY"},"companion":{"status":"ANSWERED",**correlation},"gateways":{client:{"client":client,"process_isolation":"DEDICATED",**correlation} for client in stage1_witness.CLIENTS},"attachments":core_attachments.contracts(),"observer":"OUTPOST","authority_effect":"NONE"}
 assert stage1_witness.persist(packet,key,state,boot)["status"]=="WITNESS_DURABLE";assert stage1_witness.read_current(key,state,boot)["body"]["verification"]["status"]=="STAGE1_READY"
 boot.write_text("different")
 with pytest.raises(stage1_witness.Stage1Denied,match="CURRENT_BOOT"):stage1_witness.read_current(key,state,boot)

def test_domain1_runner_orders_real_gates_and_invokes_offline_transaction():
 seen=[];correlation={"request_id":"r1","conversation_id":"stage1-stable"}
 def branch(name):seen.append(name);return {"branch":name,"status":"READY"}
 def offline():seen.append("OFFLINE");return {"status":"INSTALLED","network_effect":"NONE"}
 def companion():seen.append("COMPANION");return {"status":"ANSWERED",**correlation}
 def gateways(_):seen.append("GATEWAY");return {client:{"client":client,"process_isolation":"DEDICATED",**correlation} for client in stage1_witness.CLIENTS}
 def write(_):seen.append("WITNESS");return {"status":"WITNESS_DURABLE"}
 gpu=lambda:{"schema":"SEREIN/KernelGPUControlWitness/v1","boot_id":BOOT,"device_count":1,"driver_loaded":True,"gpu_inventory_sha256":"a"*64,"authority_effect":"NONE"}
 def commission():seen.append("ROUTER");return {"status":"COMMISSIONED","audit":AUDIT}
 result=domain1_runner.run(branch_probe=branch,router_commission=commission,gpu_probe=gpu,offline_install=offline,companion_probe=companion,gateway_probe=gateways,witness_write=write)
 assert result["status"]=="STAGE1_READY" and seen==["AUTHORITY","OPERATIONS","INTERFACE","ROUTER","OFFLINE","COMPANION","GATEWAY","WITNESS"]

def test_compute_road_allow_replay_expiry_route_and_capacity(tmp_path):
 key=tmp_path/"key";key.write_bytes(b"a"*32);journal=tmp_path/"compute.sqlite3";request={"schema":"SEREIN/KernelComputeRequest/v1","request_id":"r1","conversation_id":"stage1-stable","client":"HAOS","route":"companion.generate","prompt":"hello","ump":{"schema":"SEREIN/UMP/v1","state":"KNOWN","claims":[],"authority_effect":"NONE"}}
 health=lambda:{"bpm":60,"queues":"HEALTHY","leases":"HEALTHY","capacity_available":1};gpu=lambda:{"status":"READY","owner":"KERNEL","boot_id":BOOT}
 lease=compute_dispatch.issue_lease(request,key_path=key,now=100);answer,receipt=compute_dispatch.consume(request,lease,operations_health=health,gpu_probe=gpu,runtime=lambda _:"answer",key_path=key,journal_path=journal,now=101)
 assert answer=="answer" and receipt["request_id"]=="r1" and receipt["operations_bpm"]>=60
 with pytest.raises(compute_dispatch.ComputeDenied,match="REPLAY"):compute_dispatch.consume(request,lease,operations_health=health,gpu_probe=gpu,runtime=lambda _:"answer",key_path=key,journal_path=journal,now=101)
 with pytest.raises(compute_dispatch.ComputeDenied,match="EXPIRED"):compute_dispatch.consume({**request,"request_id":"r2"},compute_dispatch.issue_lease({**request,"request_id":"r2"},key_path=key,now=1),operations_health=health,gpu_probe=gpu,runtime=lambda _:"answer",key_path=key,journal_path=journal,now=100)
 with pytest.raises(compute_dispatch.ComputeDenied,match="ROUTE"):compute_dispatch.issue_lease({**request,"route":"ollama.direct"},key_path=key,now=100)
 with pytest.raises(compute_dispatch.ComputeDenied,match="ROUTE"):compute_dispatch.issue_lease({**request,"client":"UNKNOWN"},key_path=key,now=100)
 with pytest.raises(compute_dispatch.ComputeDenied,match="CAPACITY"):compute_dispatch.consume({**request,"request_id":"r3"},compute_dispatch.issue_lease({**request,"request_id":"r3"},key_path=key,now=100),operations_health=lambda:{"bpm":59,"queues":"HEALTHY","leases":"HEALTHY","capacity_available":1},gpu_probe=gpu,runtime=lambda _:"answer",key_path=key,journal_path=journal,now=101)

def test_compute_client_crash_is_contained_and_retryable(tmp_path):
 key=tmp_path/"key";key.write_bytes(b"a"*32);journal=tmp_path/"compute.sqlite3";request={"schema":"SEREIN/KernelComputeRequest/v1","request_id":"retry","conversation_id":"stage1-stable","client":"ANDROID","route":"companion.generate","prompt":"hello","ump":{"schema":"SEREIN/UMP/v1","state":"KNOWN","claims":[],"authority_effect":"NONE"}};lease=compute_dispatch.issue_lease(request,key_path=key,now=100)
 kwargs={"operations_health":lambda:{"bpm":60,"queues":"HEALTHY","leases":"HEALTHY","capacity_available":1},"gpu_probe":lambda:{"status":"READY","owner":"KERNEL","boot_id":BOOT},"key_path":key,"journal_path":journal,"now":101}
 with pytest.raises(RuntimeError,match="crash"):compute_dispatch.consume(request,lease,runtime=lambda _:(_ for _ in ()).throw(RuntimeError("crash")),**kwargs)
 answer,_=compute_dispatch.consume(request,lease,runtime=lambda _:"recovered",**kwargs);assert answer=="recovered"

def test_compute_dispatch_requires_and_forwards_exact_authority_contract():
 request={"schema":"SEREIN/KernelComputeRequest/v1","request_id":"r-auth","conversation_id":"c-auth","client":"HAOS","route":"companion.generate","prompt":"hello","ump":{"schema":"SEREIN/UMP/v1","state":"KNOWN","claims":[],"authority_effect":"NONE"}}
 with pytest.raises(compute_dispatch.ComputeDenied,match="ROUTE_AUTHORITY"):compute_dispatch.dispatch(request,router_dispatch=lambda _:None)
 contract=authority("kernel.route.dispatch.v1","HAOS","dispatch-compute")
 seen=[]
 with pytest.raises(FileNotFoundError):compute_dispatch.dispatch(request,authority_contract=contract,router_dispatch=lambda packet:seen.append(packet) or {"status":"ROUTED"},key_path="/missing/replay.key")
 assert seen[0]["authority_contract"]==contract

def test_router_conformance_audit_ump_pressure_withdraw_and_reconstruct(tmp_path):
 key=tmp_path/"key";key.write_bytes(b"r"*32);router=kernel_router.Router(tmp_path/"router.sqlite3",key,BOOT,clock=lambda:100,audit_verifier=lambda _,**kwargs:True)
 known={"schema":"SEREIN/UMP/v1","state":"KNOWN","claims":[],"authority_effect":"NONE"};registration={"schema":"kernel.route.register.v1/request","route":"kernel.companion.generate.v1","owner":"KERNEL","plane":"COGNITIVE","version":"v1","posture":"ELIGIBLE","qos":{"priority":1,"capacity":2,"backpressure":"REJECT"},"failover":[],"ump":known,"audit":AUDIT,"authority_contract":authority("kernel.route.register.v1","OUTPOST","register-1")}
 assert router.register(registration)["body"]["event"]=="REGISTER"
 request={"schema":"kernel.route.dispatch.v1/request","request_id":"r1","conversation_id":"stage1-stable","route":"kernel.companion.generate.v1","plane":"COGNITIVE","caller":"HAOS","ump":known,"authority_contract":authority("kernel.route.dispatch.v1","HAOS","dispatch-1")};decision=router.dispatch(request,pressure=[.91]*60)
 assert decision["body"]["details"]["expansion_evaluation"]=={"required":True,"authority":"INHERITED_EXACT","automatic_expansion":False}
 with pytest.raises(kernel_router.RouterDenied,match="CALLER"):router.dispatch({**request,"request_id":"r2","caller":"OUTPOST","authority_contract":authority("kernel.route.dispatch.v1","OUTPOST","dispatch-2")})
 assert router.reconstruct()["posture"]=="ELIGIBLE";router.withdraw(registration["route"],"health_degraded",authority("kernel.route.withdraw.v1","OUTPOST","withdraw-1"));assert router.reconstruct()["posture"]=="DEGRADED"
 with pytest.raises(kernel_router.RouterDenied,match="POSTURE"):router.dispatch({**request,"request_id":"r3","authority_contract":authority("kernel.route.dispatch.v1","HAOS","dispatch-3")})

def test_production_independent_audit_verifier_binds_operator_route_boot_source_and_expiry(tmp_path):
 private=Ed25519PrivateKey.generate();public=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo);key=tmp_path/"auditor.pem";key.write_bytes(public);key.chmod(0o600)
 generation={"commit":"e"*40,"tree":"9"*40};body={"schema":"SEREIN/IndependentRouteAudit/v1","route":"kernel.companion.generate.v1","status":"PASS","verdict":"PASS — SECURITY ROUTE INDEPENDENTLY VERIFIED","auditor":"OPERATOR_SELECTED_CODEX_01a05b9e","selected_by":"OPERATOR","boot_id":BOOT,"source_generation":generation,"issued_at":"1970-01-01T00:01:30Z","expires_at":"1970-01-01T00:01:50Z","nonce":"audit-1","evidence_sha256":"a"*64};receipt={**body,"signature":base64.urlsafe_b64encode(private.sign(independent_audit.canonical(body))).decode().rstrip("=")};verify=independent_audit.verifier(key)
 assert verify(receipt,route=receipt["route"],boot_id=BOOT,source_generation=generation,now=datetime.fromtimestamp(100,timezone.utc)) is True
 for field,value in (("route","wrong.v1"),("boot_id","wrong"),("source_generation",{"commit":"f"*40,"tree":"9"*40})):
  with pytest.raises(independent_audit.AuditDenied):verify(receipt,route=value if field=="route" else receipt["route"],boot_id=value if field=="boot_id" else BOOT,source_generation=value if field=="source_generation" else generation,now=datetime.fromtimestamp(100,timezone.utc))
 with pytest.raises(independent_audit.AuditDenied,match="SIGNATURE"):verify({**receipt,"evidence_sha256":"b"*64},route=receipt["route"],boot_id=BOOT,source_generation=generation,now=datetime.fromtimestamp(100,timezone.utc))
 with pytest.raises(independent_audit.AuditDenied,match="FRESHNESS"):verify(receipt,route=receipt["route"],boot_id=BOOT,source_generation=generation,now=datetime.fromtimestamp(121,timezone.utc))

def test_router_default_fail_closed_unknown_conflict_no_audit_and_backpressure(tmp_path):
 key=tmp_path/"key";key.write_bytes(b"r"*32);router=kernel_router.Router(tmp_path/"router.sqlite3",key,BOOT,clock=lambda:100,audit_verifier=lambda _,**kwargs:True);known={"schema":"SEREIN/UMP/v1","state":"KNOWN","claims":[],"authority_effect":"NONE"};base={"schema":"kernel.route.register.v1/request","route":"kernel.companion.generate.v1","owner":"KERNEL","plane":"COGNITIVE","version":"v1","posture":"ELIGIBLE","qos":{"priority":1,"capacity":1,"backpressure":"REJECT"},"failover":[],"ump":known,"audit":AUDIT,"authority_contract":authority("kernel.route.register.v1","OUTPOST","register-2")}
 with pytest.raises(kernel_router.RouterDenied,match="AUDIT"):router.register({**base,"audit":{"gate":"PRO-174","status":"UNKNOWN"}})
 router.register(base);request={"schema":"kernel.route.dispatch.v1/request","request_id":"r1","conversation_id":"c1","route":base["route"],"plane":"COGNITIVE","caller":"HAOS","ump":known,"authority_contract":authority("kernel.route.dispatch.v1","HAOS","dispatch-4")}
 with pytest.raises(kernel_router.RouterDenied,match="BACKPRESSURE"):router.dispatch(request,active=1)
 for state in ("UNKNOWN","CONFLICT"):
   with pytest.raises(kernel_router.RouterDenied,match=state):router.dispatch({**request,"ump":{**known,"state":state},"authority_contract":authority("kernel.route.dispatch.v1","HAOS","dispatch-"+state.lower())})

def test_withdraw_and_failover_require_authority_and_ledger_decision(tmp_path):
 key=tmp_path/"key";key.write_bytes(b"r"*32);router=kernel_router.Router(tmp_path/"router.sqlite3",key,BOOT,clock=lambda:100,audit_verifier=lambda _,**kwargs:True);known={"schema":"SEREIN/UMP/v1","state":"KNOWN","claims":[],"authority_effect":"NONE"}
 def registration(route,failover,nonce):
  contract=authority("kernel.route.register.v1","OUTPOST",nonce);contract["object"]=route;contract["scope"]={"route":route,"plane":"COGNITIVE","owner":"KERNEL"}
  return {"schema":"kernel.route.register.v1/request","route":route,"owner":"KERNEL","plane":"COGNITIVE","version":"v1","posture":"ELIGIBLE","qos":{"priority":1,"capacity":1,"backpressure":"REJECT"},"failover":failover,"ump":known,"audit":{**AUDIT,"route":route,"nonce":"audit-"+nonce},"authority_contract":contract}
 primary="kernel.companion.generate.v1";alternate="kernel.companion.reserve.v1";router.register(registration(alternate,[],"register-alt"));router.register(registration(primary,[alternate],"register-primary"))
 with pytest.raises((TypeError,kernel_router.RouterDenied)):router.withdraw(primary,"denied",None)
 selected=router.failover(primary,authority("kernel.failover.select.v1","HAOS","failover-1"),"HAOS");assert selected["route"]["route"]==alternate and selected["receipt"]["body"]["event"]=="FAILOVER_SELECT"
 with pytest.raises(kernel_router.RouterDenied,match="REPLAY"):router.failover(primary,authority("kernel.failover.select.v1","HAOS","failover-1"),"HAOS")

def test_haos_edge_exact_envelope_token_correlation_and_exclusions(tmp_path):
 token=b"t"*32;now=datetime(2026,9,10,tzinfo=timezone.utc);request={"conversation_id":"stage1-stable","request_id":"11111111-2222-4333-8444-555555555555","machine_identity":"HAOS","requested_operation":"conversation_only","utterance":"hello","observed_at":"2026-09-10T00:00:00Z"}
 accepted=haos_https_adapter.validate(json.dumps(request).encode(),"Bearer "+token.decode(),token,now=now);assert accepted==request
 for header in (None,"",token.decode(),"Bearer wrong","Bearer a b"):
  with pytest.raises(ValueError,match="token"):haos_https_adapter.validate(json.dumps(request).encode(),header,token,now=now)
 with pytest.raises(ValueError,match="envelope"):haos_https_adapter.validate(json.dumps({**request,"extra":1}).encode(),"Bearer "+token.decode(),token,now=now)
 source=(Path(__file__).parents[1]/"payload/serein_stage1/haos_https_adapter.py").read_text()
 assert haos_https_adapter.PATH=="/v1/voice/conversation" and "192.168." not in source and "/v1/stage2" not in source and "android" not in source.lower() and "ollama" not in source.lower()

def test_haos_edge_credential_custody_and_forwarding(tmp_path):
 directory=tmp_path/"credentials";directory.mkdir();token=directory/"haos-companion-token";token.write_bytes(b"x"*32);assert haos_https_adapter.credential(directory,token.name)==b"x"*32
 token.write_bytes(b"x\n"*16)
 with pytest.raises(RuntimeError,match="invalid"):haos_https_adapter.credential(directory,token.name)
 request={"conversation_id":"c","request_id":"11111111-2222-4333-8444-555555555555","machine_identity":"HAOS","requested_operation":"conversation_only","utterance":"hello","observed_at":"2026-09-10T00:00:00Z"}
 class Fake:
  def __enter__(self):return self
  def __exit__(self,*_):pass
  def settimeout(self,_):pass
  def connect(self,path):assert path=="/run/serein/kernel/gateway-haos.sock"
  def sendall(self,value):self.sent=value
  def recv(self,_):return haos_https_adapter.canonical({"schema":"SereinStage1Response/v1","request_id":request["request_id"],"status":"ANSWERED","result":{"state":"READY","conversation_id":"c","scope":"stage1-bounded-companion","authority_effect":"NONE","effects":[],"response":"answer"}})
 original=haos_https_adapter.socket.socket;haos_https_adapter.socket.socket=lambda *_:Fake()
 try:assert haos_https_adapter.forward(request)["response"]=="answer"
 finally:haos_https_adapter.socket.socket=original

def test_installed_commission_path_empty_router_to_compute_witness_and_no_audit_denial(tmp_path):
 key=tmp_path/"key";key.write_bytes(b"c"*32);router=kernel_router.Router(tmp_path/"router.sqlite3",key,BOOT,clock=lambda:100,audit_verifier=lambda _,**kwargs:True);correlation={"request_id":"r1","conversation_id":"stage1-stable"};plan={"schema":"SEREIN/OutpostKernelCommissionPlan/v1","target":"VM4010","boot_id":BOOT,**correlation,"offline_receipt":"/var/lib/serein/rollback/offline/receipt.json","audit":AUDIT,"authority_contract":authority("kernel.route.register.v1","OUTPOST","register-commission"),"signature":"test-entrypoint-injection"};seen=[]
 result=commission_runner.execute(plan,router=router,branch_probe=lambda name:{"branch":name,"status":"READY"},gpu_probe=lambda:{"schema":"SEREIN/KernelGPUControlWitness/v1","boot_id":BOOT,"device_count":1,"driver_loaded":True,"gpu_inventory_sha256":"a"*64,"authority_effect":"NONE"},offline_probe=lambda:{"status":"INSTALLED","network_effect":"NONE"},companion_probe=lambda:{"status":"ANSWERED",**correlation},gateway_probe=lambda _:{client:{"client":client,"process_isolation":"DEDICATED",**correlation} for client in stage1_witness.CLIENTS},witness_write=lambda value:(seen.append(value) or {"status":"WITNESS_DURABLE"}))
 assert result["status"]=="STAGE1_READY" and seen and router.reconstruct()["routes"][0]["route"]=="kernel.companion.generate.v1"
 assert (Path(__file__).parents[1]/"payload/bin/serein-kernel-domain1-commission").is_file()
 denied={**plan,"audit":{"gate":"PRO-174","status":"PASS"}}
 with pytest.raises(kernel_router.RouterDenied,match="AUDIT"):commission_runner.execute(denied,router=kernel_router.Router(tmp_path/"denied.sqlite3",key,BOOT),branch_probe=lambda _:None,gpu_probe=lambda:None,offline_probe=lambda:None,companion_probe=lambda:None,gateway_probe=lambda _:None,witness_write=lambda _:None)

def test_commission_post_registration_failure_withdraws_exact_route(tmp_path):
 key=tmp_path/"key";key.write_bytes(b"d"*32);router=kernel_router.Router(tmp_path/"router.sqlite3",key,BOOT,clock=lambda:100,audit_verifier=lambda _,**kwargs:True);plan={"schema":"SEREIN/OutpostKernelCommissionPlan/v1","target":"VM4010","boot_id":BOOT,"request_id":"r-fail","conversation_id":"c-fail","offline_receipt":"/receipt","audit":AUDIT,"authority_contract":authority("kernel.route.register.v1","OUTPOST","register-fail"),"signature":"injected"}
 with pytest.raises(RuntimeError,match="gateway-failed"):
  commission_runner.execute(plan,router=router,branch_probe=lambda name:{"branch":name,"status":"READY"},gpu_probe=lambda:{"schema":"SEREIN/KernelGPUControlWitness/v1","boot_id":BOOT,"device_count":1,"driver_loaded":True,"gpu_inventory_sha256":"a"*64,"authority_effect":"NONE"},offline_probe=lambda:{"status":"INSTALLED","network_effect":"NONE"},companion_probe=lambda:{"status":"ANSWERED","request_id":"r-fail","conversation_id":"c-fail"},gateway_probe=lambda _:(_ for _ in ()).throw(RuntimeError("gateway-failed")),witness_write=lambda _:None)
 route=router.reconstruct()["routes"][0]
 assert route["route"]=="kernel.companion.generate.v1" and route["state"]=="WITHDRAWN" and route["posture"]=="INELIGIBLE"

def test_router_socket_contract_accepts_only_exact_outpost_withdraw_packet():
 seen=[]
 class Stub:
  def withdraw(self,*args,**kwargs):seen.append((args,kwargs));return {"event":"WITHDRAW"}
 contract=authority("kernel.route.withdraw.v1","OUTPOST","withdraw-socket")
 packet={"operation":"WITHDRAW","route":"kernel.companion.generate.v1","reason":"commission_post_registration_failure","authority_contract":contract}
 assert kernel_router._handle_packet(Stub(),packet)["receipt"]=={"event":"WITHDRAW"}
 assert seen==[((packet["route"],packet["reason"],contract),{"caller":"OUTPOST"})]
 with pytest.raises(kernel_router.RouterDenied,match="OPERATION_DENIED"):kernel_router._handle_packet(Stub(),{**packet,"extra":"denied"})

def test_commission_probe_uses_canonical_runtime_schema(monkeypatch):
 seen={}
 def handle(payload,**kwargs):
  seen.update(json.loads(payload));return json.dumps({"status":"ANSWERED","request_id":"r","conversation_id":"c","compute_receipt":{"status":"ANSWERED"}}).encode()
 monkeypatch.setattr(conversation_runtime,"handle_payload",handle)
 now=datetime.now(timezone.utc);packet={"schema":"SereinStage1ConversationRuntimeRequest/v1","request_id":"r","conversation_id":"c","machine_identity":"INTERNAL_VM4010","requested_operation":"conversation_only","utterance":"Return a bounded Stage 1 readiness response.","observed_at":now.isoformat()}
 result=json.loads(conversation_runtime.handle_payload(commission_runner.canonical(packet),now=now))
 assert result["status"]=="ANSWERED" and seen["schema"]=="SereinStage1ConversationRuntimeRequest/v1" and seen["requested_operation"]=="conversation_only"
