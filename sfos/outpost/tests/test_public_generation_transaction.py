import base64,copy,hashlib,io,json,os,shutil,stat,subprocess,tarfile,tempfile
from pathlib import Path
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from install.transaction import Adapter,TransactionError,canonical,sha
from install.public_generation_transaction import _receipt_digest,install_public_generation,rollback_public_generation

def archive(tmp_path,commit,tree,hostile=None):
    tmp_path.mkdir(parents=True,exist_ok=True)
    payload={"outpost/__init__.py":b"", "outpost/service.py":b"pass\n"}
    release={"schema":"SereinOutpostSourceRelease/v2","classification":"PUBLIC_HOST_GATE_SAFE_UNCOMMISSIONED","replacement_unit_allowlist":["serein-outpost-host-witness.service","serein-outpost-presentation.service"],"generated_files":[{"target":"/etc/serein-outpost/rollback-root","mode":"0600","uid":0,"gid":0}],"required_immutable_inputs":[{"target":target} for target in sorted(("/etc/serein-outpost/readonly.token","/etc/serein-outpost/admission.token","/etc/serein-outpost/cognition-signing.pem","/usr/share/serein/outpost/cognition-verification.pem","/etc/serein/tls/serein-backend-cert.pem","/etc/serein/tls/serein-backend-key.pem"))],"payload":[{"path":p,"bytes":len(d),"sha256":sha(d)} for p,d in payload.items()]}
    release["self_digest"]="sha256:"+sha(canonical(release)); payload["release-manifest.json"]=(json.dumps(release,indent=2)+"\n").encode(); release["payload"].append({"path":"release-manifest.json","bytes":len(payload["release-manifest.json"]),"sha256":sha(payload["release-manifest.json"])})
    # Release cannot include its own serialized bytes in payload; regenerate with the canonical public denominator excluding itself.
    release["payload"]=[row for row in release["payload"] if row["path"]!="release-manifest.json"]
    release["self_digest"]="sha256:"+sha(canonical({k:v for k,v in release.items() if k!="self_digest"})); payload["release-manifest.json"]=(json.dumps(release,indent=2)+"\n").encode()
    target=tmp_path/"source.tar.gz"
    with tarfile.open(target,"w:gz") as tar:
        for name,data in payload.items():
            info=tarfile.TarInfo("sfos-public-"+commit+"/sfos/outpost/"+name); info.size=len(data); info.mode=0o644; tar.addfile(info,io.BytesIO(data))
        if hostile:
            name="sfos-public-"+commit+"/sfos/outpost/hostile"
            if hostile=="traversal": name="sfos-public-"+commit+"/../escape"
            info=tarfile.TarInfo(name)
            info.type={"symlink":tarfile.SYMTYPE,"hardlink":tarfile.LNKTYPE,"device":tarfile.CHRTYPE,"traversal":tarfile.REGTYPE}.get(hostile,tarfile.SYMTYPE)
            info.linkname="../../escape"; tar.addfile(info,io.BytesIO(b"") if info.isreg() else None)
    return target,release

def fixture(tmp_path,hostile=None,first=False):
    commit="a"*40; tree="b"*40; bundle,release=archive(tmp_path,commit,tree,hostile)
    private=Ed25519PrivateKey.generate(); public=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo); authority=tmp_path/"authority.pem"; authority.write_bytes(public)
    boot="11111111-2222-3333-4444-555555555555"; p=tmp_path/"proc/sys/kernel/random/boot_id"; p.parent.mkdir(parents=True); p.write_text(boot)
    cognition=Ed25519PrivateKey.generate(); cognition_private=cognition.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()); cognition_public=cognition.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    immutable_values={"/etc/serein-outpost/readonly.token":b"r"*48,"/etc/serein-outpost/admission.token":b"a"*48,"/etc/serein-outpost/cognition-signing.pem":cognition_private,"/usr/share/serein/outpost/cognition-verification.pem":cognition_public,"/etc/serein/tls/serein-backend-cert.pem":b"cert\n","/etc/serein/tls/serein-backend-key.pem":b"key\n"}
    modes={"/etc/serein-outpost/readonly.token":"0640","/etc/serein-outpost/admission.token":"0640","/etc/serein-outpost/cognition-signing.pem":"0640","/usr/share/serein/outpost/cognition-verification.pem":"0644","/etc/serein/tls/serein-backend-cert.pem":"0600","/etc/serein/tls/serein-backend-key.pem":"0600"}
    immutable_rows=[]
    for target,data in immutable_values.items():
        path=tmp_path/target.lstrip("/"); path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(data); os.chmod(path,int(modes[target],8)); immutable_rows.append({"target":target,"bytes":len(data),"sha256":sha(data),"mode":modes[target],"uid":0,"gid":0})
    selector={"schema":"SereinOutpostGenerationSelector/v1","generation":"d"*64,"release_digest":"sha256:"+"d"*64,"predecessor_receipt_sha256":"e"*64,"inventory_digest":"f"*64}; selector["selector_digest"]=sha(canonical(selector))
    state=tmp_path/"var/lib/serein-outpost/generation-state"; state.mkdir(parents=True)
    if not first:
        old=tmp_path/"usr/share/serein/outpost-generations"/("d"*64); old.mkdir(parents=True)
        old_release={"self_digest":"sha256:"+"d"*64}; old_release_bytes=(json.dumps(old_release)+"\n").encode(); (old/"release-manifest.json").write_bytes(old_release_bytes); os.chmod(old/"release-manifest.json",0o644)
        old_inventory=[{"kind":"file","path":"release-manifest.json","bytes":len(old_release_bytes),"sha256":sha(old_release_bytes),"mode":"0644","uid":0,"gid":0}]
        (old/"generation-inventory.json").write_text(json.dumps(old_inventory,sort_keys=True,separators=(",",":"))+"\n"); os.chmod(old/"generation-inventory.json",0o644)
        selector["inventory_digest"]=sha(canonical(old_inventory)); selector["selector_digest"]=sha(canonical({k:v for k,v in selector.items() if k!="selector_digest"}))
        for name in ("current.json","lkg.json"): (state/name).write_text(json.dumps(selector,indent=2)+"\n"); os.chmod(state/name,0o600)
    rollback_parent=tmp_path/"var/lib/serein/rollback"; rollback_parent.mkdir(parents=True); os.chmod(rollback_parent,0o700)
    rollback="/var/lib/serein/rollback/outpost-public-generation-20260909T200000Z-abcdef123456"
    plan={"schema":"SereinPublicOutpostGenerationPlan/v1","repository":"Kaotikking/sfos-public","repo_url":"https://github.com/Kaotikking/sfos-public.git","ref":"refs/heads/main","commit":commit,"tree":tree,"archive_url":f"https://codeload.github.com/Kaotikking/sfos-public/tar.gz/{commit}","archive_sha256":sha(bundle.read_bytes()),"release_digest":release["self_digest"],"authority_key_id":"outpost-cognition-v1","authority_sha256":sha(cognition_public),"current_boot_id":boot,"immutable_rows":immutable_rows,"rollback_selector":rollback}
    plan["signature"]=base64.urlsafe_b64encode(cognition.sign(canonical(plan))).decode().rstrip("=")
    authority=tmp_path/"usr/share/serein/outpost/cognition-verification.pem"
    adapter=Adapter(tmp_path); launcher=tmp_path/"launcher"; launcher.write_bytes(b"#!/usr/bin/python3\n"); launcher.chmod(0o755)
    fetch=lambda url:(bundle.read_bytes(),url); ok=lambda *args:{"schema":"SereinOutpostCandidateAcceptance/v1","installed_boot_preflight":"PASS","api":"PASS","vitals":"PASS","boot_id":boot,"release_digest":plan["release_digest"]}
    return adapter,plan,authority,fetch,ok,launcher

def test_exact_public_generation_installs_and_flips(tmp_path):
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path)
    result=install_public_generation(adapter,plan,authority,fetch,ok,ok)
    assert result["status"]=="COMMITTED"
    assert (tmp_path/"usr/share/serein/outpost-generations"/plan["release_digest"][7:]).is_dir()

@pytest.mark.skipif(os.name=="nt" or not hasattr(os,"geteuid") or os.geteuid()!=0 or shutil.which("runuser") is None,reason="requires root Linux service-user proof")
def test_installed_selector_is_readable_by_unprivileged_service_user():
    root=Path(tempfile.mkdtemp(prefix="serein-outpost-service-user-",dir="/tmp"));os.chmod(root,0o755)
    try:
        adapter,plan,authority,fetch,ok,launcher=fixture(root);install_public_generation(adapter,plan,authority,fetch,ok,ok)
        state=root/"var/lib/serein-outpost/generation-state";assert stat.S_IMODE(state.stat().st_mode)==0o755
        assert all(stat.S_IMODE((state/name).stat().st_mode)==0o644 for name in ("current.json","lkg.json"))
        script="from pathlib import Path;from install.generation_launcher import read_selector;read_selector(Path(r'%s'),Path(r'%s'))"%(state/"current.json",root/"usr/share/serein/outpost-generations")
        source_root=Path(__file__).resolve().parents[1]
        result=subprocess.run(["runuser","-u","nobody","--","env",f"PYTHONPATH={source_root}","PYTHONDONTWRITEBYTECODE=1","python3","-B","-c",script],text=True,capture_output=True)
        assert result.returncode==0,result.stderr
    finally: shutil.rmtree(root)

def test_next_generation_records_and_restores_readable_selector_mode(tmp_path):
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path)
    state=adapter.root/"var/lib/serein-outpost/generation-state"
    os.chmod(state/"current.json",0o644);os.chmod(state/"lkg.json",0o644)
    install_public_generation(adapter,plan,authority,fetch,ok,ok)
    assert stat.S_IMODE((state/"current.json").stat().st_mode)==0o644
    rollback=adapter.root/plan["rollback_selector"].lstrip("/")
    assert rollback_public_generation(adapter,rollback)["rollback_complete"] is True
    assert stat.S_IMODE((state/"current.json").stat().st_mode)==0o644

def test_state_directory_mode_is_receipt_bound_and_rollback_restored(tmp_path):
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path);state=adapter.root/"var/lib/serein-outpost/generation-state";os.chmod(state,0o700)
    install_public_generation(adapter,plan,authority,fetch,ok,ok)
    assert stat.S_IMODE(state.stat().st_mode)==0o755
    rollback=adapter.root/plan["rollback_selector"].lstrip("/");receipt=json.loads((rollback/"transaction-receipt.json").read_text())
    assert receipt["state_dir_pre"]["mode"]=="0700" and receipt["state_dir_post"]["mode"]=="0755"
    rollback_public_generation(adapter,rollback)
    assert stat.S_IMODE(state.stat().st_mode)==0o700

def test_failed_postflip_acceptance_restores_state_directory_and_selector_modes(tmp_path):
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path);state=adapter.root/"var/lib/serein-outpost/generation-state";os.chmod(state,0o700);calls={"n":0}
    def reject_terminal(*args):
        calls["n"]+=1
        return ok(*args) if calls["n"]==1 else {**ok(*args),"api":"FAIL"}
    with pytest.raises(TransactionError,match="PUBLIC_POSTFLIP_ACCEPTANCE_DENIED"): install_public_generation(adapter,plan,authority,fetch,ok,reject_terminal)
    assert stat.S_IMODE(state.stat().st_mode)==0o700
    assert all(stat.S_IMODE((state/name).stat().st_mode)==0o600 for name in ("current.json","lkg.json"))

def test_exact_public_generation_accepts_canonical_root_owned_archive_parent(tmp_path):
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path)
    (tmp_path/"var/lib/serein/rollback").chmod(0o755)
    assert install_public_generation(adapter,plan,authority,fetch,ok,ok)["status"]=="COMMITTED"

@pytest.mark.parametrize("field,value,code",[("repo_url","https://evil.invalid/x","SOURCE"),("ref","main","SOURCE"),("commit","c"*40,"ARCHIVE_URL"),("tree","x"*40,"LINEAGE"),("archive_sha256","0"*64,"SIGNATURE")])
def test_source_identity_and_signed_fields_deny(tmp_path,field,value,code):
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path); plan[field]=value
    with pytest.raises(TransactionError,match=code): install_public_generation(adapter,plan,authority,fetch,ok,ok)

def test_redirect_and_archive_tamper_deny(tmp_path):
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path)
    with pytest.raises(TransactionError,match="REDIRECT"): install_public_generation(adapter,plan,authority,lambda u:(fetch(u)[0],"https://evil.invalid/x"),ok,ok)
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path/"second")
    with pytest.raises(TransactionError,match="HASH"): install_public_generation(adapter,plan,authority,lambda u:(fetch(u)[0]+b"x",u),ok,ok)

@pytest.mark.parametrize("kind,code",[("symlink","MEMBER_TYPE"),("hardlink","MEMBER_TYPE"),("device","MEMBER_TYPE"),("traversal","PATH")])
def test_hostile_archive_and_probe_fail_leave_current(tmp_path,kind,code):
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path,hostile=kind); before=(tmp_path/"var/lib/serein-outpost/generation-state/current.json").read_bytes()
    with pytest.raises(TransactionError,match=code): install_public_generation(adapter,plan,authority,fetch,ok,ok)
    assert (tmp_path/"var/lib/serein-outpost/generation-state/current.json").read_bytes()==before

def test_probe_failure_leaves_current(tmp_path):
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path)
    with pytest.raises(TransactionError,match="PROBE"): install_public_generation(adapter,plan,authority,fetch,lambda *a:False,ok)

def test_postflip_failure_restores_selectors(tmp_path):
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path); state=tmp_path/"var/lib/serein-outpost/generation-state"; before={p.name:p.read_bytes() for p in state.iterdir()}; calls={"n":0}
    def accept(*args): calls["n"]+=1; return ok(*args) if calls["n"]==1 else {}
    with pytest.raises(TransactionError,match="POSTFLIP"): install_public_generation(adapter,plan,authority,fetch,ok,accept)
    assert {p.name:p.read_bytes() for p in state.iterdir()}==before

def test_update_denies_missing_predecessor_before_fetch_or_write(tmp_path):
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path,first=True)
    called=[]
    with pytest.raises(TransactionError,match="UPDATE_PREDECESSOR_REQUIRED"): install_public_generation(adapter,plan,authority,lambda url: called.append(url),ok,ok)
    assert called==[]
    assert not (adapter.root/"usr/libexec/serein/outpost-generation-launcher").exists()

def test_boot_immutable_selector_and_generation_collisions_deny(tmp_path):
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path); plan["current_boot_id"]="wrong"; plan["signature"]="bad"
    with pytest.raises(TransactionError,match="SIGNATURE"): install_public_generation(adapter,plan,authority,fetch,ok,ok)
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path/"immutable"); (adapter.root/"etc/serein-outpost/readonly.token").write_bytes(b"drift")
    with pytest.raises(TransactionError): install_public_generation(adapter,plan,authority,fetch,ok,ok)
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path/"selector"); rollback=adapter.root/plan["rollback_selector"].lstrip("/"); rollback.mkdir(parents=True)
    with pytest.raises(TransactionError,match="ROLLBACK_COLLISION"): install_public_generation(adapter,plan,authority,fetch,ok,ok)

def test_probe_failure_cleans_staging_and_retry_succeeds(tmp_path):
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path)
    with pytest.raises(TransactionError,match="PROBE"): install_public_generation(adapter,plan,authority,fetch,lambda *a:False,ok)
    assert not (adapter.root/"usr/share/serein/outpost-generations"/plan["release_digest"][7:]).exists()
    assert install_public_generation(adapter,plan,authority,fetch,ok,ok)["status"]=="COMMITTED"

def test_committed_retry_is_idempotent(tmp_path):
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path)
    install_public_generation(adapter,plan,authority,fetch,ok,ok)
    assert install_public_generation(adapter,plan,authority,fetch,ok,ok)["status"]=="ALREADY_COMMITTED"

def test_broken_current_uses_only_valid_lkg_and_both_bad_deny(tmp_path):
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path); state=adapter.root/"var/lib/serein-outpost/generation-state"; prior=(state/"lkg.json").read_bytes(); (state/"current.json").write_text("{}")
    assert install_public_generation(adapter,plan,authority,fetch,ok,ok)["status"]=="COMMITTED"
    assert (state/"lkg.json").read_bytes()==prior
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path/"bad"); state=adapter.root/"var/lib/serein-outpost/generation-state"; (state/"current.json").write_text("{}"); (state/"lkg.json").write_text("{}")
    with pytest.raises(TransactionError,match="UPDATE_PREDECESSOR_REQUIRED"): install_public_generation(adapter,plan,authority,fetch,ok,ok)

def test_selector_drift_after_probe_is_denied_by_final_cas(tmp_path):
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path); current=adapter.root/"var/lib/serein-outpost/generation-state/current.json"; armed={"value":False}; original=adapter.boundary
    def boundary():
        original()
        if armed["value"]: armed["value"]=False; current.write_bytes(b"external-selector-drift\n")
    adapter.boundary=boundary
    def acceptance(*args): armed["value"]=True; return ok(*args)
    with pytest.raises(TransactionError,match="CURRENT_SELECTOR_CAS"): install_public_generation(adapter,plan,authority,fetch,ok,acceptance)
    assert current.read_bytes()==b"external-selector-drift\n"

def test_receipt_bound_rollback_and_replay_denial(tmp_path):
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path); state=adapter.root/"var/lib/serein-outpost/generation-state"; before={p.name:p.read_bytes() for p in state.iterdir()}
    install_public_generation(adapter,plan,authority,fetch,ok,ok)
    rollback=adapter.root/plan["rollback_selector"].lstrip("/"); receipt=json.loads((rollback/"transaction-receipt.json").read_text())
    assert receipt["source"]["commit"]==plan["commit"] and receipt["generation_inventory"] and receipt["receipt_digest"]
    assert rollback_public_generation(adapter,rollback)["rollback_complete"] is True
    assert {p.name:p.read_bytes() for p in state.iterdir()}==before
    with pytest.raises(TransactionError,match="ROLLBACK_REPLAY_DENIED"): rollback_public_generation(adapter,rollback)

def test_first_install_never_enters_candidate_or_rescue_path(tmp_path):
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path,first=True); calls=[]
    with pytest.raises(TransactionError,match="UPDATE_PREDECESSOR_REQUIRED"): install_public_generation(adapter,plan,authority,lambda url:calls.append(url),ok,ok)
    assert calls==[]
    assert not (adapter.root/"usr/share/serein/outpost-generations"/plan["release_digest"][7:]).exists()
    assert not (adapter.root/"usr/libexec/serein/outpost-generation-launcher").exists()

def test_preflip_cleanup_denies_and_preserves_external_generation_drift(tmp_path):
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path)
    def drift(generation,*args): (generation/"outpost/service.py").write_bytes(b"external\n"); return {}
    with pytest.raises(TransactionError,match="STAGING_CLEANUP_CAS_DENIED"): install_public_generation(adapter,plan,authority,fetch,drift,ok)
    generation=adapter.root/"usr/share/serein/outpost-generations"/plan["release_digest"][7:]
    assert (generation/"outpost/service.py").read_bytes()==b"external\n"
    assert (generation/"release-manifest.json").is_file()

def test_recomputed_unkeyed_receipt_digest_cannot_authorize_tamper(tmp_path):
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path); install_public_generation(adapter,plan,authority,fetch,ok,ok); rollback=adapter.root/plan["rollback_selector"].lstrip("/"); path=rollback/"transaction-receipt.json"; receipt=json.loads(path.read_text()); receipt["source"]["commit"]="f"*40; receipt["receipt_digest"]=_receipt_digest(receipt); path.write_text(json.dumps(receipt,indent=2)+"\n"); os.chmod(path,0o600)
    with pytest.raises(TransactionError,match="SIGNATURE_DENIED"): rollback_public_generation(adapter,rollback)

@pytest.mark.parametrize("name",("current.json","lkg.json"))
def test_postflip_external_selector_drift_is_preserved_and_masks_no_failure(tmp_path,name):
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path); state=adapter.root/"var/lib/serein-outpost/generation-state"; calls={"n":0}; armed={"value":False}; original=adapter.boundary
    def acceptance(*args):
        calls["n"]+=1
        if calls["n"]==2: armed["value"]=True
        return ok(*args)
    def boundary():
        if armed["value"]:
            armed["value"]=False; (state/name).write_bytes(b"external-postflip-drift\n"); raise TransactionError("INJECTED_RECEIPT_FAILURE")
        original()
    adapter.boundary=boundary
    with pytest.raises(TransactionError,match="POSTFLIP_SELECTOR_CAS_DENIED"): install_public_generation(adapter,plan,authority,fetch,ok,acceptance)
    assert (state/name).read_bytes()==b"external-postflip-drift\n"

def test_rollback_is_resumable_at_every_journaled_boundary(tmp_path):
    probe=tmp_path/"probe"; adapter,plan,authority,fetch,ok,launcher=fixture(probe); install_public_generation(adapter,plan,authority,fetch,ok,ok); adapter.writes=0; rollback_public_generation(adapter,adapter.root/plan["rollback_selector"].lstrip("/")); boundaries=adapter.writes
    for point in range(1,boundaries+1):
        root=tmp_path/f"case-{point}"; adapter,plan,authority,fetch,ok,launcher=fixture(root); install_public_generation(adapter,plan,authority,fetch,ok,ok); rollback=adapter.root/plan["rollback_selector"].lstrip("/"); adapter.writes=0; adapter.fail_after=point
        with pytest.raises(TransactionError,match="INJECTED_WRITE_FAILURE"): rollback_public_generation(adapter,rollback)
        adapter.fail_after=None; rollback_public_generation(adapter,rollback)
        journal=json.loads((rollback/"rollback-state.json").read_text()); assert journal["phase"]=="COMPLETE"
        with pytest.raises(TransactionError,match="ROLLBACK_REPLAY_DENIED"): rollback_public_generation(adapter,rollback)

@pytest.mark.parametrize("mutation,code",[("digest","STATE_SIGNATURE"),("mode","STATE_CUSTODY"),("owner","STATE_CUSTODY"),("symlink","PATH_SYMLINK")])
def test_rollback_state_journal_custody_and_signature_fail_closed(tmp_path,mutation,code):
    if os.name=="nt" and mutation!="digest": pytest.skip("POSIX custody/symlink mutation unavailable")
    adapter,plan,authority,fetch,ok,launcher=fixture(tmp_path); install_public_generation(adapter,plan,authority,fetch,ok,ok); rollback=adapter.root/plan["rollback_selector"].lstrip("/"); rollback_public_generation(adapter,rollback); journal=rollback/"rollback-state.json"
    if mutation=="digest":
        value=json.loads(journal.read_text()); value["step"]+=1; value["state_digest"]=sha(canonical({k:v for k,v in value.items() if k!="state_digest"})); journal.write_text(json.dumps(value,indent=2)+"\n")
    elif mutation=="mode": os.chmod(journal,0o644)
    elif mutation=="owner":
        if os.geteuid()!=0: pytest.skip("root ownership mutation unavailable")
        os.chown(journal,1,1)
    else:
        copy=rollback/"journal-copy"; copy.write_bytes(journal.read_bytes()); journal.unlink(); journal.symlink_to(copy)
    with pytest.raises(TransactionError,match=code): rollback_public_generation(adapter,rollback)
