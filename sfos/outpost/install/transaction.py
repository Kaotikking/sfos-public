#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
import copy
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey

sys.dont_write_bytecode=True


class TransactionError(RuntimeError): pass


CANONICAL_PROTECTED_UNITS={}
IMMUTABLE_KEY_ID="outpost-cognition-v1"
OUTPOST_UNITS=("serein-outpost-host-witness.service","serein-outpost-presentation.service","serein-outpost.target")


def canonical(value): return json.dumps(value,sort_keys=True,separators=(",",":")).encode()
def sha(data): return hashlib.sha256(data).hexdigest()


def under(root,absolute):
    path=root/absolute.lstrip("/")
    if path==root or root not in path.parents: raise TransactionError("TARGET_PATH_DENIED")
    return path


def nofollow_ancestors(root,path,allow_missing=True):
    current=root
    if current.is_symlink(): raise TransactionError("ROOT_SYMLINK_DENIED")
    for part in path.relative_to(root).parts:
        current=current/part
        if os.path.lexists(current) and current.is_symlink(): raise TransactionError("PATH_SYMLINK_DENIED:"+str(current))
        if not os.path.lexists(current) and allow_missing: continue


def receipt_digest(receipt): return sha(canonical({k:v for k,v in receipt.items() if k!="receipt_digest"}))


class Adapter:
    def __init__(self,root=Path("/"),fail_after=None): self.root=Path(root).resolve(); self.fail_after=fail_after; self.writes=0; self.identities={}; self.unit_state=copy.deepcopy(CANONICAL_PROTECTED_UNITS); self.directory_metadata_overrides={}; self.file_metadata_overrides={}
    def boundary(self):
        self.writes+=1
        if self.fail_after==self.writes: raise TransactionError("INJECTED_WRITE_FAILURE")
    def identity(self,name): return self.identities.get(name)
    def planned_identity(self,policy): return {"user":policy["user"],"uid":900,"gid":900,"group":policy["group"],"group_gid":900,"home":policy["home"],"shell":policy["shell"],"supplementary_groups":[]}
    def create_identity(self,policy,planned):
        self.boundary(); self.identities[policy["user"]]={"partial":True,"user":None,"uid":None,"gid":planned["gid"],"group":planned["group"],"group_gid":planned["group_gid"]}
        self.boundary(); self.identities[policy["user"]]=dict(planned)
    def remove_identity(self,name): self.boundary(); self.identities.pop(name,None)
    def daemon_reload(self): self.boundary()
    def read_unit(self,name): return self.unit_state.get(name,{"enabled":"not-found","active":"inactive"})
    def directory_metadata(self,path):
        absolute="/"+path.relative_to(self.root).as_posix()
        if absolute in self.directory_metadata_overrides: return self.directory_metadata_overrides[absolute]
        info=path.lstat()
        return {"mode":stat.S_IMODE(info.st_mode),"uid":0,"gid":0}
    def file_metadata(self,path):
        absolute="/"+path.relative_to(self.root).as_posix()
        if absolute in self.file_metadata_overrides: return self.file_metadata_overrides[absolute]
        info=path.lstat(); return {"mode":stat.S_IMODE(info.st_mode),"uid":0,"gid":0}


class RealAdapter(Adapter):
    def __init__(self,unit_names=()):
        super().__init__(Path("/")); self.identities={}; self.unit_state={name:self.read_unit(name) for name in unit_names}
    def boundary(self): pass
    def identity(self,name):
        import grp,pwd
        try: user=pwd.getpwnam(name)
        except KeyError: user=None
        try: named_group=grp.getgrnam(name)
        except KeyError: named_group=None
        if user is None and named_group is None: return None
        if user is None:
            return {"partial":True,"user":None,"uid":None,"gid":named_group.gr_gid,"group":name,"group_gid":named_group.gr_gid}
        if named_group is None:
            return {"partial":True,"user":name,"uid":user.pw_uid,"gid":user.pw_gid,"group":None,"group_gid":None}
        primary=grp.getgrgid(user.pw_gid)
        groups=sorted(g.gr_name for g in grp.getgrall() if name in g.gr_mem)
        return {"user":name,"uid":user.pw_uid,"gid":user.pw_gid,"group":primary.gr_name,"group_gid":primary.gr_gid,"home":user.pw_dir,"shell":user.pw_shell,"supplementary_groups":groups}
    def planned_identity(self,policy):
        import grp,pwd
        used={row.pw_uid for row in pwd.getpwall()}|{row.gr_gid for row in grp.getgrall()}
        selected=next((value for value in range(policy["uid_lt"]-1,0,-1) if value not in used),None)
        if selected is None: raise TransactionError("IDENTITY_ID_UNAVAILABLE")
        return {"user":policy["user"],"uid":selected,"gid":selected,"group":policy["group"],"group_gid":selected,"home":policy["home"],"shell":policy["shell"],"supplementary_groups":[]}
    def create_identity(self,policy,planned):
        subprocess.run(["groupadd","--system","--gid",str(planned["gid"]),policy["group"]],check=True)
        subprocess.run(["useradd","--system","--uid",str(planned["uid"]),"--gid",policy["group"],"--home-dir",policy["home"],"--shell",policy["shell"],policy["user"]],check=True)
    def remove_identity(self,name):
        current=self.identity(name)
        if current is not None and current.get("user") is not None: subprocess.run(["userdel",name],check=True)
        current=self.identity(name)
        if current is not None and current.get("group") is not None: subprocess.run(["groupdel",name],check=True)
    def daemon_reload(self): subprocess.run(["systemctl","daemon-reload"],check=True)
    def directory_metadata(self,path):
        info=path.lstat()
        return {"mode":stat.S_IMODE(info.st_mode),"uid":info.st_uid,"gid":info.st_gid}
    def file_metadata(self,path):
        info=path.lstat(); return {"mode":stat.S_IMODE(info.st_mode),"uid":info.st_uid,"gid":info.st_gid}
    def read_unit(self,name):
        enabled=subprocess.run(["systemctl","is-enabled",name],text=True,capture_output=True).stdout.strip() or "not-found"
        active=subprocess.run(["systemctl","is-active",name],text=True,capture_output=True).stdout.strip() or "inactive"
        return {"enabled":enabled,"active":active}


def verify_identity(actual,policy):
    if actual is None: return "ABSENT"
    if actual.get("partial"): raise TransactionError("IDENTITY_PARTIAL_PRESTATE_DENIED")
    if actual.get("home")!=policy["home"] or actual.get("shell")!=policy["shell"] or actual.get("supplementary_groups")!=policy["supplementary_groups"]: raise TransactionError("IDENTITY_PRESTATE_DENIED")
    uid=actual.get("uid"); gid=actual.get("gid")
    if not isinstance(uid,int) or not isinstance(gid,int) or uid<=0 or gid<=0 or uid>=policy["uid_lt"] or gid>=policy["gid_lt"]: raise TransactionError("IDENTITY_ID_RANGE_DENIED")
    if actual.get("group")!=policy["group"] or actual.get("group_gid")!=gid: raise TransactionError("IDENTITY_PRIMARY_GROUP_DENIED")
    if policy.get("uid_equals_gid") is not True or uid!=gid: raise TransactionError("IDENTITY_UID_GID_RELATIONSHIP_DENIED")
    return "APPROVED_EXISTING"


def identity_matches_created(actual,planned):
    if actual is None: return True
    if actual==planned: return True
    return bool(actual and actual.get("partial") and actual.get("user") is None and actual.get("group")==planned["group"] and actual.get("gid")==planned["gid"] and actual.get("group_gid")==planned["group_gid"])


def resolve_directory_row(declared,identity):
    uid=identity["uid"] if declared.get("uid_policy")=="identity_uid" else declared["uid"]
    gid=identity["gid"] if declared.get("gid_policy")=="identity_gid" else declared["gid"]
    row={**declared,"uid":uid,"gid":gid}
    row.pop("uid_policy",None)
    row.pop("gid_policy",None)
    return row


def exact_file(adapter,path,row):
    nofollow_ancestors(adapter.root,path)
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink(): raise TransactionError("INSTALLED_TYPE_DENIED:"+str(path))
    data=path.read_bytes()
    if len(data)!=row["bytes"] or sha(data)!=row["sha256"]: raise TransactionError("INSTALLED_CONTENT_DENIED:"+str(path))
    if os.name!="nt" and stat.S_IMODE(info.st_mode)!=int(row["mode"],8): raise TransactionError("INSTALLED_MODE_DENIED:"+str(path))
    if isinstance(adapter,RealAdapter) and (info.st_uid!=row["uid"] or info.st_gid!=row["gid"]): raise TransactionError("INSTALLED_OWNER_DENIED:"+str(path))


def write_file(adapter,source,target,row):
    nofollow_ancestors(adapter.root,target)
    if not target.parent.is_dir(): raise TransactionError("TARGET_PARENT_DENIED:"+str(target.parent))
    adapter.boundary()
    data=source.read_bytes(); target.write_bytes(data); os.chmod(target,int(row["mode"],8))
    if isinstance(adapter,RealAdapter): os.chown(target,row["uid"],row["gid"])


def write_generated(adapter,target,row,data):
    nofollow_ancestors(adapter.root,target)
    if not target.parent.is_dir(): raise TransactionError("TARGET_PARENT_DENIED:"+str(target.parent))
    adapter.boundary(); target.write_bytes(data); os.chmod(target,int(row["mode"],8))
    if isinstance(adapter,RealAdapter): os.chown(target,row["uid"],row["gid"])


def immutable_inputs(adapter,manifest,plan,identity):
    if not isinstance(plan,dict) or set(plan)!={"schema","source","target","method","release_digest","key_id","public_key_fingerprint_sha256","files"}: raise TransactionError("IMMUTABLE_INPUT_PLAN_DENIED")
    if plan["schema"]!="SereinOutpostImmutableInputPlan/v1" or plan["source"] not in {"OFFLINE_USB_MEDIA","PINNED_PUBLIC_REPOSITORY","EXISTING_CANONICAL"} or plan["target"]!="SEREIN_HOST" or plan["method"]!="VERIFIED_PUBLIC_INSTALLER" or plan["release_digest"]!=manifest.get("self_digest") or plan["key_id"]!=IMMUTABLE_KEY_ID: raise TransactionError("IMMUTABLE_INPUT_AUTHORITY_DENIED")
    declared=[]
    for item in manifest.get("required_immutable_inputs",[]):
        row=resolve_directory_row(item,identity); declared.append(row)
    if len(plan["files"])!=len(declared) or {x.get("target") for x in plan["files"]}!={x["target"] for x in declared}: raise TransactionError("IMMUTABLE_INPUT_DENOMINATOR_DENIED")
    planned={x["target"]:x for x in plan["files"]}; observed=[]
    for row in declared:
        binding=planned[row["target"]]
        if set(binding)!={"target","sha256"} or not re.fullmatch(r"[0-9a-f]{64}",str(binding["sha256"])): raise TransactionError("IMMUTABLE_INPUT_BINDING_DENIED")
        path=under(adapter.root,row["target"]); nofollow_ancestors(adapter.root,path,allow_missing=False)
        if not os.path.lexists(path): raise TransactionError("IMMUTABLE_INPUT_ABSENT:"+row["target"])
        info=path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode): raise TransactionError("IMMUTABLE_INPUT_TYPE_DENIED:"+row["target"])
        metadata=adapter.file_metadata(path); expected={"mode":int(row["mode"],8),"uid":row["uid"],"gid":row["gid"]}
        if metadata!=expected: raise TransactionError("IMMUTABLE_INPUT_CUSTODY_DENIED:"+row["target"])
        data=path.read_bytes()
        if sha(data)!=binding["sha256"]: raise TransactionError("IMMUTABLE_INPUT_HASH_DENIED:"+row["target"])
        observed.append({**row,"bytes":len(data),"sha256":binding["sha256"],"classification":"REQUIRED_IMMUTABLE_INPUT"})
    private_path=under(adapter.root,"/etc/serein-outpost/cognition-signing.pem"); public_path=under(adapter.root,"/usr/share/serein/outpost/cognition-verification.pem")
    try:
        private=serialization.load_pem_private_key(private_path.read_bytes(),password=None)
        public=serialization.load_pem_public_key(public_path.read_bytes())
    except Exception as exc: raise TransactionError("IMMUTABLE_KEY_PARSE_DENIED") from exc
    if not isinstance(private,Ed25519PrivateKey) or not isinstance(public,Ed25519PublicKey): raise TransactionError("IMMUTABLE_KEY_ALGORITHM_DENIED")
    derived=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    supplied=public.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    if derived!=supplied: raise TransactionError("IMMUTABLE_KEY_PAIR_DENIED")
    fingerprint=sha(public.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))
    if fingerprint!=plan["public_key_fingerprint_sha256"]: raise TransactionError("IMMUTABLE_KEY_FINGERPRINT_DENIED")
    return observed,fingerprint


def validate_receipt(adapter,selector):
    if selector.parent!=under(adapter.root,"/var/lib/serein/rollback") or not re.fullmatch(r"outpost-first-install-\d{8}T\d{6}Z-[0-9a-f]{12}",selector.name): raise TransactionError("ROLLBACK_SELECTOR_DENIED")
    nofollow_ancestors(adapter.root,selector,allow_missing=False)
    info=selector.lstat()
    if not stat.S_ISDIR(info.st_mode) or (os.name!="nt" and stat.S_IMODE(info.st_mode)!=0o700): raise TransactionError("ROLLBACK_ROOT_POLICY_DENIED")
    if isinstance(adapter,RealAdapter) and (info.st_uid!=0 or info.st_gid!=0): raise TransactionError("ROLLBACK_ROOT_OWNER_DENIED")
    path=selector/"receipt.json"; nofollow_ancestors(adapter.root,path,allow_missing=False)
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or (os.name!="nt" and stat.S_IMODE(info.st_mode)!=0o600): raise TransactionError("ROLLBACK_RECEIPT_POLICY_DENIED")
    if isinstance(adapter,RealAdapter) and (info.st_uid!=0 or info.st_gid!=0): raise TransactionError("ROLLBACK_RECEIPT_OWNER_DENIED")
    receipt=json.loads(path.read_text(encoding="utf-8"))
    required={"schema","selector","release_digest","identity","identity_actual","identity_state","introduced_directories","introduced_files","generated_files","immutable_inputs","immutable_key_id","immutable_public_key_fingerprint_sha256","unit_prestate","rollback_complete","receipt_digest"}
    if set(receipt)!=required or receipt.get("schema")!="SereinOutpostRollback/v2" or receipt.get("selector")!=str(selector) or receipt.get("receipt_digest")!=receipt_digest(receipt): raise TransactionError("ROLLBACK_RECEIPT_INTEGRITY_DENIED")
    release=under(adapter.root,"/usr/share/serein/outpost/release-manifest.json")
    if release.is_file():
        current=json.loads(release.read_text(encoding="utf-8"))
        if current.get("self_digest")!=receipt["release_digest"]: raise TransactionError("ROLLBACK_RELEASE_CURRENTNESS_DENIED")
    return receipt


def write_receipt(selector,receipt):
    receipt["receipt_digest"]=receipt_digest(receipt)
    path=selector/"receipt.json"
    with path.open("w",encoding="utf-8",newline="\n") as handle:
        json.dump(receipt,handle,indent=2); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
    os.chmod(path,0o600)
    if hasattr(os,"O_DIRECTORY"):
        descriptor=os.open(selector,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)


def installed_parity(adapter,manifest,receipt):
    expected={row["target"] for row in manifest["install_files"]}|{row["target"] for row in receipt["generated_files"]}|{row["target"] for row in receipt["immutable_inputs"]}
    for row in manifest["install_files"]: exact_file(adapter,under(adapter.root,row["target"]),row)
    for row in receipt["generated_files"]: exact_file(adapter,under(adapter.root,row["target"]),row)
    for row in receipt["immutable_inputs"]: exact_file(adapter,under(adapter.root,row["target"]),row)
    for declared in manifest["install_directories"]:
        row=resolve_directory_row(declared,receipt["identity_actual"])
        path=under(adapter.root,row["target"]); nofollow_ancestors(adapter.root,path,allow_missing=False); info=path.lstat()
        if path.is_symlink() or not stat.S_ISDIR(info.st_mode): raise TransactionError("INSTALLED_DIRECTORY_DENIED:"+row["target"])
        actual=adapter.directory_metadata(path)
        expected_policy={"mode":int(row["mode"],8),"uid":row["uid"],"gid":row["gid"]}
        if actual!=expected_policy: raise TransactionError("INSTALLED_DIRECTORY_POLICY_DENIED:"+row["target"])
    share=under(adapter.root,"/usr/share/serein/outpost")
    actual={"/"+str(p.relative_to(adapter.root)).replace("\\","/") for p in share.rglob("*") if p.is_file() or p.is_symlink()}
    if actual!={x for x in expected if x.startswith("/usr/share/serein/outpost/")}: raise TransactionError("INSTALLED_RESIDUE_DENIED")
    for unit,state in receipt["unit_prestate"].items():
        if adapter.read_unit(unit)!=state: raise TransactionError("PROTECTED_UNIT_STATE_CHANGED:"+unit)
    for unit in ("serein-outpost-validation.service","serein-outpost.service","serein-outpost.target"):
        if adapter.read_unit(unit).get("active")=="active" or adapter.read_unit(unit).get("enabled")=="enabled": raise TransactionError("OUTPOST_UNIT_ACTIVATED_DENIED")
    for absolute in manifest["runtime_socket_paths"]:
        if os.path.lexists(under(adapter.root,absolute)): raise TransactionError("INACTIVE_SOCKET_RESIDUE_DENIED")


def rollback(adapter,selector):
    receipt=validate_receipt(adapter,selector)
    for row in receipt["introduced_files"]:
        path=under(adapter.root,row["target"]); nofollow_ancestors(adapter.root,path)
        if os.path.lexists(path): exact_file(adapter,path,row); adapter.boundary(); path.unlink()
    for row in receipt["generated_files"]:
        path=under(adapter.root,row["target"]); nofollow_ancestors(adapter.root,path)
        if os.path.lexists(path): exact_file(adapter,path,row); adapter.boundary(); path.unlink()
    for row in receipt["immutable_inputs"]: exact_file(adapter,under(adapter.root,row["target"]),row)
    share=under(adapter.root,"/usr/share/serein/outpost")
    if share.exists():
        allowed={under(adapter.root,row["target"]) for row in receipt["immutable_inputs"] if row["target"].startswith("/usr/share/serein/outpost/")}
        residue={path for path in share.rglob("*") if path.is_file() or path.is_symlink()}-allowed
        if residue: raise TransactionError("ROLLBACK_UNEXPECTED_RESIDUE_DENIED:"+str(sorted(map(str,residue))))
    for row in sorted(receipt["introduced_directories"],key=lambda value:len(value["target"]),reverse=True):
        path=under(adapter.root,row["target"]); nofollow_ancestors(adapter.root,path)
        if path.exists():
            if any(path.iterdir()): raise TransactionError("ROLLBACK_UNEXPECTED_RESIDUE_DENIED:"+row["target"])
            adapter.boundary(); path.rmdir()
    if receipt["identity_state"]=="CREATED":
        if not identity_matches_created(adapter.identity(receipt["identity"]["user"]),receipt["identity_actual"]): raise TransactionError("ROLLBACK_IDENTITY_CURRENTNESS_DENIED")
        adapter.remove_identity(receipt["identity"]["user"])
    adapter.daemon_reload()
    for row in receipt["introduced_files"]+receipt["generated_files"]:
        if os.path.lexists(under(adapter.root,row["target"])): raise TransactionError("ROLLBACK_RESIDUE_DENIED")
    for unit,state in receipt["unit_prestate"].items():
        if adapter.read_unit(unit)!=state: raise TransactionError("ROLLBACK_PROTECTED_UNIT_STATE_CHANGED:"+unit)
    receipt["rollback_complete"]=True; write_receipt(selector,receipt)
    return receipt


def install(adapter,source,manifest,selector,immutable_plan=None):
    manifest=copy.deepcopy(manifest)
    release_bytes=(source/"release-manifest.json").read_bytes()
    manifest["install_files"].append({"source":"release-manifest.json","target":"/usr/share/serein/outpost/release-manifest.json","bytes":len(release_bytes),"sha256":sha(release_bytes),"mode":"0644","uid":0,"gid":0})
    protected=manifest["protected_unit_state"]
    if protected: raise TransactionError("STALE_UNIT_MAP_DENIED")
    unit_prestate={unit:adapter.read_unit(unit) for unit in OUTPOST_UNITS}
    for unit,state in unit_prestate.items():
        if state.get("active") not in {"inactive","dead"} or state.get("enabled") not in {"disabled","not-found"}: raise TransactionError("PROTECTED_UNIT_PRESTATE_DENIED:"+unit)
    policy=manifest["identity_policy"]; identity_state=verify_identity(adapter.identity(policy["user"]),policy)
    actual_identity=adapter.identity(policy["user"])
    planned_identity=actual_identity or adapter.planned_identity(policy)
    verify_identity(planned_identity,policy)
    immutable_rows,immutable_fingerprint=immutable_inputs(adapter,manifest,immutable_plan,planned_identity)
    directory_rows=[]
    for declared in manifest["install_directories"]:
        row=resolve_directory_row(declared,planned_identity); target=under(adapter.root,row["target"]); nofollow_ancestors(adapter.root,target)
        if os.path.lexists(target):
            info=target.lstat()
            if declared.get("collision_policy")!="adopt_exact" or target.is_symlink() or not stat.S_ISDIR(info.st_mode): raise TransactionError("DIRECTORY_COLLISION_DENIED:"+row["target"])
            actual=adapter.directory_metadata(target)
            expected={"mode":int(row["mode"],8),"uid":row["uid"],"gid":row["gid"]}
            if actual!=expected: raise TransactionError("DIRECTORY_ADOPTION_PRESTATE_DENIED:"+row["target"])
        else: directory_rows.append(row)
    for row in manifest["install_files"]:
        if os.path.lexists(under(adapter.root,row["target"])): raise TransactionError("TARGET_COLLISION_DENIED:"+row["target"])
    generated_by_target={
        "/etc/serein-outpost/rollback-root":(str(selector)+"\n").encode(),
    }
    generated_data=[generated_by_target[row["target"]] for row in manifest["generated_files"]]
    generated_rows=[]
    for declared,data in zip(manifest["generated_files"],generated_data):
        gid=planned_identity["gid"] if declared.get("gid_policy")=="identity_gid" else declared["gid"]
        row={**declared,"gid":gid,"bytes":len(data),"sha256":sha(data)}; row.pop("gid_policy",None)
        if os.path.lexists(under(adapter.root,row["target"])): raise TransactionError("TARGET_COLLISION_DENIED:"+row["target"])
        generated_rows.append(row)
    selector.mkdir(parents=False,mode=0o700); os.chmod(selector,0o700)
    receipt={"schema":"SereinOutpostRollback/v2","selector":str(selector),"release_digest":manifest["self_digest"],"identity":policy,"identity_actual":planned_identity,"identity_state":"CREATED" if identity_state=="ABSENT" else identity_state,"introduced_directories":directory_rows,"introduced_files":manifest["install_files"],"generated_files":generated_rows,"immutable_inputs":immutable_rows,"immutable_key_id":IMMUTABLE_KEY_ID,"immutable_public_key_fingerprint_sha256":immutable_fingerprint,"unit_prestate":unit_prestate,"rollback_complete":False}
    write_receipt(selector,receipt)
    try:
        if identity_state=="ABSENT": adapter.create_identity(policy,planned_identity)
        actual_identity=adapter.identity(policy["user"])
        if actual_identity is not None: verify_identity(actual_identity,policy)
        for row in directory_rows:
            target=under(adapter.root,row["target"])
            if not target.parent.is_dir(): raise TransactionError("DIRECTORY_PARENT_DENIED:"+row["target"])
            adapter.boundary(); target.mkdir(mode=int(row["mode"],8)); os.chmod(target,int(row["mode"],8))
            if isinstance(adapter,RealAdapter): os.chown(target,row["uid"],row["gid"])
            else: adapter.directory_metadata_overrides[row["target"]]={"mode":int(row["mode"],8),"uid":row["uid"],"gid":row["gid"]}
        for row in manifest["install_files"]:
            write_file(adapter,source/row["source"],under(adapter.root,row["target"]),row)
        for row,data in zip(generated_rows,generated_data): write_generated(adapter,under(adapter.root,row["target"]),row,data)
        adapter.daemon_reload()
        validate_receipt(adapter,selector); installed_parity(adapter,manifest,receipt)
        return receipt
    except Exception:
        rollback(adapter,selector)
        raise


def main():
    if os.name=="nt" or not hasattr(os,"geteuid") or os.geteuid()!=0: raise SystemExit("ROOT_LINUX_REQUIRED")
    if len(sys.argv)<3 or sys.argv[1] not in {"install","rollback"}: raise SystemExit("usage: transaction.py install SOURCE IMMUTABLE_INPUT_PLAN | rollback SELECTOR")
    if sys.argv[1]=="rollback":
        adapter=RealAdapter()
        rollback(adapter,Path(sys.argv[2]).resolve()); print("ROLLBACK_RESTORED_EXACT_OUTPOST_ABSENCE"); return
    if len(sys.argv)!=4: raise SystemExit("IMMUTABLE_INPUT_PLAN_REQUIRED")
    source=Path(sys.argv[2]).resolve(); plan_path=Path(os.path.abspath(sys.argv[3])); sys.path.insert(0,str(source)); from verify_install_preflight import verify_source,verify_target
    nofollow_ancestors(Path(plan_path.anchor),plan_path,allow_missing=False); plan_info=plan_path.lstat()
    if plan_path.is_symlink() or not stat.S_ISREG(plan_info.st_mode) or stat.S_IMODE(plan_info.st_mode)&0o022 or plan_info.st_uid!=0 or plan_info.st_gid!=0: raise SystemExit("IMMUTABLE_INPUT_PLAN_CUSTODY_DENIED")
    manifest=json.loads((source/"release-manifest.json").read_text(encoding="utf-8")); verify_source(source,manifest)
    preflight=json.loads((source/"install-preflight.json").read_text(encoding="utf-8")); plan=json.loads(plan_path.read_text(encoding="utf-8")); allowed={row.get("target") for row in plan.get("files",[]) if isinstance(row,dict)}; verify_target(Path("/"),preflight,check_units=True,allowed_immutable_targets=allowed)
    adapter=RealAdapter(manifest["protected_unit_state"])
    base=Path("/var/lib/serein/rollback"); nofollow_ancestors(Path("/"),base,allow_missing=False); info=base.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode)&0o022 or info.st_uid!=0 or info.st_gid!=0: raise SystemExit("ROLLBACK_BASE_POLICY_DENIED")
    selector=base/("outpost-first-install-"+time.strftime("%Y%m%dT%H%M%SZ",time.gmtime())+"-"+os.urandom(6).hex())
    install(adapter,source,manifest,selector,plan); print("INSTALLED_INACTIVE rollback="+str(selector))


if __name__=="__main__": main()
