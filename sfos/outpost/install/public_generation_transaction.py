#!/usr/bin/env python3
"""Fail-closed installer for the one canonical public SFOS Outpost source."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tarfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key,load_pem_public_key

from .generation_launcher import read_selector
from .transaction import TransactionError, canonical, nofollow_ancestors, sha, under
from .upgrade_transaction import atomic_write, exact_file, generation_selector_digest

REPOSITORY="Kaotikking/sfos-public"
REF="refs/heads/main"
ARCHIVE_RE=re.compile(r"https://codeload\.github\.com/Kaotikking/sfos-public/tar\.gz/([0-9a-f]{40})")
ROLLBACK_RE=re.compile(r"outpost-public-generation-\d{8}T\d{6}Z-[0-9a-f]{12}")
IMMUTABLE_POLICY={
    "/etc/serein-outpost/readonly.token":"0640",
    "/etc/serein-outpost/admission.token":"0640",
    "/etc/serein-outpost/cognition-signing.pem":"0640",
    "/usr/share/serein/outpost/cognition-verification.pem":"0644",
    "/etc/serein/tls/serein-backend-cert.pem":"0600",
    "/etc/serein/tls/serein-backend-key.pem":"0600",
}
PUBLIC_UNITS={"serein-outpost-host-witness.service","serein-outpost-presentation.service"}
IMAGE_FILES={
    "install/generation_launcher.py":("/usr/libexec/serein/outpost-generation-launcher","0755"),
    "systemd/serein-outpost-host-witness.service":("/etc/systemd/system/serein-outpost-host-witness.service","0644"),
    "systemd/serein-outpost-presentation.service":("/etc/systemd/system/serein-outpost-presentation.service","0644"),
    "systemd/serein-outpost.target":("/etc/systemd/system/serein-outpost.target","0644"),
}
IMAGE_UNITS=("serein-outpost-host-witness.service","serein-outpost-presentation.service","serein-outpost.target")


def _deny(condition, code):
    if condition: raise TransactionError(code)


def _verify_plan(plan, authority_path):
    required={"schema","repository","repo_url","ref","commit","tree","archive_url","archive_sha256","release_digest","authority_key_id","authority_sha256","signature","current_boot_id","immutable_rows","rollback_selector"}
    _deny(set(plan)!=required or plan["schema"]!="SereinPublicOutpostGenerationPlan/v1","PUBLIC_PLAN_SHAPE_DENIED")
    _deny(plan["repository"]!=REPOSITORY or plan["repo_url"]!="https://github.com/Kaotikking/sfos-public.git" or plan["ref"]!=REF,"PUBLIC_SOURCE_IDENTITY_DENIED")
    match=ARCHIVE_RE.fullmatch(plan["archive_url"])
    _deny(not match or match.group(1)!=plan["commit"],"PUBLIC_ARCHIVE_URL_DENIED")
    _deny(not re.fullmatch(r"[0-9a-f]{40}",plan["commit"]) or not re.fullmatch(r"[0-9a-f]{40}",plan["tree"]),"PUBLIC_LINEAGE_DENIED")
    _deny(not re.fullmatch(r"[0-9a-f]{64}",plan["archive_sha256"]) or not re.fullmatch(r"sha256:[0-9a-f]{64}",plan["release_digest"]),"PUBLIC_DIGEST_DENIED")
    rows=plan["immutable_rows"]
    _deny(not isinstance(rows,list) or len(rows)!=len(IMMUTABLE_POLICY),"PUBLIC_IMMUTABLE_SCHEMA_DENIED")
    by_target={row.get("target"):row for row in rows if isinstance(row,dict)}
    _deny(set(by_target)!=set(IMMUTABLE_POLICY) or len(by_target)!=len(rows),"PUBLIC_IMMUTABLE_SCHEMA_DENIED")
    for target,mode in IMMUTABLE_POLICY.items():
        row=by_target[target]
        _deny(set(row)!={"target","bytes","sha256","mode","uid","gid"} or not isinstance(row["bytes"],int) or row["bytes"]<1 or not re.fullmatch(r"[0-9a-f]{64}",str(row["sha256"])) or row["mode"]!=mode or row["uid"]!=0 or not isinstance(row["gid"],int) or row["gid"]<0,"PUBLIC_IMMUTABLE_SCHEMA_DENIED")
    _deny(plan["authority_key_id"]!="outpost-cognition-v1" or by_target["/usr/share/serein/outpost/cognition-verification.pem"]["sha256"]!=plan["authority_sha256"],"PUBLIC_AUTHORITY_IDENTITY_DENIED")
    anchor=Path(authority_path); info=anchor.lstat()
    _deny(anchor.is_symlink() or not stat.S_ISREG(info.st_mode) or (os.name!="nt" and (info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)!=0o644)),"PUBLIC_AUTHORITY_TYPE_DENIED")
    anchor_bytes=anchor.read_bytes(); _deny(sha(anchor_bytes)!=plan["authority_sha256"],"PUBLIC_AUTHORITY_DENIED")
    signed={key:value for key,value in plan.items() if key!="signature"}
    try:
        signature=base64.urlsafe_b64decode(plan["signature"]+"="*(-len(plan["signature"])%4))
        load_pem_public_key(anchor_bytes).verify(signature,canonical(signed))
    except Exception as exc: raise TransactionError("PUBLIC_PLAN_SIGNATURE_DENIED") from exc


def _safe_archive(raw, plan):
    _deny(sha(raw)!=plan["archive_sha256"],"PUBLIC_ARCHIVE_HASH_DENIED")
    files={}; directories=set(); root=None
    try:
        with tarfile.open(fileobj=io.BytesIO(raw),mode="r:gz") as archive:
            for member in archive.getmembers():
                path=PurePosixPath(member.name)
                _deny(path.is_absolute() or ".." in path.parts or len(path.parts)<1,"PUBLIC_ARCHIVE_PATH_DENIED")
                root=root or path.parts[0]; _deny(path.parts[0]!=root,"PUBLIC_ARCHIVE_ROOT_DENIED")
                relative=PurePosixPath(*path.parts[1:])
                if not relative.parts: continue
                name=relative.as_posix(); _deny(name in files or name in directories,"PUBLIC_ARCHIVE_DUPLICATE_DENIED")
                if member.isdir(): directories.add(name); continue
                _deny(not member.isreg() or member.issym() or member.islnk(),"PUBLIC_ARCHIVE_MEMBER_TYPE_DENIED")
                stream=archive.extractfile(member); _deny(stream is None,"PUBLIC_ARCHIVE_MEMBER_DENIED")
                files[name]=stream.read()
    except (tarfile.TarError,OSError) as exc: raise TransactionError("PUBLIC_ARCHIVE_DENIED") from exc
    _deny("sfos/outpost/release-manifest.json" not in files,"PUBLIC_RELEASE_MISSING")
    release=json.loads(files["sfos/outpost/release-manifest.json"])
    stated=release.get("self_digest"); unsigned={k:v for k,v in release.items() if k!="self_digest"}
    _deny(stated!="sha256:"+sha(canonical(unsigned)) or stated!=plan["release_digest"],"PUBLIC_RELEASE_DIGEST_DENIED")
    _deny(release.get("schema")!="SereinOutpostSourceRelease/v2" or release.get("classification")!="PUBLIC_HOST_GATE_SAFE_UNCOMMISSIONED","PUBLIC_RELEASE_CLASSIFICATION_DENIED")
    _deny(set(release.get("replacement_unit_allowlist",[]))!=PUBLIC_UNITS,"PUBLIC_RELEASE_UNIT_DENOMINATOR_DENIED")
    _deny(release.get("generated_files")!= [{"target":"/etc/serein-outpost/rollback-root","mode":"0600","uid":0,"gid":0}],"PUBLIC_RELEASE_GENERATED_DENOMINATOR_DENIED")
    immutable=release.get("required_immutable_inputs",[])
    _deny(not isinstance(immutable,list) or {row.get("target") for row in immutable if isinstance(row,dict)}!=set(IMMUTABLE_POLICY) or len(immutable)!=len(IMMUTABLE_POLICY),"PUBLIC_RELEASE_IMMUTABLE_DENOMINATOR_DENIED")
    payload=release.get("payload"); source_only=release.get("source_only_files",[])
    _deny(not isinstance(payload,list) or not isinstance(source_only,list),"PUBLIC_PAYLOAD_DENIED")
    declared=payload+source_only; expected={row.get("path"):row for row in declared if isinstance(row,dict)}
    _deny(len(expected)!=len(declared) or any(set(row)!={"path","bytes","sha256"} for row in declared),"PUBLIC_PAYLOAD_DENIED")
    prefix="sfos/outpost/"; archive_files={name[len(prefix):]:data for name,data in files.items() if name.startswith(prefix) and name!=prefix+"release-manifest.json"}
    _deny(set(archive_files)!=set(expected),"PUBLIC_ARCHIVE_DENOMINATOR_DENIED")
    for name,data in archive_files.items():
        row=expected[name]; _deny(row["bytes"]!=len(data) or row["sha256"]!=sha(data),"PUBLIC_PAYLOAD_HASH_DENIED")
    installed={row["path"]:archive_files[row["path"]] for row in payload}
    installed["release-manifest.json"]=files[prefix+"release-manifest.json"]
    return release,installed


def _acceptance_pass(value, boot, release_digest):
    required={"schema","installed_boot_preflight","api","vitals","boot_id","release_digest","host_witness_result","host_witness_generation","host_witness_projection_digest","host_witness_observed_at"}
    return (isinstance(value,dict) and set(value)==required and value["schema"]=="SereinOutpostCandidateAcceptance/v2"
            and value["installed_boot_preflight"]==value["api"]==value["vitals"]==value["host_witness_result"]=="PASS"
            and value["boot_id"]==boot and value["release_digest"]==release_digest
            and isinstance(value["host_witness_generation"],int) and value["host_witness_generation"]>0
            and isinstance(value["host_witness_projection_digest"],str) and re.fullmatch(r"[0-9a-f]{64}",value["host_witness_projection_digest"])
            and isinstance(value["host_witness_observed_at"],(int,float)))


def _fresh_acceptance(before, after):
    return (after["host_witness_generation"]>before["host_witness_generation"]
            and after["host_witness_projection_digest"]!=before["host_witness_projection_digest"]
            and after["host_witness_observed_at"]>before["host_witness_observed_at"])


def _receipt_digest(value): return sha(canonical({key:item for key,item in value.items() if key!="receipt_digest"}))
def _receipt_signed(value): return canonical({key:item for key,item in value.items() if key not in {"receipt_digest","receipt_signature"}})


def _selector_pre(path, data, mode=None):
    if data is None: return {"target":"/"+path.as_posix().split("/",1)[-1],"state":"ABSENT"}
    return {"target":"/"+path.as_posix().split("/",1)[-1],"state":"PRESENT","bytes":len(data),"sha256":sha(data),"mode":mode or "0644","uid":0,"gid":0,"content_b64":base64.b64encode(data).decode()}


def _remove_exact_generation(adapter,generation,inventory,candidate):
    # The immutable launcher validator provides the exhaustive no-follow CAS.
    _,resolved=read_selector(candidate,generation.parent)
    _deny(resolved!=generation,"PUBLIC_GENERATION_CLEANUP_CAS_DENIED")
    for row in sorted((item for item in inventory if item["kind"]=="file"),key=lambda item:item["path"],reverse=True):
        target=generation/row["path"]
        exact_file(adapter,target,{"target":"/"+target.relative_to(adapter.root).as_posix(),**{key:row[key] for key in ("bytes","sha256","mode","uid","gid")}}); adapter.boundary(); target.unlink()
    inventory_path=generation/"generation-inventory.json"; data=(json.dumps(inventory,sort_keys=True,separators=(",",":"))+"\n").encode()
    exact_file(adapter,inventory_path,{"target":"/"+inventory_path.relative_to(adapter.root).as_posix(),"bytes":len(data),"sha256":sha(data),"mode":"0644","uid":0,"gid":0}); adapter.boundary(); inventory_path.unlink()
    for row in sorted((item for item in inventory if item["kind"]=="directory"),key=lambda item:item["path"].count("/"),reverse=True): adapter.boundary(); (generation/row["path"]).rmdir()
    adapter.boundary(); generation.rmdir()


def _state_signed(value): return canonical({key:item for key,item in value.items() if key not in {"state_digest","state_signature"}})


def _write_rollback_state(adapter,path,value,private):
    value=dict(value); value["state_signature"]=base64.urlsafe_b64encode(private.sign(_state_signed(value))).decode().rstrip("="); value["state_digest"]=sha(canonical({key:item for key,item in value.items() if key!="state_digest"}))
    atomic_write(adapter,path,(json.dumps(value,indent=2)+"\n").encode(),"0600",0,0)
    return value


def _write_forward_state(adapter,path,value,private):
    body=dict(value)
    body["state_signature"]=base64.urlsafe_b64encode(private.sign(canonical(body))).decode().rstrip("=")
    body["state_digest"]=sha(canonical({key:item for key,item in body.items() if key!="state_digest"}))
    atomic_write(adapter,path,(json.dumps(body,indent=2)+"\n").encode(),"0600",0,0)
    return body


def _write_prestate_receipt(adapter,path,value,private):
    body=dict(value)
    body["receipt_signature"]=base64.urlsafe_b64encode(private.sign(canonical(body))).decode().rstrip("=")
    body["receipt_digest"]=sha(canonical({key:item for key,item in body.items() if key!="receipt_digest"}))
    atomic_write(adapter,path,(json.dumps(body,indent=2)+"\n").encode(),"0600",0,0)
    return body


def _read_prestate_receipt(adapter,path,plan,public):
    nofollow_ancestors(adapter.root,path,allow_missing=False); info=path.lstat()
    _deny(path.is_symlink() or not stat.S_ISREG(info.st_mode) or (os.name!="nt" and (info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)!=0o600)),"PUBLIC_PRESTATE_RECEIPT_CUSTODY_DENIED")
    value=json.loads(path.read_text(encoding="utf-8")); required={"schema","source_plan_sha256","boot_id","generation_target","selector_pre","image_files","unit_prestate","receipt_signature","receipt_digest"}
    _deny(set(value)!=required or value["schema"]!="SereinPublicOutpostPrestateReceipt/v1" or value["source_plan_sha256"]!=sha(canonical(plan)) or value["boot_id"]!=plan["current_boot_id"] or value["receipt_digest"]!=sha(canonical({key:item for key,item in value.items() if key!="receipt_digest"})),"PUBLIC_PRESTATE_RECEIPT_DENIED")
    signed={key:item for key,item in value.items() if key not in {"receipt_signature","receipt_digest"}}
    try: public.verify(base64.urlsafe_b64decode(value["receipt_signature"]+"="*(-len(value["receipt_signature"])%4)),canonical(signed))
    except Exception as exc: raise TransactionError("PUBLIC_PRESTATE_RECEIPT_SIGNATURE_DENIED") from exc
    return value


def _read_forward_state(adapter,path,plan,public):
    nofollow_ancestors(adapter.root,path,allow_missing=False); info=path.lstat()
    _deny(path.is_symlink() or not stat.S_ISREG(info.st_mode) or (os.name!="nt" and (info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)!=0o600)),"PUBLIC_FORWARD_STATE_CUSTODY_DENIED")
    value=json.loads(path.read_text(encoding="utf-8")); required={"schema","source_plan_sha256","prestate_receipt_digest","boot_id","generation_target","selector_pre","image_files","unit_prestate","phase","step","state_signature","state_digest"}
    _deny(set(value)!=required or value["schema"]!="SereinPublicOutpostForwardState/v1" or value["source_plan_sha256"]!=sha(canonical(plan)) or value["boot_id"]!=plan["current_boot_id"] or value["phase"] not in {"PREPARED","IMAGE","DAEMON_RELOAD","SELECTORS","TARGET_ENABLED","TARGET_STARTED","TERMINAL_ACCEPTED","COMPLETE"} or not isinstance(value["step"],int) or value["step"]<0,"PUBLIC_FORWARD_STATE_DENIED")
    _deny(value["state_digest"]!=sha(canonical({key:item for key,item in value.items() if key!="state_digest"})),"PUBLIC_FORWARD_STATE_DENIED")
    signed={key:item for key,item in value.items() if key not in {"state_signature","state_digest"}}
    try: public.verify(base64.urlsafe_b64decode(value["state_signature"]+"="*(-len(value["state_signature"])%4)),canonical(signed))
    except Exception as exc: raise TransactionError("PUBLIC_FORWARD_STATE_SIGNATURE_DENIED") from exc
    _deny(set(value["unit_prestate"])!=set(IMAGE_UNITS) or [row.get("target") for row in value["image_files"]]!=[item[0] for item in IMAGE_FILES.values()],"PUBLIC_FORWARD_STATE_DENIED")
    return value


def _recover_forward(adapter,rollback,plan,public,generation):
    forward_path=rollback/"forward-state.json"; forward=_read_forward_state(adapter,forward_path,plan,public)
    prestate=_read_prestate_receipt(adapter,rollback/"prestate-receipt.json",plan,public)
    _deny(forward["prestate_receipt_digest"]!=prestate["receipt_digest"] or any(forward[key]!=prestate[key] for key in ("source_plan_sha256","boot_id","generation_target","selector_pre","image_files","unit_prestate")),"PUBLIC_FORWARD_PRESTATE_BINDING_DENIED")
    _deny(forward["phase"]=="COMPLETE","PUBLIC_ROLLBACK_COLLISION_DENIED")
    state=under(adapter.root,"/var/lib/serein-outpost/generation-state"); candidate=rollback/"candidate.json"
    try: _,selected=read_selector(candidate,generation.parent)
    except Exception as exc: raise TransactionError("PUBLIC_FORWARD_CANDIDATE_DENIED") from exc
    _deny(selected!=generation,"PUBLIC_FORWARD_CANDIDATE_DENIED")
    for unit in reversed(IMAGE_UNITS): _compensate_unit(adapter,unit,forward["unit_prestate"][unit])
    selector_bytes=candidate.read_bytes(); current=state/"current.json"; lkg=state/"lkg.json"
    expected={"current":selector_bytes,"lkg":base64.b64decode(forward["selector_pre"]["current"]["content_b64"]) if forward["selector_pre"]["current"]["state"]=="PRESENT" else None}
    for name,path in (("current",current),("lkg",lkg)):
        before=forward["selector_pre"][name]; present=path.read_bytes() if path.exists() and not path.is_symlink() else None
        if present==expected[name]:
            if before["state"]=="PRESENT": atomic_write(adapter,path,base64.b64decode(before["content_b64"]),before["mode"],before["uid"],before["gid"])
            elif os.path.lexists(path): adapter.boundary(); path.unlink()
        elif before["state"]=="PRESENT" and present==base64.b64decode(before["content_b64"]): pass
        elif before["state"]=="ABSENT" and present is None: pass
        else: raise TransactionError("PUBLIC_FORWARD_SELECTOR_CAS_DENIED")
    for item in reversed(forward["image_files"]): _restore_file_state(adapter,under(adapter.root,item["target"]),item["pre"],item["post"])
    adapter.daemon_reload()
    if generation.exists():
        inventory=json.loads((generation/"generation-inventory.json").read_text(encoding="utf-8")); _remove_exact_generation(adapter,generation,inventory,candidate)
    if candidate.exists(): adapter.boundary(); candidate.unlink()
    evidence=rollback.with_name(rollback.name+".recovered-"+forward["state_digest"][:12]); _deny(os.path.lexists(evidence),"PUBLIC_RECOVERY_EVIDENCE_COLLISION_DENIED")
    adapter.boundary(); rollback.rename(evidence)
    return evidence


def _read_rollback_state(adapter,path,receipt,public):
    nofollow_ancestors(adapter.root,path,allow_missing=False); info=path.lstat()
    _deny(path.is_symlink() or not stat.S_ISREG(info.st_mode) or (os.name!="nt" and (info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)!=0o600)),"PUBLIC_ROLLBACK_STATE_CUSTODY_DENIED")
    value=json.loads(path.read_text(encoding="utf-8")); required={"schema","receipt_digest","receipt_signature","phase","step","state_signature","state_digest"}
    _deny(set(value)!=required or value["schema"]!="SereinPublicOutpostRollbackState/v1" or value["receipt_digest"]!=receipt["receipt_digest"] or value["receipt_signature"]!=receipt["receipt_signature"] or value["phase"] not in {"SELECTORS","GENERATION","COMPLETE"} or not isinstance(value["step"],int) or value["step"]<0 or value["state_digest"]!=sha(canonical({key:item for key,item in value.items() if key!="state_digest"})),"PUBLIC_ROLLBACK_STATE_DENIED")
    try: public.verify(base64.urlsafe_b64decode(value["state_signature"]+"="*(-len(value["state_signature"])%4)),_state_signed(value))
    except Exception as exc: raise TransactionError("PUBLIC_ROLLBACK_STATE_SIGNATURE_DENIED") from exc
    return value


def _row_matches(adapter,path,row):
    if row["state"]=="ABSENT": return not os.path.lexists(path)
    try: exact_file(adapter,path,{"target":"/"+path.relative_to(adapter.root).as_posix(),**{key:row[key] for key in ("bytes","sha256","mode","uid","gid")}}); return True
    except Exception: return False


def _file_state(adapter,path):
    if not os.path.lexists(path): return {"target":"/"+path.relative_to(adapter.root).as_posix(),"state":"ABSENT"}
    nofollow_ancestors(adapter.root,path,allow_missing=False); info=path.lstat()
    _deny(path.is_symlink() or not stat.S_ISREG(info.st_mode),"PUBLIC_IMAGE_PRESTATE_DENIED")
    data=path.read_bytes(); metadata=adapter.file_metadata(path)
    return {"target":"/"+path.relative_to(adapter.root).as_posix(),"state":"PRESENT","bytes":len(data),"sha256":sha(data),"mode":f"{metadata['mode']:04o}","uid":metadata["uid"],"gid":metadata["gid"],"content_b64":base64.b64encode(data).decode()}


def _unit_state(adapter,name):
    state=adapter.read_unit(name)
    return {"enabled":state.get("enabled","not-found"),"active":state.get("active","inactive")}


def _unit_action(adapter,action,name):
    _deny(name not in IMAGE_UNITS or action not in {"enable","disable","start","stop"},"PUBLIC_UNIT_ACTION_DENIED")
    adapter.boundary()
    if hasattr(adapter,"unit_state") and not adapter.__class__.__name__=="RealAdapter":
        state=adapter.unit_state.setdefault(name,{"enabled":"disabled","active":"inactive"})
        if action in {"enable","disable"}: state["enabled"]="enabled" if action=="enable" else "disabled"
        else: state["active"]="active" if action=="start" else "inactive"
    else: subprocess.run(["systemctl",action,name],check=True)


def _restore_unit(adapter,name,before,after):
    current=_unit_state(adapter,name)
    _deny(current not in (before,after),"PUBLIC_UNIT_ROLLBACK_CAS_DENIED")
    if current==before: return
    if hasattr(adapter,"unit_state") and not adapter.__class__.__name__=="RealAdapter":
        adapter.boundary(); adapter.unit_state[name]=dict(before); return
    if current["active"]!=before["active"]: _unit_action(adapter,"start" if before["active"]=="active" else "stop",name)
    if current["enabled"]!=before["enabled"]: _unit_action(adapter,"enable" if before["enabled"]=="enabled" else "disable",name)


def _compensate_unit(adapter,name,before):
    current=_unit_state(adapter,name)
    if current==before: return
    if hasattr(adapter,"unit_state") and not adapter.__class__.__name__=="RealAdapter":
        adapter.boundary(); adapter.unit_state[name]=dict(before); return
    if current["active"]!=before["active"]: _unit_action(adapter,"start" if before["active"]=="active" else "stop",name)
    if current["enabled"]!=before["enabled"]: _unit_action(adapter,"enable" if before["enabled"]=="enabled" else "disable",name)


def _restore_file_state(adapter,path,before,after):
    if _row_matches(adapter,path,after):
        if before["state"]=="PRESENT": atomic_write(adapter,path,base64.b64decode(before["content_b64"]),before["mode"],before["uid"],before["gid"])
        else: adapter.boundary(); path.unlink()
    elif not _row_matches(adapter,path,before): raise TransactionError("PUBLIC_IMAGE_ROLLBACK_CAS_DENIED")


def rollback_public_generation(adapter, rollback):
    rollback=Path(rollback)
    canonical_parent=under(adapter.root,"/var/lib/serein/rollback")
    _deny(rollback.parent!=canonical_parent or not ROLLBACK_RE.fullmatch(rollback.name),"PUBLIC_ROLLBACK_SELECTOR_DENIED")
    nofollow_ancestors(adapter.root,rollback,allow_missing=False)
    parent_info=canonical_parent.lstat(); rollback_info=rollback.lstat()
    _deny(canonical_parent.is_symlink() or not stat.S_ISDIR(parent_info.st_mode) or rollback.is_symlink() or not stat.S_ISDIR(rollback_info.st_mode) or (os.name!="nt" and (parent_info.st_uid!=0 or parent_info.st_gid!=0 or stat.S_IMODE(parent_info.st_mode)!=0o700 or rollback_info.st_uid!=0 or rollback_info.st_gid!=0 or stat.S_IMODE(rollback_info.st_mode)!=0o700)),"PUBLIC_ROLLBACK_CUSTODY_DENIED")
    receipt_path=rollback/"transaction-receipt.json"; nofollow_ancestors(adapter.root,receipt_path,allow_missing=False)
    receipt_info=receipt_path.lstat(); _deny(receipt_path.is_symlink() or not stat.S_ISREG(receipt_info.st_mode) or (os.name!="nt" and (receipt_info.st_uid!=0 or receipt_info.st_gid!=0 or stat.S_IMODE(receipt_info.st_mode)!=0o600)),"PUBLIC_RECEIPT_CUSTODY_DENIED")
    value=json.loads(receipt_path.read_text(encoding="utf-8"))
    required={"schema","source","boot_id","immutable_pre","immutable_post","generation_target","generation_inventory","state_dir_pre","state_dir_post","selector_pre","selector_post","service_deltas","probe_evidence","api_vitals_evidence","terminal_evidence","rollback_selector","rollback_complete","receipt_key_fingerprint","receipt_signature","receipt_digest"}
    _deny(set(value)!=required or value.get("schema")!="SereinPublicOutpostGenerationReceipt/v1" or value.get("receipt_digest")!=_receipt_digest(value) or value.get("rollback_complete") is not False or value.get("rollback_selector")!="/"+rollback.relative_to(adapter.root).as_posix(),"PUBLIC_RECEIPT_DENIED")
    anchor=under(adapter.root,"/usr/share/serein/outpost/cognition-verification.pem"); anchor_bytes=anchor.read_bytes()
    _deny(value["receipt_key_fingerprint"]!=sha(anchor_bytes),"PUBLIC_RECEIPT_AUTHORITY_DENIED")
    public=load_pem_public_key(anchor_bytes)
    try: public.verify(base64.urlsafe_b64decode(value["receipt_signature"]+"="*(-len(value["receipt_signature"])%4)),_receipt_signed(value))
    except Exception as exc: raise TransactionError("PUBLIC_RECEIPT_SIGNATURE_DENIED") from exc
    _deny(value["generation_target"]!="/usr/share/serein/outpost-generations/"+value["source"]["release_digest"].removeprefix("sha256:"),"PUBLIC_RECEIPT_TARGET_DENIED")
    for row in value["immutable_post"]: exact_file(adapter,under(adapter.root,row["target"]),row)
    private=load_pem_private_key(under(adapter.root,"/etc/serein-outpost/cognition-signing.pem").read_bytes(),password=None)
    _deny(private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)!=anchor_bytes,"PUBLIC_RECEIPT_KEYPAIR_DENIED")
    journal_path=rollback/"rollback-state.json"
    if os.path.lexists(journal_path): journal=_read_rollback_state(adapter,journal_path,value,public)
    else: journal=_write_rollback_state(adapter,journal_path,{"schema":"SereinPublicOutpostRollbackState/v1","receipt_digest":value["receipt_digest"],"receipt_signature":value["receipt_signature"],"phase":"SELECTORS","step":0},private)
    _deny(journal["phase"]=="COMPLETE","PUBLIC_ROLLBACK_REPLAY_DENIED")
    image=value["service_deltas"]
    _deny(not isinstance(image,dict) or set(image)!={"files","units"} or set(image["units"])!=set(IMAGE_UNITS),"PUBLIC_IMAGE_RECEIPT_DENIED")
    # Stop only the target we started, then restore the exact enablement state.
    for unit in reversed(IMAGE_UNITS): _restore_unit(adapter,unit,image["units"][unit]["pre"],image["units"][unit]["post"])
    for item in reversed(image["files"]):
        _restore_file_state(adapter,under(adapter.root,item["target"]),item["pre"],item["post"])
    adapter.daemon_reload()
    state=under(adapter.root,"/var/lib/serein-outpost/generation-state"); current=state/"current.json"; lkg=state/"lkg.json"
    _deny(value["selector_post"]["current"]["target"]!="/var/lib/serein-outpost/generation-state/current.json" or value["selector_post"]["lkg"]["target"]!="/var/lib/serein-outpost/generation-state/lkg.json","PUBLIC_RECEIPT_TARGET_DENIED")
    post=value["selector_post"]
    selector_actions=((lkg,"lkg"),(current,"current"))
    if journal["phase"]=="SELECTORS":
        for index,(path,name) in enumerate(selector_actions):
            if index<journal["step"]: continue
            before=value["selector_pre"][name]; after=post[name]
            if _row_matches(adapter,path,after):
                if before["state"]=="PRESENT": atomic_write(adapter,path,base64.b64decode(before["content_b64"]),before["mode"],0,0)
                elif os.path.lexists(path): adapter.boundary(); path.unlink()
            elif not _row_matches(adapter,path,before): raise TransactionError("PUBLIC_ROLLBACK_SELECTOR_CAS_DENIED")
            journal=_write_rollback_state(adapter,journal_path,{**{key:item for key,item in journal.items() if key not in {"state_digest","state_signature"}},"step":index+1},private)
        if journal["step"]<3:
            info=state.lstat(); current_row={"target":"/var/lib/serein-outpost/generation-state","state":"PRESENT","mode":f"{stat.S_IMODE(info.st_mode):04o}","uid":info.st_uid,"gid":info.st_gid}
            if current_row==value["state_dir_post"]: adapter.boundary(); os.chmod(state,int(value["state_dir_pre"]["mode"],8))
            elif current_row!=value["state_dir_pre"]: raise TransactionError("PUBLIC_ROLLBACK_STATE_DIR_CAS_DENIED")
            journal=_write_rollback_state(adapter,journal_path,{**{key:item for key,item in journal.items() if key not in {"state_digest","state_signature"}},"step":3},private)
        journal=_write_rollback_state(adapter,journal_path,{**{key:item for key,item in journal.items() if key not in {"state_digest","state_signature"}},"phase":"GENERATION","step":0},private)
    candidate=rollback/"candidate.json"; generation=under(adapter.root,value["generation_target"])
    if journal["phase"]=="GENERATION":
        # Validate the whole candidate before the first deletion; retries then
        # accept only the exact receipt suffix already removed by prior steps.
        inventory=value["generation_inventory"]
        actions=[]
        actions.extend(("file",generation/row["path"],row) for row in sorted((item for item in inventory if item["kind"]=="file"),key=lambda item:item["path"],reverse=True))
        inventory_data=(json.dumps(inventory,sort_keys=True,separators=(",",":"))+"\n").encode(); actions.append(("file",generation/"generation-inventory.json",{"bytes":len(inventory_data),"sha256":sha(inventory_data),"mode":"0644","uid":0,"gid":0}))
        actions.extend(("directory",generation/row["path"],row) for row in sorted((item for item in inventory if item["kind"]=="directory"),key=lambda item:item["path"].count("/"),reverse=True)); actions.append(("directory",generation,{"mode":"0755","uid":0,"gid":0}))
        for index,(kind,path,row) in enumerate(actions):
            if index<journal["step"]: _deny(os.path.lexists(path),"PUBLIC_ROLLBACK_PHASE_STATE_DENIED"); continue
            if os.path.lexists(path):
                if kind=="file": exact_file(adapter,path,{"target":"/"+path.relative_to(adapter.root).as_posix(),**{key:row[key] for key in ("bytes","sha256","mode","uid","gid")}})
                else:
                    info=path.lstat(); _deny(path.is_symlink() or not stat.S_ISDIR(info.st_mode) or any(path.iterdir()) or (os.name!="nt" and (info.st_uid!=row["uid"] or info.st_gid!=row["gid"] or stat.S_IMODE(info.st_mode)!=int(row["mode"],8))),"PUBLIC_ROLLBACK_GENERATION_CAS_DENIED")
                adapter.boundary(); path.unlink() if kind=="file" else path.rmdir()
            journal=_write_rollback_state(adapter,journal_path,{**{key:item for key,item in journal.items() if key not in {"state_digest","state_signature"}},"step":index+1},private)
        journal=_write_rollback_state(adapter,journal_path,{**{key:item for key,item in journal.items() if key not in {"state_digest","state_signature"}},"phase":"COMPLETE","step":len(actions)},private)
    return {**value,"rollback_complete":True,"rollback_state_digest":journal["state_digest"]}


def install_public_generation(adapter, plan, authority_path, fetch, probe, accept):
    """Download, stage, probe and atomically select one exact public generation."""
    _verify_plan(plan,authority_path)
    boot=under(adapter.root,"/proc/sys/kernel/random/boot_id").read_text().strip()
    _deny(boot!=plan["current_boot_id"],"PUBLIC_BOOT_DRIFT_DENIED")
    for row in plan["immutable_rows"]: exact_file(adapter,under(adapter.root,row["target"]),row)
    state=under(adapter.root,"/var/lib/serein-outpost/generation-state")
    predecessor_ok=False
    for selector_path in (state/"current.json",state/"lkg.json"):
        try:
            read_selector(selector_path,under(adapter.root,"/usr/share/serein/outpost-generations")); predecessor_ok=True; break
        except Exception:
            pass
    _deny(not predecessor_ok,"PUBLIC_UPDATE_PREDECESSOR_REQUIRED")
    rollback=under(adapter.root,plan["rollback_selector"]); nofollow_ancestors(adapter.root,rollback)
    _deny(rollback.parent!=under(adapter.root,"/var/lib/serein/rollback") or not ROLLBACK_RE.fullmatch(rollback.name),"PUBLIC_ROLLBACK_SELECTOR_DENIED")
    parent_info=rollback.parent.lstat(); _deny(rollback.parent.is_symlink() or not stat.S_ISDIR(parent_info.st_mode) or (os.name!="nt" and (parent_info.st_uid!=0 or parent_info.st_gid!=0 or stat.S_IMODE(parent_info.st_mode) not in {0o700,0o755})),"PUBLIC_ROLLBACK_PARENT_DENIED")
    lock=under(adapter.root,"/var/lib/serein/rollback/.outpost-public-generation.lock")
    nofollow_ancestors(adapter.root,lock); _deny(os.path.lexists(lock),"PUBLIC_TRANSACTION_LOCKED")
    lock.parent.mkdir(parents=True,exist_ok=True); descriptor=os.open(lock,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
    generation=None; flipped=False; old_current=None; old_lkg=None; published_current=None; published_lkg=None; state_pre_mode=None; state_mode_changed=False; written=[]; written_expected={}; created_dirs=[]; image_files=[]; image_units={}; image_applied=False; target_started=False; target_enabled=False
    try:
        os.write(descriptor,b"locked\n"); os.fsync(descriptor)
        raw,final_url=fetch(plan["archive_url"])
        _deny(final_url!=plan["archive_url"],"PUBLIC_REDIRECT_DENIED")
        release,files=_safe_archive(raw,plan)
        generation_id=plan["release_digest"].removeprefix("sha256:")
        generation=under(adapter.root,"/usr/share/serein/outpost-generations/"+generation_id)
        if os.path.lexists(rollback) and (rollback/"forward-state.json").exists():
            anchor_bytes=Path(authority_path).read_bytes(); public=load_pem_public_key(anchor_bytes)
            pending=_read_forward_state(adapter,rollback/"forward-state.json",plan,public)
            if pending["phase"]!="COMPLETE": _recover_forward(adapter,rollback,plan,public,generation)
        if os.path.lexists(generation):
            current=state/"current.json"
            try: _,selected=read_selector(current,generation.parent)
            except Exception as exc: raise TransactionError("PUBLIC_GENERATION_COLLISION_DENIED") from exc
            _deny(selected!=generation or not _acceptance_pass(accept(generation,current,boot),boot,plan["release_digest"]),"PUBLIC_GENERATION_COLLISION_DENIED")
            lkg_path=state/"lkg.json"
            return {"status":"ALREADY_COMMITTED","generation":generation_id,"release_digest":plan["release_digest"],"current_selector_sha256":sha(current.read_bytes()),"lkg_selector_sha256":sha(lkg_path.read_bytes()) if lkg_path.exists() else "ABSENT"}
        _deny(os.path.lexists(rollback),"PUBLIC_ROLLBACK_COLLISION_DENIED")
        adapter.boundary(); generation.mkdir(parents=True,mode=0o755); created_dirs.append(generation)
        directory_names=sorted({parent.as_posix() for name in files for parent in PurePosixPath(name).parents if parent.as_posix()!="."},key=lambda value:(value.count("/"),value))
        inventory=[{"kind":"directory","path":name,"mode":"0755","uid":0,"gid":0} for name in directory_names]
        for name,data in sorted(files.items()):
            target=generation/name
            missing=[]; cursor=target.parent
            while cursor!=generation and not cursor.exists(): missing.append(cursor); cursor=cursor.parent
            for directory in reversed(missing): adapter.boundary(); directory.mkdir(mode=0o755); created_dirs.append(directory)
            atomic_write(adapter,target,data,"0644",0,0)
            written.append(target); written_expected[target]={"target":"/"+target.relative_to(adapter.root).as_posix(),"bytes":len(data),"sha256":sha(data),"mode":"0644","uid":0,"gid":0}
            inventory.append({"kind":"file","path":name,"bytes":len(data),"sha256":sha(data),"mode":"0644","uid":0,"gid":0})
        inventory_data=(json.dumps(inventory,sort_keys=True,separators=(",",":"))+"\n").encode(); inventory_path=generation/"generation-inventory.json"; atomic_write(adapter,inventory_path,inventory_data,"0644",0,0); written.append(inventory_path); written_expected[inventory_path]={"target":"/"+inventory_path.relative_to(adapter.root).as_posix(),"bytes":len(inventory_data),"sha256":sha(inventory_data),"mode":"0644","uid":0,"gid":0}
        selector={"schema":"SereinOutpostGenerationSelector/v1","generation":generation_id,"release_digest":plan["release_digest"],"predecessor_receipt_sha256":sha(canonical(plan)),"inventory_digest":sha(canonical(inventory))}
        selector["selector_digest"]=generation_selector_digest(selector)
        candidate=rollback/"candidate.json"; adapter.boundary(); rollback.mkdir(mode=0o700)
        candidate_data=(json.dumps(selector,indent=2)+"\n").encode(); atomic_write(adapter,candidate,candidate_data,"0600",0,0); written.append(candidate); written_expected[candidate]={"target":"/"+candidate.relative_to(adapter.root).as_posix(),"bytes":len(candidate_data),"sha256":sha(candidate_data),"mode":"0600","uid":0,"gid":0}
        read_selector(candidate,generation.parent)
        current=state/"current.json"; lkg=state/"lkg.json"
        state_info=state.lstat(); _deny(state.is_symlink() or not stat.S_ISDIR(state_info.st_mode) or (os.name!="nt" and (state_info.st_uid!=0 or state_info.st_gid!=0 or stat.S_IMODE(state_info.st_mode) not in {0o700,0o755})),"PUBLIC_STATE_DIR_CUSTODY_DENIED")
        state_pre_mode=f"{stat.S_IMODE(state_info.st_mode):04o}"
        old_current=current.read_bytes() if current.exists() and not current.is_symlink() else None; observed_current=old_current
        old_lkg=lkg.read_bytes() if lkg.exists() and not lkg.is_symlink() else None
        old_current_mode=f"{adapter.file_metadata(current)['mode']:04o}" if old_current is not None else None
        old_lkg_mode=f"{adapter.file_metadata(lkg)['mode']:04o}" if old_lkg is not None else None
        if old_current is not None:
            try: read_selector(current,generation.parent)
            except Exception:
                try: read_selector(lkg,generation.parent); old_current=old_lkg
                except Exception as exc: raise TransactionError("PUBLIC_CURRENT_AND_LKG_DENIED") from exc
        _deny(old_current is None,"PUBLIC_UPDATE_PREDECESSOR_REQUIRED")
        probe_evidence=probe(generation,candidate,boot); _deny(not _acceptance_pass(probe_evidence,boot,plan["release_digest"]),"PUBLIC_CANDIDATE_PROBE_DENIED")
        api_evidence=accept(generation,candidate,boot); _deny(not _acceptance_pass(api_evidence,boot,plan["release_digest"]),"PUBLIC_CANDIDATE_ACCEPTANCE_DENIED")
        for source,(absolute,mode) in IMAGE_FILES.items():
            _deny(source not in files,"PUBLIC_IMAGE_PAYLOAD_MISSING")
            target=under(adapter.root,absolute); before=_file_state(adapter,target); data=files[source]
            post={"target":absolute,"state":"PRESENT","bytes":len(data),"sha256":sha(data),"mode":mode,"uid":0,"gid":0,"content_b64":base64.b64encode(data).decode()}
            if before["state"]=="PRESENT": exact_file(adapter,target,before)
            else: target.parent.mkdir(parents=True,exist_ok=True)
            image_files.append({"target":absolute,"pre":before,"post":post})
        image_units={unit:{"pre":_unit_state(adapter,unit)} for unit in IMAGE_UNITS}
        verification=under(adapter.root,"/usr/share/serein/outpost/cognition-verification.pem").read_bytes(); signing=under(adapter.root,"/etc/serein-outpost/cognition-signing.pem").read_bytes(); private=load_pem_private_key(signing,password=None)
        derived=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        _deny(derived!=verification,"PUBLIC_RECEIPT_KEYPAIR_DENIED")
        forward_path=rollback/"forward-state.json"
        prestate={"schema":"SereinPublicOutpostPrestateReceipt/v1","source_plan_sha256":sha(canonical(plan)),"boot_id":boot,"generation_target":"/"+generation.relative_to(adapter.root).as_posix(),"selector_pre":{"current":_selector_pre(current,observed_current,old_current_mode),"lkg":_selector_pre(lkg,old_lkg,old_lkg_mode)},"image_files":image_files,"unit_prestate":{unit:item["pre"] for unit,item in image_units.items()}}
        prestate=_write_prestate_receipt(adapter,rollback/"prestate-receipt.json",prestate,private)
        forward={"schema":"SereinPublicOutpostForwardState/v1","source_plan_sha256":prestate["source_plan_sha256"],"prestate_receipt_digest":prestate["receipt_digest"],"boot_id":boot,"generation_target":prestate["generation_target"],"selector_pre":prestate["selector_pre"],"image_files":image_files,"unit_prestate":prestate["unit_prestate"],"phase":"PREPARED","step":0}
        forward=_write_forward_state(adapter,forward_path,forward,private)
        # A public installer must be able to replace a healthy running Outpost.
        # Stop only the captured Outpost image units after the signed prestate
        # and forward journal exist.  Compensation/re-entry restores the exact
        # captured active/enabled state if any later boundary fails.
        for unit in reversed(IMAGE_UNITS):
            if image_units[unit]["pre"]["active"]=="active": _unit_action(adapter,"stop",unit)
        forward=_write_forward_state(adapter,forward_path,{key:item for key,item in forward.items() if key not in {"state_digest","state_signature"}}|{"phase":"PREPARED","step":1},private)
        for index,(source,(absolute,mode)) in enumerate(IMAGE_FILES.items()):
            target=under(adapter.root,absolute); atomic_write(adapter,target,files[source],mode,0,0)
            forward=_write_forward_state(adapter,forward_path,{key:item for key,item in forward.items() if key not in {"state_digest","state_signature"}}|{"phase":"IMAGE","step":index+1},private)
        image_applied=True; adapter.daemon_reload()
        forward=_write_forward_state(adapter,forward_path,{key:item for key,item in forward.items() if key not in {"state_digest","state_signature"}}|{"phase":"DAEMON_RELOAD","step":0},private)
        if state_pre_mode!="0755": adapter.boundary(); os.chmod(state,0o755); state_mode_changed=True
        # Compare-and-swap the exact observed selector objects after every
        # candidate probe and immediately before publishing either selector.
        adapter.boundary()
        if observed_current is None:
            _deny(os.path.lexists(current),"PUBLIC_CURRENT_SELECTOR_CAS_DENIED")
        else:
            try:
                metadata=adapter.file_metadata(current); exact_file(adapter,current,{"target":"/"+current.relative_to(adapter.root).as_posix(),"bytes":len(observed_current),"sha256":sha(observed_current),"mode":f"{metadata['mode']:04o}","uid":metadata["uid"],"gid":metadata["gid"]})
            except Exception as exc: raise TransactionError("PUBLIC_CURRENT_SELECTOR_CAS_DENIED") from exc
        if old_lkg is None:
            _deny(os.path.lexists(lkg),"PUBLIC_LKG_SELECTOR_CAS_DENIED")
        else:
            try:
                metadata=adapter.file_metadata(lkg); exact_file(adapter,lkg,{"target":"/"+lkg.relative_to(adapter.root).as_posix(),"bytes":len(old_lkg),"sha256":sha(old_lkg),"mode":f"{metadata['mode']:04o}","uid":metadata["uid"],"gid":metadata["gid"]})
            except Exception as exc: raise TransactionError("PUBLIC_LKG_SELECTOR_CAS_DENIED") from exc
        published_current=(json.dumps(selector,indent=2)+"\n").encode(); published_lkg=old_current
        if published_lkg is not None: atomic_write(adapter,lkg,published_lkg,"0644",0,0)
        atomic_write(adapter,current,published_current,"0644",0,0); flipped=True
        forward=_write_forward_state(adapter,forward_path,{key:item for key,item in forward.items() if key not in {"state_digest","state_signature"}}|{"phase":"SELECTORS","step":0},private)
        if image_units["serein-outpost.target"]["pre"]["enabled"]!="enabled": _unit_action(adapter,"enable","serein-outpost.target"); target_enabled=True
        forward=_write_forward_state(adapter,forward_path,{key:item for key,item in forward.items() if key not in {"state_digest","state_signature"}}|{"phase":"TARGET_ENABLED","step":0},private)
        _unit_action(adapter,"start","serein-outpost.target"); target_started=True
        forward=_write_forward_state(adapter,forward_path,{key:item for key,item in forward.items() if key not in {"state_digest","state_signature"}}|{"phase":"TARGET_STARTED","step":0},private)
        for unit in IMAGE_UNITS: image_units[unit]["post"]=_unit_state(adapter,unit)
        _deny(image_units["serein-outpost.target"]["post"]["active"]!="active" or image_units["serein-outpost.target"]["post"]["enabled"]!="enabled","PUBLIC_TARGET_ACTIVATION_DENIED")
        terminal_evidence=accept(generation,current,boot)
        _deny(not _acceptance_pass(terminal_evidence,boot,plan["release_digest"]),"PUBLIC_POSTFLIP_ACCEPTANCE_DENIED")
        _deny(not _fresh_acceptance(api_evidence,terminal_evidence),"PUBLIC_STALE_VITALITY_DENIED")
        forward=_write_forward_state(adapter,forward_path,{key:item for key,item in forward.items() if key not in {"state_digest","state_signature"}}|{"phase":"TERMINAL_ACCEPTED","step":0},private)
        for row in plan["immutable_rows"]: exact_file(adapter,under(adapter.root,row["target"]),row)
        selector_bytes=(json.dumps(selector,indent=2)+"\n").encode()
        def selector_state(path,data,mode):
            if data is None: return {"target":"/"+path.relative_to(adapter.root).as_posix(),"state":"ABSENT"}
            return {"target":"/"+path.relative_to(adapter.root).as_posix(),"state":"PRESENT","bytes":len(data),"sha256":sha(data),"mode":mode,"uid":0,"gid":0,"content_b64":base64.b64encode(data).decode()}
        state_dir_pre={"target":"/var/lib/serein-outpost/generation-state","state":"PRESENT","mode":state_pre_mode,"uid":0,"gid":0}; state_dir_post={**state_dir_pre,"mode":"0755"}
        receipt={"schema":"SereinPublicOutpostGenerationReceipt/v1","source":{"repository":plan["repository"],"repo_url":plan["repo_url"],"ref":plan["ref"],"commit":plan["commit"],"tree":plan["tree"],"archive_url":plan["archive_url"],"archive_sha256":plan["archive_sha256"],"release_digest":plan["release_digest"],"authority_key_id":plan["authority_key_id"],"authority_sha256":plan["authority_sha256"],"signature":plan["signature"]},"boot_id":boot,"immutable_pre":plan["immutable_rows"],"immutable_post":plan["immutable_rows"],"generation_target":"/"+generation.relative_to(adapter.root).as_posix(),"generation_inventory":inventory,"state_dir_pre":state_dir_pre,"state_dir_post":state_dir_post,"selector_pre":{"current":selector_state(current,observed_current,old_current_mode),"lkg":selector_state(lkg,old_lkg,old_lkg_mode)},"selector_post":{"current":selector_state(current,selector_bytes,"0644"),"lkg":selector_state(lkg,old_current,"0644")},"service_deltas":{"files":image_files,"units":image_units},"probe_evidence":probe_evidence,"api_vitals_evidence":api_evidence,"terminal_evidence":terminal_evidence,"rollback_selector":plan["rollback_selector"],"rollback_complete":False}
        if old_current is None: receipt["selector_post"]["lkg"]=selector_state(lkg,None,"0644")
        receipt["receipt_key_fingerprint"]=sha(verification); receipt["receipt_signature"]=base64.urlsafe_b64encode(private.sign(_receipt_signed(receipt))).decode().rstrip("="); receipt["receipt_digest"]=_receipt_digest(receipt); atomic_write(adapter,rollback/"transaction-receipt.json",(json.dumps(receipt,indent=2)+"\n").encode(),"0600",0,0)
        _write_forward_state(adapter,forward_path,{key:item for key,item in forward.items() if key not in {"state_digest","state_signature"}}|{"phase":"COMPLETE","step":0},private)
        return {"status":"COMMITTED","generation":generation_id,"release_digest":plan["release_digest"],"current_selector_sha256":sha(current.read_bytes()),"lkg_selector_sha256":sha(lkg.read_bytes()) if lkg.exists() else "ABSENT"}
    except Exception:
        if image_units:
            for unit in reversed(IMAGE_UNITS): _compensate_unit(adapter,unit,image_units[unit]["pre"])
        if flipped:
            current=state/"current.json"; lkg=state/"lkg.json"
            try:
                exact_file(adapter,current,{"target":"/"+current.relative_to(adapter.root).as_posix(),"bytes":len(published_current),"sha256":sha(published_current),"mode":"0644","uid":0,"gid":0})
                if published_lkg is None: _deny(os.path.lexists(lkg),"PUBLIC_POSTFLIP_LKG_CAS_DENIED")
                else: exact_file(adapter,lkg,{"target":"/"+lkg.relative_to(adapter.root).as_posix(),"bytes":len(published_lkg),"sha256":sha(published_lkg),"mode":"0644","uid":0,"gid":0})
            except Exception as exc: raise TransactionError("PUBLIC_POSTFLIP_SELECTOR_CAS_DENIED") from exc
            if old_current is not None: atomic_write(adapter,current,old_current,old_current_mode,0,0)
            elif current.exists(): current.unlink()
            if old_lkg is not None: atomic_write(adapter,lkg,old_lkg,old_lkg_mode,0,0)
            elif lkg.exists(): lkg.unlink()
            candidate=rollback/"candidate.json"
            _remove_exact_generation(adapter,generation,inventory,candidate)
            candidate_data=(json.dumps(selector,indent=2)+"\n").encode(); exact_file(adapter,candidate,{"target":"/"+candidate.relative_to(adapter.root).as_posix(),"bytes":len(candidate_data),"sha256":sha(candidate_data),"mode":"0600","uid":0,"gid":0}); adapter.boundary(); candidate.unlink()
            if not any(rollback.iterdir()): adapter.boundary(); rollback.rmdir()
        if not flipped:
            for target in written:
                if os.path.lexists(target):
                    try: exact_file(adapter,target,written_expected[target])
                    except Exception as exc: raise TransactionError("PUBLIC_STAGING_CLEANUP_CAS_DENIED") from exc
            for target in reversed(written):
                if os.path.lexists(target):
                    adapter.boundary(); target.unlink()
            for directory in sorted(created_dirs,key=lambda path:len(path.parts),reverse=True):
                if directory.exists() and not any(directory.iterdir()): directory.rmdir()
            if rollback.exists() and not any(rollback.iterdir()): rollback.rmdir()
        if state_mode_changed:
            info=state.lstat(); _deny(state.is_symlink() or not stat.S_ISDIR(info.st_mode) or (os.name!="nt" and stat.S_IMODE(info.st_mode)!=0o755),"PUBLIC_STATE_DIR_COMPENSATION_CAS_DENIED")
            adapter.boundary(); os.chmod(state,int(state_pre_mode,8))
        if image_files:
            for item in reversed(image_files): _restore_file_state(adapter,under(adapter.root,item["target"]),item["pre"],item["post"])
            adapter.daemon_reload()
        forward_path=rollback/"forward-state.json"
        if forward_path.exists():
            info=forward_path.lstat(); _deny(forward_path.is_symlink() or not stat.S_ISREG(info.st_mode),"PUBLIC_FORWARD_STATE_CUSTODY_DENIED")
            adapter.boundary(); forward_path.unlink()
        prestate_path=rollback/"prestate-receipt.json"
        if prestate_path.exists():
            info=prestate_path.lstat(); _deny(prestate_path.is_symlink() or not stat.S_ISREG(info.st_mode),"PUBLIC_PRESTATE_RECEIPT_CUSTODY_DENIED")
            adapter.boundary(); prestate_path.unlink()
        if rollback.exists() and not any(rollback.iterdir()): adapter.boundary(); rollback.rmdir()
        raise
    finally:
        os.close(descriptor); os.unlink(lock)

