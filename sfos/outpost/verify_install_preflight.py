#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path


def rooted(root, absolute):
    return root / absolute.lstrip("/")


def canonical(value): return json.dumps(value,sort_keys=True,separators=(",",":")).encode()


def verify_source(root,release,allowed_extra=frozenset()):
    if release.get("schema")!="SereinOutpostSourceRelease/v2": raise SystemExit("RELEASE_SCHEMA_DENIED")
    claimed=release.get("self_digest")
    unsigned={k:v for k,v in release.items() if k!="self_digest"}
    if claimed!="sha256:"+hashlib.sha256(canonical(unsigned)).hexdigest(): raise SystemExit("RELEASE_SELF_DIGEST_DENIED")
    expected={row["path"] for row in release["payload"]+release.get("source_only_files",[])}|{"release-manifest.json"}
    actual=set()
    for path in root.rglob("*"):
        if path.is_symlink(): raise SystemExit("SOURCE_SYMLINK_DENIED:"+str(path.relative_to(root)))
        if path.is_file(): actual.add(path.relative_to(root).as_posix())
    allowed=set(allowed_extra)
    extra=actual-expected
    missing=expected-actual
    if missing or not extra.issubset(allowed):
        raise SystemExit("SOURCE_DENOMINATOR_DENIED:"+json.dumps({"extra":sorted(extra-allowed),"missing":sorted(missing)}))


def verify_legacy_outpost_predecessor(root, expected, check_units=True):
    predecessor=expected["legacy_outpost_predecessor"]
    selector=rooted(root,predecessor["selector"])
    receipt_path=selector/("upgrade-receipt.json" if predecessor.get("receipt_type")=="UPGRADE_CHAIN" else "receipt.json")
    if selector.is_symlink() or not selector.is_dir() or receipt_path.is_symlink() or not receipt_path.is_file():
        raise SystemExit("LEGACY_OUTPOST_ROLLBACK_RECEIPT_DENIED")
    receipt_bytes=receipt_path.read_bytes()
    if hashlib.sha256(receipt_bytes).hexdigest()!=predecessor["receipt_sha256"]:
        raise SystemExit("LEGACY_OUTPOST_ROLLBACK_RECEIPT_HASH_DENIED")
    receipt=json.loads(receipt_bytes)
    if predecessor.get("receipt_type")=="UPGRADE_CHAIN":
        from install.upgrade_transaction import receipt_digest
        required={"schema","selector","predecessor_selector","predecessor_receipt_sha256","candidate_release_digest","kept_files","replaced_files","introduced_files","introduced_generated_files","unit_prestate","rollback_complete","receipt_digest"}
        if set(receipt)!=required or receipt.get("schema")!="SereinOutpostUpgradeRollback/v1" or receipt.get("selector")!=str(selector) or receipt.get("receipt_digest")!=receipt_digest(receipt) or receipt.get("rollback_complete") is not False:
            raise SystemExit("UPGRADE_PREDECESSOR_RECEIPT_STATE_DENIED")
        installed=rooted(root,"/usr/share/serein/outpost/release-manifest.json")
        if installed.is_symlink() or not installed.is_file() or hashlib.sha256(installed.read_bytes()).hexdigest()!=predecessor["installed_release_manifest_sha256"]:
            raise SystemExit("UPGRADE_PREDECESSOR_RELEASE_DENIED")
        release=json.loads(installed.read_text(encoding="utf-8"))
        if receipt["candidate_release_digest"]!=release.get("self_digest"): raise SystemExit("UPGRADE_PREDECESSOR_RELEASE_BINDING_DENIED")
        rows=receipt["kept_files"]+[x["candidate"] for x in receipt["replaced_files"]]+receipt["introduced_files"]+receipt["introduced_generated_files"]
        by_target={row["target"]:row for row in rows}; expected_targets={row["target"] for row in release["install_files"]}|{row["target"] for row in release["generated_files"]}|{row["target"] for row in release.get("required_immutable_inputs",[])}|{"/usr/share/serein/outpost/release-manifest.json"}
        if set(by_target)!=expected_targets: raise SystemExit("UPGRADE_PREDECESSOR_INVENTORY_DENIED")
        for row in by_target.values():
            path=rooted(root,row["target"]); info=path.stat() if path.exists() else None; data=path.read_bytes() if info else b""
            if path.is_symlink() or info is None or len(data)!=row["bytes"] or hashlib.sha256(data).hexdigest()!=row["sha256"] or (info.st_mode&0o777)!=int(row["mode"],8) or info.st_uid!=row["uid"] or info.st_gid!=row["gid"]: raise SystemExit("UPGRADE_PREDECESSOR_FILE_DENIED:"+row["target"])
    else:
        if receipt.get("receipt_digest")!=predecessor["receipt_digest"] or receipt.get("release_digest")!=predecessor["release_digest"] or receipt.get("rollback_complete") is not predecessor["rollback_complete"]:
            raise SystemExit("LEGACY_OUTPOST_ROLLBACK_RECEIPT_STATE_DENIED")
        installed=rooted(root,"/usr/share/serein/outpost/installed-manifest.json")
        if installed.is_symlink() or not installed.is_file() or hashlib.sha256(installed.read_bytes()).hexdigest()!=predecessor["installed_manifest_sha256"]:
            raise SystemExit("LEGACY_OUTPOST_INSTALLED_MANIFEST_DENIED")
        for row in receipt["introduced_files"]+receipt["generated_files"]:
            path=rooted(root,row["target"])
            if path.is_symlink() or not path.is_file(): raise SystemExit("LEGACY_OUTPOST_FILE_DENIED:"+row["target"])
            info=path.stat(); data=path.read_bytes()
            if len(data)!=row["bytes"] or hashlib.sha256(data).hexdigest()!=row["sha256"] or (info.st_mode&0o777)!=int(row["mode"],8) or info.st_uid!=row["uid"] or info.st_gid!=row["gid"]: raise SystemExit("LEGACY_OUTPOST_FILE_STATE_DENIED:"+row["target"])
        for row in receipt["introduced_directories"]:
            path=rooted(root,row["target"])
            if path.is_symlink() or not path.is_dir(): raise SystemExit("LEGACY_OUTPOST_DIRECTORY_DENIED:"+row["target"])
            info=path.stat()
            if (info.st_mode&0o777)!=int(row["mode"],8) or info.st_uid!=row["uid"] or info.st_gid!=row["gid"]: raise SystemExit("LEGACY_OUTPOST_DIRECTORY_STATE_DENIED:"+row["target"])
    if check_units:
        import grp,pwd
        identity=predecessor["identity"]
        try: user=pwd.getpwnam(identity["user"]); group=grp.getgrnam(identity["group"])
        except KeyError: raise SystemExit("LEGACY_OUTPOST_IDENTITY_DENIED") from None
        if user.pw_uid!=identity["uid"] or user.pw_gid!=identity["gid"] or group.gr_gid!=identity["gid"] or user.pw_dir!=identity["home"] or user.pw_shell!=identity["shell"]:
            raise SystemExit("LEGACY_OUTPOST_IDENTITY_DENIED")
        for unit,state in predecessor["required_unit_state"].items():
            enabled=subprocess.run(["systemctl","is-enabled",unit],text=True,capture_output=True).stdout.strip()
            active=subprocess.run(["systemctl","is-active",unit],text=True,capture_output=True).stdout.strip()
            if enabled!=state["enabled"] or active!=state["active"]: raise SystemExit("LEGACY_OUTPOST_UNIT_STATE_DENIED:"+unit)


def verify_target(root, preflight, check_units=True, allowed_immutable_targets=frozenset()):
    if preflight.get("schema")!="SereinOutpostInstallPreflight/v2" or preflight.get("transaction")!="FIRST_INSTALL_ONLY":
        raise SystemExit("FRESH_BASE_PROFILE_DENIED")
    expected=preflight["expected_before"]
    os_release={}
    for line in rooted(root,"/etc/os-release").read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key,value=line.split("=",1); os_release[key]=value.strip().strip('"')
    hostname=rooted(root,"/etc/hostname").read_text(encoding="utf-8").strip()
    if expected.get("hostname_policy")!="PRESERVE_NONEMPTY" or not hostname or len(hostname)>253 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*",hostname): raise SystemExit("TARGET_HOSTNAME_DENIED")
    if os_release.get("ID")!=expected["os_id"] or os_release.get("VERSION_ID")!=expected["os_version_id"]: raise SystemExit("TARGET_OS_DENIED")
    rollback=expected["rollback_base"]; base=rooted(root,rollback["path"])
    if base.is_symlink() or not base.is_dir(): raise SystemExit("ROLLBACK_BASE_DENIED")
    info=base.stat()
    if stat.S_IMODE(info.st_mode)!=int(rollback["mode"],8) or info.st_uid!=rollback["uid"] or info.st_gid!=rollback["gid"]: raise SystemExit("ROLLBACK_BASE_POLICY_DENIED")
    for absolute in expected["must_be_absent"]:
        path=rooted(root,absolute)
        current=root
        for part in path.relative_to(root).parts:
            current=current/part
            if os.path.lexists(current) and current.is_symlink(): raise SystemExit("TARGET_PATH_SYMLINK_DENIED:"+absolute)
        if os.path.lexists(path):
            allowed={rooted(root,target) for target in allowed_immutable_targets if target.startswith(absolute.rstrip("/")+"/")}
            if not allowed or path.is_symlink() or not path.is_dir(): raise SystemExit("FRESH_BASE_RESIDUE_DENIED:"+absolute)
            actual={item for item in path.rglob("*") if item.is_file() or item.is_symlink()}
            if actual!=allowed: raise SystemExit("IMMUTABLE_BOOTSTRAP_RESIDUE_DENIED:"+absolute)
    if check_units:
        for unit,state in expected["unit_state"].items():
            enabled=subprocess.run(["systemctl","is-enabled",unit],text=True,capture_output=True).stdout.strip()
            active=subprocess.run(["systemctl","is-active",unit],text=True,capture_output=True).stdout.strip()
            if enabled!=state["enabled"] or active!=state["active"]: raise SystemExit("EXPECTED_BEFORE_UNIT_STATE_DENIED:"+unit)


def main():
    p=argparse.ArgumentParser(); p.add_argument("--source",required=True); p.add_argument("--mode",choices=("source","target","boot"),default="source"); p.add_argument("--target-root",default="/"); p.add_argument("--manifest"); p.add_argument("--verification-anchor"); p.add_argument("--trust-policy"); p.add_argument("--immutable-input-plan"); a=p.parse_args(); root=Path(a.source).resolve()
    release=json.loads((root/"release-manifest.json").read_text(encoding="utf-8"))
    installed_generated=set()
    if a.mode=="boot":
        prefix="/usr/share/serein/outpost/"
        installed_generated={row["target"][len(prefix):] for row in release["generated_files"]+release.get("required_immutable_inputs",[]) if row["target"].startswith(prefix)}
    verify_source(root,release,installed_generated)
    for row in release["payload"]+release.get("source_only_files",[]):
        path=(root/row["path"]).resolve()
        if root not in path.parents or not path.is_file(): raise SystemExit("PAYLOAD_PATH_DENIED")
        data=path.read_bytes()
        if len(data)!=row["bytes"] or hashlib.sha256(data).hexdigest()!=row["sha256"]: raise SystemExit("PAYLOAD_HASH_DENIED")
    graph=json.loads((root/"integration-graph.json").read_text(encoding="utf-8"))
    witness=(root/"systemd/serein-outpost-host-witness.service").read_text(encoding="utf-8")
    presentation=(root/"systemd/serein-outpost-presentation.service").read_text(encoding="utf-8")
    target=(root/"systemd/serein-outpost.target").read_text(encoding="utf-8")
    target_directives={}
    for line in target.splitlines():
        if "=" in line:
            key,value=line.split("=",1);target_directives.setdefault(key,set()).update(value.split())
    required=("Before=serein-outpost-presentation.service" in witness
              and {"serein-outpost-presentation.service","serein-outpost-host-witness.service"} <= target_directives.get("Requires",set())
              and {"serein-outpost-presentation.service","serein-outpost-host-witness.service"} <= target_directives.get("After",set())
              and "RestrictAddressFamilies=AF_UNIX" in presentation
              and "Requires=serein-outpost-host-witness.service" in presentation)
    if "stage2" in target.lower() or graph.get("downstream_state") != "NOT_INCLUDED_HOST_GATE_ONLY": raise SystemExit("OUTPOST_DOWNSTREAM_COUPLING_DENIED")
    if not required: raise SystemExit("OUTPOST_BOOT_GRAPH_DENIED")
    preflight=json.loads((root/"install-preflight.json").read_text(encoding="utf-8"))
    if preflight["install_eligible"] is not True or preflight["target"]!="GENERIC_AMD64_DEBIAN13_HOST" or preflight["install"]["enable"] is not False or preflight["install"]["start"] is not False or preflight["install"]["commission"] is not False: raise SystemExit("INSTALL_POLICY_DENIED")
    if a.mode=="target":
        target_root=Path(a.target_root).resolve()
        allowed=frozenset()
        if a.immutable_input_plan:
            supplied=json.loads(Path(a.immutable_input_plan).read_text(encoding="utf-8"))
            if set(supplied)!={"schema","source","target","method","release_digest","key_id","public_key_fingerprint_sha256","files"} or supplied.get("schema")!="SereinOutpostImmutableInputPlan/v1" or supplied.get("source") not in {"OFFLINE_USB_MEDIA","PINNED_PUBLIC_REPOSITORY","EXISTING_CANONICAL"} or supplied.get("target")!="SEREIN_HOST" or supplied.get("method")!="VERIFIED_PUBLIC_INSTALLER" or supplied.get("release_digest")!=release.get("self_digest"): raise SystemExit("IMMUTABLE_INPUT_PLAN_DENIED")
            allowed={row.get("target") for row in supplied.get("files",[]) if isinstance(row,dict)}
            if allowed!={row["target"] for row in release.get("required_immutable_inputs",[])}: raise SystemExit("IMMUTABLE_INPUT_DENOMINATOR_DENIED")
        verify_target(target_root,preflight,check_units=target_root==Path("/"),allowed_immutable_targets=allowed)
        print("PASS_OUTPOST_TARGET_EXPECTED_BEFORE")
        return
    if a.mode=="boot":
        raise SystemExit("BOOT_ADMISSION_NOT_INCLUDED_IN_HOST_GATE_RELEASE")
    print("PASS_OUTPOST_INSTALL_PREFLIGHT")


if __name__ == "__main__": main()
