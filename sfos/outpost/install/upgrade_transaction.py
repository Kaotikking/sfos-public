#!/usr/bin/env python3
from __future__ import annotations
import copy
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
try:
    from .transaction import Adapter, RealAdapter, TransactionError, canonical, exact_file, nofollow_ancestors, sha, under
except ImportError:
    from transaction import Adapter, RealAdapter, TransactionError, canonical, exact_file, nofollow_ancestors, sha, under

sys.dont_write_bytecode=True


def receipt_digest(value):
    return sha(canonical({k: v for k, v in value.items() if k != "receipt_digest"}))


def replacement_plan_digest(value):
    return sha(canonical({k: v for k, v in value.items() if k != "plan_digest"}))


def validate_replacement_plan(adapter, release, plan, expected_plan_digest):
    """Validate the externally supplied, receipt-bound replacement authority."""
    if not re.fullmatch(r"[0-9a-f]{64}",str(expected_plan_digest)) or plan.get("plan_digest")!=expected_plan_digest:
        raise TransactionError("REPLACEMENT_PLAN_AUTHORITY_DENIED")
    required={"schema","source","candidate_release_digest","candidate_source_commit",
              "candidate_source_tree","candidate_archive_sha256","current_boot_id","active_inventory","predecessor",
              "identity","immutable_rows","cognition_key_id","cognition_public_key_fingerprint_sha256",
              "unit_runtime","unit_stop_order","controlled_roots","controlled_inventory","controlled_inventory_receipt",
              "removed_files","removed_directories",
              "rollback_selector","plan_digest"}
    if set(plan)!=required or plan["schema"]!="SereinOutpostReplacementPlan/v1":
        raise TransactionError("REPLACEMENT_PLAN_SCHEMA_DENIED")
    if plan["plan_digest"]!=replacement_plan_digest(plan):
        raise TransactionError("REPLACEMENT_PLAN_DIGEST_DENIED")
    if plan["candidate_release_digest"]!=release["self_digest"]:
        raise TransactionError("REPLACEMENT_CANDIDATE_DENIED")
    if not re.fullmatch(r"[0-9a-f]{40}",str(plan["candidate_source_commit"])):
        raise TransactionError("REPLACEMENT_SOURCE_COMMIT_DENIED")
    if not re.fullmatch(r"[0-9a-f]{40}",str(plan["candidate_source_tree"])):
        raise TransactionError("REPLACEMENT_SOURCE_TREE_DENIED")
    if not re.fullmatch(r"[0-9a-f]{64}",str(plan["candidate_archive_sha256"])):
        raise TransactionError("REPLACEMENT_ARCHIVE_DENIED")
    if not isinstance(plan["source"],str) or not plan["source"]:
        raise TransactionError("REPLACEMENT_SOURCE_DENIED")
    if not re.fullmatch(r"/var/lib/serein/rollback/outpost-upgrade-\d{8}T\d{6}Z-[0-9a-f]{12}",str(plan["rollback_selector"])):
        raise TransactionError("REPLACEMENT_SELECTOR_DENIED")
    boot=under(adapter.root,"/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    if plan["current_boot_id"]!=boot: raise TransactionError("REPLACEMENT_BOOT_DENIED")
    receipt_binding=plan["predecessor"]
    if not isinstance(receipt_binding,dict) or set(receipt_binding)!={"receipt","sha256","inventory_digest"}:
        raise TransactionError("PREDECESSOR_BINDING_DENIED")
    receipt_path=under(adapter.root,receipt_binding["receipt"])
    nofollow_ancestors(adapter.root,receipt_path,allow_missing=False)
    receipt_bytes=receipt_path.read_bytes()
    if sha(receipt_bytes)!=receipt_binding["sha256"]: raise TransactionError("PREDECESSOR_RECEIPT_HASH_DENIED")
    receipt=json.loads(receipt_bytes)
    if receipt.get("receipt_digest")!=receipt_digest(receipt): raise TransactionError("PREDECESSOR_RECEIPT_DIGEST_DENIED")
    inventory={row["target"]:row for row in plan["active_inventory"]}
    if len(inventory)!=len(plan["active_inventory"]): raise TransactionError("PREDECESSOR_INVENTORY_DUPLICATE")
    if receipt_binding.get("inventory_digest")!=sha(canonical(plan["active_inventory"])):
        raise TransactionError("PREDECESSOR_INVENTORY_BINDING_DENIED")
    for row in inventory.values(): exact_file(adapter,under(adapter.root,row["target"]),row)
    controlled_roots=release.get("replacement_controlled_roots")
    if plan["controlled_roots"]!=controlled_roots or controlled_roots!=["/usr/share/serein/outpost"]:
        raise TransactionError("CONTROLLED_ROOTS_DENIED")
    controlled=validate_controlled_inventory(adapter,plan["controlled_roots"],plan["controlled_inventory"])
    controlled_binding=plan["controlled_inventory_receipt"]
    if not isinstance(controlled_binding,dict) or set(controlled_binding)!={"receipt","sha256","inventory_digest"}:
        raise TransactionError("CONTROLLED_INVENTORY_RECEIPT_BINDING_DENIED")
    controlled_receipt_path=under(adapter.root,controlled_binding["receipt"]); nofollow_ancestors(adapter.root,controlled_receipt_path,allow_missing=False)
    controlled_receipt_bytes=controlled_receipt_path.read_bytes()
    if sha(controlled_receipt_bytes)!=controlled_binding["sha256"]: raise TransactionError("CONTROLLED_INVENTORY_RECEIPT_HASH_DENIED")
    controlled_receipt=json.loads(controlled_receipt_bytes)
    if controlled_receipt.get("receipt_digest")!=receipt_digest(controlled_receipt): raise TransactionError("CONTROLLED_INVENTORY_RECEIPT_DIGEST_DENIED")
    if controlled_binding["inventory_digest"]!=sha(canonical(plan["controlled_inventory"])) or controlled_receipt.get("controlled_inventory_digest")!=controlled_binding["inventory_digest"]:
        raise TransactionError("CONTROLLED_INVENTORY_RECEIPT_DENIED")
    for target,row in controlled.items():
        if row["kind"]=="file":
            file_row={key:row[key] for key in ("target","bytes","sha256","mode","uid","gid")}
            prior=inventory.get(target)
            if prior is not None and prior!=file_row: raise TransactionError("CONTROLLED_ACTIVE_INVENTORY_CONFLICT:"+target)
            inventory[target]=file_row
    immutable={row["target"]:row for row in plan["immutable_rows"]}
    if len(immutable)!=len(plan["immutable_rows"]): raise TransactionError("IMMUTABLE_DUPLICATE_DENIED")
    required_immutable={row["target"] for row in release["required_immutable_inputs"]}
    if set(immutable)!=required_immutable: raise TransactionError("IMMUTABLE_SET_DENIED")
    for declared in release["required_immutable_inputs"]:
        target=declared["target"]; row=immutable[target]
        expected={"target":target,"mode":declared["mode"],"uid":declared["uid"],
                  "gid":plan["identity"]["gid"] if declared.get("gid_policy")=="identity_gid" else declared["gid"]}
        if set(row)!={"target","bytes","sha256","mode","uid","gid"} or any(row[key]!=value for key,value in expected.items()):
            raise TransactionError("IMMUTABLE_METADATA_DENIED:"+target)
        if not isinstance(row["bytes"],int) or row["bytes"]<=0 or not re.fullmatch(r"[0-9a-f]{64}",str(row["sha256"])):
            raise TransactionError("IMMUTABLE_CONTENT_BINDING_DENIED:"+target)
        exact_file(adapter,under(adapter.root,target),row)
    try:
        private=serialization.load_pem_private_key(under(adapter.root,"/etc/serein-outpost/cognition-signing.pem").read_bytes(),password=None)
        public=serialization.load_pem_public_key(under(adapter.root,"/usr/share/serein/outpost/cognition-verification.pem").read_bytes())
    except (TypeError,ValueError) as error:
        raise TransactionError("COGNITION_KEY_PARSE_DENIED") from error
    if not isinstance(private,Ed25519PrivateKey) or not isinstance(public,Ed25519PublicKey) or private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)!=public.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw):
        raise TransactionError("COGNITION_KEYPAIR_DENIED")
    fingerprint=sha(public.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))
    if plan["cognition_key_id"]!="outpost-cognition-v1" or plan["cognition_public_key_fingerprint_sha256"]!=fingerprint:
        raise TransactionError("COGNITION_FINGERPRINT_DENIED")
    try:
        certificate=x509.load_pem_x509_certificate(under(adapter.root,"/etc/serein/tls/serein-backend-cert.pem").read_bytes())
        tls_private=serialization.load_pem_private_key(under(adapter.root,"/etc/serein/tls/serein-backend-key.pem").read_bytes(),password=None)
    except (TypeError,ValueError) as error:
        raise TransactionError("TLS_KEY_PARSE_DENIED") from error
    cert_public=certificate.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    key_public=tls_private.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    if cert_public!=key_public: raise TransactionError("TLS_KEYPAIR_DENIED")
    if adapter.identity(release["identity_policy"]["user"])!=plan["identity"]:
        raise TransactionError("REPLACEMENT_IDENTITY_DENIED")
    allowed=set(release.get("replacement_unit_allowlist",()))
    if not allowed or set(plan["unit_runtime"])!=allowed or set(plan["unit_stop_order"])!=allowed or len(plan["unit_stop_order"])!=len(allowed):
        raise TransactionError("UNIT_RUNTIME_DENOMINATOR_DENIED")
    for unit,state in plan["unit_runtime"].items(): normalize_runtime(unit,state)
    if not isinstance(plan["removed_files"],list) or any(not isinstance(path,str) for path in plan["removed_files"]):
        raise TransactionError("REMOVED_FILES_SCHEMA_DENIED")
    if not isinstance(plan["removed_directories"],list) or any(not isinstance(path,str) for path in plan["removed_directories"]):
        raise TransactionError("REMOVED_DIRECTORIES_SCHEMA_DENIED")
    return receipt_binding,inventory,controlled


def validate_controlled_inventory(adapter,roots,rows):
    if not isinstance(rows,list): raise TransactionError("CONTROLLED_INVENTORY_SCHEMA_DENIED")
    declared={row.get("target"):row for row in rows if isinstance(row,dict)}
    if len(declared)!=len(rows) or None in declared: raise TransactionError("CONTROLLED_INVENTORY_DUPLICATE_DENIED")
    actual={}
    for absolute in roots:
        root=under(adapter.root,absolute); nofollow_ancestors(adapter.root,root,allow_missing=False)
        if root.is_symlink() or not root.is_dir(): raise TransactionError("CONTROLLED_ROOT_TYPE_DENIED:"+absolute)
        for current,directories,files in os.walk(root,topdown=True,followlinks=False):
            current_path=Path(current); names=list(directories)+list(files)
            for name in names:
                path=current_path/name; target="/"+path.relative_to(adapter.root).as_posix()
                if path.is_symlink(): raise TransactionError("CONTROLLED_SYMLINK_DENIED:"+target)
                metadata=adapter.directory_metadata(path)
                if path.is_dir(): actual[target]={"kind":"directory","target":target,"mode":f'{metadata["mode"]:04o}',"uid":metadata["uid"],"gid":metadata["gid"]}
                elif path.is_file():
                    data=path.read_bytes(); actual[target]={"kind":"file","target":target,"bytes":len(data),"sha256":sha(data),"mode":f'{metadata["mode"]:04o}',"uid":metadata["uid"],"gid":metadata["gid"]}
                else: raise TransactionError("CONTROLLED_SPECIAL_FILE_DENIED:"+target)
        metadata=adapter.directory_metadata(root); actual[absolute]={"kind":"directory","target":absolute,"mode":f'{metadata["mode"]:04o}',"uid":metadata["uid"],"gid":metadata["gid"]}
    if actual!=declared: raise TransactionError("CONTROLLED_INVENTORY_NOT_EXHAUSTIVE")
    return declared


def normalize_runtime(unit,state):
    if not isinstance(state,dict) or not isinstance(unit,str) or not unit.endswith((".service",".path",".target")):
        raise TransactionError("UNIT_RUNTIME_SCHEMA_DENIED:"+str(unit))
    required={"enabled","active","substate"}; allowed=required|{"main_pid"}
    if not required.issubset(state) or not set(state).issubset(allowed): raise TransactionError("UNIT_RUNTIME_SCHEMA_DENIED:"+unit)
    template=unit.endswith("@.service")
    if unit.endswith(".service") and not template:
        if "main_pid" not in state or not isinstance(state["main_pid"],int) or state["main_pid"]<0:
            raise TransactionError("UNIT_RUNTIME_MAINPID_DENIED:"+unit)
    elif "main_pid" in state and (not isinstance(state["main_pid"],int) or state["main_pid"]!=0):
        raise TransactionError("UNIT_RUNTIME_NONPROCESS_PID_DENIED:"+unit)
    return {"enabled":state["enabled"],"active":state["active"],"substate":state["substate"],"main_pid":state.get("main_pid",0)}


def process_running(state,unit=None):
    return (unit is None or (unit.endswith(".service") and not unit.endswith("@.service"))) and state.get("active")=="active" and state.get("substate")=="running" and int(state.get("main_pid",0))>0


def read_runtime(adapter, unit):
    if not isinstance(adapter,RealAdapter): return normalize_runtime(unit,copy.deepcopy(adapter.read_unit(unit)))
    import subprocess
    enabled=adapter.read_unit(unit)["enabled"]
    if unit.endswith("@.service"):
        pattern=unit.replace("@.service","@*.service")
        loaded=subprocess.run(["systemctl","list-units",pattern,"--all","--plain","--no-legend"],text=True,capture_output=True,check=True).stdout.strip()
        installed=subprocess.run(["systemctl","list-unit-files",pattern,"--no-legend"],text=True,capture_output=True,check=True).stdout.splitlines()
        foreign_files=[line.split()[0] for line in installed if line.split() and line.split()[0]!=unit]
        if loaded or foreign_files: raise TransactionError("UNIT_TEMPLATE_INSTANCE_DENIED:"+unit)
        return {"enabled":enabled,"active":"inactive","substate":"dead","main_pid":0}
    command=["systemctl","show",unit,"--property=ActiveState","--property=SubState"]
    if unit.endswith(".service"): command.append("--property=MainPID")
    result=subprocess.run(command,text=True,capture_output=True,check=True)
    values=dict(line.split("=",1) for line in result.stdout.splitlines() if "=" in line)
    required={"ActiveState","SubState"}|({"MainPID"} if unit.endswith(".service") else set())
    if set(values)!=required or (unit.endswith(".service") and not values["MainPID"].isdigit()):
        raise TransactionError("UNIT_RUNTIME_READ_DENIED:"+unit)
    return {"enabled":enabled,"active":values["ActiveState"],"substate":values["SubState"],"main_pid":int(values.get("MainPID",0))}


def runtime_equivalent(expected, actual):
    if {key:actual.get(key) for key in ("enabled","active","substate")} != {key:expected.get(key) for key in ("enabled","active","substate")}:
        return False
    if process_running(expected): return process_running(actual)
    return int(actual.get("main_pid",0))==0


def enforce_disjoint_targets(**groups):
    observed={}
    for name,rows in groups.items():
        targets=[]
        for row in rows:
            target=row["target"]
            targets.append(target)
            if target in observed: raise TransactionError("UPGRADE_TARGET_CLASS_OVERLAP_DENIED:"+target+":"+observed[target]+":"+name)
            observed[target]=name
        if len(targets)!=len(set(targets)): raise TransactionError("UPGRADE_TARGET_CLASS_DUPLICATE_DENIED:"+name)


def unit_action(adapter, action, unit):
    adapter.boundary()
    if isinstance(adapter,RealAdapter):
        import subprocess
        subprocess.run(["systemctl",action,unit],check=True)
    else:
        state=adapter.unit_state[unit]
        state["active"]="inactive" if action=="stop" else "active"
        state["substate"]="dead" if action=="stop" else "running"
        state["main_pid"]=0 if action=="stop" else max(1,int(state.get("main_pid",0)))


def write_receipt(adapter, selector, value):
    value["receipt_digest"] = receipt_digest(value)
    path = selector / "upgrade-receipt.json"
    atomic_write(adapter,path,(json.dumps(value,indent=2)+"\n").encode(),"0600",0,0)


def atomic_write(adapter, path, data, mode, uid, gid):
    nofollow_ancestors(adapter.root,path)
    if not path.parent.is_dir(): raise TransactionError("UPGRADE_TARGET_PARENT_DENIED:"+str(path))
    adapter.boundary()
    descriptor, temporary = tempfile.mkstemp(prefix=".serein-upgrade-", dir=path.parent)
    try:
        adapter.boundary()
        with os.fdopen(descriptor, "wb") as handle:
            descriptor=-1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, int(mode, 8))
        if isinstance(adapter,RealAdapter): os.chown(temporary, uid, gid)
        adapter.boundary(); os.replace(temporary, path)
        if isinstance(adapter,RealAdapter):
            directory_fd=os.open(path.parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
            try: os.fsync(directory_fd)
            finally: os.close(directory_fd)
    finally:
        if descriptor!=-1: os.close(descriptor)
        if os.path.exists(temporary):
            os.unlink(temporary)


def generation_selector_digest(value):
    return sha(canonical({k: v for k, v in value.items() if k != "selector_digest"}))


def _write_generation_selector(adapter, path, value):
    value = dict(value)
    value["selector_digest"] = generation_selector_digest(value)
    data=(json.dumps(value, indent=2) + "\n").encode()
    atomic_write(adapter, path, data, "0600", 0, 0)
    return {"target":"/"+path.relative_to(adapter.root).as_posix(),"bytes":len(data),"sha256":sha(data),"mode":"0600","uid":0,"gid":0}


def migration_receipt_digest(value):
    return sha(canonical({k:v for k,v in value.items() if k!="receipt_digest"}))


def write_migration_receipt(adapter,selector,value):
    value["receipt_digest"]=migration_receipt_digest(value)
    atomic_write(adapter,selector/"migration-receipt.json",(json.dumps(value,indent=2)+"\n").encode(),"0600",0,0)


def validate_migration_receipt(adapter,selector):
    path=selector/"migration-receipt.json"; nofollow_ancestors(adapter.root,path,allow_missing=False)
    value=json.loads(path.read_text(encoding="utf-8"))
    required={"schema","selector","generation_target","generation_id","copied_files","launcher","current_selector","lkg_selector","legacy_root","unit_replacements","service_deltas","introduced_directories","activated","rollback_complete","receipt_digest"}
    if set(value)!=required or value["schema"]!="SereinOutpostFlatGenerationMigration/v1" or value["selector"]!="/"+selector.relative_to(adapter.root).as_posix() or value["receipt_digest"]!=migration_receipt_digest(value):
        raise TransactionError("GENERATION_MIGRATION_RECEIPT_DENIED")
    return value


OUTPOST_UNIT_ENTRYPOINTS={
    "serein-outpost.service":("/usr/bin/python3 -m outpost.service","/usr/libexec/serein/outpost-generation-launcher outpost/service.py"),
    "serein-outpost-host-witness.service":("/usr/bin/python3 -m outpost.host_witness_runner","/usr/libexec/serein/outpost-generation-launcher outpost/host_witness_runner.py"),
    "serein-outpost-presentation.service":("/usr/bin/python3 -m outpost.presentation_service","/usr/libexec/serein/outpost-generation-launcher outpost/presentation_service.py"),
    "serein-outpost-validation.service":("/usr/bin/python3 /usr/share/serein/outpost/verify_install_preflight.py --source /usr/share/serein/outpost","/usr/libexec/serein/outpost-generation-launcher verify_install_preflight.py --source-selector /var/lib/serein-outpost/generation-state/current.json"),
    "serein-outpost-stage1-install.service":("/usr/bin/python3 -B /usr/share/serein/outpost/install/stage1_transaction_runner.py","/usr/libexec/serein/outpost-generation-launcher install/stage1_transaction_runner.py"),
    "serein-outpost-stage1-verify.service":("/usr/bin/python3 -B /usr/share/serein/outpost/install/stage1_verification_runner.py","/usr/libexec/serein/outpost-generation-launcher install/stage1_verification_runner.py"),
    "serein-outpost-kernel-branch-verify.service":("/usr/bin/python3 -B /usr/share/serein/outpost/install/kernel_branch_verification_runner.py","/usr/libexec/serein/outpost-generation-launcher install/kernel_branch_verification_runner.py"),
    "serein-outpost-domain-dispatch.service":("/usr/bin/python3 /usr/share/serein/outpost/install/domain_dispatch_runner.py","/usr/libexec/serein/outpost-generation-launcher install/domain_dispatch_runner.py"),
    "serein-outpost-domain-install@.service":("/usr/bin/python3 /usr/share/serein/outpost/install/domain_transaction_runner.py","/usr/libexec/serein/outpost-generation-launcher install/domain_transaction_runner.py"),
}


def _planned_unit_replacements(adapter, inventory):
    replacements=[]
    for unit,(old,new) in OUTPOST_UNIT_ENTRYPOINTS.items():
        target="/etc/systemd/system/"+unit
        row=inventory.get(target)
        if row is None: continue
        path=under(adapter.root,target); exact_file(adapter,path,row); before=path.read_bytes()
        try: text=before.decode("utf-8")
        except UnicodeDecodeError as exc: raise TransactionError("GENERATION_UNIT_ENCODING_DENIED:"+unit) from exc
        if text.count(old)!=1 or new in text: raise TransactionError("GENERATION_UNIT_SOURCE_DENIED:"+unit)
        after=text.replace(old,new,1).encode()
        replacements.append({"target":target,"before":sha(before),"after":sha(after),"before_bytes":len(before),"after_bytes":len(after),"mode":row["mode"],"uid":row["uid"],"gid":row["gid"],"backup":"unit-prestate/"+unit,"content":after.decode("utf-8")})
    return replacements


def _migrate_flat_predecessor_locked(adapter, release, plan, selector, launcher_source):
    """Copy the bound flat predecessor into generation storage without activating it."""
    selector=Path(selector)
    rollback_parent=under(adapter.root,"/var/lib/serein/rollback")
    nofollow_ancestors(adapter.root,selector)
    if selector.parent!=rollback_parent or not re.fullmatch(r"outpost-upgrade-\d{8}T\d{6}Z-[0-9a-f]{12}",selector.name):
        raise TransactionError("GENERATION_MIGRATION_SELECTOR_DENIED")
    _, inventory, controlled = validate_replacement_plan(adapter, release, plan, plan["plan_digest"])
    unit_replacements=_planned_unit_replacements(adapter,inventory)
    legacy_release_path=under(adapter.root,"/usr/share/serein/outpost/release-manifest.json")
    legacy_manifest_absent=not os.path.lexists(legacy_release_path)
    if not legacy_manifest_absent:
        try: legacy_release=json.loads(legacy_release_path.read_text(encoding="utf-8"))
        except (OSError,ValueError) as error: raise TransactionError("LEGACY_RELEASE_MANIFEST_DENIED") from error
        legacy_release_digest=str(legacy_release.get("self_digest",""))
    else:
        # The first admitted flat installer generation predates release manifests.
        # Its validated predecessor receipt and complete active inventory are the
        # only permissible identity fallback; never synthesize an unbound ID.
        if "/usr/share/serein/outpost/release-manifest.json" in inventory:
            raise TransactionError("LEGACY_RELEASE_MANIFEST_DENIED")
        legacy_release_digest="sha256:"+str(plan["predecessor"]["inventory_digest"])
    generation_id = legacy_release_digest[7:] if legacy_release_digest.startswith("sha256:") else legacy_release_digest
    if not re.fullmatch(r"[0-9a-f]{64}", generation_id):
        raise TransactionError("GENERATION_ID_DENIED")
    legacy_release_digest="sha256:"+generation_id
    generation_base = under(adapter.root, "/usr/share/serein/outpost-generations")
    state_root = under(adapter.root, "/var/lib/serein-outpost/generation-state")
    generation = generation_base / generation_id
    launcher_target = under(adapter.root, "/usr/libexec/serein/outpost-generation-launcher")
    if os.path.lexists(generation): raise TransactionError("GENERATION_COLLISION_DENIED")
    if os.path.lexists(selector): raise TransactionError("GENERATION_MIGRATION_SELECTOR_COLLISION_DENIED")
    for target in (state_root/"current.json",state_root/"lkg.json",launcher_target):
        if os.path.lexists(target): raise TransactionError("GENERATION_CONTROL_COLLISION_DENIED:"+str(target))
    if generation_base.is_dir() and any(generation_base.iterdir()): raise TransactionError("GENERATION_FOREIGN_RESIDUE_DENIED")
    if state_root.is_dir() and any(state_root.iterdir()): raise TransactionError("GENERATION_STATE_RESIDUE_DENIED")
    introduced_directories=[]
    for parent,mode in ((generation_base,0o755),(state_root,0o700),(launcher_target.parent,0o755)):
        nofollow_ancestors(adapter.root, parent)
        if os.path.lexists(parent):
            if parent.is_symlink() or not parent.is_dir(): raise TransactionError("GENERATION_PARENT_DENIED:" + str(parent))
            metadata=adapter.directory_metadata(parent)
            if metadata!={"mode":mode,"uid":0,"gid":0}: raise TransactionError("GENERATION_PARENT_POLICY_DENIED:"+str(parent))
        else:
            missing=[]; cursor=parent
            while cursor!=adapter.root and not cursor.exists(): missing.append(cursor); cursor=cursor.parent
            for created in reversed(missing):
                created_mode=mode if created==parent else 0o755
                adapter.boundary(); created.mkdir(mode=created_mode); os.chmod(created,created_mode)
                introduced_directories.append("/"+created.relative_to(adapter.root).as_posix())
    try:
        adapter.boundary(); selector.mkdir(mode=0o700); os.chmod(selector, 0o700)
        adapter.boundary(); generation.mkdir(mode=0o755); os.chmod(generation, 0o755)
        copied=[]
        root_prefix="/usr/share/serein/outpost/"
        copied_directories=[]
        directory_rows=[row for target,row in controlled.items() if row["kind"]=="directory" and target.startswith(root_prefix)]
        for row in sorted(directory_rows,key=lambda value:value["target"].count("/")):
            relative=row["target"][len(root_prefix):]; destination=generation/relative
            adapter.boundary(); destination.mkdir(mode=int(row["mode"],8)); os.chmod(destination,int(row["mode"],8))
            if isinstance(adapter,RealAdapter): os.chown(destination,row["uid"],row["gid"])
            copied_directories.append({"kind":"directory","path":relative,"mode":row["mode"],"uid":row["uid"],"gid":row["gid"]})
        for target,row in sorted(controlled.items()):
            if row["kind"] != "file" or not target.startswith(root_prefix): continue
            relative=target[len(root_prefix):]
            destination=generation/relative
            if not destination.parent.is_dir(): raise TransactionError("GENERATION_DIRECTORY_INVENTORY_DENIED:"+relative)
            source=under(adapter.root,target); exact_file(adapter,source,{k:row[k] for k in ("target","bytes","sha256","mode","uid","gid")})
            atomic_write(adapter,destination,source.read_bytes(),row["mode"],row["uid"],row["gid"])
            copied.append({"target":"/"+destination.relative_to(adapter.root).as_posix(),"bytes":row["bytes"],"sha256":row["sha256"],"mode":row["mode"],"uid":row["uid"],"gid":row["gid"]})
        if legacy_manifest_absent:
            descriptor=(json.dumps({"schema":"SereinOutpostLegacyGeneration/v1","self_digest":legacy_release_digest,"predecessor_receipt_sha256":plan["predecessor"]["sha256"]},sort_keys=True)+"\n").encode()
            descriptor_target=generation/"release-manifest.json"
            atomic_write(adapter,descriptor_target,descriptor,"0644",0,0)
            copied.append({"target":"/"+descriptor_target.relative_to(adapter.root).as_posix(),"bytes":len(descriptor),"sha256":sha(descriptor),"mode":"0644","uid":0,"gid":0})
        launcher_path=Path(launcher_source)
        launcher_info=launcher_path.lstat()
        if launcher_path.is_symlink() or not stat.S_ISREG(launcher_info.st_mode) or (os.name!="nt" and (launcher_info.st_uid!=0 or launcher_info.st_gid!=0 or stat.S_IMODE(launcher_info.st_mode)!=0o755)):
            raise TransactionError("GENERATION_LAUNCHER_SOURCE_DENIED")
        launcher_data=launcher_path.read_bytes()
        launcher_declarations=[row for row in release.get("install_files",[]) if row.get("target")=="/usr/libexec/serein/outpost-generation-launcher"]
        if len(launcher_declarations)!=1:
            raise TransactionError("GENERATION_LAUNCHER_DECLARATION_DENIED")
        declaration=launcher_declarations[0]
        if set(declaration)!={"source","target","bytes","sha256","mode","uid","gid"} or declaration["source"]!="install/generation_launcher.py" or declaration["bytes"]!=len(launcher_data) or declaration["sha256"]!=sha(launcher_data) or declaration["mode"]!="0755" or declaration["uid"]!=0 or declaration["gid"]!=0:
            raise TransactionError("GENERATION_LAUNCHER_BINDING_DENIED")
        if os.path.lexists(launcher_target): raise TransactionError("GENERATION_LAUNCHER_COLLISION_DENIED")
        launcher_row={"target":"/usr/libexec/serein/outpost-generation-launcher","bytes":len(launcher_data),"sha256":sha(launcher_data),"mode":"0755","uid":0,"gid":0}
        atomic_write(adapter,launcher_target,launcher_data,"0755",0,0)
        generation_prefix="/"+generation.relative_to(adapter.root).as_posix()+"/"
        inventory_rows=copied_directories+[{"kind":"file","path":row["target"][len(generation_prefix):],"bytes":row["bytes"],"sha256":row["sha256"],"mode":row["mode"],"uid":row["uid"],"gid":row["gid"]} for row in copied]
        inventory_rows=sorted(inventory_rows,key=lambda row:row["path"])
        inventory_data=(json.dumps(inventory_rows,sort_keys=True,separators=(",",":"))+"\n").encode()
        atomic_write(adapter,generation/"generation-inventory.json",inventory_data,"0644",0,0)
        selector_value={"schema":"SereinOutpostGenerationSelector/v1","generation":generation_id,"release_digest":legacy_release_digest,"predecessor_receipt_sha256":plan["predecessor"]["sha256"],"inventory_digest":sha(canonical(inventory_rows))}
        lkg_selector=_write_generation_selector(adapter,state_root/"lkg.json",selector_value)
        current_selector=_write_generation_selector(adapter,state_root/"current.json",selector_value)
        receipt={"schema":"SereinOutpostFlatGenerationMigration/v1","selector":"/"+selector.relative_to(adapter.root).as_posix(),"generation_target":"/"+generation.relative_to(adapter.root).as_posix(),"generation_id":generation_id,"copied_files":copied,"launcher":launcher_row,"current_selector":current_selector,"lkg_selector":lkg_selector,"legacy_root":"/usr/share/serein/outpost","unit_replacements":unit_replacements,"service_deltas":[],"introduced_directories":introduced_directories,"activated":False,"rollback_complete":False}
        write_migration_receipt(adapter,selector,receipt)
        prestate=selector/"unit-prestate"; adapter.boundary(); prestate.mkdir(mode=0o700); os.chmod(prestate,0o700)
        for replacement in unit_replacements:
            target=under(adapter.root,replacement["target"]); before=target.read_bytes()
            atomic_write(adapter,prestate/Path(replacement["backup"]).name,before,"0600",0,0)
            atomic_write(adapter,target,replacement["content"].encode(),replacement["mode"],replacement["uid"],replacement["gid"])
        if unit_replacements: adapter.daemon_reload()
        return receipt
    except Exception:
        if (selector/"migration-receipt.json").exists(): rollback_flat_migration(adapter,selector)
        else:
            for target in (state_root/"current.json",state_root/"lkg.json",launcher_target):
                if os.path.lexists(target): adapter.boundary(); target.unlink()
            if generation.exists():
                for residue in sorted(generation.rglob("*"),key=lambda p:len(p.parts),reverse=True): adapter.boundary(); residue.rmdir() if residue.is_dir() else residue.unlink()
                adapter.boundary(); generation.rmdir()
            if selector.exists():
                for residue in sorted(selector.rglob("*"),key=lambda p:len(p.parts),reverse=True): adapter.boundary(); residue.rmdir() if residue.is_dir() else residue.unlink()
                adapter.boundary(); selector.rmdir()
            for directory in reversed(introduced_directories):
                target=under(adapter.root,directory)
                if target.exists() and not any(target.iterdir()): adapter.boundary(); target.rmdir()
        raise


def migrate_flat_predecessor(adapter, release, plan, selector, launcher_source):
    """Serialize migration with a lock outside both immutable generations and selector state."""
    lock=under(adapter.root,"/var/lib/serein/rollback/.outpost-generation-migration.lock")
    nofollow_ancestors(adapter.root,lock)
    if not lock.parent.is_dir(): raise TransactionError("GENERATION_LOCK_PARENT_DENIED")
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)
    try: descriptor=os.open(lock,flags,0o600)
    except FileExistsError as exc: raise TransactionError("GENERATION_TRANSACTION_LOCKED") from exc
    try:
        if isinstance(adapter,RealAdapter): os.fchown(descriptor,0,0)
        os.write(descriptor,(str(os.getpid())+"\n").encode()); os.fsync(descriptor)
        return _migrate_flat_predecessor_locked(adapter,release,plan,selector,launcher_source)
    finally:
        os.close(descriptor)
        try: os.unlink(lock)
        except FileNotFoundError: pass


def rollback_flat_migration(adapter, selector, allow_missing_receipt=False):
    receipt_path=selector/"migration-receipt.json"
    receipt=validate_migration_receipt(adapter,selector) if receipt_path.exists() else None
    if receipt is None and not allow_missing_receipt: raise TransactionError("GENERATION_MIGRATION_RECEIPT_DENIED")
    if receipt is not None:
        # Validate the complete compensation set before the first rollback effect.
        for selector_row in (receipt["current_selector"],receipt["lkg_selector"]):
            exact_file(adapter,under(adapter.root,selector_row["target"]),selector_row)
        exact_file(adapter,under(adapter.root,receipt["launcher"]["target"]),receipt["launcher"])
        generation_root=under(adapter.root,"/usr/share/serein/outpost-generations")
        for selector_row in (receipt["current_selector"],receipt["lkg_selector"]):
            try: value=json.loads(under(adapter.root,selector_row["target"]).read_text(encoding="utf-8"))
            except Exception as exc: raise TransactionError("GENERATION_ROLLBACK_INVENTORY_DENIED") from exc
            required={"schema","generation","release_digest","predecessor_receipt_sha256","inventory_digest","selector_digest"}
            if set(value)!=required or value["schema"]!="SereinOutpostGenerationSelector/v1" or value["selector_digest"]!=generation_selector_digest(value) or value["generation"]!=receipt["generation_id"] or generation_root/value["generation"]!=under(adapter.root,receipt["generation_target"]):
                raise TransactionError("GENERATION_ROLLBACK_SELECTOR_DENIED")
        for replacement in reversed(receipt["unit_replacements"]):
            target=under(adapter.root,replacement["target"]); backup=selector/replacement["backup"]
            current=sha(target.read_bytes()) if target.is_file() and not target.is_symlink() else None
            if current==replacement["before"]: continue
            if not backup.is_file() or backup.is_symlink() or sha(backup.read_bytes())!=replacement["before"]: raise TransactionError("GENERATION_UNIT_BACKUP_DENIED")
            if current!=replacement["after"]: raise TransactionError("GENERATION_UNIT_ROLLBACK_CAS_DENIED")
        # Restore launch definitions first so every subsequent removal prefix is runnable.
        for replacement in reversed(receipt["unit_replacements"]):
            target=under(adapter.root,replacement["target"]); backup=selector/replacement["backup"]
            if sha(target.read_bytes())==replacement["before"]: continue
            atomic_write(adapter,target,backup.read_bytes(),replacement["mode"],replacement["uid"],replacement["gid"])
        if receipt["unit_replacements"]: adapter.daemon_reload()
        generation=under(adapter.root,receipt["generation_target"])
        if generation.exists():
            # The earlier read protects the pre-effect decision.  Re-read the
            # complete no-follow inventory after unit restoration and its
            # daemon-reload boundary so cleanup can never consume late drift.
            try: final_value=json.loads(under(adapter.root,receipt["current_selector"]["target"]).read_text(encoding="utf-8"))
            except Exception as exc: raise TransactionError("GENERATION_ROLLBACK_FINAL_INVENTORY_DENIED") from exc
            if final_value.get("generation")!=receipt["generation_id"] or generation_root/final_value["generation"]!=generation:
                raise TransactionError("GENERATION_ROLLBACK_FINAL_INVENTORY_DENIED")
            inventory_path=generation/"generation-inventory.json"
            inventory=json.loads(inventory_path.read_text(encoding="utf-8"))
            declared={row["path"] for row in inventory}
            actual=set()
            for item in generation.rglob("*"):
                relative=item.relative_to(generation).as_posix()
                if item.is_symlink(): raise TransactionError("GENERATION_ROLLBACK_FINAL_INVENTORY_DENIED")
                if relative!="generation-inventory.json": actual.add(relative)
            if actual!=declared: raise TransactionError("GENERATION_ROLLBACK_FINAL_INVENTORY_DENIED")
            file_rows=[row for row in inventory if row.get("kind")=="file"]
            directory_rows=[row for row in inventory if row.get("kind")=="directory"]
            # Remove only receipt/inventory-bound members.  A foreign entry is
            # preserved and makes the final directory removal fail closed.
            for row in sorted(file_rows,key=lambda value:value["path"],reverse=True):
                target=generation/row["path"]
                exact_file(adapter,target,{"target":"/"+target.relative_to(adapter.root).as_posix(),**{key:row[key] for key in ("bytes","sha256","mode","uid","gid")}})
                adapter.boundary(); target.unlink()
            exact_file(adapter,inventory_path,{"target":"/"+inventory_path.relative_to(adapter.root).as_posix(),"bytes":len((json.dumps(inventory,sort_keys=True,separators=(",",":"))+"\n").encode()),"sha256":sha((json.dumps(inventory,sort_keys=True,separators=(",",":"))+"\n").encode()),"mode":"0644","uid":0,"gid":0})
            adapter.boundary(); inventory_path.unlink()
            for row in sorted(directory_rows,key=lambda value:value["path"].count("/"),reverse=True):
                target=generation/row["path"]
                adapter.boundary(); target.rmdir()
            adapter.boundary(); generation.rmdir()
        for selector_row in (receipt["current_selector"],receipt["lkg_selector"]):
            target=under(adapter.root,selector_row["target"]); exact_file(adapter,target,selector_row); adapter.boundary(); target.unlink()
        launcher=under(adapter.root,receipt["launcher"]["target"]); exact_file(adapter,launcher,receipt["launcher"]); adapter.boundary(); launcher.unlink()
        receipt["rollback_complete"]=True; write_migration_receipt(adapter,selector,receipt)
    elif selector.exists():
        for residue in sorted(selector.rglob("*"),key=lambda p:len(p.parts),reverse=True): adapter.boundary(); residue.rmdir() if residue.is_dir() else residue.unlink()
        adapter.boundary(); selector.rmdir()
    return receipt


def validate_upgrade_receipt(selector):
    selector=selector.resolve()
    if not re.fullmatch(r"outpost-upgrade-\d{8}T\d{6}Z-[0-9a-f]{12}",selector.name):
        raise TransactionError("UPGRADE_SELECTOR_DENIED")
    if tuple(part.lower() for part in selector.parent.parts[-4:])!=("var","lib","serein","rollback"):
        raise TransactionError("UPGRADE_SELECTOR_PARENT_DENIED")
    root=selector.parents[4]
    nofollow_ancestors(root,selector,allow_missing=False)
    selector_info=selector.lstat()
    if not stat.S_ISDIR(selector_info.st_mode) or selector.is_symlink() or (os.name!="nt" and (stat.S_IMODE(selector_info.st_mode)!=0o700 or selector_info.st_uid!=0 or selector_info.st_gid!=0)):
        raise TransactionError("UPGRADE_SELECTOR_POLICY_DENIED")
    path = selector / "upgrade-receipt.json"
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or (os.name!="nt" and (stat.S_IMODE(info.st_mode)!=0o600 or info.st_uid!=0 or info.st_gid!=0)):
        raise TransactionError("UPGRADE_RECEIPT_POLICY_DENIED")
    value = json.loads(path.read_text(encoding="utf-8"))
    required = {
        "schema", "selector", "predecessor_selector", "predecessor_receipt_sha256",
        "replacement_plan_digest", "candidate_source_commit", "candidate_source_tree", "candidate_archive_sha256", "current_boot_id",
        "candidate_release_digest", "kept_files", "replaced_files", "removed_files", "introduced_files",
        "removed_directories", "introduced_generated_files", "unit_prestate", "action_journal", "rollback_complete", "receipt_digest",
    }
    if set(value) != required or value["schema"] != "SereinOutpostUpgradeRollback/v1":
        raise TransactionError("UPGRADE_RECEIPT_SCHEMA_DENIED")
    if value["selector"] != str(selector) or value["receipt_digest"] != receipt_digest(value):
        raise TransactionError("UPGRADE_RECEIPT_INTEGRITY_DENIED")
    return value


def rollback(adapter, selector):
    receipt = validate_upgrade_receipt(selector)
    started={row["unit"] for row in receipt["action_journal"] if row["action"]=="start"}
    stopped={row["unit"] for row in receipt["action_journal"] if row["action"]=="stop"}
    failure=None
    try:
        for unit in reversed([row["unit"] for row in receipt["action_journal"] if row["action"]=="start"]):
            if process_running(read_runtime(adapter,unit),unit): unit_action(adapter,"stop",unit)
        for row in receipt["introduced_generated_files"] + receipt["introduced_files"]:
            target = under(adapter.root, row["target"])
            if os.path.lexists(target):
                exact_file(adapter, target, row)
                adapter.boundary(); target.unlink()
        for row in receipt["replaced_files"]:
            target = under(adapter.root, row["target"])
            backup = selector / row["backup"]
            if sha(backup.read_bytes()) != row["predecessor"]["sha256"]:
                raise TransactionError("UPGRADE_BACKUP_HASH_DENIED:" + row["target"])
            try:
                exact_file(adapter, target, row["predecessor"])
                continue
            except TransactionError:
                exact_file(adapter, target, row["candidate"])
            atomic_write(adapter,target, backup.read_bytes(), row["predecessor"]["mode"], row["predecessor"]["uid"], row["predecessor"]["gid"])
        for row in sorted(receipt["removed_directories"],key=lambda item:item["target"].count("/")):
            target=under(adapter.root,row["target"])
            if os.path.lexists(target):
                if target.is_symlink() or not target.is_dir(): raise TransactionError("ROLLBACK_REMOVED_DIRECTORY_COLLISION_DENIED:"+row["target"])
                if adapter.directory_metadata(target)!={"mode":int(row["mode"],8),"uid":row["uid"],"gid":row["gid"]}: raise TransactionError("ROLLBACK_REMOVED_DIRECTORY_POLICY_DENIED:"+row["target"])
            else:
                adapter.boundary(); target.mkdir(mode=int(row["mode"],8)); os.chmod(target,int(row["mode"],8))
                if isinstance(adapter,RealAdapter): os.chown(target,row["uid"],row["gid"])
        for row in receipt["removed_files"]:
            target=under(adapter.root,row["target"]); backup=selector/row["backup"]
            if os.path.lexists(target):
                try:
                    exact_file(adapter,target,row["predecessor"])
                    continue
                except TransactionError as error:
                    raise TransactionError("ROLLBACK_REMOVED_COLLISION_DENIED:"+row["target"]) from error
            if sha(backup.read_bytes())!=row["predecessor"]["sha256"]: raise TransactionError("ROLLBACK_REMOVED_BACKUP_DENIED:"+row["target"])
            atomic_write(adapter,target,backup.read_bytes(),row["predecessor"]["mode"],row["predecessor"]["uid"],row["predecessor"]["gid"])
    except Exception as error:
        failure=error
    try:
        adapter.daemon_reload()
        for unit in receipt["unit_prestate"]:
            if unit in stopped and unit not in started and not process_running(read_runtime(adapter,unit),unit):
                unit_action(adapter,"start",unit)
        for unit, expected in receipt["unit_prestate"].items():
            if not runtime_equivalent(expected,read_runtime(adapter,unit)):
                raise TransactionError("UPGRADE_ROLLBACK_UNIT_STATE_DENIED:" + unit)
    except Exception as error:
        if failure is None: failure=error
    if failure is not None: raise failure
    receipt["rollback_complete"] = True
    write_receipt(adapter,selector, receipt)
    return receipt


def upgrade(adapter, source, release, plan, selector, expected_plan_sha256=None):
    predecessor,old_by_target,controlled=validate_replacement_plan(adapter,release,plan,expected_plan_sha256)
    expected_selector=under(adapter.root,plan["rollback_selector"])
    if selector.resolve()!=expected_selector.resolve(): raise TransactionError("REPLACEMENT_SELECTOR_MISMATCH_DENIED")
    rollback_base=under(adapter.root,"/var/lib/serein/rollback")
    nofollow_ancestors(adapter.root,rollback_base,allow_missing=False)
    info=rollback_base.lstat()
    if not stat.S_ISDIR(info.st_mode) or rollback_base.is_symlink() or (os.name!="nt" and (stat.S_IMODE(info.st_mode)&0o022 or info.st_uid!=0 or info.st_gid!=0)):
        raise TransactionError("ROLLBACK_BASE_POLICY_DENIED")
    unit_prestate = {unit: read_runtime(adapter,unit) for unit in plan["unit_runtime"]}
    planned_runtime={unit:normalize_runtime(unit,state) for unit,state in plan["unit_runtime"].items()}
    if unit_prestate != planned_runtime: raise TransactionError("UNIT_RUNTIME_PRESTATE_DENIED")
    if os.path.lexists(selector): raise TransactionError("UPGRADE_SELECTOR_COLLISION_DENIED")
    kept, replaced, removed, introduced = [], [], [], []
    install_rows = list(release["install_files"])
    release_bytes = (source / "release-manifest.json").read_bytes()
    install_rows.append({"source": "release-manifest.json", "target": "/usr/share/serein/outpost/release-manifest.json", "bytes": len(release_bytes), "sha256": sha(release_bytes), "mode": "0644", "uid": 0, "gid": 0})
    candidate_targets={row["target"] for row in install_rows}|{row["target"] for row in release["generated_files"]}|{row["target"] for row in release["required_immutable_inputs"]}
    expected_removed=set(old_by_target)-candidate_targets
    if set(plan["removed_files"])!=expected_removed: raise TransactionError("REMOVED_FILES_SET_DENIED")
    candidate_directories={row["target"] for row in release["install_directories"]}
    controlled_directories={target for target,row in controlled.items() if row["kind"]=="directory"}
    expected_removed_directories=controlled_directories-candidate_directories
    if set(plan["removed_directories"])!=expected_removed_directories: raise TransactionError("REMOVED_DIRECTORIES_SET_DENIED")
    for index,target_name in enumerate(sorted(expected_removed)):
        removed.append({"target":target_name,"backup":f"predecessor/removed-{index:04d}.bin","predecessor":old_by_target[target_name]})
    removed_directories=[controlled[target] for target in sorted(expected_removed_directories,key=lambda value:value.count("/"),reverse=True)]
    for index, candidate in enumerate(install_rows):
        target = under(adapter.root, candidate["target"])
        previous = old_by_target.get(candidate["target"])
        if previous:
            exact_file(adapter, target, previous)
            if all(previous.get(key)==candidate.get(key) for key in ("bytes","sha256","mode","uid","gid")):
                kept.append(candidate)
                continue
            backup_name = f"predecessor/{index:04d}.bin"
            replaced.append({"target": candidate["target"], "backup": backup_name, "predecessor": previous, "candidate": candidate})
        else:
            if os.path.lexists(target):
                raise TransactionError("UNBOUND_TARGET_COLLISION_DENIED:" + candidate["target"])
            introduced.append(candidate)
    generated = []
    generated_payload = {}
    cognition_key = None
    for declared in release["generated_files"]:
        target = under(adapter.root,declared["target"]); previous=old_by_target.get(declared["target"])
        if previous and declared["target"] in {"/etc/serein-outpost/readonly.token","/etc/serein-outpost/admission.token","/etc/serein-outpost/cognition-signing.pem","/usr/share/serein/outpost/cognition-verification.pem"}:
            exact_file(adapter,target,previous)
            gid=old_by_target.get("/etc/serein-outpost/readonly.token",{}).get("gid",declared.get("gid",0)) if declared.get("gid_policy")=="identity_gid" else declared["gid"]
            candidate={**declared,"gid":gid,"bytes":previous["bytes"],"sha256":previous["sha256"]}; candidate.pop("gid_policy",None)
            if all(previous.get(key)==candidate.get(key) for key in ("mode","uid","gid")):
                kept.append(previous)
            else:
                generated_payload[declared["target"]]=target.read_bytes()
                backup_name=f"predecessor/generated-{len(replaced):04d}.bin"
                replaced.append({"target":declared["target"],"backup":backup_name,"predecessor":previous,"candidate":candidate})
            continue
        if declared["target"]=="/etc/serein-outpost/rollback-root": data=(str(selector)+"\n").encode()
        elif declared["target"] in {"/etc/serein-outpost/cognition-signing.pem","/usr/share/serein/outpost/cognition-verification.pem"}:
            raise TransactionError("UPGRADE_IMMUTABLE_KEY_GENERATION_DENIED:"+declared["target"])
        else: raise TransactionError("UPGRADE_GENERATED_TARGET_DENIED:"+declared["target"])
        gid=old_by_target.get("/etc/serein-outpost/readonly.token",{}).get("gid",declared.get("gid",0)) if declared.get("gid_policy")=="identity_gid" else declared["gid"]
        candidate={**declared,"gid":gid,"bytes":len(data),"sha256":sha(data)}; candidate.pop("gid_policy",None)
        generated_payload[declared["target"]]=data
        if previous:
            exact_file(adapter,target,previous)
            backup_name=f"predecessor/generated-{len(replaced):04d}.bin"
            replaced.append({"target":declared["target"],"backup":backup_name,"predecessor":previous,"candidate":candidate})
        else:
            if os.path.lexists(target): raise TransactionError("UNBOUND_GENERATED_COLLISION_DENIED:"+declared["target"])
            generated.append(candidate)
    enforce_disjoint_targets(
        kept=kept,
        replaced=[row["candidate"] for row in replaced],
        removed=[row["predecessor"] for row in removed],
        introduced=introduced,
        generated=generated,
    )
    try:
        adapter.boundary(); selector.mkdir(mode=0o700); os.chmod(selector,0o700)
        backups=selector/"predecessor"; adapter.boundary(); backups.mkdir(mode=0o700); os.chmod(backups,0o700)
        for row in replaced:
            target=under(adapter.root,row["target"]); atomic_write(adapter,selector/row["backup"],target.read_bytes(),"0600",0,0)
        for row in removed:
            target=under(adapter.root,row["target"]); atomic_write(adapter,selector/row["backup"],target.read_bytes(),"0600",0,0)
        receipt = {
            "schema": "SereinOutpostUpgradeRollback/v1", "selector": str(selector),
            "predecessor_selector": predecessor["receipt"].rsplit("/",1)[0], "predecessor_receipt_sha256": predecessor["sha256"],
            "replacement_plan_digest": plan["plan_digest"], "candidate_source_commit":plan["candidate_source_commit"],
            "candidate_source_tree":plan["candidate_source_tree"], "candidate_archive_sha256":plan["candidate_archive_sha256"], "current_boot_id":plan["current_boot_id"],
            "candidate_release_digest": release["self_digest"], "kept_files": kept,
            "replaced_files": replaced, "removed_files": removed, "removed_directories":removed_directories, "introduced_files": introduced,
            "introduced_generated_files": generated, "unit_prestate": unit_prestate, "action_journal":[], "rollback_complete": False,
        }
        write_receipt(adapter,selector, receipt)
        for unit in plan["unit_stop_order"]:
            state=unit_prestate[unit]
            if process_running(state,unit):
                receipt["action_journal"].append({"action":"stop","unit":unit}); write_receipt(adapter,selector,receipt)
                unit_action(adapter,"stop",unit)
        for row in removed:
            target=under(adapter.root,row["target"])
            exact_file(adapter,target,row["predecessor"]); adapter.boundary(); target.unlink()
        for row in removed_directories:
            target=under(adapter.root,row["target"])
            if target.is_symlink() or not target.is_dir() or any(target.iterdir()): raise TransactionError("REMOVE_DIRECTORY_NOT_EMPTY_DENIED:"+row["target"])
            adapter.boundary(); target.rmdir()
        for row in replaced:
            candidate = row["candidate"]
            data=generated_payload.get(candidate["target"])
            if data is None: data=(source / candidate["source"]).read_bytes()
            atomic_write(adapter,under(adapter.root, candidate["target"]),data,candidate["mode"],candidate["uid"],candidate["gid"])
        for candidate in introduced:
            target = under(adapter.root, candidate["target"])
            atomic_write(adapter,target,(source / candidate["source"]).read_bytes(),candidate["mode"],candidate["uid"],candidate["gid"])
        for candidate in generated:
            atomic_write(adapter,under(adapter.root,candidate["target"]),generated_payload[candidate["target"]],candidate["mode"],candidate["uid"],candidate["gid"])
        adapter.daemon_reload()
        for candidate in install_rows+generated: exact_file(adapter,under(adapter.root,candidate["target"]),candidate)
        for unit,state in unit_prestate.items():
            actual=read_runtime(adapter,unit)
            if process_running(state,unit):
                if actual.get("active")!="inactive" or actual.get("substate")!="dead" or int(actual.get("main_pid",0))!=0:
                    raise TransactionError("UPGRADE_RUNNING_UNIT_NOT_STOPPED:"+unit)
            elif actual!=state:
                raise TransactionError("UPGRADE_NONPROCESS_UNIT_STATE_CHANGED:"+unit)
        return receipt
    except Exception:
        if (selector/"upgrade-receipt.json").exists(): rollback(adapter, selector)
        elif selector.exists():
            for residue in sorted(selector.rglob("*"),key=lambda p:len(p.parts),reverse=True):
                adapter.boundary(); residue.rmdir() if residue.is_dir() else residue.unlink()
            adapter.boundary(); selector.rmdir()
        raise


def main():
    if os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise SystemExit("ROOT_LINUX_REQUIRED")
    if len(sys.argv) not in {3,5} or sys.argv[1] not in {"upgrade", "rollback"} or (sys.argv[1]=="upgrade" and len(sys.argv)!=5) or (sys.argv[1]=="rollback" and len(sys.argv)!=3):
        raise SystemExit("usage: upgrade_transaction.py upgrade SOURCE PLAN EXPECTED_PLAN_DIGEST | rollback SELECTOR")
    release_for_units=json.loads((Path(sys.argv[2])/"release-manifest.json").read_text(encoding="utf-8")) if sys.argv[1]=="upgrade" else None
    adapter = RealAdapter(release_for_units["protected_unit_state"] if release_for_units else ())
    if sys.argv[1] == "rollback":
        rollback(adapter, Path(sys.argv[2]))
        print("ROLLBACK_RESTORED_EXACT_LEGACY_OUTPOST")
        return
    source = Path(sys.argv[2]).resolve()
    sys.path.insert(0,str(source))
    from verify_install_preflight import verify_source
    release = json.loads((source / "release-manifest.json").read_text(encoding="utf-8"))
    plan_path=Path(sys.argv[3]).resolve(); plan=json.loads(plan_path.read_bytes())
    verify_source(source,release)
    base=Path("/var/lib/serein/rollback"); nofollow_ancestors(Path("/"),base,allow_missing=False)
    info=base.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode)&0o022 or info.st_uid!=0 or info.st_gid!=0:
        raise SystemExit("ROLLBACK_BASE_POLICY_DENIED")
    selector=under(Path("/"),plan["rollback_selector"])
    upgrade(adapter,source,release,plan,selector,sys.argv[4])
    print("UPGRADED_INACTIVE rollback=" + str(selector))


if __name__ == "__main__":
    main()
