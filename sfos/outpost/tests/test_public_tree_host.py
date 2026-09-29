import base64
import hashlib

import pytest

from outpost import public_tree_host as subject
from outpost.host_vitality import HostVitalityError, HostVitalityStore, digest, validate


def test_public_tree_contract_is_compared_to_installed_packages(monkeypatch,tmp_path):
    lock=b"python3=3.13.5-1\nsystemd=257.13-1~deb13u1\n"
    policy=b'{"schema":"SFOSDebianBasePolicy/v1","source_kinds":["OFFLINE_USB_MEDIA","PINNED_PUBLIC_REPOSITORY"]}'
    monkeypatch.setattr(subject,"_public_blob",lambda commit,tree,path:lock if path==subject.LOCK_PATH else policy)
    monkeypatch.setattr(subject,"_installed_packages",lambda:{"python3":"3.13.5-1","systemd":"257.13.0"})
    monkeypatch.setattr(subject,"_gpu",lambda:{"pci_present":True,"driver_loaded":True,"device_count":1,"driver_packages":{},"status":"PASS"})
    release=tmp_path/"os-release";release.write_text('ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian 13"\n')
    machine=tmp_path/"machine-id";machine.write_text("machine\n")
    value=subject.collect("11111111-2222-4333-8444-555555555555",1.0,release,machine)
    assert value["public_base"]["repository"]=="Kaotikking/sfos-public"
    assert value["public_base"]["status"]=="DRIFT"
    assert value["public_base"]["expected_packages"]["systemd"]=="257.13-1~deb13u1"


@pytest.mark.parametrize("line_ending", ["", "\n", "\r\n"])
def test_pinned_public_git_blob_rejects_any_other_tree(monkeypatch, line_ending):
    data=b"python3=3.13.5-1\nsystemd=257.13-1~deb13u1\nca-certificates=20250419\n"; blob=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
    encoded=base64.b64encode(data).decode()
    # The canonical GitHub API response wraps Base64 at 60 characters.
    content=line_ending.join(encoded[i:i+60] for i in range(0,len(encoded),60))+line_ending
    responses={
        "/commits/"+subject.BASE_COMMIT:{"sha":subject.BASE_COMMIT,"commit":{"tree":{"sha":subject.BASE_TREE}}},
        "/git/trees/"+subject.BASE_TREE+"?recursive=1":{"sha":subject.BASE_TREE,"truncated":False,"tree":[{"path":subject.LOCK_PATH,"type":"blob","sha":blob}]},
        "/git/blobs/"+blob:{"sha":blob,"encoding":"base64","content":content},
    }
    monkeypatch.setattr(subject,"_api",lambda path:responses[path])
    assert subject._public_blob(subject.BASE_COMMIT,subject.BASE_TREE,subject.LOCK_PATH)==data
    with pytest.raises(subject.PublicTreeHostError,match="LINEAGE_DENIED"):
        subject._public_blob("f"*40,subject.BASE_TREE,subject.LOCK_PATH)
    responses["/git/blobs/"+blob]["content"]=content+"!"
    with pytest.raises(subject.PublicTreeHostError,match="PUBLIC_BLOB_DENIED"):
        subject._public_blob(subject.BASE_COMMIT,subject.BASE_TREE,subject.LOCK_PATH)
    responses["/git/blobs/"+blob]["content"]=base64.b64encode(data+b"tampered").decode()
    with pytest.raises(subject.PublicTreeHostError,match="PUBLIC_BLOB_HASH_DENIED"):
        subject._public_blob(subject.BASE_COMMIT,subject.BASE_TREE,subject.LOCK_PATH)


def test_public_tree_observation_is_the_host_gate_input(tmp_path):
    body={"schema":"SereinOutpostHostVitalityObservation/v2","target":"VM4010","boot_id":"11111111-2222-4333-8444-555555555555","observed_at":1.0,"host":{"hostname":"vm4010","os_id":"debian","os_version_id":"13","machine_id":"m","status":"PASS"},"gpu":{"pci_present":True,"driver_loaded":True,"device_count":1,"driver_packages":{},"status":"PASS"},"public_base":{"repository":"Kaotikking/sfos-public","commit":"a"*40,"tree":"b"*40,"lock_path":"sfos/base/packages.lock","lock_sha256":"a"*64,"policy_path":"sfos/base/installer/base-policy.json","policy_sha256":"b"*64,"expected_packages":{"python3":"3.13.5-1"},"observed_packages":{"python3":"3.13.5-1"},"exact_diff":[],"unknowns":[],"status":"PASS"}}
    historical={**body,"evidence_digest":digest(body)}
    assert validate(historical)["schema"]=="SereinOutpostHostVitalityObservation/v2"
    with pytest.raises(HostVitalityError,match="ACTIVE_SCHEMA_DENIED"):
        HostVitalityStore(tmp_path).record(historical)


def test_public_tree_contract_requires_the_locked_version_in_signed_debian_evidence(monkeypatch):
    lock=b"python3=3.13.5-1\n";policy=b'{"schema":"SFOSDebianBasePolicy/v1","source_kinds":["OFFLINE_USB_MEDIA","PINNED_PUBLIC_REPOSITORY"],"components":["main","contrib","non-free","non-free-firmware"]}'
    monkeypatch.setattr(subject,"_public_blob",lambda commit,tree,path:lock if path==subject.LOCK_PATH else policy)
    body={"schema":"SereinOutpostHostVitalityObservation/v1","target":"SEREIN_HOST","boot_id":"11111111-2222-4333-8444-555555555555","observed_at":1.0,"host":{"hostname":"vm4010","os_id":"debian","os_version_id":"13","machine_id":"m","status":"PASS"},"gpu":{"pci_present":True,"driver_loaded":True,"device_count":1,"driver_packages":{},"status":"PASS"},"debian":{"release":"Debian 13","release_sha256":"a"*64,"signer_fingerprint":"b"*64,"repositories":["deb.debian.org","security.debian.org"],"installed_identity":{},"installed_packages":{"python3":"3.13.5-1"},"repository_packages":{"python3":"3.13.5-1"},"exact_diff":[],"pins":[],"exceptions":[],"unknowns":[],"correction_result":"NOT_REQUIRED","status":"PASS"}}
    body["debian"]["pins"]=[{"sources":[{"components":["main","contrib","non-free","non-free-firmware"]}]}]
    joined=subject.bind_signed_debian_observation({**body,"evidence_digest":digest(body)})
    assert joined["schema"]=="SereinOutpostHostVitalityObservation/v3" and joined["public_base"]["status"]=="PASS"
    body["debian"]["repository_packages"]["python3"]="3.13.5-2"
    drift=subject.bind_signed_debian_observation({**body,"evidence_digest":digest(body)})
    assert drift["public_base"]["status"]=="DRIFT" and drift["public_base"]["unknowns"]==["PUBLIC_LOCK_VERSION_NOT_IN_SIGNED_INDEX:python3"]


@pytest.mark.parametrize("components,configured,expected",[
    (["main","contrib","non-free-firmware"],["main","contrib","non-free","non-free-firmware"],"PUBLIC_BASE_COMPONENTS_MISMATCH"),
    (None,["main"],"PUBLIC_BASE_COMPONENT_POLICY_UNKNOWN"),
    (["main"],None,"INSTALLED_SOURCE_COMPONENTS_UNKNOWN"),
])
def test_policy_component_disagreement_is_evidence_not_silent_host_pass(monkeypatch,components,configured,expected):
    import copy,json
    from tests.test_host_vitality import observation
    body=observation();body.pop("public_base");body["schema"]="SereinOutpostHostVitalityObservation/v1"
    body["debian"]["pins"]=[] if configured is None else [{"sources":[{"components":configured}]}]
    body["evidence_digest"]=digest({key:value for key,value in body.items() if key!="evidence_digest"})
    before=copy.deepcopy(body)
    policy={"schema":"SFOSDebianBasePolicy/v1","source_kinds":["OFFLINE_USB_MEDIA","PINNED_PUBLIC_REPOSITORY"],"components":components}
    encoded=json.dumps(policy).encode()
    monkeypatch.setattr(subject,"_public_blob",lambda commit,tree,path:b"base-files=13.6\n" if path==subject.LOCK_PATH else encoded)
    result=subject.bind_signed_debian_observation(body)
    assert result["public_base"]["status"]=="DRIFT"
    assert expected in result["public_base"]["unknowns"]
    assert body==before and json.loads(encoded)==policy


def test_unrelated_upstream_update_does_not_redefine_public_lock(monkeypatch):
    import copy, json
    from tests.test_host_vitality import observation
    body=observation();body.pop("public_base")
    body["schema"]="SereinOutpostHostVitalityObservation/v1"
    debian=body["debian"]
    debian.update(status="DRIFT",correction_result="PENDING",
                  exact_diff=[{"package":"unselected","installed":"1","repository":"2"}])
    debian["installed_packages"]["unselected"]="1"
    debian["repository_packages"]["unselected"]="2"
    debian["pins"]=[{"sources":[{"components":["main"]}]}]
    body["evidence_digest"]=digest({k:v for k,v in body.items() if k!="evidence_digest"})
    policy=json.dumps({"schema":"SFOSDebianBasePolicy/v1",
                       "source_kinds":["OFFLINE_USB_MEDIA","PINNED_PUBLIC_REPOSITORY"],
                       "components":["main"]}).encode()
    monkeypatch.setattr(subject,"_public_blob",lambda commit,tree,path:b"base-files=13.6\n" if path==subject.LOCK_PATH else policy)
    before=copy.deepcopy(body)
    joined=subject.bind_signed_debian_observation(body)
    assert joined["public_base"]["expected_packages"]=={"base-files":"13.6"}
    assert joined["public_base"]["status"]=="PASS"
    assert joined["debian"]==before["debian"] and body==before
    # A five-package (or fixture one-package) parity check is not a complete
    # host-generation admission; preserve the independent unresolved evidence.
    from outpost.host_vitality import classify
    assert classify(joined,None)=="DRIFT_DETECTED"


def _existing_recipe_inputs():
    import json
    from pathlib import Path
    recipe=json.loads((Path(__file__).parents[2]/"base/host-manifest.json").read_text())
    packages={r["package"]:{"version":r["version"],"architecture":r["architecture"]} for r in recipe["packages"]}
    packages["serein-outpost"]={"version":"1.0.31+1fa5603","architecture":"all"}
    return recipe,dict(installed=packages,
        authenticated={r["package"]:dict(r) for r in recipe["packages"]},
        sources=recipe["sources"],preferences=[],
        host={"os_id":"debian","os_version_id":"13","architecture":"amd64","machine_id":"1"*32,"hostname":"fixture"},
        gpu={"status":"PASS","pci_present":True,"driver_loaded":True,"device_count":1},
        boot_id="11111111-2222-4333-8444-555555555555",
        authenticated_release=recipe["signed_debian"]["release"],
        authenticated_indexes=recipe["signed_debian"]["indexes"])


def test_exact_existing_recipe_is_comparison_not_install_or_admission():
    recipe,inputs=_existing_recipe_inputs()
    result=subject.inspect_existing_host_manifest(recipe,**inputs)
    assert result["result"]=="EXACT_EXISTING_RECIPE_MATCH"
    assert result["package_count"]==570
    assert result["package_mutation"]==result["admission_effect"]==result["downstream_activation"]=="NONE"
    assert result["outpost_generation_acceptance"]=="SEPARATE_REQUIRED"
    assert result["host"]==inputs["host"] and result["gpu"]==inputs["gpu"]
    assert result["evidence_digest"]==digest({k:v for k,v in result.items() if k!="evidence_digest"})


@pytest.mark.parametrize("defect",["newer_package","missing_package","extra_package","artifact_hash","snapshot","sources","preferences","identity","gpu"])
def test_existing_recipe_does_not_adopt_drift_or_unknown_provenance(defect):
    import copy
    recipe,inputs=_existing_recipe_inputs();inputs=copy.deepcopy(inputs)
    name=recipe["packages"][0]["package"]
    if defect=="newer_package":inputs["installed"][name]["version"]="999"
    elif defect=="missing_package":inputs["installed"].pop(name)
    elif defect=="extra_package":inputs["installed"]["tailscale"]={"version":"1","architecture":"amd64"}
    elif defect=="artifact_hash":inputs["authenticated"][name]["sha256"]="0"*64
    elif defect=="snapshot":inputs["authenticated_release"]["sha256"]="0"*64
    elif defect=="sources":inputs["sources"]=[]
    elif defect=="preferences":inputs["preferences"]=[{"path":"/etc/apt/preferences","sha256":"a"*64,"bytes":1}]
    elif defect=="identity":inputs["host"]["os_id"]="ubuntu"
    elif defect=="gpu":inputs["gpu"]["driver_loaded"]=False
    before=copy.deepcopy(inputs)
    result=subject.inspect_existing_host_manifest(recipe,**inputs)
    assert result["result"]=="HOST_RECIPE_UNPROVEN"
    assert result["admission_effect"]=="NONE" and inputs==before


def _cached_recipe_fixture(tmp_path):
    from tests.test_debian_host_collector import _fixture,_write,_runner
    recipe,_=_existing_recipe_inputs()
    root,_,_=_fixture(tmp_path)
    recipe["packages"]=[r for r in recipe["packages"] if r["package"] in {"base-files","nvidia-driver"}]
    rows=[];indexes=[]
    for component in ("main","contrib","non-free","non-free-firmware"):
        records=["Package: {package}\nVersion: {version}\nArchitecture: {architecture}\nSHA256: {sha256}\n".format(**r)
                 for r in recipe["packages"] if r["component"]==component]
        data=("\n".join(records)+("\n" if records else "")).encode()
        name=component+"/binary-amd64/Packages"
        _write(root/("var/lib/apt/lists/deb.debian.org_debian_dists_trixie_"+component+"_binary-amd64_Packages"),data)
        sha=hashlib.sha256(data).hexdigest()
        rows.append(f" {sha} {len(data)} {name}")
        indexes.append({"path":name,"sha256":sha,"bytes":len(data)})
    release=("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nSuite: stable\nCodename: trixie\n"
             "Date: Sun, 06 Sep 2026 00:00:00 +0000\nSHA256:\n"+"\n".join(rows)+
             "\n-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\n").encode()
    _write(root/"var/lib/apt/lists/deb.debian.org_debian_dists_trixie_InRelease",release)
    recipe["signed_debian"]={"release":{"sha256":hashlib.sha256(release).hexdigest(),
        "date":"Sun, 06 Sep 2026 00:00:00 +0000","valid_until":None,"suite":"stable","codename":"trixie","signers":["A"*40]},"indexes":indexes}
    status="\n\n".join("Package: {package}\nVersion: {version}\nArchitecture: {architecture}\nStatus: install ok installed".format(**r)
        for r in recipe["packages"]+recipe["separately_verified_packages"])+"\n"
    _write(root/"var/lib/dpkg/status",status)
    return root,recipe,_runner


def test_cached_recipe_native_files_join_exact_snapshot_without_package_effect(tmp_path):
    root,recipe,runner=_cached_recipe_fixture(tmp_path)
    before={p.relative_to(root).as_posix():p.read_bytes() for p in root.rglob("*") if p.is_file()}
    result=subject.collect_existing_host_manifest(recipe,root,runner=runner)
    assert result["result"]=="EXACT_EXISTING_RECIPE_MATCH" and result["package_count"]==2
    assert result["host"]["machine_id"]=="a"*32
    assert before=={p.relative_to(root).as_posix():p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_cached_recipe_denies_boot_transition_during_collection(tmp_path):
    root,recipe,runner=_cached_recipe_fixture(tmp_path)
    def boot_change(argv,**kwargs):
        if argv[0]=="nvidia-smi":
            (root/"proc/sys/kernel/random/boot_id").write_text("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\n")
        return runner(argv,**kwargs)
    with pytest.raises(subject.PublicTreeHostError,match="BOOT_CHANGED"):
        subject.collect_existing_host_manifest(recipe,root,runner=boot_change)


@pytest.mark.parametrize("defect",["signature","index","snapshot"])
def test_cached_recipe_requires_actual_signature_index_and_manifest_binding(tmp_path,defect):
    from subprocess import CompletedProcess
    from outpost.debian_host_collector import DebianHostEvidenceError
    root,recipe,runner=_cached_recipe_fixture(tmp_path)
    if defect=="index":
        with (root/"var/lib/apt/lists/deb.debian.org_debian_dists_trixie_main_binary-amd64_Packages").open("ab") as f:f.write(b"tampered")
    if defect=="snapshot":recipe["signed_debian"]["release"]["sha256"]="0"*64
    def checked(argv,**kwargs):
        if defect=="signature" and argv[0]=="gpgv":return CompletedProcess(argv,2,"","")
        return runner(argv,**kwargs)
    with pytest.raises((subject.PublicTreeHostError,DebianHostEvidenceError)):
        subject.collect_existing_host_manifest(recipe,root,runner=checked)


def test_installed_source_requires_inventory_and_source_plan_binding(tmp_path,monkeypatch):
    import json
    from tests.test_generation_launcher import native_generation
    from install import generation_launcher as launcher
    from install.transaction import canonical,sha
    root,generation,current,selector=native_generation(tmp_path)
    source={"schema":"SereinOutpostPublicSource/v1","repository":subject.REPOSITORY,
            "commit":"a"*40,"tree":"b"*40,"archive_sha256":"c"*64,
            "release_digest":selector["release_digest"],"source_plan_sha256":"a"*64}
    path=generation/"public-source.json";path.write_bytes(canonical(source));path.chmod(0o644)
    inventory=json.loads((generation/"generation-inventory.json").read_text())
    inventory.append({"kind":"file","path":"public-source.json","bytes":path.stat().st_size,
                      "sha256":sha(path.read_bytes()),"mode":"0644","uid":0,"gid":0})
    (generation/"generation-inventory.json").write_bytes(canonical(inventory))
    selector["inventory_digest"]=sha(canonical(inventory));selector["selector_digest"]=launcher._digest(selector)
    current.write_bytes(canonical(selector))
    reader=launcher.read_selector
    monkeypatch.setattr(launcher,"read_selector",lambda *_:reader(current,root))
    monkeypatch.setattr(subject,"__file__",str(generation/"outpost/public_tree_host.py"))
    assert subject.installed_public_source(tmp_path)==source
    path.write_bytes(canonical({**source,"commit":"f"*40}))
    with pytest.raises(launcher.LaunchDenied,match="GENERATION_FILE_DENIED"):
        subject.installed_public_source(tmp_path)


def test_public_recipe_collection_rechecks_installed_source_after_inspection(monkeypatch,tmp_path):
    import json
    source={"schema":"SereinOutpostPublicSource/v1","repository":subject.REPOSITORY,
            "commit":"a"*40,"tree":"b"*40,"archive_sha256":"c"*64,
            "release_digest":"sha256:"+"d"*64,"source_plan_sha256":"e"*64}
    recipe,_=_existing_recipe_inputs();calls=[]
    monkeypatch.setattr(subject,"installed_public_source",lambda root:dict(source))
    def blob(commit,tree,path,**kwargs):
        calls.append((commit,tree,path,kwargs["installed_source"]))
        return json.dumps(recipe).encode()
    monkeypatch.setattr(subject,"_public_blob",blob)
    monkeypatch.setattr(subject,"collect_existing_host_manifest",lambda *a,**k:{"result":"HOST_RECIPE_UNPROVEN"})
    result=subject.collect_public_host_recipe(tmp_path)
    assert calls==[("a"*40,"b"*40,"sfos/base/host-manifest.json",source)]
    assert result["source"]==source and result["admission_effect"]=="NONE"
    states=iter([source,{**source,"commit":"f"*40}])
    monkeypatch.setattr(subject,"installed_public_source",lambda root:next(states))
    with pytest.raises(subject.PublicTreeHostError,match="SOURCE_CHANGED"):
        subject.collect_public_host_recipe(tmp_path)
