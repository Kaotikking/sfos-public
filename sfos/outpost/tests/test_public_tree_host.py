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
