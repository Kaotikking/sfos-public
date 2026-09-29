"""G0 startup consumer contract; no unit installation or actual exec."""
import pytest
from install import generation_launcher as launcher
from install.public_generation_transaction import generation_inventory
from install.transaction import canonical, sha
import json


def native_generation(tmp_path):
    """Synthetic runtime layout only; no installed or signed authority."""
    body=b"# synthetic G0 module\n"
    release={"schema":"SereinOutpostSourceRelease/v2",
             "classification":"PUBLIC_HOST_GATE_SAFE_UNCOMMISSIONED",
             "payload":[{"path":"outpost/service.py","bytes":len(body),"sha256":sha(body)}],
             "source_only_files":[]}
    release["self_digest"]="sha256:"+sha(canonical(release))
    identifier=release["self_digest"].removeprefix("sha256:")
    root=tmp_path/"generations";generation=root/identifier
    (generation/"outpost").mkdir(parents=True)
    generation.chmod(0o755);(generation/"outpost").chmod(0o755)
    material={"outpost/service.py":body,"release-manifest.json":canonical(release)+b"\n"}
    inventory=generation_inventory(material)
    for name,data in material.items():
        path=generation/name;path.write_bytes(data);path.chmod(0o644)
    path=generation/"generation-inventory.json"
    path.write_bytes(canonical(inventory)+b"\n");path.chmod(0o644)
    selector={"schema":"SereinOutpostGenerationSelector/v1","generation":identifier,
              "release_digest":release["self_digest"],"predecessor_receipt_sha256":"a"*64,
              "inventory_digest":sha(canonical(inventory))}
    selector["selector_digest"]=launcher._digest(selector)
    current=tmp_path/"current.json";current.write_bytes(canonical(selector)+b"\n");current.chmod(0o644)
    return root,generation,current,selector


def test_native_inventory_and_source_schema_match_existing_consumer(tmp_path):
    root,generation,current,selector=native_generation(tmp_path)
    assert launcher.read_selector(current,root)==(selector,generation)


@pytest.mark.parametrize("defect",["payload","inventory","selector","extra","symlink"])
def test_native_bad_current_never_uses_lkg(tmp_path,defect):
    root,generation,current,selector=native_generation(tmp_path)
    lkg=tmp_path/"lkg.json";lkg.write_bytes(current.read_bytes());lkg.chmod(0o644)
    if defect=="payload":(generation/"outpost/service.py").write_bytes(b"changed")
    elif defect=="inventory":(generation/"generation-inventory.json").write_text("[]")
    elif defect=="selector":current.write_text("{}")
    elif defect=="extra":(generation/"unexpected").write_text("extra")
    else:
        current.unlink();current.symlink_to(lkg)
    before=lkg.read_bytes()
    with pytest.raises(launcher.LaunchDenied):
        launcher.select_generation(current,lkg,root)
    assert lkg.read_bytes()==before


def test_current_failure_does_not_select_historical_generation(monkeypatch, tmp_path):
    calls=[]
    def read(path, root):
        calls.append(path.name)
        if path.name=="current.json":
            raise launcher.LaunchDenied("GENERATION_RELEASE_DENIED")
        return {"generation":"historical"},root/"historical"
    monkeypatch.setattr(launcher,"read_selector",read)
    with pytest.raises(launcher.LaunchDenied,match="GENERATION_RELEASE_DENIED"):
        launcher.select_generation(tmp_path/"current.json",tmp_path/"lkg.json",tmp_path/"generations")
    assert calls==["current.json"]


def test_current_success_retains_attributable_selection(monkeypatch,tmp_path):
    value={"generation":"a"*64};generation=tmp_path/value["generation"]
    monkeypatch.setattr(launcher,"read_selector",lambda *args:(value,generation))
    assert launcher.select_generation(tmp_path/"current.json",tmp_path/"lkg.json",tmp_path)==(value,generation,"current")


def test_g0_arguments_forward_without_identity_or_permission_changes(monkeypatch,tmp_path):
    generation=tmp_path/"generation";(generation/"outpost").mkdir(parents=True)
    (generation/"outpost/service.py").write_text("# synthetic module\n")
    monkeypatch.setattr(launcher,"select_generation",lambda *args:({},generation,"current"))
    def forbidden(*args,**kwargs):pytest.fail("Launcher must not change identity or permissions")
    for name in ("setuid","setgid","setgroups","chmod","chown"):
        monkeypatch.setattr(launcher.os,name,forbidden)
    calls=[]
    monkeypatch.setattr(launcher.os,"execve",lambda *args:calls.append(args))
    launcher.launch(tmp_path/"current.json",tmp_path,"outpost/service.py",["--host-vitality-root","/var/lib/serein-outpost/host-vitality"])
    executable,args,environment=calls[0]
    assert executable=="/usr/bin/python3"
    assert args==["/usr/bin/python3","-B","-m","outpost.service","--host-vitality-root","/var/lib/serein-outpost/host-vitality"]
    assert environment["PYTHONPATH"]==str(generation)
    assert environment["PYTHONDONTWRITEBYTECODE"]=="1"
