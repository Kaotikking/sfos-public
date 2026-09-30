"""Exact source-byte regressions, not an installable Kernel fixture."""
import ast
import configparser
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "kernel_manifest_refresh", Path(__file__).resolve().parents[1] / "refresh_manifest.py"
)
refresh = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(refresh)


@pytest.fixture
def package(tmp_path, monkeypatch):
    monkeypatch.setattr(refresh, "ROOT", tmp_path)
    files = (
        "payload/serein_stage1/authority.py",
        "payload/serein_stage1/operations.py",
        "payload/serein_stage1/interface.py",
        "install/kernel_first_install.py",
        "install/offline_ollama_transaction.py",
    )
    for name in files:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"# Non-installable source-byte fixture.\n")
    manifest = tmp_path / "release-manifest.json"
    manifest.write_text(json.dumps({
        "branch_order": ["AUTHORITY", "OPERATIONS", "INTERFACE"],
        "payload": [], "self_digest": "UNPROVEN", "activation": "INACTIVE_OUTPOST_OWNED",
    }) + "\n", encoding="utf-8")
    (tmp_path / "install-layout.json").write_text(json.dumps({
        "payload_roots": {"payload/serein_stage1": "/usr/lib/python3/dist-packages/serein_stage1"},
        "payload_branches": dict(zip(files[:3], ("AUTHORITY", "OPERATIONS", "INTERFACE"))),
    }) + "\n", encoding="utf-8")
    return tmp_path, files, manifest.read_bytes()


def test_lf_manifest_binds_actual_payload_and_installer_bytes(package):
    root, files, _ = package
    refresh.main()
    manifest = json.loads((root / "release-manifest.json").read_bytes())
    rows = manifest["payload"] + manifest["installer_files"]
    assert {row[0] for row in rows} == set(files)
    for path, size, digest, _ in rows:
        actual = (root / path).read_bytes()
        assert (size, digest) == (len(actual), hashlib.sha256(actual).hexdigest())
    unsigned = {k: v for k, v in manifest.items() if k != "self_digest"}
    assert manifest["self_digest"] == "sha256:" + refresh.sha(refresh.canonical(unsigned))
    assert b"\r" not in (root / "release-manifest.json").read_bytes()
    assert manifest["activation"] == "INACTIVE_OUTPOST_OWNED"


def test_current_unsealed_layout_covers_retained_payload_and_generated_paths():
    """Placement closure only: no release seal, execution, or admission."""
    root = Path(__file__).resolve().parents[1]
    layout = json.loads((root / "install-layout.json").read_bytes())
    paths = {p.relative_to(root).as_posix() for p in (root / "payload").rglob("*") if p.is_file()}
    assert set(layout["payload_branches"]) == paths
    assert set(layout["payload_branches"].values()) == {"AUTHORITY", "OPERATIONS", "INTERFACE"}
    for name in paths:
        assert len([prefix for prefix in layout["payload_roots"]
                    if name == prefix or name.startswith(prefix + "/")]) == 1
    assert layout["activation"] == "INACTIVE_OUTPOST_OWNED"
    spec = importlib.util.spec_from_file_location("layout_installer_contract", root / "install/kernel_first_install.py")
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    generated = {row["target"]: row for row in layout["generated_vm_local"]}
    assert len(generated) == len(layout["generated_vm_local"])
    assert set(generated) == set(installer.GENERATED)
    assert generated[installer.NATIVE_KEY]["mode"] == "0600"
    assert generated[installer.NATIVE_KEY]["export"] == "DENIED"
    assert generated[installer.NATIVE_REGISTRY]["mode"] == "0644"
    assert layout["payload_branches"]["payload/serein_stage1/__init__.py"] == "INTERFACE"
    assert layout["payload_branches"]["payload/serein_stage1/companion_provider.py"] == "INTERFACE"


def test_retained_audit_unit_covers_exact_writer_without_changing_legacy_code():
    """Read inert unit/source contract only; does not start systemd."""
    root = Path(__file__).resolve().parents[1]
    unit = configparser.ConfigParser(interpolation=None)
    unit.read(root / "payload/systemd/serein-observation-audit.service")
    launcher = root / "payload/bin/serein-observation-audit"
    calls = [node for node in ast.walk(ast.parse(launcher.read_bytes()))
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
             and node.func.id == "Path"]
    assert len(calls) == 1
    destination = Path(ast.literal_eval(calls[0].args[0]))
    assert destination.parent == Path("/var/lib") / unit["Service"]["StateDirectory"]
    assert unit["Service"]["StateDirectoryMode"] == "0700"
    assert unit["Service"]["User"] == unit["Service"]["Group"] == "serein-stage1"
    assert unit["Service"]["ProtectSystem"] == "strict"
    assert unit["Service"]["RestrictAddressFamilies"] == "AF_UNIX"
    assert unit["Service"]["ExecStart"] == "/usr/libexec/serein/serein-observation-audit"
    assert unit["Unit"]["Requires"] == "serein-observation-audit.socket"


@pytest.mark.parametrize("index", range(5))
def test_crlf_source_is_rejected_without_resealing_manifest(package, index):
    root, files, prior = package
    path = root / files[index]
    changed = path.read_bytes().replace(b"\n", b"\r\n")
    path.write_bytes(changed)
    with pytest.raises(ValueError, match="KERNEL_SOURCE_REQUIRES_EXACT_LF_BYTES"):
        refresh.main()
    assert (root / "release-manifest.json").read_bytes() == prior
    assert path.read_bytes() == changed


def test_authority_only_material_cannot_be_sealed_as_complete_kernel(package):
    root, files, prior = package
    for name in files[1:3]:
        (root / name).unlink()
    path = root / "install-layout.json"
    layout = json.loads(path.read_bytes())
    for name in files[1:3]:
        del layout["payload_branches"][name]
    path.write_text(json.dumps(layout), encoding="utf-8")
    with pytest.raises(ValueError, match="KERNEL_COMPLETE_BRANCH_SET_REQUIRED"):
        refresh.main()
    assert (root / "release-manifest.json").read_bytes() == prior


def test_declared_payload_cannot_silently_disappear_during_refresh(package):
    root, _, _ = package
    extra = "payload/serein_stage1/authority_support.py"
    (root / extra).write_bytes(b"# Previously declared Authority material.\n")
    layout_path = root / "install-layout.json"
    layout = json.loads(layout_path.read_bytes())
    layout["payload_branches"][extra] = "AUTHORITY"
    layout_path.write_text(json.dumps(layout), encoding="utf-8")
    refresh.main()
    prior = (root / "release-manifest.json").read_bytes()
    (root / extra).unlink()
    del layout["payload_branches"][extra]
    layout_path.write_text(json.dumps(layout), encoding="utf-8")
    with pytest.raises(ValueError, match="KERNEL_DECLARED_PAYLOAD_MISSING"):
        refresh.main()
    assert (root / "release-manifest.json").read_bytes() == prior


def test_explicit_phase_overrides_misleading_filename(package):
    root, files, _ = package
    path = root / "install-layout.json"
    layout = json.loads(path.read_bytes())
    layout["payload_branches"] = dict(zip(files[:3], ("INTERFACE", "AUTHORITY", "OPERATIONS")))
    path.write_text(json.dumps(layout), encoding="utf-8")
    refresh.main()
    manifest = json.loads((root / "release-manifest.json").read_bytes())
    rows = []
    for relative, size, digest, mode in manifest["payload"]:
        rows.append({"branch": layout["payload_branches"][relative], "source": relative,
                     "target": "/usr/lib/python3/dist-packages/serein_stage1/" + Path(relative).name,
                     "bytes": size, "sha256": digest, "mode": mode})
    rows.sort(key=lambda row: (("AUTHORITY", "OPERATIONS", "INTERFACE").index(row["branch"]), row["target"]))
    assert manifest["install_denominator_digest"] == "sha256:" + refresh.sha(refresh.canonical(rows))


@pytest.mark.parametrize("bad", (None, [], {}, {"extra.py": "AUTHORITY"}, "AUTHORITY"))
def test_missing_or_nonexact_phase_map_never_reseals(package, bad):
    root, _, prior = package
    path = root / "install-layout.json"
    layout = json.loads(path.read_bytes())
    layout["payload_branches"] = bad
    path.write_text(json.dumps(layout), encoding="utf-8")
    with pytest.raises(ValueError, match="KERNEL_BRANCH_MAP_DENIED"):
        refresh.main()
    assert (root / "release-manifest.json").read_bytes() == prior


@pytest.mark.parametrize("bad", ("ROOT", "authority", None, [], 1))
def test_unknown_phase_never_reseals(package, bad):
    root, files, prior = package
    path = root / "install-layout.json"
    layout = json.loads(path.read_bytes())
    layout["payload_branches"][files[0]] = bad
    path.write_text(json.dumps(layout), encoding="utf-8")
    with pytest.raises(ValueError, match="KERNEL_BRANCH_MAP_DENIED"):
        refresh.main()
    assert (root / "release-manifest.json").read_bytes() == prior


@pytest.mark.parametrize("reverse", (False, True))
def test_overlapping_roots_never_reseal_regardless_of_json_order(package, reverse):
    root, _, prior = package
    path = root / "install-layout.json"
    layout = json.loads(path.read_bytes())
    items = [("payload", "/wrong-prefix"),
             ("payload/serein_stage1", "/usr/lib/python3/dist-packages/serein_stage1")]
    layout["payload_roots"] = dict(reversed(items) if reverse else items)
    path.write_text(json.dumps(layout), encoding="utf-8")
    with pytest.raises(ValueError, match="KERNEL_LAYOUT_DENIED"):
        refresh.main()
    assert (root / "release-manifest.json").read_bytes() == prior
