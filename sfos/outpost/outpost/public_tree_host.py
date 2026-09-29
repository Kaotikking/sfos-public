"""Bind the admitted public SFOS Base contract to signed Debian Host evidence."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any, Mapping

from .host_vitality import (
    ADMITTED_PUBLIC_BASE_COMMIT, ADMITTED_PUBLIC_BASE_TREE,
    JOINED_SCHEMA, digest, validate,
)

REPOSITORY = "Kaotikking/sfos-public"
BASE_COMMIT = ADMITTED_PUBLIC_BASE_COMMIT
BASE_TREE = ADMITTED_PUBLIC_BASE_TREE
LOCK_PATH = "sfos/base/packages.lock"
POLICY_PATH = "sfos/base/installer/base-policy.json"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class PublicTreeHostError(ValueError):
    pass


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise PublicTreeHostError("PUBLIC_GIT_REDIRECT_DENIED")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def _api(path: str) -> dict:
    request = urllib.request.Request(
        "https://api.github.com/repos/" + REPOSITORY + path,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "serein-outpost-host-witness/1"},
    )
    try:
        opener = urllib.request.build_opener(_RejectRedirect())
        with opener.open(request, timeout=15) as response:
            if response.geturl() != request.full_url:
                raise PublicTreeHostError("PUBLIC_GIT_REDIRECT_DENIED")
            if response.status != 200:
                raise PublicTreeHostError("PUBLIC_GIT_STATUS_DENIED")
            value = json.load(response)
    except PublicTreeHostError:
        raise
    except Exception as exc:
        raise PublicTreeHostError("PUBLIC_GIT_UNAVAILABLE") from exc
    if not isinstance(value, dict):
        raise PublicTreeHostError("PUBLIC_GIT_RESPONSE_DENIED")
    return value


def _public_blob(commit: str, tree: str, path: str, *, installed_source: Mapping[str,Any] | None = None) -> bytes:
    expected=(BASE_COMMIT,BASE_TREE) if installed_source is None else (installed_source.get("commit"),installed_source.get("tree"))
    if ((commit,tree)!=expected or not HEX40.fullmatch(str(commit)) or not HEX40.fullmatch(str(tree))
            or (installed_source is not None and (installed_source.get("repository")!=REPOSITORY
                or installed_source.get("schema")!="SereinOutpostPublicSource/v1"))):
        raise PublicTreeHostError("PUBLIC_BASE_LINEAGE_DENIED")
    head = _api("/commits/" + commit)
    if head.get("sha") != commit or head.get("commit", {}).get("tree", {}).get("sha") != tree:
        raise PublicTreeHostError("PUBLIC_COMMIT_TREE_DENIED")
    listing = _api("/git/trees/" + tree + "?recursive=1")
    if listing.get("sha") != tree or listing.get("truncated") is True:
        raise PublicTreeHostError("PUBLIC_TREE_DENIED")
    rows = [row for row in listing.get("tree", []) if isinstance(row, dict) and row.get("path") == path and row.get("type") == "blob"]
    if len(rows) != 1 or not HEX40.fullmatch(str(rows[0].get("sha", ""))):
        raise PublicTreeHostError("PUBLIC_BASE_PATH_DENIED")
    value = _api("/git/blobs/" + rows[0]["sha"])
    if value.get("sha") != rows[0]["sha"] or value.get("encoding") != "base64" or not isinstance(value.get("content"), str):
        raise PublicTreeHostError("PUBLIC_BLOB_DENIED")
    try:
        # GitHub wraps its Base64 response in lines. Strip only transport line
        # endings: all other invalid characters still fail strict decoding.
        encoded = value["content"].replace("\r", "").replace("\n", "")
        data = __import__("base64").b64decode(encoded, validate=True)
    except Exception as exc:
        raise PublicTreeHostError("PUBLIC_BLOB_DENIED") from exc
    if _git_blob(data) != rows[0]["sha"]:
        raise PublicTreeHostError("PUBLIC_BLOB_HASH_DENIED")
    return data


def installed_public_source(root: Path = Path("/")) -> dict:
    """Read only non-secret provenance inside the verified current generation."""
    from install.generation_launcher import read_selector, _read_regular
    root=Path(root)
    selector,generation=read_selector(root/"var/lib/serein-outpost/generation-state/current.json",
                                      root/"usr/share/serein/outpost-generations")
    if Path(__file__).absolute()!=generation.absolute()/"outpost/public_tree_host.py":
        raise PublicTreeHostError("INSTALLED_PUBLIC_SOURCE_RUNTIME_MISMATCH")
    raw,_=_read_regular(generation/"public-source.json",0o644)
    from install.transaction import strict_json
    value=strict_json(raw)
    required={"schema","repository","commit","tree","archive_sha256","release_digest","source_plan_sha256"}
    if (not isinstance(value,dict) or set(value)!=required
            or value.get("schema")!="SereinOutpostPublicSource/v1" or value.get("repository")!=REPOSITORY
            or value.get("release_digest")!=selector["release_digest"]
            or value.get("source_plan_sha256")!=selector["predecessor_receipt_sha256"]
            or not HEX40.fullmatch(str(value.get("commit"))) or not HEX40.fullmatch(str(value.get("tree")))
            or not HEX64.fullmatch(str(value.get("archive_sha256")))):
        raise PublicTreeHostError("INSTALLED_PUBLIC_SOURCE_DENIED")
    return value


def collect_public_host_recipe(root: Path = Path("/"), *, runner=None) -> dict:
    """Pinned Git recipe -> authenticated installed snapshot -> bounded witness."""
    from install.transaction import strict_json
    source=installed_public_source(root)
    path="sfos/base/host-manifest.json"
    raw=_public_blob(source["commit"],source["tree"],path,installed_source=source)
    manifest=strict_json(raw)
    comparison=collect_existing_host_manifest(manifest,root,runner=runner)
    if installed_public_source(root)!=source:
        raise PublicTreeHostError("INSTALLED_PUBLIC_SOURCE_CHANGED")
    body={"schema":"SFOSPublicHostRecipeWitness/v1","source":source,"manifest_path":path,
          "manifest_sha256":_sha(raw),"manifest_git_blob":_git_blob(raw),"comparison":comparison,
          "admission_effect":"NONE","downstream_activation":"NONE"}
    return {**body,"evidence_digest":digest(body)}


def _lock(data: bytes) -> dict[str, str]:
    packages: dict[str, str] = {}
    for line in data.decode("utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.count("=") != 1:
            raise PublicTreeHostError("PUBLIC_BASE_LOCK_DENIED")
        name, version = line.split("=", 1)
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", name) or not version or name in packages:
            raise PublicTreeHostError("PUBLIC_BASE_LOCK_DENIED")
        packages[name] = version
    if not packages:
        raise PublicTreeHostError("PUBLIC_BASE_LOCK_DENIED")
    return dict(sorted(packages.items()))


def inspect_existing_host_manifest(manifest: Mapping[str, Any], *, installed: Mapping[str, Any],
                                   authenticated: Mapping[str, Any], sources: list,
                                   preferences: list, host: Mapping[str, Any],
                                   gpu: Mapping[str, Any], boot_id: str,
                                   authenticated_release: Mapping[str, Any],
                                   authenticated_indexes: list) -> dict:
    """Inspect the source-owned existing-Debian recipe; never mutate packages.

    The caller must collect authenticated entries from signature/hash-verified
    indexes. The observed target cannot supply its own desired recipe. This
    comparison is a candidate witness, not authority or downstream admission.
    """
    from .host_vitality import BOOT
    required={"schema","status","scope","source_lineage","host","convergence",
              "signed_debian","sources","apt_preferences","packages","separately_verified_packages"}
    convergence={"mode":"ADOPT_EXACT_EXISTING","package_mutation":False,
                 "unlisted_package_policy":"DENY","downstream_activation":"NONE",
                 "admission":"INDEPENDENT_VERIFICATION_REQUIRED"}
    if (not isinstance(manifest,Mapping) or set(manifest)!=required
            or manifest.get("schema")!="SFOSExistingDebianHostManifest/v1"
            or manifest.get("status")!="CANDIDATE_NOT_ADMITTED"
            or manifest.get("scope")!="VM4010_MINIMUM_SEREIN_PROOF"
            or manifest.get("convergence")!=convergence
            or not BOOT.fullmatch(str(boot_id))):
        raise PublicTreeHostError("PUBLIC_HOST_MANIFEST_DENIED")
    expected={}
    for row in manifest.get("packages",[]):
        if (not isinstance(row,dict) or set(row)!={"package","version","architecture","sha256","component"}
                or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*",str(row.get("package")))
                or not isinstance(row.get("version"),str) or not row["version"]
                or row.get("architecture") not in {"amd64","all"}
                or not HEX64.fullmatch(str(row.get("sha256")))
                or row.get("component") not in {"main","contrib","non-free","non-free-firmware"}
                or row["package"] in expected):
            raise PublicTreeHostError("PUBLIC_HOST_PACKAGE_DENIED")
        expected[row["package"]]=row
    legacy=manifest.get("separately_verified_packages")
    if not expected or legacy!=[{"package":"serein-outpost","version":"1.0.31+1fa5603",
            "architecture":"all","role":"LEGACY_DPKG_METADATA_NOT_CURRENT_OUTPOST_GENERATION",
            "acceptance":"EXACT_CURRENT_GENERATION_INSTALLER_WITNESS_REQUIRED"}]:
        raise PublicTreeHostError("PUBLIC_HOST_PACKAGE_BOUNDARY_DENIED")
    desired={name:{"version":row["version"],"architecture":row["architecture"]} for name,row in expected.items()}
    desired["serein-outpost"]={"version":legacy[0]["version"],"architecture":"all"}
    differences=[{"package":name,"expected":desired.get(name),"observed":installed.get(name)}
                 for name in sorted(set(desired)|set(installed)) if desired.get(name)!=installed.get(name)]
    unknowns=[]
    if manifest["signed_debian"]!={"release":authenticated_release,"indexes":authenticated_indexes}:
        unknowns.append("PINNED_DEBIAN_SNAPSHOT_MISMATCH")
    for name,row in expected.items():
        if authenticated.get(name)!=row:unknowns.append("EXACT_SIGNED_PACKAGE_UNPROVEN:"+name)
    if sources!=manifest["sources"]:unknowns.append("HOST_SOURCE_POLICY_MISMATCH")
    if preferences!=manifest["apt_preferences"]:unknowns.append("HOST_APT_PREFERENCES_MISMATCH")
    policy=manifest["host"]
    if policy!={"os_id":"debian","version_id":"13","suite":"trixie","architecture":"amd64",
                "identity_policy":"PRESERVE","boot_policy":"PRESERVE_CURRENT_BOOT","gpu_policy":"PRESERVE_WORKING_NVIDIA"}:
        raise PublicTreeHostError("PUBLIC_HOST_POLICY_DENIED")
    if host.get("os_id")!="debian" or host.get("os_version_id")!="13" or host.get("architecture")!="amd64":
        unknowns.append("HOST_IDENTITY_MISMATCH")
    if not re.fullmatch(r"[0-9a-f]{32}",str(host.get("machine_id"))) or not host.get("hostname"):
        unknowns.append("HOST_IDENTITY_UNKNOWN")
    if (gpu.get("status")!="PASS" or gpu.get("pci_present") is not True
            or gpu.get("driver_loaded") is not True or type(gpu.get("device_count")) is not int
            or gpu["device_count"]<1):unknowns.append("HOST_GPU_UNPROVEN")
    body={"schema":"SFOSExistingDebianHostComparison/v1","boot_id":boot_id,
          "host":dict(host),"gpu":dict(gpu),
          "debian":{"authenticated_release":dict(authenticated_release),
                    "authenticated_indexes":authenticated_indexes,
                    "expected":dict(expected),"installed":dict(installed),"authenticated":dict(authenticated),
                    "sources":sources,"preferences":preferences},
          "manifest_sha256":_sha(json.dumps(manifest,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()),
          "package_count":len(expected),"exact_diff":differences,"unknowns":unknowns,
          "result":"EXACT_EXISTING_RECIPE_MATCH" if not differences and not unknowns else "HOST_RECIPE_UNPROVEN",
          "package_mutation":"NONE","identity_mutation":"NONE","downstream_activation":"NONE",
          "outpost_generation_acceptance":"SEPARATE_REQUIRED","admission_effect":"NONE"}
    return {**body,"evidence_digest":digest(body)}


def collect_existing_host_manifest(manifest: Mapping[str, Any], root: Path = Path("/"), *, runner=None) -> dict:
    """Reuse the installed Debian verifier against the exact cached snapshot.

    No APT update, package apply, repair or network fallback occurs. Absence or
    mismatch remains evidence. Publication/acquisition supplies the recipe;
    this function only reads the destination and authenticates content.
    """
    from . import debian_host_collector as collector
    root=Path(root)
    runner=collector._run if runner is None else runner
    boot_path=root/"proc/sys/kernel/random/boot_id"
    boot_before=collector._read_regular(boot_path).decode().strip()
    keyring=root/collector.CANONICAL_KEYRING.lstrip("/")
    collector.verify_effective_source_paths(runner)
    sources,_=collector._verify_source_files(collector.discover_sources(root),keyring,root)
    lists=root/"var/lib/apt/lists"
    release=collector.verify_inrelease(lists/"deb.debian.org_debian_dists_trixie_InRelease",keyring=keyring,runner=runner)
    if release["suite"]!="stable" or release["codename"]!="trixie":
        raise PublicTreeHostError("PINNED_DEBIAN_SNAPSHOT_MISMATCH")
    components=("main","contrib","non-free","non-free-firmware")
    paths={"debian:trixie:"+component+"/binary-amd64/Packages":
           lists/("deb.debian.org_debian_dists_trixie_"+component+"_binary-amd64_Packages") for component in components}
    indexes=collector.verify_indexes({"debian:trixie":release},paths)
    index_rows=[{"path":component+"/binary-amd64/Packages",
                 "sha256":_sha(indexes["debian:trixie:"+component+"/binary-amd64/Packages"]),
                 "bytes":len(indexes["debian:trixie:"+component+"/binary-amd64/Packages"])} for component in components]
    release_row={"sha256":release["sha256"],"date":release["date"],
                 "valid_until":release["valid_until"] or None,"suite":release["suite"],
                 "codename":release["codename"],"signers":[x.upper() for x in release["fingerprints"]]}
    expected_release=dict(manifest["signed_debian"]["release"])
    expected_release["signers"]=sorted(expected_release["signers"])
    release_row["signers"]=sorted(release_row["signers"])
    # Signature ordering is not signer identity. All remaining bytes/digests
    # must match the published recipe's pinned snapshot exactly.
    if expected_release!=release_row or manifest["signed_debian"]["indexes"]!=index_rows:
        raise PublicTreeHostError("PINNED_DEBIAN_SNAPSHOT_MISMATCH")
    desired={row["package"]:row for row in manifest["packages"]}
    authenticated={}
    for binding,data in indexes.items():
        component=binding.split(":",2)[2].split("/",1)[0]
        for row in collector._deb822_records(data.decode("utf-8")):
            name=row.get("Package");expected=desired.get(name)
            if expected and row.get("Version")==expected["version"] and row.get("Architecture")==expected["architecture"]:
                value={"package":name,"version":row["Version"],"architecture":row["Architecture"],
                       "sha256":row.get("SHA256"),"component":component}
                if name in authenticated and authenticated[name]!=value:
                    raise PublicTreeHostError("PINNED_PACKAGE_AMBIGUOUS")
                authenticated[name]=value
    status=collector._read_regular(root/"var/lib/dpkg/status").decode("utf-8")
    installed={}
    for row in collector._deb822_records(status):
        if row.get("Status")=="install ok installed":
            name=row.get("Package")
            if not name or name in installed:raise PublicTreeHostError("HOST_PACKAGE_OBSERVATION_DENIED")
            installed[name]={"version":row.get("Version"),"architecture":row.get("Architecture")}
    preferences=[]
    directory=root/"etc/apt/preferences.d"
    if directory.is_symlink():raise PublicTreeHostError("HOST_APT_PREFERENCES_DENIED")
    paths=[root/"etc/apt/preferences"]+sorted(directory.iterdir() if directory.exists() else [])
    for path in paths:
        if path.exists() or path.is_symlink():
            data=collector._read_regular(path)
            preferences.append({"path":"/"+path.relative_to(root).as_posix(),"bytes":len(data),"sha256":_sha(data)})
    identity=collector._os_release(root/"etc/os-release")
    arch=runner(("dpkg","--print-architecture"))
    host={"os_id":identity.get("ID"),"os_version_id":identity.get("VERSION_ID"),
          "architecture":arch.stdout.strip() if arch.returncode==0 else None,
          "machine_id":collector._read_regular(root/"etc/machine-id").decode().strip(),
          "hostname":collector._read_regular(root/"etc/hostname").decode().strip()}
    gpu=collector._gpu_facts(root/"sys",root/"proc/modules",runner,{name:row["version"] for name,row in installed.items()})
    boot=collector._read_regular(boot_path).decode().strip()
    if boot!=boot_before:raise PublicTreeHostError("HOST_BOOT_CHANGED_DURING_COLLECTION")
    # Pass the original signer order after independent set/order normalization.
    return inspect_existing_host_manifest(manifest,installed=installed,authenticated=authenticated,
        sources=sources,preferences=preferences,host=host,gpu=gpu,boot_id=boot,
        authenticated_release=manifest["signed_debian"]["release"],authenticated_indexes=index_rows)


def _os_release(path: Path) -> dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PublicTreeHostError("HOST_OS_RELEASE_DENIED") from exc
    values = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    if values.get("ID") != "debian" or values.get("VERSION_ID") != "13":
        raise PublicTreeHostError("HOST_BASE_IDENTITY_DENIED")
    return values


def _installed_packages() -> dict[str, str]:
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${binary:Package}=${Version}\\n"],
            text=True, capture_output=True, check=True, timeout=15,
        )
    except Exception as exc:
        raise PublicTreeHostError("HOST_PACKAGE_OBSERVATION_DENIED") from exc
    rows = {}
    for line in result.stdout.splitlines():
        if line.count("=") != 1:
            raise PublicTreeHostError("HOST_PACKAGE_OBSERVATION_DENIED")
        name, version = line.split("=", 1)
        rows[name] = version
    return rows


def _gpu() -> dict[str, Any]:
    try:
        result = subprocess.run(["nvidia-smi", "-L"], text=True, capture_output=True, check=True, timeout=15)
    except Exception:
        return {"pci_present": False, "driver_loaded": False, "device_count": 0, "driver_packages": {}, "status": "FAIL"}
    count = len([line for line in result.stdout.splitlines() if line.strip()])
    return {"pci_present": count > 0, "driver_loaded": count > 0, "device_count": count, "driver_packages": {}, "status": "PASS" if count else "FAIL"}


def bind_signed_debian_observation(observation: Mapping[str, Any]) -> dict:
    """Join one signature-verified Debian observation to the pinned SFOS tree.

    The public tree specifies Serein's exact Base contract. Debian's signed
    Release/index evidence independently establishes that the observed package
    facts are authentic Debian facts. Either denominator can fail the Host gate.
    """
    checked = validate(observation)
    if checked.get("schema") != "SereinOutpostHostVitalityObservation/v1":
        raise PublicTreeHostError("SIGNED_DEBIAN_OBSERVATION_DENIED")
    lock_bytes = _public_blob(BASE_COMMIT, BASE_TREE, LOCK_PATH)
    policy_bytes = _public_blob(BASE_COMMIT, BASE_TREE, POLICY_PATH)
    try:
        policy = json.loads(policy_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicTreeHostError("PUBLIC_BASE_POLICY_DENIED") from exc
    if not isinstance(policy, dict) or policy.get("schema") != "SFOSDebianBasePolicy/v1" or policy.get("source_kinds") != ["OFFLINE_USB_MEDIA", "PINNED_PUBLIC_REPOSITORY"]:
        raise PublicTreeHostError("PUBLIC_BASE_POLICY_DENIED")
    expected = _lock(lock_bytes)
    debian = checked["debian"]
    installed = debian["installed_packages"]
    repository = debian["repository_packages"]
    exact_diff = [{"package": name, "expected": version, "observed": installed.get(name)} for name, version in expected.items() if installed.get(name) != version]
    unknowns = ["PUBLIC_LOCK_VERSION_NOT_IN_SIGNED_INDEX:" + name for name, version in expected.items() if repository.get(name) != version]
    configured = [row for pin in debian["pins"] if isinstance(pin,dict)
                  for row in pin.get("sources",[]) if isinstance(row,dict)]
    components = policy.get("components")
    if (not isinstance(components,list) or not components
            or any(not isinstance(item,str) or not item for item in components)
            or len(set(components)) != len(components)):
        unknowns.append("PUBLIC_BASE_COMPONENT_POLICY_UNKNOWN")
    elif not configured:
        unknowns.append("INSTALLED_SOURCE_COMPONENTS_UNKNOWN")
    elif any(not isinstance(row.get("components"),list)
             or any(not isinstance(item,str) for item in row["components"])
             or set(row["components"]) != set(components) for row in configured):
        # Do not silently narrow signed Host evidence or rewrite the Base
        # policy to conceal their disagreement. Outpost remains observable.
        unknowns.append("PUBLIC_BASE_COMPONENTS_MISMATCH")
    source = {
        "repository": REPOSITORY,
        "commit": BASE_COMMIT,
        "tree": BASE_TREE,
        "lock_path": LOCK_PATH,
        "lock_sha256": _sha(lock_bytes),
        "policy_path": POLICY_PATH,
        "policy_sha256": _sha(policy_bytes),
        "expected_packages": expected,
        "observed_packages": {name: installed.get(name) for name in expected},
        "exact_diff": exact_diff,
        "unknowns": unknowns,
        # This verdict describes this exact public contract, not every package
        # in a moving Debian index. Keep the independent Debian evidence below
        # unchanged. Public-contract parity alone is never SFOS admission.
        "status": "PASS" if not exact_diff and not unknowns else "DRIFT",
    }
    body = {
        "schema": JOINED_SCHEMA,
        "target": checked["target"],
        "boot_id": checked["boot_id"],
        "observed_at": checked["observed_at"],
        "host": checked["host"],
        "gpu": checked["gpu"],
        "debian": debian,
        "public_base": source,
    }
    return validate({**body, "evidence_digest": digest(body)})


def collect(boot_id: str, observed_at: float | None = None, os_release_path: Path = Path("/etc/os-release"), machine_id_path: Path = Path("/etc/machine-id")) -> dict:
    lock_bytes = _public_blob(BASE_COMMIT, BASE_TREE, LOCK_PATH)
    policy_bytes = _public_blob(BASE_COMMIT, BASE_TREE, POLICY_PATH)
    try:
        policy = json.loads(policy_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicTreeHostError("PUBLIC_BASE_POLICY_DENIED") from exc
    if not isinstance(policy, dict) or policy.get("schema") != "SFOSDebianBasePolicy/v1" or policy.get("source_kinds") != ["OFFLINE_USB_MEDIA", "PINNED_PUBLIC_REPOSITORY"]:
        raise PublicTreeHostError("PUBLIC_BASE_POLICY_DENIED")
    expected = _lock(lock_bytes)
    observed = _installed_packages()
    exact_diff = [{"package": name, "expected": version, "observed": observed.get(name)} for name, version in expected.items() if observed.get(name) != version]
    source = {
        "repository": REPOSITORY,
        "commit": BASE_COMMIT,
        "tree": BASE_TREE,
        "lock_path": LOCK_PATH,
        "lock_sha256": _sha(lock_bytes),
        "policy_path": POLICY_PATH,
        "policy_sha256": _sha(policy_bytes),
        "expected_packages": expected,
        "observed_packages": {name: observed.get(name) for name in expected},
        "exact_diff": exact_diff,
        "unknowns": [],
        "status": "PASS" if not exact_diff else "DRIFT",
    }
    os_values = _os_release(os_release_path)
    return {
        "schema": "SereinOutpostHostVitalityObservation/v2",
        "target": "SEREIN_HOST",
        "boot_id": boot_id,
        "observed_at": time.time() if observed_at is None else observed_at,
        "host": {"hostname": os_values.get("PRETTY_NAME", "debian"), "os_id": "debian", "os_version_id": "13", "machine_id": machine_id_path.read_text(encoding="utf-8").strip(), "status": "PASS"},
        "gpu": _gpu(),
        "public_base": source,
    }
