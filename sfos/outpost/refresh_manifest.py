#!/usr/bin/env python3
"""Regenerate the exact secret-free Host-gate Outpost release manifest."""
import hashlib, json
from pathlib import Path
ROOT=Path(__file__).resolve().parent
def digest(data): return hashlib.sha256(data).hexdigest()
def row(path):
 data=(ROOT/path).read_bytes(); return {"path":path,"bytes":len(data),"sha256":digest(data)}
def main():
 files=sorted(p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*") if p.is_file() and not any(part.startswith(".") for part in p.relative_to(ROOT).parts[:-1]) and "__pycache__" not in p.parts and p.suffix!=".pyc" and p.name!="release-manifest.json")
 payload=[row(p) for p in files if not p.startswith("tests/")]
 tests=[row(p) for p in files if p.startswith("tests/")]
 installable=[x for x in payload if x["path"].startswith(("outpost/","install/","systemd/")) or x["path"] in {"integration-graph.json","verify_install_preflight.py"}]
 install=[{"source":x["path"],"target":"/usr/share/serein/outpost/"+x["path"],"bytes":x["bytes"],"sha256":x["sha256"],"mode":"0644","uid":0,"gid":0} for x in installable]
 for unit in ("serein-outpost-host-witness.service","serein-outpost-presentation.service","serein-outpost-kernel-install.service","serein-outpost.target"):
  x=next(v for v in payload if v["path"]=="systemd/"+unit); install.append({"source":x["path"],"target":"/etc/systemd/system/"+unit,"bytes":x["bytes"],"sha256":x["sha256"],"mode":"0644","uid":0,"gid":0})
 launcher=next(v for v in payload if v["path"]=="install/generation_launcher.py")
 install.append({"source":launcher["path"],"target":"/usr/libexec/serein/outpost-generation-launcher","bytes":launcher["bytes"],"sha256":launcher["sha256"],"mode":"0755","uid":0,"gid":0})
 dirs=[{"target":"/usr/share/serein","mode":"0755","uid":0,"gid":0,"collision_policy":"adopt_exact"},{"target":"/usr/libexec","mode":"0755","uid":0,"gid":0,"collision_policy":"adopt_exact"},{"target":"/usr/libexec/serein","mode":"0755","uid":0,"gid":0,"collision_policy":"adopt_exact"},{"target":"/usr/share/serein/outpost","mode":"0755","uid":0,"gid":0,"collision_policy":"adopt_exact"},{"target":"/etc/serein-outpost","mode":"0750","uid":0,"gid_policy":"identity_gid","collision_policy":"adopt_exact"},{"target":"/var/lib/serein-outpost","mode":"0750","uid_policy":"identity_uid","gid_policy":"identity_gid","collision_policy":"deny"},{"target":"/run/serein/outpost","mode":"0750","uid_policy":"identity_uid","gid_policy":"identity_gid","collision_policy":"deny"}]
 for target in sorted({str(Path(x["target"]).parent).replace("\\","/") for x in install if x["target"].startswith("/usr/share/serein/outpost/")},key=lambda x:(x.count("/"),x)):
  if target not in {x["target"] for x in dirs}: dirs.append({"target":target,"mode":"0755","uid":0,"gid":0,"collision_policy":"deny"})
 release={"schema":"SereinOutpostSourceRelease/v2","generation":"host-gate-public-v2","classification":"PUBLIC_HOST_GATE_SAFE_UNCOMMISSIONED","replacement_unit_allowlist":["serein-outpost-host-witness.service","serein-outpost-presentation.service"],"replacement_controlled_roots":["/usr/share/serein/outpost"],"payload":payload,"source_only_files":tests,"install_files":install,"install_directories":dirs,"generated_files":[{"target":"/etc/serein-outpost/rollback-root","mode":"0600","uid":0,"gid":0}],"required_immutable_inputs":[{"target":"/etc/serein-outpost/readonly.token","classification":"REQUIRED_IMMUTABLE_INPUT","sha256_policy":"PLAN_BOUND_REQUIRED","mode":"0640","uid":0,"gid_policy":"identity_gid"},{"target":"/etc/serein-outpost/admission.token","classification":"REQUIRED_IMMUTABLE_INPUT","sha256_policy":"PLAN_BOUND_REQUIRED","mode":"0640","uid":0,"gid_policy":"identity_gid"},{"target":"/etc/serein-outpost/cognition-signing.pem","classification":"REQUIRED_IMMUTABLE_INPUT","sha256_policy":"PLAN_BOUND_REQUIRED","key_id":"outpost-cognition-v1","mode":"0640","uid":0,"gid_policy":"identity_gid"},{"target":"/usr/share/serein/outpost/cognition-verification.pem","classification":"REQUIRED_IMMUTABLE_INPUT","sha256_policy":"PLAN_BOUND_REQUIRED","key_id":"outpost-cognition-v1","fingerprint_policy":"PLAN_BOUND_REQUIRED","mode":"0644","uid":0,"gid":0},{"target":"/etc/serein/tls/serein-backend-cert.pem","classification":"REQUIRED_IMMUTABLE_INPUT","sha256_policy":"PLAN_BOUND_REQUIRED","mode":"0600","uid":0,"gid":0},{"target":"/etc/serein/tls/serein-backend-key.pem","classification":"REQUIRED_IMMUTABLE_INPUT","sha256_policy":"PLAN_BOUND_REQUIRED","mode":"0600","uid":0,"gid":0}],"runtime_socket_paths":["/run/serein/outpost/readonly.sock","/run/serein/outpost/admission.sock","/run/serein/outpost-presentation/status.sock"],"protected_unit_state":{},"identity_policy":{"user":"serein-outpost","group":"serein-outpost","uid_lt":1000,"gid_lt":1000,"uid_equals_gid":True,"home":"/nonexistent","shell":"/usr/sbin/nologin","supplementary_groups":[]},"runtime_dependencies":[{"python_module":"cryptography","purpose":"Ed25519 witness signing","required_before_install":True},{"executable":"gpgv","purpose":"Debian InRelease verification","required_before_install":True},{"path":"/usr/share/keyrings/debian-archive-keyring.gpg","debian_package":"debian-archive-keyring","purpose":"Debian archive trust anchor","required_before_install":True},{"executable":"nvidia-smi","purpose":"GPU driver evidence","required_before_install":True}]}
 release["replacement_unit_allowlist"].append("serein-outpost-kernel-install.service")
 release["self_digest"]="sha256:"+digest(json.dumps(release,sort_keys=True,separators=(",",":")).encode()); (ROOT/"release-manifest.json").write_text(json.dumps(release,indent=2)+"\n",encoding="utf-8",newline="\n")
 public_root=ROOT.parent
 public_manifest=public_root/"public-installer-manifest.json"
 public_files=[]
 for path in sorted(public_root.rglob("*"),key=lambda value:value.as_posix()):
  relative=path.relative_to(public_root)
  if path==public_manifest or not path.is_file() or path.is_symlink() or "__pycache__" in relative.parts or ".pytest_cache" in relative.parts or path.suffix==".pyc": continue
  data=path.read_bytes(); public_files.append({"path":relative.as_posix(),"bytes":len(data),"sha256":digest(data)})
 public={"schema":"SFOSPublicInstallerManifest/v1","repository":"Kaotikking/sfos-public","ref":"refs/heads/main","scope":"DEBIAN_BASE_AND_OUTPOST_ONLY","files":public_files}
 public["self_digest"]="sha256:"+digest(json.dumps(public,sort_keys=True,separators=(",",":")).encode())
 public_manifest.write_text(json.dumps(public,indent=2)+"\n",encoding="utf-8",newline="\n")
if __name__=="__main__": main()
