#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path


class LaunchDenied(RuntimeError):
    pass


def _reject_symlink_ancestors(path: Path, stop: Path) -> None:
    cursor=path
    stop=stop.absolute()
    while cursor.absolute()!=stop:
        if cursor.is_symlink(): raise LaunchDenied("GENERATION_ANCESTOR_SYMLINK_DENIED")
        if cursor.parent==cursor: raise LaunchDenied("GENERATION_ANCESTOR_BOUNDARY_DENIED")
        cursor=cursor.parent


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(value):
    return hashlib.sha256(_canonical({k: v for k, v in value.items() if k != "selector_digest"})).hexdigest()


def _read_regular(path: Path, mode: int | None = None) -> tuple[bytes, os.stat_result]:
    info=path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise LaunchDenied("GENERATION_FILE_TYPE_DENIED:"+str(path))
    if os.name != "nt" and (info.st_uid != 0 or info.st_gid != 0 or (mode is not None and stat.S_IMODE(info.st_mode) != mode)):
        raise LaunchDenied("GENERATION_FILE_POLICY_DENIED:"+str(path))
    flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)
    descriptor=os.open(path,flags)
    try:
        opened=os.fstat(descriptor)
        if (opened.st_dev,opened.st_ino)!=(info.st_dev,info.st_ino) or not stat.S_ISREG(opened.st_mode):
            raise LaunchDenied("GENERATION_FILE_RACE_DENIED:"+str(path))
        data=b""
        while True:
            block=os.read(descriptor,1024*1024)
            if not block: break
            data+=block
    finally: os.close(descriptor)
    return data,opened


def read_selector(path: Path, generation_root: Path) -> tuple[dict, Path]:
    if path.is_symlink(): raise LaunchDenied("GENERATION_SELECTOR_TYPE_DENIED")
    _reject_symlink_ancestors(path, path.parent.parent)
    try: selector_bytes,info=_read_regular(path,0o600)
    except LaunchDenied as exc: raise LaunchDenied("GENERATION_SELECTOR_TYPE_DENIED") from exc
    value = json.loads(selector_bytes.decode("utf-8"))
    required = {"schema", "generation", "release_digest", "predecessor_receipt_sha256", "inventory_digest", "selector_digest"}
    if set(value) != required or value["schema"] != "SereinOutpostGenerationSelector/v1" or value["selector_digest"] != _digest(value):
        raise LaunchDenied("GENERATION_SELECTOR_INTEGRITY_DENIED")
    if not all(c in "0123456789abcdef" for c in value["generation"]) or len(value["generation"]) != 64:
        raise LaunchDenied("GENERATION_ID_DENIED")
    generation = generation_root / value["generation"]
    _reject_symlink_ancestors(generation,generation_root.parent)
    generation_info=generation.lstat()
    if generation.is_symlink() or not generation.is_dir() or generation.resolve().parent != generation_root.resolve() or (os.name!="nt" and (generation_info.st_uid!=0 or generation_info.st_gid!=0 or stat.S_IMODE(generation_info.st_mode)!=0o755)):
        raise LaunchDenied("GENERATION_ROOT_DENIED")
    manifest = generation / "release-manifest.json"
    manifest_bytes,_=_read_regular(manifest,0o644)
    release = json.loads(manifest_bytes.decode("utf-8"))
    if release.get("self_digest") != value["release_digest"] or value["generation"] != value["release_digest"].removeprefix("sha256:"):
        raise LaunchDenied("GENERATION_RELEASE_DENIED")
    inventory_path=generation/"generation-inventory.json"
    inventory_bytes,_=_read_regular(inventory_path,0o644)
    inventory=json.loads(inventory_bytes.decode("utf-8"))
    if hashlib.sha256(_canonical(inventory)).hexdigest()!=value["inventory_digest"]:
        raise LaunchDenied("GENERATION_INVENTORY_DIGEST_DENIED")
    declared={row["path"]:row for row in inventory if isinstance(row,dict) and isinstance(row.get("path"),str)}
    if len(declared)!=len(inventory): raise LaunchDenied("GENERATION_INVENTORY_DUPLICATE_DENIED")
    actual=set()
    for item in generation.rglob("*"):
        relative=item.relative_to(generation).as_posix()
        if item.is_symlink(): raise LaunchDenied("GENERATION_SYMLINK_DENIED:"+relative)
        if item.is_file() and relative!="generation-inventory.json":
            actual.add(relative); row=declared.get(relative)
            if row is None or set(row)!={"kind","path","bytes","sha256","mode","uid","gid"} or row["kind"]!="file": raise LaunchDenied("GENERATION_FILE_DENIED:"+relative)
            data,opened=_read_regular(item,int(row["mode"],8))
            if row["uid"]!=opened.st_uid and os.name!="nt" or row["gid"]!=opened.st_gid and os.name!="nt" or row["bytes"]!=len(data) or row["sha256"]!=hashlib.sha256(data).hexdigest():
                raise LaunchDenied("GENERATION_FILE_DENIED:"+relative)
        elif item.is_dir():
            actual.add(relative); row=declared.get(relative); info=item.lstat()
            if row is None or set(row)!={"kind","path","mode","uid","gid"} or row["kind"]!="directory" or (os.name!="nt" and (stat.S_IMODE(info.st_mode)!=int(row["mode"],8) or info.st_uid!=row["uid"] or info.st_gid!=row["gid"])): raise LaunchDenied("GENERATION_DIRECTORY_DENIED:"+relative)
        elif not item.is_file(): raise LaunchDenied("GENERATION_SPECIAL_DENIED:"+relative)
    if actual!=set(declared): raise LaunchDenied("GENERATION_INVENTORY_NOT_EXHAUSTIVE")
    return value, generation


def select_generation(current: Path, lkg: Path, generation_root: Path) -> tuple[dict,Path,str]:
    try:
        value,generation=read_selector(current,generation_root)
        return value,generation,"current"
    except (LaunchDenied,OSError,ValueError,KeyError) as current_error:
        try:
            value,generation=read_selector(lkg,generation_root)
        except (LaunchDenied,OSError,ValueError,KeyError) as lkg_error:
            raise LaunchDenied("GENERATION_CURRENT_AND_LKG_DENIED") from lkg_error
        print(json.dumps({"schema":"SereinOutpostGenerationRecoveryWitness/v1","selected":"lkg","current_error":type(current_error).__name__},sort_keys=True),file=sys.stderr)
        return value,generation,"lkg"


def launch(selector: Path, generation_root: Path, entrypoint: str, argv: list[str]) -> None:
    if not entrypoint or entrypoint.startswith(('/', '\\')) or ".." in Path(entrypoint).parts:
        raise LaunchDenied("GENERATION_ENTRYPOINT_DENIED")
    _, generation, _ = select_generation(selector, selector.with_name("lkg.json"), generation_root)
    target = generation / entrypoint
    if target.is_symlink() or not target.is_file() or target.resolve().parent != generation.resolve() / Path(entrypoint).parent:
        raise LaunchDenied("GENERATION_ENTRYPOINT_DENIED")
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(generation)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    module=entrypoint[:-3].replace("/",".") if entrypoint.endswith(".py") else ""
    if not module or any(not part.isidentifier() for part in module.split(".")):
        raise LaunchDenied("GENERATION_ENTRYPOINT_MODULE_DENIED")
    os.execve("/usr/bin/python3", ["/usr/bin/python3", "-B", "-m", module, *argv], environment)


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: generation_launcher.py ENTRYPOINT [ARGS...]")
    launch(Path("/var/lib/serein-outpost/generation-state/current.json"), Path("/usr/share/serein/outpost-generations"), sys.argv[1], sys.argv[2:])


if __name__ == "__main__":
    main()
