#!/usr/bin/env python3
"""Executable, fail-closed public Outpost generation installer."""
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

from install.public_generation_transaction import install_public_generation, rollback_public_generation
from install.transaction import RealAdapter, TransactionError, nofollow_ancestors

MAX_ARCHIVE_BYTES=256*1024*1024
TIMEOUT_SECONDS=30
CANONICAL_AUTHORITY=Path("/usr/share/serein/outpost/cognition-verification.pem")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise TransactionError("PUBLIC_REDIRECT_DENIED")


def fetch_exact(url:str)->tuple[bytes,str]:
    opener=urllib.request.build_opener(_NoRedirect,urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request=urllib.request.Request(url,headers={"Accept":"application/octet-stream","User-Agent":"sfos-public-installer/1"})
    try:
        with opener.open(request,timeout=TIMEOUT_SECONDS) as response:
            final=response.geturl(); length=response.headers.get("Content-Length")
            if length is not None and not length.isdigit(): raise TransactionError("PUBLIC_CONTENT_LENGTH_DENIED")
            expected=int(length) if length is not None else None
            if expected is not None and (expected<1 or expected>MAX_ARCHIVE_BYTES): raise TransactionError("PUBLIC_ARCHIVE_SIZE_DENIED")
            data=response.read(MAX_ARCHIVE_BYTES+1)
            if not data or len(data)>MAX_ARCHIVE_BYTES: raise TransactionError("PUBLIC_ARCHIVE_SIZE_DENIED")
            if expected is not None and len(data)!=expected: raise TransactionError("PUBLIC_ARCHIVE_TRUNCATED")
            return data,final
    except TransactionError: raise
    except (urllib.error.URLError,TimeoutError,socket.timeout,ssl.SSLError,OSError) as exc:
        raise TransactionError("PUBLIC_FETCH_DENIED:"+type(exc).__name__) from None


def _candidate_acceptance(generation:Path,selector:Path,boot_id:str)->dict:
    program="""
import json,sys
from pathlib import Path
from install.generation_launcher import read_selector
selector,generation,boot=map(Path,sys.argv[1:4]); release=json.loads((generation/'release-manifest.json').read_text())
read_selector(selector,generation.parent)
sys.path.insert(0,str(generation))
from outpost.host_vitality import HostVitalityStore
from outpost.http_readonly import present
store=HostVitalityStore(Path('/var/lib/serein-outpost/host-vitality'))
j=present(store,'GET','/v1/runtime/status','application/json',str(boot)); h=present(store,'GET','/v1/runtime/status','text/html',str(boot))
ok=j.status==200 and h.status==200 and j.content_type=='application/json' and h.content_type.startswith('text/html') and b'Serein Vitals' in h.body
print(json.dumps({'schema':'SereinOutpostCandidateAcceptance/v1','installed_boot_preflight':'PASS','api':'PASS' if ok else 'FAIL','vitals':'PASS' if ok else 'FAIL','boot_id':str(boot),'release_digest':release['self_digest']},sort_keys=True))
"""
    environment={**os.environ,"PYTHONPATH":str(generation),"PYTHONDONTWRITEBYTECODE":"1"}
    result=subprocess.run([sys.executable,"-B","-c",program,str(selector),str(generation),boot_id],text=True,capture_output=True,timeout=TIMEOUT_SECONDS,env=environment)
    if result.returncode or result.stderr or len(result.stdout)>4096: raise TransactionError("PUBLIC_CANDIDATE_PROBE_DENIED")
    try: return json.loads(result.stdout)
    except (ValueError,TypeError): raise TransactionError("PUBLIC_CANDIDATE_PROBE_DENIED") from None


def _load_plan(path:Path)->dict:
    path=path.resolve(); nofollow_ancestors(Path("/"),path,allow_missing=False); info=path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or (os.name!="nt" and (info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)!=0o600)):
        raise TransactionError("PUBLIC_PLAN_CUSTODY_DENIED")
    return json.loads(path.read_text(encoding="utf-8"))


def main()->None:
    if os.name=="nt" or not hasattr(os,"geteuid") or os.geteuid()!=0: raise SystemExit("ROOT_LINUX_REQUIRED")
    parser=argparse.ArgumentParser(); sub=parser.add_subparsers(dest="operation",required=True)
    update=sub.add_parser("install-update"); update.add_argument("--plan",required=True)
    rollback=sub.add_parser("rollback"); rollback.add_argument("receipt")
    args=parser.parse_args(); adapter=RealAdapter()
    try:
        if args.operation=="rollback": result=rollback_public_generation(adapter,Path(args.receipt))
        else:
            plan=_load_plan(Path(args.plan)); result=install_public_generation(adapter,plan,CANONICAL_AUTHORITY,fetch_exact,_candidate_acceptance,_candidate_acceptance)
        print(json.dumps({"status":result.get("status","ROLLBACK_COMPLETE"),"generation":result.get("generation"),"release_digest":result.get("release_digest"),"rollback_complete":result.get("rollback_complete")},sort_keys=True))
    except (TransactionError,ValueError,KeyError,json.JSONDecodeError) as exc:
        print(json.dumps({"status":"DENIED","reason":str(exc).split(":",1)[0]}),file=sys.stderr); raise SystemExit(1)


if __name__=="__main__": main()
