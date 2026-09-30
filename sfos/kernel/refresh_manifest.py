#!/usr/bin/env python3
"""Refresh exact LF Kernel bytes; a manifest is not runtime admission.

ADAPT sfos-public0dca6bd7/blob85f5c8cf. Reject transport-changing CRLF
instead of sealing a local representation that differs from published bytes.
"""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parent
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def sha(data):return hashlib.sha256(data).hexdigest()
def source_bytes(path):
 data=path.read_bytes()
 if b"\r" in data:raise ValueError("KERNEL_SOURCE_REQUIRES_EXACT_LF_BYTES")
 data.decode("utf-8")
 return data

def main():
 path=ROOT/"release-manifest.json";manifest=json.loads(path.read_text())
 modes={row[0]:row[3] for row in manifest["payload"]};payload=[]
 for item in sorted((ROOT/"payload").rglob("*")):
  if not item.is_file():continue
  relative=item.relative_to(ROOT).as_posix();data=source_bytes(item);mode=modes.get(relative,"0755" if relative.startswith("payload/bin/") else "0644")
  payload.append([relative,len(data),sha(data),mode])
 if set(modes)-{row[0] for row in payload}:
  raise ValueError("KERNEL_DECLARED_PAYLOAD_MISSING")
 manifest["payload"]=payload;manifest["payload_digest"]="sha256:"+sha(canonical(payload))
 layout=json.loads((ROOT/"install-layout.json").read_text());rows=[]
 branches=layout.get("payload_branches");paths=[row[0] for row in payload]
 # The signed package declares installation phase; filenames do not own it.
 if not isinstance(branches,dict) or set(branches)!=set(paths) or any(not isinstance(branch,str) or branch not in ("AUTHORITY","OPERATIONS","INTERFACE") for branch in branches.values()):
  raise ValueError("KERNEL_BRANCH_MAP_DENIED")
 for relative,size,digest,mode in payload:
  matches=[prefix for prefix in layout["payload_roots"] if relative==prefix or relative.startswith(prefix+"/")]
  if len(matches)!=1:raise ValueError("KERNEL_LAYOUT_DENIED")
  prefix=matches[0];suffix=relative[len(prefix):].lstrip("/");target=layout["payload_roots"][prefix].rstrip("/")+"/"+suffix
  rows.append({"branch":branches[relative],"source":relative,"target":target,"bytes":size,"sha256":digest,"mode":mode})
 rows.sort(key=lambda row:(("AUTHORITY","OPERATIONS","INTERFACE").index(row["branch"]),row["target"]));manifest["install_denominator_digest"]="sha256:"+sha(canonical(rows))
 if manifest.get("branch_order")!=["AUTHORITY","OPERATIONS","INTERFACE"] or {row["branch"] for row in rows}!={"AUTHORITY","OPERATIONS","INTERFACE"}:
  raise ValueError("KERNEL_COMPLETE_BRANCH_SET_REQUIRED")
 installers=[]
 for relative in ("install/kernel_first_install.py","install/offline_ollama_transaction.py"):
  data=source_bytes(ROOT/relative);installers.append([relative,len(data),sha(data),"0755"])
 manifest["installer_files"]=installers
 manifest.pop("self_digest",None);manifest["self_digest"]="sha256:"+sha(canonical(manifest));path.write_text(json.dumps(manifest,indent=2)+"\n",newline="\n")
if __name__=="__main__":main()

