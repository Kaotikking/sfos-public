#!/usr/bin/env python3
"""Refresh the exhaustive public Kernel payload denominator."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parent
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def sha(data):return hashlib.sha256(data).hexdigest()
def main():
 path=ROOT/"release-manifest.json";manifest=json.loads(path.read_text())
 modes={row[0]:row[3] for row in manifest["payload"]};payload=[]
 for item in sorted((ROOT/"payload").rglob("*")):
  if not item.is_file():continue
  relative=item.relative_to(ROOT).as_posix();data=item.read_bytes();mode=modes.get(relative,"0755" if relative.startswith("payload/bin/") else "0644")
  payload.append([relative,len(data),sha(data),mode])
 manifest["payload"]=payload;manifest["payload_digest"]="sha256:"+sha(canonical(payload))
 layout=json.loads((ROOT/"install-layout.json").read_text());rows=[]
 for relative,size,digest,mode in payload:
  prefix=next(prefix for prefix in layout["payload_roots"] if relative==prefix or relative.startswith(prefix+"/"));suffix=relative[len(prefix):].lstrip("/");target=layout["payload_roots"][prefix].rstrip("/")+"/"+suffix;name=Path(relative).name
  branch="INTERFACE" if "interface" in name else ("OPERATIONS" if "operations" in name else "AUTHORITY");rows.append({"branch":branch,"source":relative,"target":target,"bytes":size,"sha256":digest,"mode":mode})
 rows.sort(key=lambda row:(("AUTHORITY","OPERATIONS","INTERFACE").index(row["branch"]),row["target"]));manifest["install_denominator_digest"]="sha256:"+sha(canonical(rows))
 installers=[]
 for relative in ("install/kernel_first_install.py","install/offline_ollama_transaction.py"):
  data=(ROOT/relative).read_bytes();installers.append([relative,len(data),sha(data),"0755"])
 manifest["installer_files"]=installers
 manifest.pop("self_digest",None);manifest["self_digest"]="sha256:"+sha(canonical(manifest));path.write_text(json.dumps(manifest,indent=2)+"\n",newline="\n")
if __name__=="__main__":main()
