"""Read-only, current-boot Kernel GPU custody evidence."""
from __future__ import annotations
import hashlib,json,re,subprocess
from pathlib import Path
HEX64=re.compile(r"[0-9a-f]{64}\Z")
class GPUControlDenied(ValueError):pass
def _canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def collect(root="/",runner=subprocess.run):
 root=Path(root);boot=(root/"proc/sys/kernel/random/boot_id").read_text().strip();devices=[]
 for node in sorted((root/"sys/bus/pci/devices").glob("*")):
  try:vendor=(node/"vendor").read_text().strip().lower();kind=(node/"class").read_text().strip().lower()
  except OSError:continue
  if vendor=="0x10de" and kind.startswith("0x03"):devices.append(node.name)
 try:modules=(root/"proc/modules").read_text().splitlines()
 except OSError:modules=[]
 loaded=any(line.split()[:1]==["nvidia"] for line in modules)
 proc=runner(("nvidia-smi","--query-gpu=pci.bus_id,uuid,name,driver_version","--format=csv,noheader,nounits"),capture_output=True,text=True,timeout=15,check=False)
 rows=sorted(line.strip() for line in proc.stdout.splitlines() if line.strip()) if proc.returncode==0 else []
 inventory={"pci_devices":devices,"nvidia_smi":rows}
 witness={"schema":"SEREIN/KernelGPUControlWitness/v1","boot_id":boot,"device_count":len(devices),"driver_loaded":loaded,"gpu_inventory_sha256":hashlib.sha256(_canonical(inventory)).hexdigest(),"authority_effect":"NONE"}
 verify(witness)
 if len(rows)!=len(devices):raise GPUControlDenied("GPU_RUNTIME_CUSTODY_DENIED")
 return {**witness,"inventory":inventory}
def verify(witness):
 required={"schema","boot_id","device_count","driver_loaded","gpu_inventory_sha256","authority_effect"};core={key:witness[key] for key in required} if isinstance(witness,dict) and required<=set(witness) else witness
 if not isinstance(core,dict) or set(core)!=required or core.get("schema")!="SEREIN/KernelGPUControlWitness/v1" or core.get("authority_effect")!="NONE" or not isinstance(core.get("boot_id"),str) or not core["boot_id"] or not isinstance(core.get("device_count"),int) or core["device_count"]<1 or core.get("driver_loaded") is not True or not HEX64.fullmatch(str(core.get("gpu_inventory_sha256"))):raise GPUControlDenied("GPU_CONTROL_DENIED")
 return {"status":"READY","owner":"KERNEL","boot_id":core["boot_id"],"device_count":core["device_count"],"authority_effect":"NONE"}
