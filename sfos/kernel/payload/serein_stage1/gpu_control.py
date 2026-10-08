"""Read-only GPU observations; device presence never proves Kernel custody."""
from __future__ import annotations
import csv,hashlib,json,re,subprocess
from pathlib import Path
HEX64=re.compile(r"[0-9a-f]{64}\Z")
class GPUControlDenied(ValueError):pass
def _canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def _pci(value):
 # Reuse Outpost debian_host_collector._gpu_facts PCI normalization.
 match=re.fullmatch(r'([0-9a-fA-F]{4,8}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])',value)
 if match is None:raise GPUControlDenied('GPU_PCI_IDENTITY_DENIED')
 identity=tuple(int(part,16) for part in match.groups())
 if identity[2]>0x1f:raise GPUControlDenied('GPU_PCI_IDENTITY_DENIED')
 return identity

def _inventory(devices,rows):
 """Compare actual PCI identities, not just two equal device counts."""
 try:
  expected={_pci(value) for value in devices};seen=set();uuids=set()
  for row in csv.reader(rows,skipinitialspace=True,strict=True):
   if len(row)!=4:raise GPUControlDenied('GPU_RUNTIME_INVENTORY_DENIED')
   bus,uuid,name,driver=(value.strip() for value in row);pci=_pci(bus)
   if (pci in seen or uuid in uuids or not re.fullmatch(r'GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',uuid)
       or not name or not re.fullmatch(r'[0-9]+(?:\.[0-9]+)+',driver)
       or any('\x00' in value for value in row)):
    raise GPUControlDenied('GPU_RUNTIME_INVENTORY_DENIED')
   seen.add(pci);uuids.add(uuid)
  if len(expected)!=len(devices) or seen!=expected:raise GPUControlDenied('GPU_RUNTIME_INVENTORY_DENIED')
 except (csv.Error,TypeError,ValueError) as error:
  raise GPUControlDenied('GPU_RUNTIME_INVENTORY_DENIED') from error

def _host_gpu_facts(root):
 """Observed PCI identity and driver presence, not mutable module use counts."""
 devices=[]
 for node in sorted((root/"sys/bus/pci/devices").glob("*")):
  try:vendor=(node/"vendor").read_text().strip().lower();kind=(node/"class").read_text().strip().lower()
  except OSError:continue
  if vendor=="0x10de" and kind.startswith("0x03"):devices.append((node.name,vendor,kind))
 try:modules=(root/"proc/modules").read_text().splitlines()
 except OSError:modules=[]
 loaded=any(line.split()[:1]==["nvidia"] for line in modules)
 return devices,loaded

def collect(root="/",runner=subprocess.run):
 root=Path(root);boot=(root/"proc/sys/kernel/random/boot_id").read_text().strip()
 host_before=_host_gpu_facts(root);devices=[row[0] for row in host_before[0]];loaded=host_before[1]
 try:
  proc=runner(("nvidia-smi","--query-gpu=pci.bus_id,uuid,name,driver_version","--format=csv,noheader,nounits"),capture_output=True,text=True,timeout=15,check=False)
 except (OSError,subprocess.TimeoutExpired) as error:
  raise GPUControlDenied('GPU_OBSERVATION_UNAVAILABLE') from error
 rows=sorted(line.strip() for line in proc.stdout.splitlines() if line.strip()) if proc.returncode==0 else []
 inventory={"pci_devices":devices,"nvidia_smi":rows}
 witness={"schema":"SEREIN/KernelGPUControlWitness/v1","boot_id":boot,"device_count":len(devices),"driver_loaded":loaded,"gpu_inventory_sha256":hashlib.sha256(_canonical(inventory)).hexdigest(),"authority_effect":"NONE"}
 verify(witness)
 _inventory(devices,rows)
 if _host_gpu_facts(root)!=host_before:
  raise GPUControlDenied('GPU_HOST_OBSERVATION_CHANGED')
 if (root/"proc/sys/kernel/random/boot_id").read_text().strip()!=boot:
  raise GPUControlDenied('GPU_CURRENT_BOOT_CHANGED')
 return {**witness,"inventory":inventory}
def verify(witness):
 required={"schema","boot_id","device_count","driver_loaded","gpu_inventory_sha256","authority_effect"};core={key:witness[key] for key in required} if isinstance(witness,dict) and required<=set(witness) else witness
 if not isinstance(core,dict) or set(core)!=required or core.get("schema")!="SEREIN/KernelGPUControlWitness/v1" or core.get("authority_effect")!="NONE" or not isinstance(core.get("boot_id"),str) or not core["boot_id"] or type(core.get("device_count")) is not int or core["device_count"]<1 or core.get("driver_loaded") is not True or not HEX64.fullmatch(str(core.get("gpu_inventory_sha256"))):raise GPUControlDenied("GPU_CONTROL_DENIED")
 if 'inventory' in witness:
  inventory=witness['inventory']
  if (not isinstance(inventory,dict) or set(inventory)!={'pci_devices','nvidia_smi'}
      or not isinstance(inventory['pci_devices'],list) or not isinstance(inventory['nvidia_smi'],list)
      or len(inventory['pci_devices'])!=core['device_count']
      or hashlib.sha256(_canonical(inventory)).hexdigest()!=core['gpu_inventory_sha256']):
   raise GPUControlDenied('GPU_INVENTORY_DIGEST_DENIED')
  _inventory(inventory['pci_devices'],inventory['nvidia_smi'])
 return {"status":"UNPROVEN","owner":"UNPROVEN","boot_id":core["boot_id"],"device_count":core["device_count"],"authority_effect":"NONE"}
