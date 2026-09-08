import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

ROOT=Path(__file__).parents[2]
SCRIPT=ROOT/'base/installer/verify-source-road.py'
SPEC=importlib.util.spec_from_file_location('verify_source_road',SCRIPT)
MOD=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(MOD)

def release_digest():
 return json.loads((ROOT/'outpost/release-manifest.json').read_text())['self_digest']

def write(path,value): path.write_text(json.dumps(value),encoding='utf-8')

def test_public_requires_exact_commit_and_tree(tmp_path,monkeypatch):
 commit=subprocess.run(['git','-C',str(ROOT.parent),'rev-parse','HEAD'],text=True,capture_output=True,check=True).stdout.strip()
 tree=subprocess.run(['git','-C',str(ROOT.parent),'rev-parse','HEAD^{tree}'],text=True,capture_output=True,check=True).stdout.strip()
 receipt=tmp_path/'receipt.json'; write(receipt,{'schema':'SFOSSourceRoadReceipt/v1','source_kind':'PINNED_PUBLIC_REPOSITORY','outpost_release_digest':release_digest(),'repository':MOD.PUBLIC_REPOSITORY,'commit':commit,'tree':tree})
 monkeypatch.setattr(MOD,'github_tree',lambda value: tree if value==commit else 'f'*40)
 MOD.verify(ROOT.parent,'PINNED_PUBLIC_REPOSITORY',receipt)
 value=json.loads(receipt.read_text()); value['tree']='0'*40; write(receipt,value)
 with pytest.raises(SystemExit,match='PUBLIC_IDENTITY_MISMATCH'): MOD.verify(ROOT.parent,'PINNED_PUBLIC_REPOSITORY',receipt)

def test_public_label_without_cryptographic_identity_is_denied(tmp_path):
 receipt=tmp_path/'receipt.json'; write(receipt,{'schema':'SFOSSourceRoadReceipt/v1','source_kind':'PINNED_PUBLIC_REPOSITORY','outpost_release_digest':release_digest(),'repository':MOD.PUBLIC_REPOSITORY})
 with pytest.raises(SystemExit,match='PUBLIC_RECEIPT_SHAPE'): MOD.verify(ROOT.parent,'PINNED_PUBLIC_REPOSITORY',receipt)

def test_offline_receipt_binds_media_lock_and_debian_iso(tmp_path,monkeypatch):
 lock_path=ROOT/'base/installer/media-lock.json'; lock=json.loads(lock_path.read_text())
 count,payload_hash=MOD.payload_identity(ROOT.parent); commit='1'*40; tree='2'*40
 monkeypatch.setattr(MOD,'github_tree',lambda value: tree if value==commit else 'f'*40)
 monkeypatch.setattr(MOD,'github_payload',lambda value: MOD.payload_blobs(ROOT.parent) if value==tree else {})
 receipt=tmp_path/'receipt.json'; value={'schema':'SFOSSourceRoadReceipt/v1','source_kind':'OFFLINE_USB_MEDIA','outpost_release_digest':release_digest(),'build_id':'sfos-usb-20260908-001','media_lock_sha256':hashlib.sha256(lock_path.read_bytes()).hexdigest(),'debian_iso_sha256':lock['image_sha256'],'public_repository':MOD.PUBLIC_REPOSITORY,'public_commit':commit,'public_tree':tree,'payload_file_count':count,'payload_manifest_sha256':payload_hash}; write(receipt,value)
 MOD.verify(ROOT.parent,'OFFLINE_USB_MEDIA',receipt)
 value['media_lock_sha256']='0'*64; write(receipt,value)
 with pytest.raises(SystemExit,match='OFFLINE_MEDIA_LOCK_MISMATCH'): MOD.verify(ROOT.parent,'OFFLINE_USB_MEDIA',receipt)

def test_offline_payload_must_equal_provider_blob_tree(tmp_path,monkeypatch):
 lock_path=ROOT/'base/installer/media-lock.json'; lock=json.loads(lock_path.read_text()); count,payload_hash=MOD.payload_identity(ROOT.parent); commit='3'*40; tree='4'*40
 monkeypatch.setattr(MOD,'github_tree',lambda value: tree)
 monkeypatch.setattr(MOD,'github_payload',lambda value: {'sfos/not-the-real-tree':'5'*40})
 receipt=tmp_path/'receipt.json'; write(receipt,{'schema':'SFOSSourceRoadReceipt/v1','source_kind':'OFFLINE_USB_MEDIA','outpost_release_digest':release_digest(),'build_id':'sfos-usb-20260908-002','media_lock_sha256':hashlib.sha256(lock_path.read_bytes()).hexdigest(),'debian_iso_sha256':lock['image_sha256'],'public_repository':MOD.PUBLIC_REPOSITORY,'public_commit':commit,'public_tree':tree,'payload_file_count':count,'payload_manifest_sha256':payload_hash})
 with pytest.raises(SystemExit,match='OFFLINE_PROVIDER_PAYLOAD_MISMATCH'): MOD.verify(ROOT.parent,'OFFLINE_USB_MEDIA',receipt)
