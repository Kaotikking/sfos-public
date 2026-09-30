"""Candidate-only domain identity proof; synthetic keys and in-memory rows only."""
import copy
import importlib.util
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_SPEC = importlib.util.spec_from_file_location(
    "kernel_domain_identity", Path(__file__).parents[1] /
    "payload/serein_stage1/domain_identity.py")
identity = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(identity)


COMMIT = "a" * 40
RECEIPT = "b" * 64


def key():
    return Ed25519PrivateKey.generate()


def entropy(*values):
    rows = iter(bytes.fromhex(value) for value in values)
    return lambda size: next(rows)


def make_install(instance="0011223344556677", domain="KERNEL"):
    installer, domain_key = key(), key()
    record = identity.candidate(
        domain, source_commit=COMMIT, governance_receipt=RECEIPT,
        installer_key=installer, domain_key=domain_key, used_ids=set(),
        random_bytes=entropy(instance))
    records = [record]
    checkpoint = identity.digest(records)
    verified = identity.verify_lineage(
        records, installer_public=identity.public_hex(installer),
        expected_checkpoint=checkpoint, expected_domain=domain)
    return installer, domain_key, records, checkpoint, verified


def test_installation_id_is_exact_16_hex_and_retries_collision():
    used = {"0011223344556677"}
    value = identity.installation_id(
        used, entropy("0011223344556677", "8899aabbccddeeff"))
    assert value == "8899aabbccddeeff"
    assert identity.HEX16.fullmatch(value)


def test_installation_id_collision_exhaustion_fails_closed():
    used = {"0011223344556677"}
    with pytest.raises(identity.IdentityDenied, match="IDENTITY_COLLISION_DENIED"):
        identity.installation_id(used, lambda size: bytes.fromhex(next(iter(used))))


@pytest.mark.parametrize("fault", ("copied_id", "body", "installer_signature",
                                    "domain_signature", "self_checkpoint"))
def test_copied_or_forged_identity_needs_independent_checkpoint_and_signatures(fault):
    installer, _, records, checkpoint, _ = make_install()
    forged = copy.deepcopy(records)
    if fault == "copied_id":
        reserved = {forged[0]["body"]["instance_id"]}
        with pytest.raises(identity.IdentityDenied, match="IDENTITY_COLLISION_DENIED"):
            identity.verify_lineage(
                forged, installer_public=identity.public_hex(installer),
                expected_checkpoint=checkpoint, expected_domain="KERNEL",
                reserved_ids=reserved)
        return
    if fault == "body":
        forged[0]["body"]["source_commit"] = "c" * 40
    elif fault == "installer_signature":
        forged[0]["installer_signature"] = "0" * 128
    elif fault == "domain_signature":
        forged[0]["domain_signature"] = "0" * 128
    else:
        checkpoint = identity.digest(forged[0])
    with pytest.raises(identity.IdentityDenied, match="CHECKPOINT|SIGNATURE"):
        identity.verify_lineage(
            forged, installer_public=identity.public_hex(installer),
            expected_checkpoint=checkpoint, expected_domain="KERNEL")


def test_dual_key_rotations_keep_immutable_instance_id():
    installer, first_key, records, _, _ = make_install()
    second_key, third_key = key(), key()
    used = {records[0]["body"]["instance_id"]}
    second = identity.candidate(
        "KERNEL", source_commit="c" * 40, governance_receipt="d" * 64,
        installer_key=installer, domain_key=second_key, used_ids=used,
        random_bytes=lambda size: pytest.fail("rotation minted an ID"),
        previous=records[-1], previous_key=first_key)
    records.append(second)
    third = identity.candidate(
        "KERNEL", source_commit="e" * 40, governance_receipt="f" * 64,
        installer_key=installer, domain_key=third_key, used_ids=used,
        random_bytes=lambda size: pytest.fail("rotation minted an ID"),
        previous=records[-1], previous_key=second_key)
    records.append(third)
    result = identity.verify_lineage(
        records, installer_public=identity.public_hex(installer),
        expected_checkpoint=identity.digest(records), expected_domain="KERNEL")
    assert {row["body"]["instance_id"] for row in records} == used
    assert [row["body"]["operation"] for row in records] == ["INSTALL", "ROTATE", "ROTATE"]
    assert result["instance_id"] == next(iter(used))


def test_replacement_gets_new_id_and_explicit_rebind_history():
    installer, _, records, _, _ = make_install()
    old = records[0]["body"]["instance_id"]
    replacement = identity.candidate(
        "KERNEL", source_commit="c" * 40, governance_receipt="d" * 64,
        installer_key=installer, domain_key=key(), used_ids={old},
        random_bytes=entropy("8899aabbccddeeff"), previous=records[-1],
        replacement=True)
    records.append(replacement)
    result = identity.verify_lineage(
        records, installer_public=identity.public_hex(installer),
        expected_checkpoint=identity.digest(records), expected_domain="KERNEL")
    assert replacement["body"]["operation"] == "REPLACE"
    assert replacement["body"]["instance_id"] != old
    assert replacement["body"]["replaces_instance_id"] == old
    assert replacement["body"]["prior_record"] == identity.digest(records[0])
    assert result["instance_id"] == replacement["body"]["instance_id"]


@pytest.mark.parametrize("fault", ("altered", "truncated", "rolled_back"))
def test_restored_altered_or_rolled_back_history_fails_exact_checkpoint(fault):
    installer, first_key, records, _, _ = make_install()
    rotated = identity.candidate(
        "KERNEL", source_commit="c" * 40, governance_receipt="d" * 64,
        installer_key=installer, domain_key=key(),
        used_ids={records[0]["body"]["instance_id"]},
        random_bytes=lambda size: pytest.fail("rotation minted an ID"),
        previous=records[0], previous_key=first_key)
    records.append(rotated)
    checkpoint = identity.digest(records)
    restored = copy.deepcopy(records)
    if fault == "altered":
        restored[-1]["body"]["governance_receipt"] = "e" * 64
    else:
        restored = restored[:1]
    with pytest.raises(identity.IdentityDenied, match="IDENTITY_CHECKPOINT_DENIED"):
        identity.verify_lineage(
            restored, installer_public=identity.public_hex(installer),
            expected_checkpoint=checkpoint, expected_domain="KERNEL")


def test_reserved_other_domain_id_denies_install_and_replacement():
    installer, _, records, _, _ = make_install()
    old = records[0]["body"]["instance_id"]
    replacement = identity.candidate(
        "KERNEL", source_commit="c" * 40, governance_receipt="d" * 64,
        installer_key=installer, domain_key=key(), used_ids={old},
        random_bytes=entropy("8899aabbccddeeff"), previous=records[0],
        replacement=True)
    records.append(replacement)
    with pytest.raises(identity.IdentityDenied, match="IDENTITY_REPLACEMENT_DENIED"):
        identity.verify_lineage(
            records, installer_public=identity.public_hex(installer),
            expected_checkpoint=identity.digest(records), expected_domain="KERNEL",
            reserved_ids={replacement["body"]["instance_id"]})


def test_possession_binds_exact_fresh_challenge_envelope_without_authority():
    installer, domain_key, records, checkpoint, verified = make_install()
    challenge = b"fresh-challenge-from-independent-caller"
    envelope = {"domain": verified["domain"], "instance_id": verified["instance_id"],
                "checkpoint": verified["checkpoint"], "challenge": challenge.hex()}
    signature = domain_key.sign(identity.canonical(envelope)).hex()
    proof = identity.verify_possession(
        records, installer_public=identity.public_hex(installer),
        expected_checkpoint=checkpoint, expected_domain="KERNEL",
        challenge=challenge, signature=signature)
    assert proof == {"identity_proof": "VERIFIED", "freshness": "CALLER_MUST_VERIFY",
                     "authority_effect": "NONE", "admission_effect": "NONE"}
    with pytest.raises(identity.IdentityDenied, match="IDENTITY_SIGNATURE_DENIED"):
        identity.verify_possession(
            records, installer_public=identity.public_hex(installer),
            expected_checkpoint=checkpoint, expected_domain="KERNEL",
            challenge=challenge + b"!", signature=signature)

    forged = copy.deepcopy(records)
    forged[0]["body"]["instance_id"] = "8899aabbccddeeff"
    with pytest.raises(identity.IdentityDenied, match="IDENTITY_CHECKPOINT_DENIED"):
        identity.verify_possession(
            forged, installer_public=identity.public_hex(installer),
            expected_checkpoint=checkpoint, expected_domain="KERNEL",
            challenge=challenge, signature=signature)


def test_identity_integrity_never_grants_authority_or_admission():
    _, _, records, _, verified = make_install()
    assert records[0]["body"]["authority_effect"] == "NONE"
    assert records[0]["body"]["admission_effect"] == "NONE"
    assert verified["authority_effect"] == "NONE"
    assert verified["admission_effect"] == "NONE"


@pytest.fixture
def material_case(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "kernel_identity_installer", Path(__file__).parents[1] /
        "install/kernel_first_install.py")
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    source = tmp_path / "source"
    relative = "payload/serein_stage1/domain_identity.py"
    destination = source / relative
    destination.parent.mkdir(parents=True)
    data = (Path(__file__).parents[1] / relative).read_bytes()
    destination.write_bytes(data)
    plan = {"source_commit": COMMIT, "current_boot_id": "synthetic-boot",
            "payload": [{"source": relative, "branch": "AUTHORITY",
                         "bytes": len(data), "sha256": installer.sha(data)}]}
    signer = key()
    material = installer.prepare_native_identity(
        source, plan, signer, reserved_ids=set(),
        random_bytes=entropy("0011223344556677"))
    return installer, source, plan, signer, material


def test_memory_only_material_binds_plan_and_does_not_persist_or_admit(material_case):
    installer, source, plan, signer, material = material_case
    before = sorted(str(path.relative_to(source)) for path in source.rglob("*"))
    result = installer.verify_native_identity_material(
        source, plan, material, identity.public_hex(signer), reserved_ids=set())
    assert result == material["binding"]
    assert "private" not in result and "registry" not in result
    assert result["instance_id"] == "0011223344556677"
    assert sorted(str(path.relative_to(source)) for path in source.rglob("*")) == before
    assert list(source.parent.iterdir()) == [source]


@pytest.mark.parametrize("fault", (
    "registry_bytes", "private_bytes", "binding_key", "plan_context",
    "source_commit", "wrong_installer", "collision", "source_bytes",
    "wrong_branch", "duplicate_source", "private_replaced_with_new_hash"))
def test_prepared_identity_rejects_mismatched_material_or_context(material_case, fault):
    installer, source, plan, signer, material = material_case
    material = copy.deepcopy(material)
    plan = copy.deepcopy(plan)
    public = identity.public_hex(signer)
    reserved = set()
    if fault == "registry_bytes":
        material["registry"] += b" "
    elif fault == "private_bytes":
        material["private"] += b" "
    elif fault == "binding_key":
        material["binding"]["public_key"] = identity.public_hex(key())
    elif fault == "plan_context":
        plan["current_boot_id"] = "other-boot"
    elif fault == "source_commit":
        plan["source_commit"] = "c" * 40
    elif fault == "wrong_installer":
        public = identity.public_hex(key())
    elif fault == "collision":
        reserved = {material["binding"]["instance_id"]}
    elif fault == "source_bytes":
        (source / plan["payload"][0]["source"]).write_bytes(b"raise RuntimeError('must not execute')")
    elif fault == "wrong_branch":
        plan["payload"][0]["branch"] = "OPERATIONS"
    elif fault == "duplicate_source":
        plan["payload"].append(copy.deepcopy(plan["payload"][0]))
    else:
        material["private"] = key().private_bytes(
            installer.Encoding.PEM, installer.PrivateFormat.PKCS8, installer.NoEncryption())
        material["binding"]["private_sha256"] = installer.sha(material["private"])
    with pytest.raises(installer.Denied):
        installer.verify_native_identity_material(
            source, plan, material, public, reserved_ids=reserved)


def test_material_rejects_noncanonical_registry_even_with_matching_digest(material_case):
    installer, source, plan, signer, material = material_case
    material["registry"] += b" "
    material["binding"]["registry_sha256"] = installer.sha(material["registry"])
    with pytest.raises(installer.Denied, match="REGISTRY_DENIED"):
        installer.verify_native_identity_material(
            source, plan, material, identity.public_hex(signer), reserved_ids=set())

