"""Canonical existing-Debian Outpost installation and independent readback."""
from __future__ import annotations
from dataclasses import dataclass
from contextlib import contextmanager
import importlib.util
import json
import os
import re
import socket
import ssl
import stat
import urllib.error
import urllib.request
from pathlib import Path
from .transaction import TransactionError, nofollow_ancestors, sha, strict_json

MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
TIMEOUT_SECONDS = 30
ARCHIVE_RE = re.compile(r"https://codeload\.github\.com/Kaotikking/sfos-public/tar\.gz/[0-9a-f]{40}\Z")


@dataclass(frozen=True)
class InstallRequest:
    """The existing Base wrappers' arguments, not verified authority."""
    source: str
    action: str
    target: str
    plan_path: str
    expected_plan_sha256: str
    source_kind: str
    source_receipt: str


def parse_install_request(arguments) -> InstallRequest:
    """Validate the shared seven-field entry before any I/O or effect.

    Preserve caller path spelling: resolving here could follow a symlink and
    hide it from the later custody checks. Source receipt content, plan
    signature/custody and destination identity still require verification.
    This parser never upgrades an offline integrity receipt into authority.
    """
    if not isinstance(arguments, (list, tuple)) or len(arguments) != 7:
        raise TransactionError("OUTPOST_ENTRY_ARGUMENTS_REQUIRED")
    if any(not isinstance(value, str) or not value or "\0" in value for value in arguments):
        raise TransactionError("OUTPOST_ENTRY_ARGUMENT_INVALID")
    request = InstallRequest(*arguments)
    if request.action != "install":
        raise TransactionError("OUTPOST_ENTRY_ACTION_DENIED")
    if request.target not in ("/", "/target"):
        raise TransactionError("OUTPOST_ENTRY_TARGET_DENIED")
    if not re.fullmatch(r"[0-9a-f]{64}", request.expected_plan_sha256):
        raise TransactionError("PUBLIC_PLAN_BYTES_REQUIRED")
    if request.source_kind not in ("OFFLINE_USB_MEDIA", "PINNED_PUBLIC_REPOSITORY"):
        raise TransactionError("OUTPOST_ENTRY_SOURCE_KIND_DENIED")
    if request.target == "/target" and request.source_kind != "OFFLINE_USB_MEDIA":
        raise TransactionError("OFFLINE_INSTALLER_SOURCE_REQUIRED")
    return request


def _source_road_module():
    # Execute only the verifier shipped beside this entry implementation,
    # never code selected by the caller's SOURCE or receipt argument.
    path = Path(__file__).absolute().parents[2] / "base/installer/verify-source-road.py"
    nofollow_ancestors(Path(path.anchor), path, allow_missing=False)
    spec = importlib.util.spec_from_file_location("outpost_base_source_road", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def preflight_install_request(arguments):
    """Bind the existing entry roads to source bytes and signed target plan.

    Read-only integration, not the installation entry. The offline verifier
    currently denies unproven portable authority; it must not fall through to
    this running-host plan reader. No install, staging or service is invoked.
    """
    from verify_install_preflight import _read_regular, verify_source
    from .public_generation_transaction import _verify_plan, preflight_target
    request = parse_install_request(arguments)
    source = Path(request.source)
    if source.parts[-2:] != ("sfos", "outpost") or ".." in source.parts:
        raise TransactionError("OUTPOST_ENTRY_CANONICAL_SOURCE_PATH_REQUIRED")
    release = strict_json(_read_regular(source / "release-manifest.json"))
    verify_source(source, release)
    road = _source_road_module()
    receipt = road.verify(source.parent.parent, request.source_kind, Path(request.source_receipt))
    # The only admitted plan reader is current-host bound. Never silently
    # inspect / as if it were the fresh install's /target.
    if request.target != "/" or request.source_kind != "PINNED_PUBLIC_REPOSITORY":
        raise TransactionError("OFFLINE_SOURCE_AUTHORITY_UNPROVEN")
    plan = _verify_plan(_load_plan(Path(request.plan_path), request.expected_plan_sha256))
    fields = plan.as_dict()
    if (not isinstance(receipt, dict)
            or receipt.get("schema") != "SFOSSourceRoadReceipt/v1"
            or receipt.get("source_kind") != request.source_kind
            or receipt.get("repository") != "https://github.com/" + fields["repository"]
            or receipt.get("commit") != fields["commit"]
            or receipt.get("tree") != fields["tree"]
            or receipt.get("outpost_release_digest") != fields["release_digest"]
            or release.get("self_digest") != fields["release_digest"]):
        raise TransactionError("OUTPOST_ENTRY_SOURCE_PLAN_MISMATCH")
    target = preflight_target(plan)
    verify_source(source, release)
    return request, plan, {"result":"ENTRY_PREFLIGHT_ONLY_NOT_INSTALLED",
                           "source_receipt":receipt, "target_prestate":target,
                           "mutation_effect":"NONE", "installed":"UNPROVEN"}


def prepare_install_request(arguments):
    """Acquire inactive material using the entry's already verified identity."""
    from .public_generation_transaction import preflight_target
    request, plan, entry = preflight_install_request(arguments)
    release, material = fetch_verified_source(plan)
    after = preflight_target(plan)
    if after != entry["target_prestate"]:
        raise TransactionError("PUBLIC_TARGET_CHANGED_DURING_ACQUISITION")
    fields = plan.as_dict()
    evidence = {"result":"SOURCE_PREPARED_INACTIVE", "entry":entry,
                "plan_sha256":request.expected_plan_sha256,
                "source_plan_sha256":sha(plan.encoded),
                "source":{key:fields[key] for key in
                          ("repository", "commit", "tree", "archive_sha256", "release_digest")},
                "target_prestate":after, "installed":"UNPROVEN",
                "authority_effect":"NONE", "mutation_effect":"NONE"}
    return evidence, release, material


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise TransactionError("PUBLIC_REDIRECT_DENIED")


def fetch_exact(url: str) -> tuple[bytes, str]:
    if not isinstance(url, str) or not ARCHIVE_RE.fullmatch(url):
        raise TransactionError("PUBLIC_ARCHIVE_URL_DENIED")
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, headers={"Accept": "application/octet-stream", "User-Agent": "sfos-public-installer/1"})
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            final = response.geturl()
            if final != url:
                raise TransactionError("PUBLIC_REDIRECT_DENIED")
            if response.status != 200:
                raise TransactionError("PUBLIC_STATUS_DENIED")
            length = response.headers.get("Content-Length")
            if length is not None and not re.fullmatch(r"[0-9]+", length):
                raise TransactionError("PUBLIC_CONTENT_LENGTH_DENIED")
            expected = int(length) if length is not None else None
            if expected is not None and not 1 <= expected <= MAX_ARCHIVE_BYTES:
                raise TransactionError("PUBLIC_ARCHIVE_SIZE_DENIED")
            data = response.read(MAX_ARCHIVE_BYTES + 1)
            if not data or len(data) > MAX_ARCHIVE_BYTES:
                raise TransactionError("PUBLIC_ARCHIVE_SIZE_DENIED")
            if expected is not None and len(data) != expected:
                raise TransactionError("PUBLIC_ARCHIVE_TRUNCATED")
            return data, final
    except TransactionError:
        raise
    except (urllib.error.URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError) as error:
        raise TransactionError("PUBLIC_FETCH_DENIED:" + type(error).__name__) from None


def _load_plan(path: Path, expected_sha256: str) -> dict:
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise TransactionError("PUBLIC_PLAN_BYTES_REQUIRED")
    path = Path(os.path.abspath(path))
    nofollow_ancestors(Path(path.anchor), path, allow_missing=False)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o600):
        raise TransactionError("PUBLIC_PLAN_CUSTODY_DENIED")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid, opened.st_gid, opened.st_nlink) != (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink):
            raise TransactionError("PUBLIC_PLAN_CUSTODY_DENIED")
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise TransactionError("PUBLIC_PLAN_SIZE_DENIED")
    if sha(raw) != expected_sha256:
        raise TransactionError("PUBLIC_PLAN_BYTES_DENIED")
    return strict_json(raw)


def fetch_verified_source(plan):
    """Prepare signed source bytes only; never grant install authority."""
    from .public_generation_transaction import VerifiedSourcePlan, _safe_archive
    if type(plan) is not VerifiedSourcePlan or not plan.authority_custody_proven:
        raise TransactionError("PUBLIC_VERIFIED_PLAN_REQUIRED")
    fields = plan.as_dict()
    raw, final_url = fetch_exact(fields["archive_url"])
    if final_url != fields["archive_url"]:
        raise TransactionError("PUBLIC_REDIRECT_DENIED")
    return _safe_archive(raw, plan)


def prepare_generation(plan_path: Path, expected_plan_sha256: str):
    """Join the canonical read-only preflight and exact download road.

    Returns inactive bytes and supporting evidence only. No extraction, target
    writes, service operations or admission occur. Preparation is not a target
    lock: the complete install transaction must independently recheck prestate.
    """
    from .public_generation_transaction import _verify_plan, preflight_target
    raw_plan=_load_plan(plan_path,expected_plan_sha256)
    plan=_verify_plan(raw_plan)
    before=preflight_target(plan)
    release,material=fetch_verified_source(plan)
    after=preflight_target(plan)
    if before!=after:
        raise TransactionError("PUBLIC_TARGET_CHANGED_DURING_ACQUISITION")
    fields=plan.as_dict()
    evidence={"result":"SOURCE_PREPARED_INACTIVE","plan_sha256":expected_plan_sha256,
              "source_plan_sha256":sha(plan.encoded),
              "source":{key:fields[key] for key in ("repository","commit","tree","archive_sha256","release_digest")},
              "target_prestate":after,"installed":"UNPROVEN",
              "authority_effect":"NONE","mutation_effect":"NONE"}
    return evidence,release,material


def prepare_and_stage_generation(plan_path: Path, expected_plan_sha256: str, *, staging_parent: Path):
    """Stage the exact prepared release, without a caller-selected identity.

    This is inactive package construction only, not the install entry or an
    admission witness. The complete transaction still owns target revalidation,
    installation, startup and independent acceptance.
    """
    evidence, release, material = prepare_generation(plan_path, expected_plan_sha256)
    staged = _stage_prepared(evidence, release, material, staging_parent)
    recheck_prepared_target(plan_path, expected_plan_sha256, evidence)
    return staged


def prepare_and_stage_install_request(arguments, *, staging_parent: Path):
    """The seven-field request reaches the same inactive staging primitive.

    Not a substitute canonical entry: complete placement/startup and atomic
    acceptance are still required before anything can be called installed.
    """
    evidence, release, material = prepare_install_request(arguments)
    staged = _stage_prepared(evidence, release, material, staging_parent)
    request = parse_install_request(arguments)
    recheck_prepared_target(Path(request.plan_path), request.expected_plan_sha256, evidence)
    return staged


def recheck_prepared_target(plan_path, expected_plan_sha256, evidence, *, placed=None):
    """Rebind source and destination after staging, and before a future effect.

    The same native plan-custody/signature and target preflight are reused.
    Failed revalidation leaves staged bytes inactive as evidence. This does
    not acquire a lock, promote a selector, restore or confer admission.
    """
    from .public_generation_transaction import _verify_plan, preflight_target, preflight_placed_target
    plan = _verify_plan(_load_plan(Path(plan_path), expected_plan_sha256))
    fields = plan.as_dict()
    source = {key: fields[key] for key in
              ('repository', 'commit', 'tree', 'archive_sha256', 'release_digest')}
    if (not isinstance(evidence, dict)
            or evidence.get('source_plan_sha256') != sha(plan.encoded)
            or evidence.get('plan_sha256') != expected_plan_sha256
            or evidence.get('source') != source):
        raise TransactionError('PREPARED_SOURCE_BINDING_CHANGED')
    expected=evidence.get('target_prestate')
    if placed is None:
        observed=preflight_target(plan)
    else:
        observed=preflight_placed_target(plan,placed['selector'],placed['record'])
        old=expected.get('generation_destination',{});new=observed.get('generation_destination',{})
        if (old.get('state')!='ABSENT' or new.get('state')!='PRESENT'
                or new.get('target')!=old.get('target') or new.get('parent')!=old.get('parent')):
            raise TransactionError('PUBLIC_GENERATION_DESTINATION_CHANGED')
        # Compare all other target facts literally; only candidate placement
        # is permitted. Do not require absence after the authorized write.
        observed={**observed,'generation_destination':old}
    if observed != expected:
        raise TransactionError('PUBLIC_TARGET_CHANGED_DURING_STAGING')
    return plan


@contextmanager
def locked_prepared_generation(plan_path, expected_plan_sha256, evidence,
                               release, material, *, staging_parent):
    """Hold the canonical transaction lock across preparation consumption.

    Joins the existing donor primitives without publication, selector changes,
    services or admission. The private capture is not a durable receipt yet;
    callers must not promote until that remaining predicate is implemented.
    Production target is fixed to /; tests substitute only the native seams.
    """
    from .public_generation_transaction import (public_generation_lock,
        capture_bootstrap_predecessor, capture_selector_predecessor,
        read_bootstrap_unit)
    plan = recheck_prepared_target(plan_path, expected_plan_sha256, evidence)
    with public_generation_lock(Path('/'), sha(plan.encoded),
                                plan.as_dict()['current_boot_id']) as lock:
        recheck_prepared_target(plan_path, expected_plan_sha256, evidence)
        target = evidence['target_prestate']
        images = capture_bootstrap_predecessor(Path('/'), target['bootstrap_prestate'],
                                               read_bootstrap_unit)
        selectors = capture_selector_predecessor(Path('/'), target['installed_prestate'])
        recheck_prepared_target(plan_path, expected_plan_sha256, evidence)
        staged = _stage_prepared(evidence, release, material, staging_parent)
        recheck_prepared_target(plan_path, expected_plan_sha256, evidence)
        yield staged, {'image_bytes':images, 'selector_bytes':selectors}, lock


@contextmanager
def prepare_recorded_install_request(arguments, *, staging_parent):
    """Join the canonical seven-field source entry to locked durable staging.

    Inactive placement only: no selector promotion, service action or admission. The
    transaction remains locked while the caller inspects the bound result.
    """
    request = parse_install_request(arguments)
    evidence, release, material = prepare_install_request(arguments)
    with recorded_prepared_generation(Path(request.plan_path),request.expected_plan_sha256,
                                      evidence,release,material,staging_parent=staging_parent) as result:
        yield result


@contextmanager
def recorded_prepared_generation(plan_path, expected_plan_sha256, evidence,
                                 release, material, *, staging_parent, promote=False):
    """Durably bind captured prestate inside the same transaction lock.

    Existing transaction selectors collide rather than resume or overwrite.
    Promotion is entered only by the canonical seven-field install entry.
    Expose record digests, never private captures or signing material.
    """
    from .public_generation_transaction import (prepared_prestate_receipt,
        load_prestate_signer, seal_prestate_receipt, persist_prestate_receipt,
        reread_prestate_receipt, seal_prepared_forward_state, prepared_forward_record,
        prepared_candidate_record, bootstrap_candidate_precheck)
    if promote:
        # Non-secret public provenance derived from the signed plan, not a
        # second authority file or a private-plan permission change. It joins
        # the same atomic generation inventory and is checked again in staging.
        if 'public-source.json' in material:
            raise TransactionError('PREPARED_PUBLIC_SOURCE_COLLISION')
        material={**material,'public-source.json':_public_source_bytes(evidence)}
    precheck = bootstrap_candidate_precheck(release,material,evidence['source_plan_sha256']) if promote else None
    service_account = _bootstrap_service_account() if promote else None
    with locked_prepared_generation(plan_path,expected_plan_sha256,evidence,
                                    release,material,staging_parent=staging_parent) as (staged,capture,lock):
        body = prepared_prestate_receipt(evidence,release,material,capture)
        plan = recheck_prepared_target(plan_path,expected_plan_sha256,evidence)
        private, public = load_prestate_signer(plan)
        raw = seal_prestate_receipt(body,private,public)
        recheck_prepared_target(plan_path,expected_plan_sha256,evidence)
        receipt = persist_prestate_receipt(Path('/'),plan.as_dict()['rollback_selector'],raw,body,public)
        recheck_prepared_target(plan_path,expected_plan_sha256,evidence)
        reread_prestate_receipt(Path('/'),receipt,body,public)
        forward_raw = seal_prepared_forward_state(raw,body,private,public)
        forward = prepared_forward_record(Path('/'),receipt,raw,body,public,create_raw=forward_raw)
        recheck_prepared_target(plan_path,expected_plan_sha256,evidence)
        prepared_forward_record(Path('/'),receipt,raw,body,public,journal=forward)
        candidate = prepared_candidate_record(Path('/'),receipt,raw,body,public,
            staged['candidate_selector'],staging_parent,create=True)
        recheck_prepared_target(plan_path,expected_plan_sha256,evidence)
        prepared_candidate_record(Path('/'),receipt,raw,body,public,
            staged['candidate_selector'],staging_parent)
        from .transaction import place_inactive_generation
        recheck_prepared_target(plan_path,expected_plan_sha256,evidence)
        placement = place_inactive_generation(Path('/'),release,material,
            evidence['target_prestate']['generation_destination'])
        recheck_prepared_target(plan_path,expected_plan_sha256,evidence,
            placed={'selector':staged['candidate_selector'],'record':candidate})
        prepared_forward_record(Path('/'),receipt,raw,body,public,journal=forward)
        prepared_candidate_record(Path('/'),receipt,raw,body,public,
            staged['candidate_selector'],Path('/usr/share/serein/outpost-generations'),placed=True)
        prepared = {**staged,'prestate_receipt':receipt,'forward_state':forward,
                    'candidate_record':candidate,'placement':placement,'transaction_lock':lock}
        if promote:
            from .public_generation_transaction import _GenerationFileIO, _complete_bootstrap_promotion, _target_prestate, _verify_plan
            fields = plan.as_dict()
            immutable_before = _target_prestate(Path('/'),fields)
            expected_target = evidence['target_prestate']
            if any(immutable_before[key]!=expected_target[key] for key in ('current_boot_id','host_identity','immutable_rows')):
                raise TransactionError('PUBLIC_TARGET_CHANGED_BEFORE_PROMOTION')
            def invariants():
                checked=_verify_plan(_load_plan(Path(plan_path),expected_plan_sha256))
                if (checked.encoded!=plan.encoded or _target_prestate(Path('/'),fields)!=immutable_before
                        or _bootstrap_service_account()!=service_account):
                    raise TransactionError('PUBLIC_TARGET_CHANGED_DURING_PROMOTION')
                reread_prestate_receipt(Path('/'),receipt,body,public)
            def accept(selector,not_before):
                return read_postpromotion_witness(plan_path,expected_plan_sha256,selector,not_before=not_before)
            io=_GenerationFileIO(Path('/'),str(Path(receipt['path']).parent))
            result=_complete_bootstrap_promotion(io,prepared,body,raw,private,public,precheck,invariants,accept)
            yield result
        else:
            yield prepared


def _public_source_bytes(evidence):
    from .transaction import canonical
    try:
        source=evidence['source']
        return canonical({'schema':'SereinOutpostPublicSource/v1',
            **{k:source[k] for k in ('repository','commit','tree','archive_sha256','release_digest')},
            'source_plan_sha256':evidence['source_plan_sha256']})
    except (KeyError,TypeError):
        raise TransactionError('PREPARED_PUBLIC_SOURCE_DENIED') from None


def _stage_prepared(evidence, release, material, staging_parent):
    from .transaction import stage_inactive_generation
    from .public_generation_transaction import bind_generation_material, prepared_generation_selector, prepared_bootstrap_image
    release_digest = evidence["source"]["release_digest"]
    if (not isinstance(release_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", release_digest)
            or release.get("self_digest") != release_digest):
        raise TransactionError("PREPARED_RELEASE_IDENTITY_DENIED")
    material = bind_generation_material(release, material, release_digest)
    if 'public-source.json' in material and material['public-source.json']!=_public_source_bytes(evidence):
        raise TransactionError('PREPARED_PUBLIC_SOURCE_CHANGED')
    selector = prepared_generation_selector(release, material, evidence.get('source_plan_sha256'))
    image = prepared_bootstrap_image(release, material, evidence.get('target_prestate'))
    staged = stage_inactive_generation(staging_parent, release_digest.removeprefix("sha256:"), material)
    if staged['inventory_digest'] != selector['inventory_digest']:
        raise TransactionError('PREPARED_STAGED_INVENTORY_MISMATCH')
    return {"preparation":evidence, "staging":staged, "candidate_selector":selector, 'bootstrap_image':image,
            "installed":"UNPROVEN", "authority_effect":"NONE", "activation":"NONE"}


def _bootstrap_service_account():
    """Existing unprivileged identity, checked before any service effect."""
    import pwd,grp
    try:
        user=pwd.getpwnam('serein-outpost');group=grp.getgrnam('serein-outpost')
    except KeyError:raise TransactionError('PUBLIC_WITNESS_ACCOUNT_REQUIRED') from None
    if user.pw_uid<=0 or group.gr_gid<=0:
        raise TransactionError('PUBLIC_WITNESS_ACCOUNT_DENIED')
    return user.pw_uid,group.gr_gid


def read_postpromotion_witness(plan_path, expected_plan_sha256, expected_generation, *, not_before):
    """Read the existing native witness; never promote or declare admission.

    Bind to the signed source plan and actual service account. No caller may
    redirect the target, choose its custody, substitute the current time or
    treat predecessor output as this candidate's post-promotion observation.
    """
    import pwd
    import grp
    from .public_generation_transaction import _verify_plan, _target_prestate, read_generation_witness
    plan = _verify_plan(_load_plan(Path(plan_path),expected_plan_sha256))
    fields = plan.as_dict()
    if (not isinstance(expected_generation,dict)
            or expected_generation.get('release_digest')!=fields['release_digest']
            or expected_generation.get('predecessor_receipt_sha256')!=sha(plan.encoded)):
        raise TransactionError('PUBLIC_WITNESS_SOURCE_BINDING_DENIED')
    before = _target_prestate(Path('/'),fields)
    try:
        user = pwd.getpwnam('serein-outpost')
        group = grp.getgrnam('serein-outpost')
    except KeyError:
        raise TransactionError('PUBLIC_WITNESS_ACCOUNT_REQUIRED') from None
    if user.pw_uid<=0 or group.gr_gid<=0:
        raise TransactionError('PUBLIC_WITNESS_ACCOUNT_DENIED')
    result = read_generation_witness(Path('/'),expected_generation=expected_generation,
        boot_id=fields['current_boot_id'],not_before=not_before,
        service_uid=user.pw_uid,service_gid=group.gr_gid)
    if _target_prestate(Path('/'),fields)!=before:
        raise TransactionError('PUBLIC_TARGET_CHANGED_DURING_WITNESS')
    return result


def install_request(arguments):
    """One source entry: pinned download -> stage -> promote -> readback.

    VM4010's signed, current-boot plan is required. This entry cannot select a
    different root, grant authority, install a domain or repair permissions.
    Evidence/staging is preserved after failure; no old transaction is reused.
    """
    import tempfile
    request=parse_install_request(arguments)
    evidence,release,material=prepare_install_request(arguments)
    if os.geteuid()!=0 or os.getegid()!=0:
        raise TransactionError('PUBLIC_INSTALLER_ROOT_REQUIRED')
    from .public_generation_transaction import bootstrap_candidate_precheck
    bootstrap_candidate_precheck(release,material,evidence['source_plan_sha256'])
    parent=Path('/var/lib/serein/rollback')
    nofollow_ancestors(Path('/'),parent,allow_missing=False)
    info=parent.lstat()
    if (info.st_uid,info.st_gid)!=(0,0) or stat.S_IMODE(info.st_mode) not in {0o700,0o755}:
        raise TransactionError('PUBLIC_STAGING_PARENT_DENIED')
    staging=Path(tempfile.mkdtemp(prefix='outpost-inactive-',dir=parent))
    with recorded_prepared_generation(Path(request.plan_path),request.expected_plan_sha256,
            evidence,release,material,staging_parent=staging,promote=True) as result:
        return result


def main(arguments=None):
    import sys
    try:
        result=install_request(sys.argv[1:] if arguments is None else arguments)
        print(json.dumps(result,sort_keys=True))
        return 0
    except (TransactionError,OSError,ValueError):
        # Do not print private plan/captures or arbitrary exception content.
        print(json.dumps({'result':'INSTALL_FAILED','admission':'UNPROVEN',
                          'evidence':'PRESERVED_IN_BOUND_TRANSACTION'}))
        return 1


if __name__=='__main__':
    raise SystemExit(main())
