"""Bind signed Debian metadata and the pinned public SFOS contract into Host evidence."""
from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import tempfile
import urllib.request
import time
from pathlib import Path

from .debian_host_collector import collect_host_observation, verify_inrelease
from .host_vitality import HostVitalityStore, HostCollectionAttempts, validate_state
from .public_tree_host import bind_signed_debian_observation

RELEASES = {
    "debian:trixie": "https://deb.debian.org/debian/dists/trixie/InRelease",
    "debian:trixie-updates": "https://deb.debian.org/debian/dists/trixie-updates/InRelease",
    "security:trixie-security": "https://security.debian.org/debian-security/dists/trixie-security/InRelease",
}
COMPONENTS = ("main", "contrib", "non-free", "non-free-firmware")
INDEXES = tuple(f"{component}/binary-amd64/Packages.xz" for component in COMPONENTS)
MAX_INRELEASE = 2 * 1024 * 1024
MAX_PACKAGES = 256 * 1024 * 1024
FAILURE_CODES = frozenset({
    "DEBIAN_DOWNLOAD_REDIRECT_DENIED", "DEBIAN_DOWNLOAD_SIZE_DENIED",
    "DEBIAN_DOWNLOAD_URL_DENIED", "DEBIAN_INRELEASE_SIGNATURE_DENIED",
    "DEBIAN_INRELEASE_SIGNER_UNKNOWN", "DEBIAN_INRELEASE_FORMAT_DENIED",
    "DEBIAN_RELEASE_METADATA_DENIED", "DEBIAN_RELEASE_TIME_DENIED",
    "DEBIAN_RELEASE_STALE", "DEBIAN_RELEASE_BINDING_DENIED", "DEBIAN_RELEASE_SET_DENIED",
    "DEBIAN_INDEX_BINDING_DENIED", "DEBIAN_INDEX_HASH_DENIED", "DEBIAN_INDEX_SET_EMPTY",
    "DEBIAN_INDEX_SIZE_DENIED",
    "DEBIAN_INDEX_COVERAGE_DENIED", "DEBIAN_ARCHITECTURE_UNKNOWN",
    "DEBIAN_SOURCE_DIRECTORY_DENIED", "DEBIAN_SOURCE_SET_EMPTY", "DEBIAN_SOURCE_FIELDS_DENIED",
    "DEBIAN_SOURCE_TRUST_DENIED", "DEBIAN_SOURCE_SET_DENIED", "DEBIAN_SOURCE_OVERRIDE_DENIED",
    "DEBIAN_SOURCE_CONFIGURATION_UNKNOWN", "DEBIAN_SOURCE_CONFIGURATION_DENIED",
    "PUBLIC_GIT_REDIRECT_DENIED", "PUBLIC_GIT_STATUS_DENIED", "PUBLIC_GIT_UNAVAILABLE",
    "PUBLIC_GIT_RESPONSE_DENIED", "PUBLIC_BASE_LINEAGE_DENIED", "PUBLIC_COMMIT_TREE_DENIED",
    "PUBLIC_TREE_DENIED", "PUBLIC_BASE_PATH_DENIED", "PUBLIC_BLOB_DENIED",
    "PUBLIC_BLOB_HASH_DENIED", "PUBLIC_BASE_LOCK_DENIED", "PUBLIC_BASE_POLICY_DENIED",
    "HOST_VITALITY_DIGEST_DENIED", "HOST_VITALITY_HISTORY_DENIED",
    "HOST_ATTEMPT_RESULT_DENIED", "HOST_ATTEMPT_SEQUENCE_DENIED",
})


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise RuntimeError("DEBIAN_DOWNLOAD_REDIRECT_DENIED")


def download(url: str, destination: Path, maximum: int, *, expected_sha256: str | None = None) -> None:
    allowed = set(RELEASES.values()) | {base.rsplit("/", 1)[0] + "/" + index for base in RELEASES.values() for index in INDEXES}
    if expected_sha256 is not None:
        if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise RuntimeError("DEBIAN_INDEX_BINDING_DENIED")
        allowed.update(base.rsplit("/", 1)[0] + "/" + index.rsplit("/", 1)[0] + "/by-hash/SHA256/" + expected_sha256
                       for base in RELEASES.values() for index in INDEXES)
    if url not in allowed:
        raise RuntimeError("DEBIAN_DOWNLOAD_URL_DENIED")
    request = urllib.request.Request(url, headers={"User-Agent": "Serein-Outpost-Host-Witness/1"})
    opener = urllib.request.build_opener(_RejectRedirect())
    with opener.open(request, timeout=30) as response, destination.open("wb") as stream:
        if response.geturl() != url:
            raise RuntimeError("DEBIAN_DOWNLOAD_REDIRECT_DENIED")
        total = 0
        actual = hashlib.sha256()
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise RuntimeError("DEBIAN_DOWNLOAD_SIZE_DENIED")
            actual.update(chunk)
            stream.write(chunk)
        if expected_sha256 is not None and (actual.hexdigest() != expected_sha256 or total != maximum):
            raise RuntimeError("DEBIAN_INDEX_HASH_DENIED")


def download_index(release_url: str, index: str, verified_metadata: dict, destination: Path) -> None:
    """Use Debian's advertised by-hash road, bound to verified Release bytes.

    Called only after signature/time/codename validation; no fallback to a
    different digest or mirror on failure. Non-by-hash archives retain the
    exact signed hash/size check on their canonical index URL.
    """
    if release_url not in RELEASES.values() or index not in INDEXES:
        raise RuntimeError("DEBIAN_INDEX_BINDING_DENIED")
    expected = verified_metadata.get("indexes", {}).get(index)
    if (not isinstance(expected, tuple) or len(expected) != 2
            or not isinstance(expected[0], str) or not re.fullmatch(r"[0-9a-f]{64}", expected[0])):
        raise RuntimeError("DEBIAN_INDEX_BINDING_DENIED")
    checksum, size = expected
    if type(size) is not int or not 1 <= size <= MAX_PACKAGES:
        raise RuntimeError("DEBIAN_INDEX_SIZE_DENIED")
    suffix = index
    if verified_metadata.get("acquire_by_hash") is True:
        suffix = index.rsplit("/", 1)[0] + "/by-hash/SHA256/" + checksum
    download(release_url.rsplit("/", 1)[0] + "/" + suffix, destination, size, expected_sha256=checksum)


def _current_boot_id() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def run(state_root: Path) -> dict:
    state_root.mkdir(parents=True, exist_ok=True)
    boot_id = _current_boot_id()
    attempts = HostCollectionAttempts(state_root)
    attempt_id = attempts.start(boot_id, time.time())
    temporary = None
    try:
        temporary = Path(tempfile.mkdtemp(prefix=".debian-witness-", dir=state_root))
        releases = {}
        indexes = {}
        for ordinal, (binding, url) in enumerate(RELEASES.items()):
            release_path = temporary / f"release-{ordinal}.InRelease"
            download(url, release_path, MAX_INRELEASE)
            metadata = verify_inrelease(release_path)
            if metadata["codename"] != binding.split(":", 1)[1] or not set(INDEXES) <= set(metadata["indexes"]):
                raise RuntimeError("DEBIAN_RELEASE_BINDING_DENIED")
            releases[binding] = release_path
            for component_ordinal, index in enumerate(INDEXES):
                index_path = temporary / f"packages-{ordinal}-{component_ordinal}.xz"
                download_index(url, index, metadata, index_path)
                indexes[f"{binding}:{index}"] = index_path
        debian = collect_host_observation(
            inrelease_files=releases,
            index_files=indexes,
            package_exceptions=("serein-outpost",),
        )
        state = HostVitalityStore(state_root).record(bind_signed_debian_observation(debian))
        attempts.finish(attempt_id, time.time(), state=state)
        return state
    except BaseException as error:
        # Never persist arbitrary exception text (URLs, paths or secrets).
        code = str(error).split(":", 1)[0]
        if code not in FAILURE_CODES:
            code = "HOST_COLLECTION_INTERRUPTED" if not isinstance(error, Exception) else "HOST_COLLECTION_UNAVAILABLE"
        attempts.finish(attempt_id, time.time(), error_code=code)
        raise
    finally:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", required=True)
    args = parser.parse_args()
    # A completed observation is not Host admission. Keep Outpost running
    # with the exact degraded dataset; malformed/unjoined evidence still fails.
    validate_state(run(Path(args.state_root)), active=True)


if __name__ == "__main__":
    main()
