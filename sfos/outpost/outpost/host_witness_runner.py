"""Fetch signed Debian metadata and persist the current Serein Host witness."""
from __future__ import annotations

import argparse
import shutil
import tempfile
import urllib.request
from pathlib import Path

from .debian_host_collector import collect_host_observation, verify_inrelease
from .host_vitality import HostVitalityStore

RELEASES = {
    "debian:trixie": "https://deb.debian.org/debian/dists/trixie/InRelease",
    "debian:trixie-updates": "https://deb.debian.org/debian/dists/trixie-updates/InRelease",
    "security:trixie-security": "https://security.debian.org/debian-security/dists/trixie-security/InRelease",
}
COMPONENTS = ("main", "contrib", "non-free", "non-free-firmware")
INDEXES = tuple(f"{component}/binary-amd64/Packages.xz" for component in COMPONENTS)
MAX_INRELEASE = 2 * 1024 * 1024
MAX_PACKAGES = 256 * 1024 * 1024


def download(url: str, destination: Path, maximum: int) -> None:
    if url not in RELEASES.values() and not any(url == base.rsplit("/", 1)[0] + "/" + index for base in RELEASES.values() for index in INDEXES):
        raise RuntimeError("DEBIAN_DOWNLOAD_URL_DENIED")
    request = urllib.request.Request(url, headers={"User-Agent": "Serein-Outpost-Host-Witness/1"})
    with urllib.request.urlopen(request, timeout=30) as response, destination.open("wb") as stream:
        if response.geturl() != url:
            raise RuntimeError("DEBIAN_DOWNLOAD_REDIRECT_DENIED")
        total = 0
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise RuntimeError("DEBIAN_DOWNLOAD_SIZE_DENIED")
            stream.write(chunk)


def run(state_root: Path) -> dict:
    state_root.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".debian-witness-", dir=state_root))
    try:
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
                download(url.rsplit("/", 1)[0] + "/" + index, index_path, MAX_PACKAGES)
                indexes[f"{binding}:{index}"] = index_path
        # Private Serein payloads are verified by Outpost's own signed source
        # and install manifests; they are not members of Debian's public index.
        observation = collect_host_observation(
            inrelease_files=releases,
            index_files=indexes,
            package_exceptions=("serein-outpost",),
        )
        return HostVitalityStore(state_root).record(observation)
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", required=True)
    args = parser.parse_args()
    result = run(Path(args.state_root))
    if result["classification"] == "DRIFT_DETECTED":
        raise SystemExit("HOST_GATE_DRIFT_DETECTED")


if __name__ == "__main__":
    main()
