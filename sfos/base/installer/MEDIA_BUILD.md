# SFOS public two-path installation media

Current candidate: OUTPOST_INCOMPLETE. The complete signed Debian/Outpost image
has not been built, booted or admitted. The native xorriso timestamp regression
uses explicitly nonbootable fixtures and does not satisfy this artifact gate.

`build-media.sh` is the existing builder for a flashable hybrid ISO from one exact Debian image and
the target-neutral `sfos/` public installer tree. It never selects, partitions,
formats, or confirms destruction of a destination disk.

The build requires `python3`, `gpgv`, `sha256sum`, `xorriso`, and Debian Trixie's
GNU `mv` with `-T --update=none-fail`. Both fresh Trixie
installation and bounded existing-Debian conversion remain required paths of
the same complete generation; neither is proven by loose source scripts.
Supply the exact
ISO, signed checksum document, detached signature, and Debian CD signing keyring
named by `media-lock.json`. The builder first verifies the lock, artifact hashes,
Debian signature fingerprint, signed ISO checksum, embedded lock equality, safe
payload file types, and interactive storage guards. It then asks xorriso to replay
the verified Debian image's existing BIOS/UEFI boot equipment while adding:

- `/sfos` — the public installer payload;
- `/sfos/source-road-receipt.json` — the exact, pre-install Debian-media and Outpost-release binding;
- `/sfos/immutable-input-plan.json` — the bounded captured plan, separately bound
  by the rendered preseed and external receipt, never granted authority by its name;
- `/preseed.cfg` — a convenience copy of the target-neutral preseed.

Invocation shape (not a completed release command): the ten positional inputs
include the exact public-source receipt and immutable-input plan. Bind
SOURCE_DATE_EPOCH to the frozen release's deterministic build input. Do not use
the wall clock, mutable source mtimes, private key contents or VM-specific secrets
as public-media input. Portable final-media authority is not established yet;
the current offline source verifier deliberately denies installation authority.

```sh
SOURCE_DATE_EPOCH="$ADMITTED_SOURCE_EPOCH" sh sfos/base/installer/build-media.sh \
  sfos/base/installer/media-lock.json \
  downloads/debian-13.6.0-amd64-netinst.iso \
  downloads/SHA256SUMS downloads/SHA256SUMS.sign \
  /usr/share/keyrings/debian-role-keys.gpg \
  . source-road-receipt.json immutable-input-plan.json \
  dist/sfos-public-13.6.0-amd64.iso \
  dist/sfos-public-13.6.0-amd64.receipt.json
```

At the Debian installer boot prompt, select the normal installer and append the
official file-preseed arguments:

```text
auto=true priority=critical preseed/file=/cdrom/preseed.cfg
```

Disk choice and both destructive confirmations remain interactive. The preseed's
late command invokes only the embedded Outpost bootstrap and enables Outpost for
the first host boot. It does not reboot or activate a downstream Serein domain.
On that first boot, Outpost must verify the Debian Base and GPU host gate before
any Kernel material can be requested or installed.

The external JSON receipt binds the upstream ISO and media lock, every embedded payload
file, the embedded source-road receipt, the resulting ISO hash, the replayed-boot declaration, and the interactive
storage policy. `BUILT_NOT_INSTALLED` is media-build evidence only; it is not
hardware boot, installation, GPU, Host-gate, or Outpost witness proof.

The finished ISO hash belongs in that external build receipt, never embedded in
the image that it hashes. The mounted-tree source receipt is separate. Offline
mounted-tree integrity performs no network request and cannot authenticate an
unsigned receipt by comparing it with itself. Actual input/output file hashing
also remains distinct from Debian signature validation and embedded-byte readback.
No new signer or portable authority is invented to close that missing contract.

Generated receipt/plan paths must be absent from the public source tree. The
offline source comparison excludes only these exact generated overlays; the
online provider comparison still includes every public source byte. A bounded
regular captured plan is not itself portable installation authority.

Final image and receipt handoffs reject existing files, directories and symlinks,
including destinations created after initial checks. These are two separate
no-replacement moves, not an atomic pair: a receipt collision can leave the image
as incomplete build evidence, but cannot print `SFOS_PUBLIC_MEDIA_BUILT` or
overwrite the competing receipt. Preserve that evidence; do not reuse it as a
completed release.

Before writing the external receipt or handing off outputs, the builder extracts
the staged image's actual public payload and rendered preseed with xorriso. It
checks the captured overlays byte-for-byte, verifies mounted payload integrity,
and rejects source drift since the embedded receipt. External payload rows come
from those extracted bytes. This is not bootability or portable authority proof.

Reproducible timestamp controls use xorriso's documented SOURCE_DATE_EPOCH,
-no_rc and -volume_date all_file_dates behavior:
https://manpages.debian.org/trixie/xorriso/xorriso.1.en.html .
This candidate still requires complete package freeze, final-media authority,
actual deterministic image build/readback and both installation witnesses.
