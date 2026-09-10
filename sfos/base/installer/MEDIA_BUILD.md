# SFOS public bare-install media

`build-media.sh` produces a flashable hybrid ISO from one exact Debian image and
the target-neutral `sfos/` public installer tree. It never selects, partitions,
formats, or confirms destruction of a destination disk.

The build requires `python3`, `gpgv`, `sha256sum`, and `xorriso`. Supply the exact
ISO, signed checksum document, detached signature, and Debian CD signing keyring
named by `media-lock.json`. The builder first verifies the lock, artifact hashes,
Debian signature fingerprint, signed ISO checksum, embedded lock equality, safe
payload file types, and interactive storage guards. It then asks xorriso to replay
the verified Debian image's existing BIOS/UEFI boot equipment while adding:

- `/sfos` — the public installer payload;
- `/sfos/source-road-receipt.json` — the exact, pre-install Debian-media and Outpost-release binding;
- `/preseed.cfg` — a convenience copy of the target-neutral preseed.

Example (from the public repository root):

```sh
sh sfos/base/installer/build-media.sh \
  sfos/base/installer/media-lock.json \
  downloads/debian-13.6.0-amd64-netinst.iso \
  downloads/SHA256SUMS downloads/SHA256SUMS.sign \
  /usr/share/keyrings/debian-role-keys.gpg \
  . dist/sfos-public-13.6.0-amd64.iso \
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

The JSON receipt binds the upstream ISO and media lock, every embedded payload
file, the embedded source-road receipt, the resulting ISO hash, the replayed-boot declaration, and the interactive
storage policy. `BUILT_NOT_INSTALLED` is media-build evidence only; it is not
hardware boot, installation, GPU, Host-gate, or Outpost witness proof.
