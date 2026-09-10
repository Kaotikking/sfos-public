# SFOS Public Installer

This repository is the public, target-neutral installer for SFOS. It converts a
compatible Debian 13 amd64 host or builds flashable media from one exact,
signature-verified Debian image.

The first Serein component installed is **Outpost**. Outpost initially verifies
only Debian Base and GPU continuity, exposes the read-only **Serein Vitals**
surface, and is enabled as the Base OS installer completes. On bare hardware it
starts on the first host boot; on an already-running compatible Debian host it
starts after convergence. No downstream Serein domain is activated by either
road.
Kernel and every later API domain are installed and witnessed by Outpost in the
canonical order; this public tree does not embed private credentials, machine
identity, network topology, models, or downstream domain payloads.

Start with [`sfos/base/installer/MEDIA_BUILD.md`](sfos/base/installer/MEDIA_BUILD.md)
for bare-machine media. On an existing compatible Debian 13 amd64 installation,
use `sfos/base/installer/converge-existing.sh` only after its Host/GPU/Debian
witness prerequisites pass. Both roads require an externally supplied,
root-owned mode `0600` immutable-input plan; the public installer never creates,
embeds, or exports private keys or tokens.

Public updates are pinned to `https://github.com/Kaotikking/sfos-public` on
`refs/heads/main` and require the exact full commit, tree, archive SHA-256,
release self-digest, admitted signature, and authority. A candidate is installed
as a content-addressed generation and probed through the immutable launcher
before the current selector is changed. The last-known-good selector remains an
independent rescue generation. Rollback consumes only its signed canonical
receipt and fails closed on selector, inventory, custody, or service drift.

Installation order is recovery order:

`BASE OS -> OUTPOST -> KERNEL[AUTHORITY -> OPERATIONS -> INTERFACE] -> GPU-BACKED LOCAL COMPANION/GATEWAY -> OUTPOST-VERIFIED STAGE 1 -> PLATFORM -> ROOT -> MEMORY -> KNOWLEDGE -> UI -> AUDIO -> PERSONALITY -> MODULAR -> CLOUD`

