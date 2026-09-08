# SFOS Public Installer

This repository is the public, target-neutral installer for SFOS. It converts a
compatible Debian 13 amd64 host or builds flashable media from one exact,
signature-verified Debian image.

The first Serein component installed is **Outpost**. Outpost initially verifies
only Debian Base and GPU continuity, exposes the read-only **Serein Vitals**
surface, and remains inactive until its separately admitted activation step.
Kernel and every later API domain are installed and witnessed by Outpost in the
canonical order; this public tree does not embed private credentials, machine
identity, network topology, models, or downstream domain payloads.

Start with [`sfos/base/installer/MEDIA_BUILD.md`](sfos/base/installer/MEDIA_BUILD.md)
for bare-machine media. On an existing compatible Debian 13 amd64 installation,
use `sfos/base/installer/converge-existing.sh` only after its Host/GPU/Debian
witness prerequisites pass.

Installation order is recovery order:

`BASE OS -> OUTPOST -> KERNEL[AUTHORITY -> OPERATIONS -> INTERFACE] -> GPU-BACKED LOCAL COMPANION/GATEWAY -> OUTPOST-VERIFIED STAGE 1 -> PLATFORM -> ROOT -> MEMORY -> KNOWLEDGE -> UI -> AUDIO -> PERSONALITY -> MODULAR -> CLOUD`


