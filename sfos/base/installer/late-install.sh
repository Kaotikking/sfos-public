#!/bin/sh
set -eu
export PYTHONDONTWRITEBYTECODE=1
[ "$#" -eq 6 ] || { echo "usage: late-install.sh TARGET PUBLIC_TREE SOURCE_KIND SOURCE_RECEIPT IMMUTABLE_INPUT_PLAN EXPECTED_PLAN_SHA256" >&2; exit 64; }
TARGET=$1 PUBLIC_TREE=$2 SOURCE_KIND=$3 SOURCE_RECEIPT=$4 IMMUTABLE_INPUT_PLAN=$5 EXPECTED_PLAN_SHA256=$6
case "$EXPECTED_PLAN_SHA256" in ''|*[!0-9a-f]*) echo EXPECTED_PLAN_SHA256_REQUIRED >&2; exit 64 ;; esac
[ "${#EXPECTED_PLAN_SHA256}" -eq 64 ] || { echo EXPECTED_PLAN_SHA256_REQUIRED >&2; exit 64; }
[ "$TARGET" = /target ] && [ -d "$TARGET" ] && [ ! -L "$TARGET" ] || { echo OFFLINE_INSTALLER_TARGET_REQUIRED >&2; exit 64; }
[ "$(id -u)" -eq 0 ] || { echo ROOT_REQUIRED >&2; exit 1; }
[ "$SOURCE_KIND" = OFFLINE_USB_MEDIA ] || { echo OFFLINE_INSTALLER_SOURCE_REQUIRED >&2; exit 64; }
[ -r "$TARGET/etc/os-release" ] || { echo DEBIAN_TARGET_REQUIRED >&2; exit 1; }
grep -q '^ID=debian$' "$TARGET/etc/os-release" && grep -Eq '^VERSION_ID="?13"?$' "$TARGET/etc/os-release" || { echo DEBIAN_TARGET_REQUIRED >&2; exit 1; }
SOURCE=$PUBLIC_TREE/sfos/outpost
ENTRY=$SOURCE/install/install-outpost.sh
[ -f "$ENTRY" ] && [ ! -L "$ENTRY" ] || { echo CANONICAL_OUTPOST_ENTRY_UNAVAILABLE >&2; exit 1; }
# One package entry owns source authority, exact immutable-input custody,
# staging, installation and enable-only first-host-boot behavior. This Base
# wrapper must neither copy a partial package nor execute a second transaction.
# d-i itself need not provide Python: the complete package entry must use the
# installed target's declared toolchain through Debian's in-target/chroot road.
# The offline source receipt remains explicit input, not an authority claim.
# Portable media authority and the complete entry are not implemented yet;
# this delegation alone is not a fresh-install witness.
exec /bin/sh "$ENTRY" "$SOURCE" install "$TARGET" "$IMMUTABLE_INPUT_PLAN" "$EXPECTED_PLAN_SHA256" "$SOURCE_KIND" "$SOURCE_RECEIPT"
