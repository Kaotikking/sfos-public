#!/bin/sh
set -eu
[ "$#" -eq 4 ] || exit 64
TARGET=$1 SOURCE_ROOT=$2 SOURCE_KIND=$3 SOURCE_RECEIPT=$4
[ "$(id -u)" -eq 0 ] || { echo ROOT_REQUIRED >&2; exit 1; }
[ "$SOURCE_KIND" = OFFLINE_USB_MEDIA ] || [ "$SOURCE_KIND" = PINNED_PUBLIC_REPOSITORY ] || exit 1
[ "$TARGET" = /target ] && [ -r "$TARGET/etc/os-release" ] || exit 1
grep -q '^ID=debian$' "$TARGET/etc/os-release" && grep -Eq '^VERSION_ID="?13"?$' "$TARGET/etc/os-release" || exit 1
SOURCE=$SOURCE_ROOT/sfos/outpost
python3 -B "$SOURCE/verify_install_preflight.py" --source "$SOURCE" --mode source
python3 -B "$SOURCE_ROOT/sfos/base/installer/verify-source-road.py" "$SOURCE_ROOT" "$SOURCE_KIND" "$SOURCE_RECEIPT"
for path in "$TARGET/usr/share/serein/outpost" "$TARGET/etc/serein-outpost" "$TARGET/var/lib/serein-outpost"; do [ ! -e "$path" ] || { echo NEW_OUTPOST_REQUIRED >&2; exit 1; }; done
STAGE=$(mktemp -d "$TARGET/var/tmp/sfos-outpost-source.XXXXXXXX")
[ ! -L "$STAGE" ] && [ "$(stat -c '%u:%a:%F' "$STAGE")" = '0:700:directory' ] || { echo SECURE_STAGE_DENIED >&2; exit 1; }
cleanup() { [ -n "${STAGE:-}" ] && [ ! -L "$STAGE" ] && rm -rf -- "$STAGE"; }
trap cleanup EXIT HUP INT TERM
cp -a "$SOURCE/." "$STAGE/"
GUEST_STAGE=${STAGE#"$TARGET"}
chroot "$TARGET" /usr/bin/python3 -B "$GUEST_STAGE/verify_install_preflight.py" --source "$GUEST_STAGE" --mode source
RESULT=$(chroot "$TARGET" /usr/bin/python3 -B "$GUEST_STAGE/install/transaction.py" bootstrap "$GUEST_STAGE" "$SOURCE_KIND")
SELECTOR=${RESULT#INSTALLED_INACTIVE rollback=}
case "$SELECTOR" in /var/lib/serein/rollback/outpost-first-install-*) ;; *) echo ROLLBACK_SELECTOR_READBACK_DENIED >&2; exit 1;; esac
printf '{"schema":"SFOSBaseRoadReceipt/v1","mode":"BARE_INSTALL","source_kind":"%s","state":"OUTPOST_INSTALLED_INACTIVE","authority_effect":"NONE","rollback_selector":"%s"}\n' "$SOURCE_KIND" "$SELECTOR" >"$TARGET$SELECTOR/base-road-complete.json"
echo OUTPOST_INSTALLED_INACTIVE
