#!/bin/sh
# Canonical Base-to-Outpost package entry. No alternate target or transport.
set -eu
test "$#" -eq 7 || { echo 'OUTPOST_ENTRY_ARGUMENTS_REQUIRED' >&2; exit 2; }
PACKAGE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd -- "$PACKAGE"
exec /usr/bin/env -u PYTHONPATH -u PYTHONHOME PYTHONDONTWRITEBYTECODE=1 \
    /usr/bin/python3 -s -B -m install.public_installer_cli "$@"
