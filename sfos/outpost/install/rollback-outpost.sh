#!/bin/sh
set -eu
export PYTHONDONTWRITEBYTECODE=1
ROLLBACK=${1:-}
[ -n "$ROLLBACK" ] || { echo "usage: rollback-outpost.sh SELECTOR" >&2; exit 64; }
test -f "$ROLLBACK/receipt.json"
exec /usr/bin/python3 -B /usr/share/serein/outpost/install/transaction.py rollback "$ROLLBACK"
