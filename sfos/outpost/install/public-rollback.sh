#!/bin/sh
set -eu
[ "$#" -eq 1 ] || { echo "usage: public-rollback.sh SIGNED_TRANSACTION_RECEIPT" >&2; exit 64; }
exec /usr/bin/python3 -B /usr/share/serein/outpost/install/public_installer_cli.py rollback "$1"
