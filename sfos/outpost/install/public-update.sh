#!/bin/sh
set -eu
[ "$#" -eq 1 ] || { echo "usage: public-update.sh SIGNED_PLAN" >&2; exit 64; }
exec /usr/bin/python3 -B /usr/share/serein/outpost/install/public_installer_cli.py install-update --plan "$1"
