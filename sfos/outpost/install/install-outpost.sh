#!/bin/sh
set -eu
export PYTHONDONTWRITEBYTECODE=1
SOURCE=${1:-}
ACTION=${2:-preflight}
TARGET_ROOT=${3:-/}
IMMUTABLE_INPUT_PLAN=${4:-}
EXPECTED_PLAN_SHA256=${5:-}
[ -n "$SOURCE" ] || { echo "usage: install-outpost.sh SOURCE [preflight|install] [target-root] [immutable-input-plan]" >&2; exit 64; }
[ "$ACTION" = preflight ] || [ "$TARGET_ROOT" = / ] || exit 64
/usr/bin/python3 -B "$SOURCE/verify_install_preflight.py" --source "$SOURCE" --mode source
if [ "$ACTION" = install ] && [ -n "$IMMUTABLE_INPUT_PLAN" ]; then
  /usr/bin/python3 -B "$SOURCE/verify_install_preflight.py" --source "$SOURCE" --mode target --target-root "$TARGET_ROOT" --immutable-input-plan "$IMMUTABLE_INPUT_PLAN"
else
  /usr/bin/python3 -B "$SOURCE/verify_install_preflight.py" --source "$SOURCE" --mode target --target-root "$TARGET_ROOT"
fi
[ "$ACTION" = preflight ] && { printf '%s\n' PASS_OUTPOST_HOST_EXPECTED_BEFORE; exit 0; }
[ "$ACTION" = install ] || exit 64
[ -n "$IMMUTABLE_INPUT_PLAN" ] || { echo "immutable input plan required" >&2; exit 64; }
exec /usr/bin/python3 -B "$SOURCE/install/transaction.py" install "$SOURCE" "$IMMUTABLE_INPUT_PLAN"
