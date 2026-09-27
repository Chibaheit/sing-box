#!/usr/bin/env bash
set +x +v
set -euo pipefail
umask 077
tools=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ $# == 1 && "$1" == cleanup ]]; then
  python3 "$tools/signing.py" cleanup
  exit
fi
[[ $# == 2 ]] || { echo "Usage: sign.sh CORE SIGNED_OUTPUT | cleanup" >&2; exit 2; }
python3 "$tools/signing.py" preflight
trap 'python3 "$tools/signing.py" cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
python3 "$tools/signing.py" sign "$1" "$2"
