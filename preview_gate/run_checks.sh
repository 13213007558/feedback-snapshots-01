#!/usr/bin/env bash
# Create the three local caches and run every one through the real outlet.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$HERE/../.venv/bin/python"
if [ ! -x "$PY" ]; then PY="$(command -v python3)"; fi
"$PY" "$HERE/verify.py"
