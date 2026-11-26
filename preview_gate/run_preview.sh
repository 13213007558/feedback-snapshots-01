#!/usr/bin/env bash
# Serve the real preview gate over http://127.0.0.1:8077 (real TCP socket).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$HERE/../.venv/bin/python"
if [ ! -x "$PY" ]; then PY="$(command -v python3)"; fi
export PYTHONPATH="$HERE${PYTHONPATH:+:$PYTHONPATH}"
exec "$PY" -m ticket_preview.serve --port "${PREVIEW_PORT:-8077}" "$@"
