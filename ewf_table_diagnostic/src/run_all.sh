#!/usr/bin/env bash
# Reproduce every fixture and diagnostic report from scratch.
# The pristine baseline image is regenerated but never patched in place.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"

echo "[1/3] building fixtures and manifest (writes separate files only)"
"$PYTHON" "$DIR/src/build_images.py"

echo "[2/3] running table/table2 diagnostic (text + JSON)"
"$PYTHON" "$DIR/src/diagnose.py" "$DIR"/images/*.E01 --json-dir "$DIR/output" \
    > "$DIR/output/diagnostic.txt"

echo "[3/3] recording dissect.evidence reference behaviour"
"$PYTHON" "$DIR/src/dissect_reference.py" > "$DIR/output/dissect_reference.txt"

echo "done. artefacts in $DIR/images and $DIR/output"
