#!/usr/bin/env bash
# Reproduce the two-page SQLite audit export.
# Output lands in sample/ and is byte-stable across repeated runs.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

rm -f audit.sqlite3
rm -f sample/audit-page-*.jsonl sample/export-summary.json

python manage.py makemigrations auditcase --noinput >/dev/null
python manage.py migrate --noinput >/dev/null
python manage.py seed_audit_demo

# Annual review window, approved rows only, LEGAL access rule, 3 rows/page.
python manage.py export_audit auditcase.casefile \
  --page-size 3 \
  --max-pages 10 \
  --start-time 2026-01-01T00:00:00Z \
  --end-time 2027-01-01T00:00:00Z \
  --access-callback auditcase.access.legal_department_access \
  --out-dir sample 2> sample/export-summary.json

python verify_demo.py
