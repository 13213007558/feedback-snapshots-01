#!/usr/bin/env bash
# Reproduce every diagnostic artifact from scratch.
# Run from the repository root:  bash diagnostics/run_all.sh
set -euo pipefail

PY="${PY:-.venv/bin/python}"
OUT="diagnostics/out"
mkdir -p "$OUT"

"$PY" diagnostics/build_fixtures.py
echo

"$PY" diagnostics/diagnose.py compare diagnostics/fixtures/manifest_v1_v2.etl \
  --candidate v1=diagnostics/manifests/provider_v1.xml \
  --candidate v2=diagnostics/manifests/provider_v2.xml \
  --load-order --json "$OUT/manifest_v1_v2.json" | tee "$OUT/manifest_v1_v2.txt"

"$PY" diagnostics/diagnose.py compare diagnostics/fixtures/manifest_v1_v2.etl \
  --candidate repo \
  --candidate v1=diagnostics/manifests/provider_v1.xml \
  --candidate v2=diagnostics/manifests/provider_v2.xml \
  --load-order --json "$OUT/manifest_v1_v2_three_way.json" | tee "$OUT/manifest_v1_v2_three_way.txt"

"$PY" diagnostics/diagnose.py compare diagnostics/fixtures/alpc_conflict.etl \
  --candidate repo \
  --candidate b=diagnostics/manifests/exporter_b_24byte.xml \
  --candidate c=diagnostics/manifests/exporter_c_24byte.xml \
  --candidate probe34=diagnostics/manifests/probe_opcode_34.xml \
  --candidate probev1=diagnostics/manifests/probe_version_1.xml \
  --candidate probeother=diagnostics/manifests/probe_other_event.xml \
  --load-order --json "$OUT/alpc_conflict.json" | tee "$OUT/alpc_conflict.txt"

"$PY" diagnostics/diagnose.py compare diagnostics/fixtures/shellcore_collision.etl \
  --candidate repo --load-order --json "$OUT/shellcore_collision.json" | tee "$OUT/shellcore_collision.txt"

"$PY" diagnostics/diagnose.py compare diagnostics/fixtures/pointer_width.etl \
  --candidate ptr=diagnostics/manifests/pointer_provider.xml \
  --load-order --json "$OUT/pointer_width.json" | tee "$OUT/pointer_width.txt"

"$PY" diagnostics/diagnose.py cache-order diagnostics/fixtures/alpc_conflict.etl \
  --candidate repo \
  --candidate b=diagnostics/manifests/exporter_b_24byte.xml \
  --candidate c=diagnostics/manifests/exporter_c_24byte.xml \
  --json "$OUT/cache_order.json" | tee "$OUT/cache_order.txt"

"$PY" diagnostics/diagnose.py cache-order diagnostics/fixtures/manifest_v1_v2.etl \
  --candidate v1=diagnostics/manifests/provider_v1.xml \
  --candidate v2=diagnostics/manifests/provider_v2.xml \
  --json "$OUT/cache_order_v1_v2.json" | tee "$OUT/cache_order_v1_v2.txt"

"$PY" diagnostics/diagnose.py compare diagnostics/fixtures/broken_manifest.etl \
  --candidate repo --json "$OUT/broken_manifest.json" | tee "$OUT/broken_manifest.txt"

"$PY" diagnostics/diagnose.py inspect diagnostics/fixtures/alpc_conflict.etl | tee "$OUT/inspect_alpc.txt"

"$PY" diagnostics/two_machines.py | tee "$OUT/two_machines.txt"

"$PY" diagnostics/diagnose.py probe 30336ed4-e327-447c-9de0-51b652c86108 --candidate repo --id 6206 \
  | tee "$OUT/probe_shellcore.txt"
