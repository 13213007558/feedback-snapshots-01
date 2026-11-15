"""Demonstrate the two-collection-machine failure mode in one process.

Both files carry the same provider GUID and descriptor, but each was written
with a different manifest revision.  dissect.etl caches by GUID only, so the
second file silently reuses the first file's template -- including across
different ETL objects, because the cache is module-global.

Run from the repository root:

    .venv/bin/python diagnostics/two_machines.py
"""

from __future__ import annotations

import io
from pathlib import Path
from uuid import UUID

from dissect.etl import manifest
from dissect.etl.etl import ETL

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MANIFESTS = Path(__file__).resolve().parent / "manifests"
GUID = UUID("13976d09-a327-438c-950b-7f03192815c7")


def run(label: str, fixture: str) -> None:
    etl = ETL(io.BytesIO((FIXTURES / fixture).read_bytes()))
    records = [record for buffer in etl.buffers() for record in buffer]
    try:
        event = records[1].event
    except Exception as exc:  # noqa: BLE001 - this is the finding
        print(f"  {label:<28} raised {type(exc).__name__}: {exc}")
        return
    values = dict(event._struct.__values__) if event._struct is not None else None
    print(f"  {label:<28} provider={event.provider_name()!r} symbol={event.symbol()!r}")
    print(f"  {'':<28} values={values}")


def main() -> None:
    print("A. cold process reading exporter_a.etl, then exporter_b.etl")
    manifest.CACHE.clear()
    manifest.CACHE[GUID] = manifest.compile_file(
        GUID,
        str(MANIFESTS / "provider_v1.xml"),
    )
    run("exporter_a.etl (v1 first)", "exporter_a.etl")
    run("exporter_b.etl (reuses v1)", "exporter_b.etl")

    print("\nB. cold process reading exporter_b.etl, then exporter_a.etl")
    manifest.CACHE.clear()
    manifest.CACHE[GUID] = manifest.compile_file(
        GUID,
        str(MANIFESTS / "provider_v2.xml"),
    )
    run("exporter_b.etl (v2 first)", "exporter_b.etl")
    run("exporter_a.etl (reuses v2)", "exporter_a.etl")

    print("\nC. same files, fresh cache per file (isolation)")
    for fixture, candidate in (("exporter_a.etl", "provider_v1.xml"), ("exporter_b.etl", "provider_v2.xml")):
        manifest.CACHE.clear()
        manifest.CACHE[GUID] = manifest.compile_file(
            GUID,
            str(MANIFESTS / candidate),
        )
        run(f"{fixture} ({candidate})", fixture)


if __name__ == "__main__":
    main()
