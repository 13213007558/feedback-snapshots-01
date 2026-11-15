"""Record how unmodified dissect.evidence behaves on each fixture.

This is evidence of the tool's trust model, not part of the verdict: dissect only
consumes primary "table" sections (Segment.tables filters out Table2Section) and
never validates Adler-32 checksums, so a decompressible primary table is treated
as authoritative even when table2 disagrees.
"""
from __future__ import annotations

from pathlib import Path

from dissect.evidence.ewf.ewf import EWF, Table2Section

IMAGES = Path(__file__).resolve().parents[1] / "images"

for image in sorted(IMAGES.glob("*.E01")):
    with image.open("rb") as fh:
        try:
            ewf = EWF(fh)
            segment = ewf.segment(0)
            table2_present = any(isinstance(section, Table2Section) for section in segment.sections)
            payload = ewf.open().read()
            status = f"READS primary-only, table2_present={table2_present}, first16={payload[:16]!r}"
        except Exception as exc:  # noqa: BLE001 - reference report wants any failure
            status = f"RAISES {type(exc).__name__}: {exc}"
    print(f"{image.name:<32} {status}")
