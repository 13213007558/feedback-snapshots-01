"""Cross-check every scenario with the stock dissect.evidence reader.

dissect.evidence deliberately ignores ``table2`` (see
``dissect/evidence/ewf/ewf.py`` ``Segment.tables``) and follows the primary
table only. Recording its behaviour next to the independent audit shows where a
tool that "just reads the image" would silently succeed, fail, or stop.

The library is imported read-only; this script never writes into its package.
"""

from __future__ import annotations

import hashlib
import json
import sys
import traceback
from pathlib import Path

from dissect.evidence.ewf.ewf import EWF, Segment

IMAGES = Path(__file__).resolve().parent.parent / "images"
REPORTS = Path(__file__).resolve().parent.parent / "reports"


def check_image(path: Path) -> dict:
    result: {"file": str} = {"file": path.name}
    with path.open("rb") as handle:
        try:
            segment = Segment(handle)
            result["segment_number"] = segment.number
            result["sections"] = [
                {
                    "type": section.descriptor.type,
                    "offset": hex(section.descriptor.offset),
                    "descriptor_checksum_ok": _descriptor_ok(path.read_bytes(), section.descriptor.offset),
                }
                for section in segment.sections
            ]
            result["tables_seen_by_dissect"] = [
                section.descriptor.type for section in segment.sections if type(section).__name__ == "TableSection"
            ]
        except Exception as exc:  # noqa: BLE001 - forensic record wants every failure
            result["segment_parse_error"] = f"{type(exc).__name__}: {exc}"

    with path.open("rb") as handle:
        try:
            ewf = EWF(handle)
            stitched = ewf.open().read()
            result["dissect_read"] = "ok"
            result["dissect_size"] = len(stitched)
            result["dissect_sha256"] = hashlib.sha256(stitched).hexdigest()
        except Exception as exc:  # noqa: BLE001
            result["dissect_read"] = "error"
            result["dissect_error"] = f"{type(exc).__name__}: {exc}"
            result["dissect_traceback_tail"] = traceback.format_exc().splitlines()[-3:]
    return result


def _descriptor_ok(data: bytes, offset: int) -> bool:
    import zlib

    return (zlib.adler32(data[offset : offset + 72]) & 0xFFFFFFFF) == int.from_bytes(
        data[offset + 72 : offset + 76], "little"
    )


def main() -> None:
    rows = [check_image(path) for path in sorted(IMAGES.glob("*.E01"))]
    (REPORTS / "dissect_crosscheck.json").write_text(json.dumps(rows, indent=2, sort_keys=True))
    for row in rows:
        print(
            f"{row['file']:48s} dissect={row.get('dissect_read'):5s} "
            f"sha={row.get('dissect_sha256', '-')[:16]} "
            f"err={row.get('dissect_error', '')}"
        )


if __name__ == "__main__":
    sys.exit(main())
