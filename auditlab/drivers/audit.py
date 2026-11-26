"""Independent post-install audit verifier.

It does NOT trust the installer. For every target it:
  1. recomputes sha256/size of each file actually on disk,
  2. parses the wheel's source RECORD and the target RECORD (if any),
  3. classifies each item into one of four states,
  4. flags generated artifacts that never made it into the final RECORD.

States:
  VERIFIED_SOURCE   : an archive member whose recomputed hash == source RECORD
  WRITTEN_PENDING   : on disk, source-verifiable, but no target RECORD committed
  COMMITTED         : present and listed with matching hash in target RECORD
  UNVERIFIABLE      : no usable source/RECORD basis to confirm provenance
"""
import base64
import csv
import hashlib
import json
import sys
import zipfile
from pathlib import Path

WS = Path(sys.argv[1]).resolve()
LAB = WS / "auditlab"
WHEEL = LAB / "wheelhouse/auditdemo-1.0.0-py3-none-any.whl"
DIST_INFO = "auditdemo-1.0.0.dist-info"


def urlsafe_b64_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
            size += len(chunk)
    return f"sha256={urlsafe_b64_nopad(h.digest())}", size


def load_source_record(wheel: Path) -> dict:
    with zipfile.ZipFile(wheel) as zf:
        text = zf.read(f"{DIST_INFO}/RECORD").decode("utf-8")
    out = {}
    for row in csv.reader(text.splitlines(), delimiter=",", quotechar='"'):
        out[row[0]] = {"hash": row[1], "size": row[2]}
    return out


def load_target_record(record_path: Path) -> dict | None:
    if not record_path.exists():
        return None
    out = {}
    with record_path.open(encoding="utf-8") as fh:
        for row in csv.reader(fh, delimiter=",", quotechar='"'):
            out[row[0]] = {"hash": row[1], "size": row[2]}
    return out


# Map an on-disk logical path -> source archive member it derives from (or None).
DATA_DIR_MEMBER = "auditdemo-1.0.0.data/scripts/bundled-tool"
SOURCE_PROVENANCE = {
    "purelib/auditdemo/__init__.py": "auditdemo/__init__.py",
    "purelib/auditdemo/core.py": "auditdemo/core.py",
    "purelib/auditdemo/data.txt": "auditdemo/data.txt",
    "scripts/bundled-tool": DATA_DIR_MEMBER,
    f"purelib/{DIST_INFO}/METADATA": f"{DIST_INFO}/METADATA",
    f"purelib/{DIST_INFO}/WHEEL": f"{DIST_INFO}/WHEEL",
    f"purelib/{DIST_INFO}/entry_points.txt": f"{DIST_INFO}/entry_points.txt",
    f"purelib/{DIST_INFO}/top_level.txt": f"{DIST_INFO}/top_level.txt",
}
# Launchers generated from entry-point declarations (never appear in the wheel).
GENERATED = {"scripts/audited-entry"}
# The target RECORD's own row always has empty hash/size by PEP 376.
RECORD_LOGICAL = f"purelib/{DIST_INFO}/RECORD"


def target_record_key(logical: str) -> str:
    """Translate an on-disk logical path to its key in the target RECORD."""
    if logical.startswith("purelib/"):
        return logical[len("purelib/"):]
    if logical.startswith("scripts/"):
        return "../" + logical
    return logical


def audit_target(target: Path, source_rec: dict) -> dict:
    record_path = target / f"purelib/{DIST_INFO}/RECORD"
    target_rec = load_target_record(record_path)
    files = sorted(p for p in target.rglob("*") if p.is_file())
    items = []
    for f in files:
        logical = str(f.relative_to(target))
        actual_hash, actual_size = sha256_file(f)
        src_member = SOURCE_PROVENANCE.get(logical)
        is_generated = logical in GENERATED
        is_record_self = logical == RECORD_LOGICAL

        src_match = None
        if src_member and src_member in source_rec:
            s = source_rec[src_member]
            src_match = (s["hash"] == actual_hash) and (int(s["size"]) == actual_size)

        rec_key = target_record_key(logical)
        in_target = target_rec is not None and rec_key in target_rec
        target_match = None
        if in_target:
            t = target_rec[rec_key]
            if is_record_self:
                # RECORD describes itself with empty hash/size: presence is the check.
                target_match = t["hash"] == "" and t["size"] == ""
            else:
                target_match = (t["hash"] == actual_hash) and (
                    t["size"] == "" or int(t["size"]) == actual_size
                )

        if is_record_self:
            provenance = "RECORD_SELF"
            basis = "RECORD row has empty hash/size by PEP 376"
        elif is_generated:
            provenance = "GENERATED_FROM_ENTRY_POINT"
            basis = "not in wheel; built via installer.scripts.Script.generate"
        elif src_member:
            provenance = "WHEEL_ARCHIVE_MEMBER"
            basis = src_member
        else:
            provenance = "UNKNOWN"
            basis = None

        if target_rec is None:
            # No committed RECORD: source-verified members and generated files are
            # written but not yet committed.
            if is_record_self:
                state = "UNVERIFIABLE"  # absent when interrupted; nothing to check
            elif provenance == "WHEEL_ARCHIVE_MEMBER" and src_match:
                state = "WRITTEN_PENDING"
            elif is_generated:
                state = "WRITTEN_PENDING"
            else:
                state = "UNVERIFIABLE"
        else:
            if in_target and target_match:
                state = "COMMITTED"
            elif provenance == "WHEEL_ARCHIVE_MEMBER" and src_match:
                state = "VERIFIED_SOURCE"
            else:
                state = "UNVERIFIABLE"

        items.append({
            "logical_path": logical,
            "provenance": provenance,
            "source_basis": basis,
            "actual_sha256": actual_hash,
            "actual_size": actual_size,
            "source_record_hash_match": src_match,
            "in_target_record": in_target,
            "target_record_hash_match": target_match,
            "state": state,
        })

    # Generated artifacts that never entered the final RECORD.
    orphan_generated = [
        i["logical_path"] for i in items
        if i["provenance"] == "GENERATED_FROM_ENTRY_POINT"
        and not i["in_target_record"]
    ]
    return {
        "target": str(target),
        "target_record_present": target_rec is not None,
        "target_record_path": str(record_path),
        "file_count": len(files),
        "states": {
            s: sum(1 for i in items if i["state"] == s)
            for s in ("COMMITTED", "VERIFIED_SOURCE", "WRITTEN_PENDING", "UNVERIFIABLE")
        },
        "generated_artifacts_missing_from_final_record": orphan_generated,
        "items": items,
    }


def main() -> None:
    source_rec = load_source_record(WHEEL)
    result = {
        "wheel": str(WHEEL),
        "source_record_entries": len(source_rec),
        "targets": {},
    }
    for name in ("full", "interrupted", "tampered", "partial-record"):
        result["targets"][name] = audit_target(LAB / "targets" / name, source_rec)
    out = LAB / "evidence/audit-report.json"
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"\n[written] {out}")


if __name__ == "__main__":
    main()
