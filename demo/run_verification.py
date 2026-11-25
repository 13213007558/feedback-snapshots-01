"""End-to-end verification of the fail-closed de-identification export.

Scenarios exercised (see task statement):

1. Two fictional DICOM samples are read with deferred (lazy) loading.
2. Sample A: some elements are accessed first, then the dataset is deep-copied
   before export ("read then copy").
3. Sample B: the dataset is deep-copied without touching element values first
   ("direct copy" while still fully lazy).
4. A third copy is prepared while lazy and its source file is disconnected
   *before* commit. Preparation either fails closed (if the source was already
   gone) or produces a self-contained prepared dataset that survives the move.
5. Every produced file is re-opened from disk and checked against the explicit
   allow-list: approved attributes survive, identity/private/nested PHI is gone,
   UIDs are re-mapped, pixel data is retained.
6. Failed attempts are inspected to prove they leave no file that could be
   mistaken for an official output.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
from pathlib import Path

os.environ.setdefault("HOME", os.path.join(os.environ["TMPDIR"], "fakehome"))

import pydicom  # noqa: E402
from pydicom.dataelem import RawDataElement  # noqa: E402
from pydicom.tag import Tag  # noqa: E402

from deid_export.core import (  # noqa: E402
    BLOCKED_TAGS,
    DeidentificationStrategy,
    SourceUnavailableError,
    export_deidentified,
    prepare_deidentified,
)
from demo.build_samples import main as build_samples  # noqa: E402

FORBIDDEN_VALUES = (
    "Bogus",
    "FAKE-PID",
    "PRIVATE-MRN",
    "Synthetic General",
    "19900101",
    "19910203",
)


def section(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def assert_true(condition: bool, message: str, results: list) -> None:
    status = "PASS" if condition else "FAIL"
    results.append({"check": message, "status": status})
    print(f"[{status}] {message}")
    if not condition:
        raise AssertionError(message)


def reopen_and_verify(path: Path, original: pydicom.Dataset, strategy, results):
    """Re-open the actual shipped file and validate the de-identification."""
    assert_true(path.exists(), f"official output exists: {path.name}", results)
    shipped = pydicom.dcmread(str(path))

    # No blocked identity tag and no private (odd group) element remains.
    remaining_blocked = [Tag(t) for t in shipped._dict if Tag(t) in BLOCKED_TAGS]
    assert_true(
        not remaining_blocked, f"{path.name}: no blocked identity tags remain", results
    )
    private = [t for t in shipped._dict if Tag(t).group % 2 == 1]
    assert_true(not private, f"{path.name}: no private elements remain", results)

    # Every surviving top-level tag is on the explicit approval list.
    unapproved = [Tag(t) for t in shipped._dict if not strategy.allows(Tag(t))]
    assert_true(
        not unapproved,
        f"{path.name}: every tag is explicitly approved {[str(t) for t in unapproved]}",
        results,
    )

    # No original identifier string leaks anywhere in the encoded values.
    blob = "\n".join(str(e.value) for e in shipped).encode("utf-8", "ignore")
    leaked = [v for v in FORBIDDEN_VALUES if v.encode() in blob]
    assert_true(
        not leaked, f"{path.name}: no original identifier strings leak", results
    )

    # UIDs were re-mapped (different values) but stay internally consistent.
    assert_true(
        shipped.SOPInstanceUID != original.SOPInstanceUID,
        f"{path.name}: SOP Instance UID re-mapped",
        results,
    )
    assert_true(
        shipped.StudyInstanceUID != original.StudyInstanceUID,
        f"{path.name}: Study Instance UID re-mapped",
        results,
    )
    assert_true(
        shipped.file_meta.MediaStorageSOPInstanceUID == shipped.SOPInstanceUID,
        f"{path.name}: file-meta and dataset SOP UIDs stay consistent",
        results,
    )

    # Retained, non-identifying content is byte-identical.
    assert_true(
        bytes(shipped.PixelData) == bytes(original.PixelData),
        f"{path.name}: pixel data retained verbatim",
        results,
    )
    assert_true(
        shipped.Modality == original.Modality,
        f"{path.name}: approved technical attribute (Modality) retained",
        results,
    )
    assert_true(
        shipped.PatientSex == "M",
        f"{path.name}: non-identifying attribute (PatientSex) retained",
        results,
    )

    # De-identification module stamped.
    assert_true(
        shipped.PatientIdentityRemoved == "YES",
        f"{path.name}: PatientIdentityRemoved == YES",
        results,
    )
    assert_true(
        bool(shipped.DeidentificationMethod),
        f"{path.name}: DeidentificationMethod stamped",
        results,
    )
    return shipped


def main() -> dict:
    results: list = []
    root = Path(os.environ["VERIFY_DIR"])
    if root.exists():
        shutil.rmtree(root)
    source_dir = root / "sources"
    output_dir = root / "exports"
    quarantine = root / "quarantine"
    output_dir.mkdir(parents=True)
    quarantine.mkdir(parents=True)

    sample_a_path, sample_b_path = build_samples(source_dir)
    strategy = DeidentificationStrategy.review_export()

    section("Scenario 1/2: read (partially accessed) then deep-copy, export A")
    lazy_a = pydicom.dcmread(str(sample_a_path), defer_size=1)
    assert_true(
        all(isinstance(e, RawDataElement) for e in lazy_a._dict.values()),
        "sample A loads with deferred (raw) elements",
        results,
    )
    # Access one element up front: it converts to a native DataElement while
    # the rest stay raw - one policy must still cover both kinds at write.
    accessed_name = lazy_a.PatientName
    assert_true(
        not isinstance(lazy_a._dict[Tag(0x00100010)], RawDataElement),
        "PatientName converted to a native element after access",
        results,
    )
    assert_true(
        str(accessed_name) == "Bogus^Alice",
        "accessed element still readable on the controlled side",
        results,
    )
    copy_a = copy.deepcopy(lazy_a)
    raw_in_copy = sum(isinstance(e, RawDataElement) for e in copy_a._dict.values())
    assert_true(
        raw_in_copy > 0,
        f"deep copy keeps {raw_in_copy} deferred elements referencing source",
        results,
    )
    original_a = pydicom.dcmread(str(sample_a_path))
    out_a = output_dir / "sample_a_deid.dcm"
    export_deidentified(copy_a, out_a, strategy)
    reopen_and_verify(out_a, original_a, strategy, results)

    section("Scenario 3: deep-copy a fully lazy dataset, export B")
    lazy_b = pydicom.dcmread(str(sample_b_path), defer_size=1)
    copy_b = copy.deepcopy(lazy_b)
    assert_true(
        all(isinstance(e, RawDataElement) for e in copy_b._dict.values()),
        "sample B copy is still fully deferred before preparation",
        results,
    )
    original_b = pydicom.dcmread(str(sample_b_path))
    out_b = output_dir / "sample_b_deid.dcm"
    export_deidentified(copy_b, out_b, strategy)
    reopen_and_verify(out_b, original_b, strategy, results)

    section("Scenario 4a: prepare fully, then disconnect source before commit")
    lazy_c = pydicom.dcmread(str(sample_a_path), defer_size=1)
    prepared_c = prepare_deidentified(lazy_c, strategy)
    assert_true(
        prepared_c.dataset.filename is None,
        "prepared dataset detaches its source filename",
        results,
    )
    shutil.move(str(sample_a_path), quarantine / sample_a_path.name)
    assert_true(
        not sample_a_path.exists(), "source A moved away after prepare", results
    )
    out_c = output_dir / "sample_a_prepared_then_moved.dcm"
    prepared_c.commit(out_c)  # must succeed: all values already resolved
    reopen_and_verify(out_c, original_a, strategy, results)

    section("Scenario 4b: disconnect a still-lazy source, then attempt export")
    lazy_d = pydicom.dcmread(str(sample_b_path), defer_size=1)
    # The controlled side materializes one attribute it legitimately needs
    # before the source is disconnected; that native value must stay usable.
    controlled_modality = str(lazy_d.Modality)
    assert_true(
        not isinstance(lazy_d._dict[Tag(0x00080060)], RawDataElement),
        "controlled-side Modality materialized before disconnect",
        results,
    )
    shutil.move(str(sample_b_path), quarantine / sample_b_path.name)
    assert_true(
        not sample_b_path.exists(), "source B moved away while still lazy", results
    )
    out_d = output_dir / "sample_b_must_not_exist.dcm"
    failure_record: dict = {"output_attempted": str(out_d)}
    try:
        export_deidentified(lazy_d, out_d, strategy)
        failure_record["raised"] = None
        assert_true(False, "export of a dangling lazy dataset must fail", results)
    except SourceUnavailableError as exc:
        failure_record["raised"] = type(exc).__name__
        failure_record["message"] = str(exc).splitlines()[0]
        assert_true(True, "dangling lazy export raises SourceUnavailableError", results)
    # The controlled side keeps using attributes it already resolved itself.
    assert_true(
        str(lazy_d.Modality) == controlled_modality == "OT",
        "controlled side can still read already-converted attributes",
        results,
    )
    # No official output and no leftover temp/partial file may exist.
    assert_true(
        not out_d.exists(), "failed attempt leaves no official output file", results
    )
    leftovers = sorted(
        p.name
        for p in output_dir.iterdir()
        if p.name.startswith(".") or p.name.endswith(".part")
    )
    assert_true(
        not leftovers,
        f"failed attempt leaves no temp/partial files {leftovers}",
        results,
    )
    failure_record["official_output_present"] = out_d.exists()
    failure_record["partial_files"] = leftovers

    section("Scenario 5: caller datasets are never mutated by the pipeline")
    # copy_b was the export input; re-read its still-lazy source and confirm the
    # in-memory object retains its original identity element and raw entries.
    assert_true(
        sum(isinstance(e, RawDataElement) for e in copy_b._dict.values()) > 0,
        "input copy keeps its deferred entries after export",
        results,
    )
    restored_b = pydicom.dcmread(str(quarantine / sample_b_path.name))
    assert_true(
        str(restored_b.PatientName) == "Bogus^Bob",
        "source file on disk keeps its original (un-exported) identity",
        results,
    )

    section("Summary")
    passed = sum(1 for r in results if r["status"] == "PASS")
    print(f"{passed}/{len(results)} checks passed")
    report = {
        "checks": results,
        "failure_attempt": failure_record,
        "exports": sorted(p.name for p in output_dir.glob("*.dcm")),
    }
    (root / "verification_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"report written to {root / 'verification_report.json'}")
    return report


if __name__ == "__main__":
    os.environ.setdefault(
        "VERIFY_DIR", os.path.join(os.environ["TMPDIR"], "deid-verification")
    )
    main()
