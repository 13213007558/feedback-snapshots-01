"""Synthetic FileSet classification and downstream handoff checks.

This module is both a pytest regression and a runnable scenario::

    .venv/bin/python tests/test_synthetic_archive_handoff.py --output ./handoff-run

All patient, study, UID, and pixel values are generated in memory and are
intentionally synthetic.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from pydicom import dcmread
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.fileset import FileSet
from pydicom.uid import (
    CTImageStorage,
    ExplicitVRLittleEndian,
    generate_uid,
)


PUBLIC_CLASSIFICATION = "PUBLIC-SYNTHETIC-7558"
INDEX_CLASSIFICATION_BEFORE = "INDEX-RESTRICTED-SYNTHETIC-7558"
INSTANCE_CLASSIFICATION_BEFORE = "INSTANCE-INTERNAL-SYNTHETIC-7558"

INSTANCE_PRIVATE_GROUP = 0x0041
INSTANCE_PRIVATE_CREATOR = "SYNTHETIC.HANDOFF.INSTANCE"
INDEX_PRIVATE_GROUP = 0x0047
INDEX_PRIVATE_CREATOR = "SYNTHETIC.HANDOFF.INDEX"

PUBLIC_INSTANCE_FIELDS = frozenset(
    {
        "SOPClassUID",
        "SOPInstanceUID",
        "ConfidentialityCode",
        "PatientID",
        "StudyDate",
        "StudyTime",
        "StudyInstanceUID",
        "StudyID",
        "Modality",
        "SeriesInstanceUID",
        "SeriesNumber",
        "InstanceNumber",
        "ImageType",
        "SamplesPerPixel",
        "PhotometricInterpretation",
        "Rows",
        "Columns",
        "BitsAllocated",
        "BitsStored",
        "HighBit",
        "PixelRepresentation",
        "PixelData",
    }
)

FORBIDDEN_PUBLIC_FIELDS = frozenset(
    {
        "PatientName",
        "PatientBirthDate",
        "AccessionNumber",
        "StudyDescription",
    }
)

FIELD_COMPARISONS = (
    ("IMAGE", "ReferencedSOPInstanceUIDInFile", "SOPInstanceUID"),
    ("IMAGE", "ReferencedSOPClassUIDInFile", "SOPClassUID"),
    ("IMAGE", "ReferencedTransferSyntaxUIDInFile", "__TransferSyntaxUID__"),
    ("PATIENT", "PatientID", "PatientID"),
    ("STUDY", "StudyInstanceUID", "StudyInstanceUID"),
    ("STUDY", "StudyDate", "StudyDate"),
    ("SERIES", "SeriesInstanceUID", "SeriesInstanceUID"),
    ("SERIES", "Modality", "Modality"),
    ("IMAGE", "InstanceNumber", "InstanceNumber"),
)


class HandoffBlockedError(RuntimeError):
    """Raised when a written handoff fails the public-scope audit."""

    def __init__(self, audit: HandoffAudit) -> None:
        self.audit = audit
        super().__init__("; ".join(audit.violations))


@dataclass
class HandoffAudit:
    """Result of reopening and auditing a written FileSet."""

    root: Path
    expected_classification: str
    violations: list[str] = field(default_factory=list)
    references: list[dict[str, str]] = field(default_factory=list)
    instance_fields: list[list[str]] = field(default_factory=list)
    index_fields: list[dict[str, list[str]]] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.violations

    def summary(self) -> dict[str, Any]:
        result = asdict(self)
        result["root"] = os.fspath(self.root)
        result["passed"] = self.passed
        return result


def make_synthetic_instance(item_number: int = 1) -> Dataset:
    """Create one minimal CT instance containing no real-world data."""
    sop_uid = generate_uid()
    study_uid = generate_uid()
    series_uid = generate_uid()

    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = CTImageStorage
    file_meta.MediaStorageSOPInstanceUID = sop_uid
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian

    ds = Dataset()
    ds.file_meta = file_meta
    ds.SOPClassUID = CTImageStorage
    ds.SOPInstanceUID = sop_uid

    ds.PatientID = f"SYN-PAT-7558-{item_number}"
    ds.PatientName = "SYNTHETIC^PRIVATE_NAME"
    ds.PatientBirthDate = "19000101"

    ds.StudyDate = "20261125"
    ds.StudyTime = "120000"
    ds.StudyID = f"SYN-ST-{item_number}-7558"
    ds.AccessionNumber = "SYN-ACC-7558"
    ds.StudyDescription = "SYNTHETIC PRIVATE STUDY SUMMARY"
    ds.StudyInstanceUID = study_uid

    ds.Modality = "CT"
    ds.SeriesInstanceUID = series_uid
    ds.SeriesNumber = item_number
    ds.InstanceNumber = item_number
    ds.ImageType = ["ORIGINAL", "PRIMARY", "AXIAL"]

    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.Rows = 2
    ds.Columns = 2
    ds.BitsAllocated = 8
    ds.BitsStored = 8
    ds.HighBit = 7
    ds.PixelRepresentation = 0
    ds.PixelData = bytes((0, 1, 2, 3))

    ds.ConfidentialityCode = INSTANCE_CLASSIFICATION_BEFORE
    block = ds.private_block(
        INSTANCE_PRIVATE_GROUP, INSTANCE_PRIVATE_CREATOR, create=True
    )
    block.add_new(0x10, "LO", "SYNTHETIC-PRIVATE-INSTANCE-NOTE")

    return ds


def build_classified_fileset(item_count: int = 1) -> FileSet:
    """Build a FileSet with deliberately different index/instance labels."""
    fileset = FileSet()

    for item_number in range(1, item_count + 1):
        instance = fileset.add(make_synthetic_instance(item_number))

        leaf_record = instance.node._record
        leaf_record.ConfidentialityCode = INDEX_CLASSIFICATION_BEFORE
        index_block = leaf_record.private_block(
            INDEX_PRIVATE_GROUP, INDEX_PRIVATE_CREATOR, create=True
        )
        index_block.add_new(0x10, "LO", "SYNTHETIC-PRIVATE-INDEX-SUMMARY")

    return fileset


def apply_public_scope(source: Dataset) -> Dataset:
    """Return an allowlisted public projection of one instance."""
    public_meta = FileMetaDataset()
    public_meta.MediaStorageSOPClassUID = source.SOPClassUID
    public_meta.MediaStorageSOPInstanceUID = source.SOPInstanceUID
    public_meta.TransferSyntaxUID = ExplicitVRLittleEndian

    public = Dataset()
    public.file_meta = public_meta

    for keyword in PUBLIC_INSTANCE_FIELDS:
        if keyword == "ConfidentialityCode":
            continue
        if keyword in source:
            public.add(copy.deepcopy(source[keyword]))

    public.ConfidentialityCode = PUBLIC_CLASSIFICATION
    return public


def build_public_fileset(
    source: FileSet, *, leak_private_index: bool = False
) -> FileSet:
    """Project source instances to the new public classification.

    The faulty mode models an index summary that was relabelled but not
    re-projected. Its instance content is clean; its DICOMDIR record is not.
    """
    published = FileSet()

    for item_index, source_instance in enumerate(source):
        public_instance = apply_public_scope(source_instance.load())
        handed_off = published.add(public_instance)
        leaf_record = handed_off.node._record
        leaf_record.ConfidentialityCode = PUBLIC_CLASSIFICATION

        for node in handed_off.node.reverse():
            for keyword in FORBIDDEN_PUBLIC_FIELDS:
                if keyword in node._record:
                    del node._record[keyword]

        if leak_private_index and item_index == 0:
            index_block = leaf_record.private_block(
                INDEX_PRIVATE_GROUP, INDEX_PRIVATE_CREATOR, create=True
            )
            index_block.add_new(0x10, "LO", "STALE-PRIVATE-INDEX-SUMMARY")

            patient_record = next(
                node._record
                for node in handed_off.node.ancestors
                if node.record_type == "PATIENT"
            )
            patient_record.PatientName = "STALE^PRIVATE_INDEX_NAME"

    return published


def field_names(dataset: Dataset) -> list[str]:
    """Return stable human-readable names for top-level visible elements."""
    return sorted(element.keyword or str(element.tag) for element in dataset)


def audit_dataset(dataset: Dataset, location: str) -> list[str]:
    """Return private-field and forbidden-summary violations."""
    violations: list[str] = []

    def audit_element(current: Dataset, element: Any) -> None:
        if element.tag.is_private:
            violations.append(
                f"{location}: private element {element.tag!r} "
                f"({element.keyword or 'unknown private'}) remains visible"
            )

        keyword = element.keyword or ""
        if keyword in FORBIDDEN_PUBLIC_FIELDS:
            violations.append(f"{location}: non-public field {keyword} is present")

    dataset.walk(audit_element)
    file_meta = getattr(dataset, "file_meta", None)
    if file_meta is not None:
        file_meta.walk(audit_element)

    return violations


def _comparison_value(dataset: Dataset, keyword: str) -> str | None:
    if keyword == "__TransferSyntaxUID__":
        value = getattr(dataset.file_meta, "TransferSyntaxUID", None)
    else:
        value = dataset.get(keyword)
    return None if value is None else str(value)


def audit_written_handoff(
    root: str | os.PathLike[str],
    expected_classification: str = PUBLIC_CLASSIFICATION,
) -> HandoffAudit:
    """Reopen DICOMDIR and referenced instances and audit consistency."""
    root_path = Path(root)
    audit = HandoffAudit(root_path, expected_classification)
    dicomdir_path = root_path / "DICOMDIR"

    if not dicomdir_path.is_file():
        audit.violations.append("target DICOMDIR is missing")
        return audit

    try:
        dicomdir = dcmread(dicomdir_path)
        fileset = FileSet(dicomdir_path)
    except Exception as exc:  # noqa: BLE001 - report any reopen failure
        audit.violations.append(f"unable to reopen FileSet: {exc}")
        return audit

    audit.violations.extend(audit_dataset(dicomdir, "DICOMDIR"))

    for instance in fileset:
        instance_uid = str(instance.SOPInstanceUID)
        location = f"instance {instance_uid}"
        leaf = instance.node._record

        record_by_type: dict[str, Dataset] = {}
        for node in instance.node.reverse():
            record_by_type[node.record_type] = node._record
            audit.violations.extend(
                audit_dataset(node._record, f"DICOMDIR {node.record_type}")
            )

        leaf_classification = leaf.get("ConfidentialityCode")
        if leaf_classification != expected_classification:
            audit.violations.append(
                f"DICOMDIR IMAGE classification is "
                f"{leaf_classification!r}, expected {expected_classification!r}"
            )

        try:
            loaded = instance.load()
        except Exception as exc:  # noqa: BLE001 - audit must continue
            audit.violations.append(
                f"{location}: unable to load referenced file: {exc}"
            )
            continue

        audit.instance_fields.append(field_names(loaded))
        audit.index_fields.append(
            {
                record_type: field_names(record)
                for record_type, record in record_by_type.items()
            }
        )
        audit.violations.extend(audit_dataset(loaded, location))

        if field_names(loaded) != sorted(PUBLIC_INSTANCE_FIELDS):
            missing = sorted(PUBLIC_INSTANCE_FIELDS - set(field_names(loaded)))
            extra = sorted(set(field_names(loaded)) - PUBLIC_INSTANCE_FIELDS)
            audit.violations.append(
                f"{location}: visible fields do not match the public allowlist "
                f"(missing={missing}, extra={extra})"
            )

        instance_classification = loaded.get("ConfidentialityCode")
        if instance_classification != expected_classification:
            audit.violations.append(
                f"{location}: classification is "
                f"{instance_classification!r}, expected {expected_classification!r}"
            )

        file_id = leaf.get("ReferencedFileID")
        if not file_id:
            audit.violations.append("DICOMDIR IMAGE has no ReferencedFileID")
            continue

        parts = [file_id] if isinstance(file_id, str) else list(file_id)
        referenced_path = root_path.joinpath(*parts)
        root_resolved = root_path.resolve()

        try:
            referenced_resolved = referenced_path.resolve(strict=True)
        except (FileNotFoundError, OSError):
            audit.violations.append(
                f"DICOMDIR reference {parts!r} does not resolve to a file"
            )
            continue

        if not referenced_path.is_file():
            audit.violations.append(
                f"DICOMDIR reference {parts!r} is not a regular file"
            )
            continue

        if not referenced_resolved.is_relative_to(root_resolved):
            audit.violations.append(
                f"DICOMDIR reference {parts!r} escapes the handoff root"
            )
            continue

        if Path(instance.path).resolve() != referenced_resolved:
            audit.violations.append(
                "FileInstance.path and ReferencedFileID resolve differently"
            )

        audit.references.append(
            {
                "sop_instance_uid": instance_uid,
                "referenced_file_id": "/".join(parts),
                "path": os.fspath(referenced_resolved),
            }
        )

        for record_type, index_keyword, instance_keyword in FIELD_COMPARISONS:
            record = record_by_type.get(record_type)
            if record is None:
                audit.violations.append(f"DICOMDIR is missing {record_type} record")
                continue

            index_value = _comparison_value(record, index_keyword)
            instance_value = _comparison_value(loaded, instance_keyword)
            if index_value != instance_value:
                audit.violations.append(
                    f"{record_type}.{index_keyword}={index_value!r} does not match "
                    f"instance {instance_keyword}={instance_value!r}"
                )

    return audit


def promote_verified_handoff(
    attempt_root: str | os.PathLike[str],
    downstream_root: str | os.PathLike[str],
    expected_classification: str = PUBLIC_CLASSIFICATION,
) -> HandoffAudit:
    """Move a written attempt downstream only if reopening and audit pass."""
    attempt_path = Path(attempt_root)
    downstream_path = Path(downstream_root)
    audit = audit_written_handoff(attempt_path, expected_classification)

    if not audit.passed:
        raise HandoffBlockedError(audit)

    if downstream_path.exists():
        raise FileExistsError(f"Downstream target already exists: {downstream_path}")

    downstream_path.parent.mkdir(parents=True, exist_ok=True)
    os.replace(attempt_path, downstream_path)

    final_audit = audit_written_handoff(downstream_path, expected_classification)
    if not final_audit.passed:
        raise HandoffBlockedError(final_audit)
    return final_audit


def _write_report(output: Path, audits: dict[str, HandoffAudit]) -> None:
    report = {name: audit.summary() for name, audit in audits.items()}
    (output / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    lines = ["Synthetic FileSet handoff report", "=" * 36]
    for name, audit in audits.items():
        lines.append(f"\n[{name}] root={audit.root}")
        lines.append(f"passed={audit.passed}")
        lines.extend(f"reference={reference}" for reference in audit.references)
        lines.extend(f"violation={violation}" for violation in audit.violations)
    (output / "report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_scenario(output: str | os.PathLike[str]) -> dict[str, HandoffAudit]:
    """Write one blocked failure and one successful handoff under ``output``."""
    output_path = Path(output)
    if output_path.exists():
        raise FileExistsError(f"Refusing to overwrite existing output: {output_path}")
    output_path.mkdir(parents=True)

    source_path = output_path / "source-fileset"
    failed_attempt = output_path / "attempts" / "failed-index-leak"
    failed_downstream = output_path / "downstream" / "blocked-failed-case"
    success_attempt = output_path / "attempts" / "success"
    success_downstream = output_path / "downstream" / "synthetic-public-fileset"

    source = build_classified_fileset()
    source.write(source_path)

    faulty = build_public_fileset(source, leak_private_index=True)
    faulty.write(failed_attempt)
    failed_audit = audit_written_handoff(failed_attempt)
    try:
        promote_verified_handoff(failed_attempt, failed_downstream)
    except HandoffBlockedError as exc:
        failed_audit = exc.audit
    else:
        raise AssertionError("Private DICOMDIR field did not block handoff")

    clean = build_public_fileset(source)
    clean.write(success_attempt)
    success_audit = promote_verified_handoff(success_attempt, success_downstream)

    audits = {"failed_index_leak": failed_audit, "success": success_audit}
    _write_report(output_path, audits)
    return audits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(os.environ.get("TMPDIR", "/tmp"))
        / f"pydicom-synthetic-handoff-{uuid4().hex}",
        help="directory to create with source, attempts, and downstream data",
    )
    args = parser.parse_args(argv)

    audits = run_scenario(args.output)
    print(f"Synthetic FileSet scenario written to: {args.output}")
    for name, audit in audits.items():
        status = "PASS" if audit.passed else "BLOCKED"
        print(f"  {name}: {status} ({audit.root})")
        for violation in audit.violations[:4]:
            print(f"    - {violation}")
    return 0


def test_classifications_are_intentionally_different(tmp_path: Path) -> None:
    source = build_classified_fileset()
    source_root = tmp_path / "source"
    source.write(source_root)

    reopened = FileSet(source_root / "DICOMDIR")
    instance = next(iter(reopened))
    loaded = instance.load()

    assert instance.node._record.ConfidentialityCode == INDEX_CLASSIFICATION_BEFORE
    assert loaded.ConfidentialityCode == INSTANCE_CLASSIFICATION_BEFORE
    assert instance.node._record.ConfidentialityCode != loaded.ConfidentialityCode
    assert audit_dataset(loaded, "source instance")
    assert audit_dataset(instance.node._record, "source index")


def test_clean_content_with_private_index_is_blocked(tmp_path: Path) -> None:
    source = build_classified_fileset()
    faulty = build_public_fileset(source, leak_private_index=True)
    attempt = tmp_path / "failed-attempt"
    faulty.write(attempt)

    audit = audit_written_handoff(attempt)
    reopened = FileSet(attempt / "DICOMDIR")
    item = next(iter(reopened))

    assert audit_dataset(item.load(), "instance") == []
    index_violations = audit_dataset(item.node._record, "IMAGE record")
    assert any("private element" in violation for violation in index_violations)
    assert not audit.passed
    assert any("private element" in violation for violation in audit.violations)

    downstream = tmp_path / "downstream"
    with pytest.raises(HandoffBlockedError):
        promote_verified_handoff(attempt, downstream)
    assert not downstream.exists()
    assert attempt.exists()


def test_one_bad_index_stops_entire_mixed_batch(tmp_path: Path) -> None:
    source = build_classified_fileset(item_count=2)
    mixed = build_public_fileset(source, leak_private_index=True)
    attempt = tmp_path / "mixed-attempt"
    mixed.write(attempt)

    audit = audit_written_handoff(attempt)
    reopened = FileSet(attempt / "DICOMDIR")
    items = list(reopened)

    instance_violations = [audit_dataset(item.load(), "instance") for item in items]
    index_violations = [
        audit_dataset(item.node._record, "IMAGE record") for item in items
    ]

    assert len(items) == 2
    assert all(violations == [] for violations in instance_violations)
    assert sum(not violations for violations in index_violations) == 1
    assert len(audit.references) == 2
    assert not audit.passed

    downstream = tmp_path / "mixed-downstream"
    with pytest.raises(HandoffBlockedError):
        promote_verified_handoff(attempt, downstream)
    assert not downstream.exists()


def test_successful_handoff_reopens_consistent_fields_and_refs(
    tmp_path: Path,
) -> None:
    source = build_classified_fileset()
    clean = build_public_fileset(source)
    attempt = tmp_path / "success-attempt"
    clean.write(attempt)

    downstream = tmp_path / "public-fileset"
    audit = promote_verified_handoff(attempt, downstream)

    assert audit.passed, audit.violations
    assert len(audit.references) == 1
    assert not attempt.exists()
    assert (downstream / "DICOMDIR").is_file()

    reopened = FileSet(downstream / "DICOMDIR")
    item = next(iter(reopened))
    leaf = item.node._record
    loaded = dcmread(downstream / Path(*leaf.ReferencedFileID))

    assert audit_dataset(loaded, "reopened instance") == []
    assert loaded.ConfidentialityCode == PUBLIC_CLASSIFICATION
    assert leaf.ConfidentialityCode == PUBLIC_CLASSIFICATION
    assert field_names(loaded) == sorted(PUBLIC_INSTANCE_FIELDS)
    assert str(loaded.SOPInstanceUID) == str(leaf.ReferencedSOPInstanceUIDInFile)
    assert str(loaded.SOPClassUID) == str(leaf.ReferencedSOPClassUIDInFile)
    assert (
        str(loaded.file_meta.TransferSyntaxUID)
        == leaf.ReferencedTransferSyntaxUIDInFile
    )

    referenced = downstream / Path(*leaf.ReferencedFileID)
    assert referenced.is_file()
    assert Path(item.path).resolve() == referenced.resolve()
    assert item.FileID == Path(*leaf.ReferencedFileID).as_posix()


def test_cli_scenario_creates_blocked_and_successful_outputs(
    tmp_path: Path,
) -> None:
    output = tmp_path / "scenario"
    result = main(["--output", str(output)])

    assert result == 0
    assert (output / "report.json").is_file()
    assert (output / "source-fileset" / "DICOMDIR").is_file()
    assert not (output / "downstream" / "blocked-failed-case").exists()
    assert (output / "downstream" / "synthetic-public-fileset" / "DICOMDIR").is_file()


if __name__ == "__main__":
    raise SystemExit(main())
