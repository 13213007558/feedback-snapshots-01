"""Forensic regression tests for DICOM transfer-syntax transcoding.

These tests prove, on fully synthetic de-identified material, that a real
encoding rewrite took place and that the resulting evidence only exposes an
approved set of field categories and summaries.

The evidence model deliberately distinguishes a *completed* transcode from an
*interrupted* one even though both records carry the same SOP Instance UID:

* the completed record is backed by a file produced through real ``write()``
  calls and re-opened from disk, with every emitted byte accounted for;
* the interrupted record only proves that a rewrite was attempted: it keeps the
  same file meta information but no conformant product exists.
"""

from __future__ import annotations

import hashlib
import json
import warnings
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np
import pytest

import pydicom
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.errors import InvalidDicomError
from pydicom.filewriter import dcmwrite
from pydicom.uid import (
    ExplicitVRLittleEndian,
    PYDICOM_IMPLEMENTATION_UID,
    RLELossless,
    generate_uid,
)

# Same instance number is shared on purpose: the evidence outcome must differ
# even though the records describe the same DICOM instance.
FORENSIC_SOP_INSTANCE_UID = "1.2.840.10008.12345.7558.128.1"
FORENSIC_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.7"

# Fixed abort point inside the File Meta Information region (the first dataset
# element starts later), so the interrupted artefact cannot be re-opened.
INTERRUPT_AFTER_BYTES = 256

# Categories an examiner is allowed to cite in a public-facing report.
APPROVED_CATEGORIES = frozenset(
    {
        "case_id",
        "sop_instance_uid",
        "transfer_syntax",
        "encoding_flags",
        "byte_provenance",
        "outcome",
        "summary",
        "categories",
    }
)

# Outcomes are controlled vocabulary, never free-form narratives.
OUTCOME_COMPLETED = "completed"
OUTCOME_INTERRUPTED = "interrupted"


class TranscodeInterrupted(IOError):
    """Raised by a recording target once its byte budget is exhausted."""


@pytest.fixture(scope="module")
def synthetic_case(tmp_path_factory) -> dict[str, object]:
    """Build a synthetic, de-identified DICOM instance on disk.

    All identifiers are generated for the test and the pixel data is a
    deterministic numeric pattern, so the material contains no patient data.
    """
    workdir = tmp_path_factory.mktemp("forensic_transcode")
    rows = columns = 16

    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = FORENSIC_SOP_CLASS_UID
    file_meta.MediaStorageSOPInstanceUID = FORENSIC_SOP_INSTANCE_UID
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    file_meta.ImplementationClassUID = PYDICOM_IMPLEMENTATION_UID

    ds = Dataset()
    ds.file_meta = file_meta
    ds.SOPClassUID = FORENSIC_SOP_CLASS_UID
    ds.SOPInstanceUID = FORENSIC_SOP_INSTANCE_UID
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.Modality = "OT"
    ds.Rows = rows
    ds.Columns = columns
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.BitsAllocated = 16
    ds.BitsStored = 16
    ds.HighBit = 15
    ds.PixelRepresentation = 0

    pixels = (np.arange(rows * columns, dtype=np.uint16) * 7).reshape(
        rows, columns
    )
    ds.PixelData = pixels.tobytes()

    source_path = workdir / "synthetic_source.dcm"
    # Real write call to disk, enforcing the DICOM File Format.
    dcmwrite(source_path, ds, enforce_file_format=True)

    return {
        "workdir": workdir,
        "source_path": source_path,
        "pixels": pixels,
        "rows": rows,
        "columns": columns,
    }


@dataclass
class TranscriptChunk:
    """One observable ``write()`` call against the recording target."""

    index: int
    offset: int
    length: int
    sha256: str


@dataclass
class EvidenceRecord:
    """Approved evidence schema; only these categories may be published."""

    case_id: str
    sop_instance_uid: str
    transfer_syntax: dict[str, str]
    encoding_flags: dict[str, bool]
    byte_provenance: dict[str, object]
    outcome: str
    summary: str
    categories: list[str] = field(
        default_factory=lambda: sorted(APPROVED_CATEGORIES)
    )

    def __post_init__(self) -> None:
        if self.outcome not in (OUTCOME_COMPLETED, OUTCOME_INTERRUPTED):
            raise ValueError(f"Unknown evidence outcome: {self.outcome!r}")
        if set(self.categories) - APPROVED_CATEGORIES:
            raise ValueError("Evidence record contains an unapproved category")

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)


class RecordingTarget:
    """File-like write target that records every byte it accepts.

    The same class backs both forensic scenarios:

    * with ``byte_limit=None`` it lets the whole transcode finish;
    * with a finite ``byte_limit`` it raises :class:`TranscodeInterrupted`
      mid-stream while preserving the bytes already written to disk.
    """

    def __init__(self, path: str | Path, byte_limit: int | None = None) -> None:
        self._path = Path(path)
        self._byte_limit = byte_limit
        # A real, re-openable OS file handle; no in-memory fakes.
        self._handle = self._path.open("wb")
        self._closed = False
        self.transcript: list[TranscriptChunk] = []
        self.bytes_accepted = 0

    def write(self, data: bytes | bytearray | memoryview) -> int:
        payload = bytes(data)
        if self._byte_limit is not None:
            remaining = self._byte_limit - self.bytes_accepted
            if remaining <= 0:
                raise TranscodeInterrupted(
                    f"Byte budget of {self._byte_limit} bytes already exhausted"
                )
            payload = payload[:remaining]

        offset = self._handle.tell()
        written = self._handle.write(payload)
        self._handle.flush()
        self.bytes_accepted = max(self.bytes_accepted, offset + written)
        self.transcript.append(
            TranscriptChunk(
                index=len(self.transcript),
                offset=offset,
                length=written,
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        )

        if (
            self._byte_limit is not None
            and self.bytes_accepted >= self._byte_limit
        ):
            # Preserve everything accepted so far before signalling failure.
            self.close()
            raise TranscodeInterrupted(
                f"Interrupted after {self.bytes_accepted} of "
                f"{self._byte_limit} budgeted bytes"
            )
        return written

    def flush(self) -> None:
        if not self._closed:
            self._handle.flush()

    def tell(self) -> int:
        return self._handle.tell()

    def seek(self, offset: int, whence: int = 0) -> int:
        # Delegate to the real OS handle so length-backfill seeks work too.
        return self._handle.seek(offset, whence)

    def close(self) -> None:
        if not self._closed:
            self._handle.flush()
            self._handle.close()
            self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed

    def transcript_bytes(self) -> bytes:
        """Re-read the on-disk artefact rather than trusting in-memory state."""
        if not self._closed:
            self.close()
        return self._path.read_bytes()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def contiguous_offsets(chunks: list[TranscriptChunk]) -> list[tuple[int, int]]:
    """Return expected (offset, chunk-index) pairs for a sequential stream.

    The transcoded write is append-only (no sequence length backfill), so the
    recorded chunks must tile the stream without gaps or overlaps.
    """
    offset = 0
    pairs: list[tuple[int, int]] = []
    for chunk in chunks:
        pairs.append((offset, chunk.index))
        offset += chunk.length
    return pairs


def transcode_to_rle(source_path: Path) -> Dataset:
    """Load, re-encode to RLE Lossless and keep the original instance UID."""
    ds = pydicom.dcmread(source_path)
    ds.compress(RLELossless, generate_instance_uid=False)
    return ds


def write_completed_product(product_ds: Dataset, product_path: Path):
    """Run the full transcode write against a recording target."""
    target = RecordingTarget(product_path)
    product_ds.save_as(target, enforce_file_format=True)
    target.close()
    return target


def write_interrupted_product(product_ds: Dataset, interrupted_path: Path):
    """Abort the write once INTERRUPT_AFTER_BYTES have been accepted."""
    target = RecordingTarget(
        interrupted_path, byte_limit=INTERRUPT_AFTER_BYTES
    )
    with pytest.raises(TranscodeInterrupted):
        product_ds.save_as(target, enforce_file_format=True)
    assert target.closed is True
    return target


def build_public_report(records: list[EvidenceRecord]) -> str:
    """Render a report that only references approved categories/summaries."""
    lines = ["FORENSIC TRANSCODING REPORT", "=" * 30]
    for record in records:
        unapproved = set(asdict(record)) - APPROVED_CATEGORIES
        if unapproved:
            raise ValueError(
                f"Refusing to publish unapproved categories: {sorted(unapproved)}"
            )
        lines.append("")
        lines.append(f"case_id: {record.case_id}")
        lines.append(f"sop_instance_uid: {record.sop_instance_uid}")
        lines.append(
            "transfer_syntax: "
            f"{record.transfer_syntax['source']} -> "
            f"{record.transfer_syntax['product']}"
        )
        flags = record.encoding_flags
        lines.append(
            "encoding_flags: "
            f"implicit_vr={flags['product_implicit_vr']} "
            f"little_endian={flags['product_little_endian']} "
            f"encapsulated={flags['product_encapsulated']}"
        )
        provenance = record.byte_provenance
        lines.append(
            "byte_provenance: "
            f"chunks={provenance['chunks_emitted']} "
            f"bytes={provenance['bytes_emitted']} "
            f"sha256={provenance['stream_sha256']}"
        )
        lines.append(f"outcome: {record.outcome}")
        lines.append(f"summary: {record.summary}")
    return "\n".join(lines) + "\n"


def test_completed_transcode_is_proven_by_real_write_and_reopen(
    synthetic_case,
) -> None:
    source_path: Path = synthetic_case["source_path"]
    workdir: Path = synthetic_case["workdir"]
    pixels: np.ndarray = synthetic_case["pixels"]

    # --- Source encoding, observed by re-opening the original file ---
    source = pydicom.dcmread(source_path)
    assert source.file_meta.TransferSyntaxUID == ExplicitVRLittleEndian
    assert source.is_implicit_VR is False
    assert source.is_little_endian is True
    source_bytes = source_path.read_bytes()
    assert source_bytes[128:132] == b"DICM"

    # --- Transcode to the selected output encoding ---
    product_ds = transcode_to_rle(source_path)
    assert product_ds.file_meta.TransferSyntaxUID == RLELossless
    assert product_ds.SOPInstanceUID == FORENSIC_SOP_INSTANCE_UID

    product_path = workdir / "product_rle.dcm"
    target = write_completed_product(product_ds, product_path)

    # --- Re-open the finished product from disk ---
    product = pydicom.dcmread(product_path)
    assert product.file_meta.TransferSyntaxUID == RLELossless
    assert product.file_meta.TransferSyntaxUID.is_encapsulated is True
    assert product.is_implicit_VR is False
    assert product.is_little_endian is True
    assert np.array_equal(product.pixel_array, pixels)

    # The instance identifier survives the rewrite unchanged.
    assert product.SOPInstanceUID == source.SOPInstanceUID
    assert (
        product.file_meta.MediaStorageSOPInstanceUID
        == source.file_meta.MediaStorageSOPInstanceUID
    )

    # --- Byte provenance: transcript chunks reconcile to the final file ---
    on_disk = product_path.read_bytes()
    reassembled = target.transcript_bytes()
    assert reassembled == on_disk
    assert target.bytes_accepted == len(on_disk)
    assert sum(chunk.length for chunk in target.transcript) == len(on_disk)
    for expected_offset, chunk_index in contiguous_offsets(target.transcript):
        assert target.transcript[chunk_index].offset == expected_offset

    # A real encoding rewrite happened: identical pixel content, different
    # on-disk bytes and transfer syntax from the source.
    assert digest(on_disk) != digest(source_bytes)
    assert on_disk[128:132] == b"DICM"

    record = EvidenceRecord(
        case_id="FB-7558-128-COMPLETED",
        sop_instance_uid=FORENSIC_SOP_INSTANCE_UID,
        transfer_syntax={
            "source": str(ExplicitVRLittleEndian),
            "product": str(RLELossless),
        },
        encoding_flags={
            "source_implicit_vr": source.is_implicit_VR,
            "source_little_endian": source.is_little_endian,
            "product_implicit_vr": product.is_implicit_VR,
            "product_little_endian": product.is_little_endian,
            "product_encapsulated": (
                product.file_meta.TransferSyntaxUID.is_encapsulated
            ),
        },
        byte_provenance={
            "chunks_emitted": len(target.transcript),
            "bytes_emitted": target.bytes_accepted,
            "stream_sha256": digest(on_disk),
            "source_sha256": digest(source_bytes),
            "transcript_matches_disk": reassembled == on_disk,
        },
        outcome=OUTCOME_COMPLETED,
        summary=(
            "RLE Lossless rewrite completed; product re-opened from disk and "
            "all emitted bytes reconcile to the final file"
        ),
    )
    evidence_path = workdir / "evidence_completed.json"
    evidence_path.write_text(record.to_json())
    persisted = json.loads(evidence_path.read_text())
    assert persisted["outcome"] == OUTCOME_COMPLETED
    assert set(persisted) - APPROVED_CATEGORIES == set()


def test_interrupted_transcode_only_proves_an_attempt(synthetic_case) -> None:
    source_path: Path = synthetic_case["source_path"]
    workdir: Path = synthetic_case["workdir"]

    # Reference product from a full write, using the same file meta info.
    reference_ds = transcode_to_rle(source_path)
    product_path = workdir / "reference_rle.dcm"
    write_completed_product(reference_ds, product_path)
    full_stream = product_path.read_bytes()

    # A second write of the same instance is cut off mid-stream.
    interrupted_ds = transcode_to_rle(source_path)
    interrupted_path = workdir / "interrupted_rle.dcm"
    target = write_interrupted_product(interrupted_ds, interrupted_path)

    # The partial stream is a strict prefix of what a full write emits.
    partial_on_disk = interrupted_path.read_bytes()
    assert len(partial_on_disk) == INTERRUPT_AFTER_BYTES
    assert target.bytes_accepted == INTERRUPT_AFTER_BYTES
    assert full_stream.startswith(partial_on_disk)
    assert len(partial_on_disk) < len(full_stream)

    # The recorded chunks are exactly the bytes that entered the partial file.
    assert target.transcript_bytes() == partial_on_disk
    for expected_offset, chunk_index in contiguous_offsets(target.transcript):
        chunk = target.transcript[chunk_index]
        assert chunk.offset == expected_offset
        assert (
            chunk.sha256
            == digest(
                partial_on_disk[chunk.offset : chunk.offset + chunk.length]
            )
        )

    # The partial artefact keeps the same file meta information but cannot be
    # re-opened as a conformant, pixel-bearing DICOM product.
    assert partial_on_disk[128:132] == b"DICM"
    reopen_proves_failure = False
    with warnings.catch_warnings(record=True) as reopen_warnings:
        warnings.simplefilter("always")
        try:
            partial_ds = pydicom.dcmread(interrupted_path)
        except InvalidDicomError:
            # Strict failure: the truncated stream is not a DICOM file at all.
            reopen_proves_failure = True
        else:
            # Lenient parse: the incomplete dataset cannot yield pixel data,
            # either because PixelData is absent or its codestream is broken.
            with pytest.raises((AttributeError, NotImplementedError, OSError)):
                partial_ds.pixel_array
            reopen_proves_failure = True
    assert reopen_proves_failure is True
    # Reading the malformed/truncated UID bytes must surface a recorded warning.
    assert any(issubclass(w.category, UserWarning) for w in reopen_warnings)

    record = EvidenceRecord(
        case_id="FB-7558-128-INTERRUPTED",
        sop_instance_uid=FORENSIC_SOP_INSTANCE_UID,
        transfer_syntax={
            "source": str(ExplicitVRLittleEndian),
            "product": str(RLELossless),
        },
        encoding_flags={
            "source_implicit_vr": False,
            "source_little_endian": True,
            "product_implicit_vr": False,
            "product_little_endian": True,
            "product_encapsulated": True,
        },
        byte_provenance={
            "chunks_emitted": len(target.transcript),
            "bytes_emitted": target.bytes_accepted,
            "byte_limit": INTERRUPT_AFTER_BYTES,
            "stream_sha256": digest(partial_on_disk),
            "partial_sha256": digest(partial_on_disk),
            "is_prefix_of_completed_stream": full_stream.startswith(
                partial_on_disk
            ),
        },
        outcome=OUTCOME_INTERRUPTED,
        summary=(
            "RLE Lossless rewrite attempted and interrupted after a partial "
            "write; no conformant product exists and the record proves an "
            "attempt only"
        ),
    )
    evidence_path = workdir / "evidence_interrupted.json"
    evidence_path.write_text(record.to_json())
    persisted = json.loads(evidence_path.read_text())
    assert persisted["outcome"] == OUTCOME_INTERRUPTED
    assert set(persisted) - APPROVED_CATEGORIES == set()


def test_same_instance_records_yield_distinct_evidence_and_safe_report(
    synthetic_case,
) -> None:
    source_path: Path = synthetic_case["source_path"]
    workdir: Path = synthetic_case["workdir"]

    # Independently reproduce both records for the same instance number.
    full_ds = transcode_to_rle(source_path)
    product_path = workdir / "report_product_rle.dcm"
    full_target = write_completed_product(full_ds, product_path)
    full_bytes = product_path.read_bytes()
    product = pydicom.dcmread(product_path)

    interrupted_ds = transcode_to_rle(source_path)
    interrupted_path = workdir / "report_interrupted_rle.dcm"
    interrupted_target = write_interrupted_product(
        interrupted_ds, interrupted_path
    )
    partial_bytes = interrupted_path.read_bytes()

    completed = EvidenceRecord(
        case_id="FB-7558-128-COMPLETED",
        sop_instance_uid=FORENSIC_SOP_INSTANCE_UID,
        transfer_syntax={
            "source": str(ExplicitVRLittleEndian),
            "product": str(RLELossless),
        },
        encoding_flags={
            "source_implicit_vr": False,
            "source_little_endian": True,
            "product_implicit_vr": product.is_implicit_VR,
            "product_little_endian": product.is_little_endian,
            "product_encapsulated": (
                product.file_meta.TransferSyntaxUID.is_encapsulated
            ),
        },
        byte_provenance={
            "chunks_emitted": len(full_target.transcript),
            "bytes_emitted": full_target.bytes_accepted,
            "stream_sha256": digest(full_bytes),
            "source_sha256": digest(source_path.read_bytes()),
            "transcript_matches_disk": full_target.transcript_bytes()
            == full_bytes,
        },
        outcome=OUTCOME_COMPLETED,
        summary=(
            "RLE Lossless rewrite completed; product re-opened from disk and "
            "all emitted bytes reconcile to the final file"
        ),
    )
    interrupted = EvidenceRecord(
        case_id="FB-7558-128-INTERRUPTED",
        sop_instance_uid=FORENSIC_SOP_INSTANCE_UID,
        transfer_syntax={
            "source": str(ExplicitVRLittleEndian),
            "product": str(RLELossless),
        },
        encoding_flags={
            "source_implicit_vr": False,
            "source_little_endian": True,
            "product_implicit_vr": False,
            "product_little_endian": True,
            "product_encapsulated": True,
        },
        byte_provenance={
            "chunks_emitted": len(interrupted_target.transcript),
            "bytes_emitted": interrupted_target.bytes_accepted,
            "byte_limit": INTERRUPT_AFTER_BYTES,
            "stream_sha256": digest(partial_bytes),
            "partial_sha256": digest(partial_bytes),
            "is_prefix_of_completed_stream": full_bytes.startswith(
                partial_bytes
            ),
        },
        outcome=OUTCOME_INTERRUPTED,
        summary=(
            "RLE Lossless rewrite attempted and interrupted after a partial "
            "write; no conformant product exists and the record proves an "
            "attempt only"
        ),
    )

    # Same instance number, opposite evidentiary conclusions.
    assert completed.sop_instance_uid == interrupted.sop_instance_uid
    assert completed.outcome != interrupted.outcome
    assert (
        completed.byte_provenance["stream_sha256"]
        != interrupted.byte_provenance["stream_sha256"]
    )
    assert completed.byte_provenance["bytes_emitted"] > (
        interrupted.byte_provenance["bytes_emitted"]
    )
    assert completed.byte_provenance["transcript_matches_disk"] is True
    assert (
        interrupted.byte_provenance["is_prefix_of_completed_stream"] is True
    )

    # The public report references approved categories and summaries only.
    report = build_public_report([completed, interrupted])
    for category in (
        "outcome",
        "summary",
        "byte_provenance",
        "transfer_syntax",
        "encoding_flags",
    ):
        assert category in report
    # Raw pixel data and file-system paths never appear in the report.
    for forbidden in ("PixelData", "synthetic_source", ".dcm"):
        assert forbidden not in report

    report_path = workdir / "public_report.txt"
    report_path.write_text(report)
    published = report_path.read_text()
    assert "outcome: completed" in published
    assert "outcome: interrupted" in published
    assert "no conformant product exists" in published
