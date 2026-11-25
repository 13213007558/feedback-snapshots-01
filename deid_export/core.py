"""Fail-closed de-identification and atomic export built on pydicom.

Design goals (see the task statement):

* The caller must pass one *explicit* :class:`DeidentificationStrategy`. There
  is no implicit default policy and no per-element opt-out: un-expanded
  deferred elements, elements already converted to native values, and elements
  reached through copied datasets are all filtered by the same approval set at
  write time.
* Preparation fully resolves every deferred (lazy) element before any output
  file is opened. If the original file is missing or moved, preparation fails
  loudly with :class:`SourceUnavailableError`; the code never falls back to
  unverified in-memory attributes.
* The finished file is written atomically (temporary file in the destination
  directory, ``os.replace`` only after a clean write). A failure therefore
  never leaves a file that could be mistaken for the official export.
"""

from __future__ import annotations

import copy
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pydicom
from pydicom.dataelem import DataElement, RawDataElement
from pydicom.dataset import Dataset, FileDataset, FileMetaDataset
from pydicom.tag import BaseTag, Tag
from pydicom.uid import generate_uid

# Patient identity attributes (and other direct identifiers) that must never
# survive an export. They are dropped even if a caller mistakenly lists them.
BLOCKED_TAGS: frozenset[BaseTag] = frozenset(
    Tag(t)
    for t in (
        0x00100010,  # Patient's Name
        0x00100020,  # Patient ID
        0x00100030,  # Patient's Birth Date
        0x00100050,  # Patient's Insurance Plan Code ID
        0x00101000,  # Other Patient IDs
        0x00101001,  # Other Patient Names
        0x00101040,  # Patient's Address
        0x00102154,  # Patient's Telephone Numbers
        0x00080080,  # Institution Name
        0x00080081,  # Institution Address
        0x00080090,  # Referring Physician's Name
        0x00081040,  # Institutional Department Name
        0x00081050,  # Performing Physician's Name
        0x00080094,  # Referring Physician's Identification Sequence
        0x0018A003,  # Contribution Description (free text)
        0x0040A170,  # Purpose of Reference Code Sequence (carries nested PHI here)
    )
)

# UID-bearing attributes whose value is replaced by a freshly generated UID.
# A stable per-export map keeps the same source UID mapped to the same new UID
# so referential integrity inside one export is preserved.
UID_TAGS: frozenset[BaseTag] = frozenset(
    Tag(t)
    for t in (
        0x00080018,  # SOP Instance UID
        0x0020000D,  # Study Instance UID
        0x0020000E,  # Series Instance UID
        0x00081155,  # Referenced SOP Instance UID
    )
)

# File Meta Information group (0002) elements that are permitted. The group
# never contains patient identity and is required for a conformant DICOM file.
FILE_META_ALLOWED: frozenset[BaseTag] = frozenset(
    Tag(t)
    for t in (
        0x00020001,  # File Meta Information Version
        0x00020002,  # Media Storage SOP Class UID
        0x00020003,  # Media Storage SOP Instance UID
        0x00020010,  # Transfer Syntax UID
        0x00020012,  # Implementation Class UID
        0x00020013,  # Implementation Version Name
        0x00020016,  # Source Application Entity Title
        0x00020017,  # Sending Application Entity Title
    )
)

# Top-level and sequence attributes approved for the review export. This is an
# *allow-list*: anything not enumerated here (and not an allowed file-meta
# element) is removed, including every private (odd group) element.
APPROVED_TAGS: frozenset[BaseTag] = frozenset(
    Tag(t)
    for t in (
        0x00080016,  # SOP Class UID
        0x00080018,  # SOP Instance UID (re-mapped)
        0x00080060,  # Modality
        0x00080070,  # Manufacturer
        0x00100040,  # Patient's Sex
        0x0020000D,  # Study Instance UID (re-mapped)
        0x0020000E,  # Series Instance UID (re-mapped)
        0x00200010,  # Study ID
        0x00200011,  # Series Number
        0x00200013,  # Instance Number
        0x00280002,  # Samples per Pixel
        0x00280004,  # Photometric Interpretation
        0x00280008,  # Number of Frames
        0x00280010,  # Rows
        0x00280011,  # Columns
        0x00280100,  # Bits Allocated
        0x00280101,  # Bits Stored
        0x00280102,  # High Bit
        0x00280103,  # Pixel Representation
        0x7FE00010,  # Pixel Data
        # De-identification module (PS3.15) - populated by the exporter.
        0x00120062,  # Patient Identity Removed
        0x00120063,  # De-identification Method
        0x00120064,  # De-identification Method Code Sequence
    )
)

PATIENT_IDENTITY_REMOVED = "YES"
DEIDENTIFICATION_METHOD = "allow-list; identity/private tags removed; UIDs re-mapped"


class DeidentificationError(RuntimeError):
    """Raised when a dataset cannot be exported under the approved policy."""


class SourceUnavailableError(DeidentificationError):
    """Raised when a deferred element cannot be resolved from its source.

    This is an explicit failure: the original file is missing or unreadable, so
    the export is aborted rather than falling back to unverified attributes.
    """


@dataclass(frozen=True)
class DeidentificationStrategy:
    """The single, explicit approval decision applied to one export.

    The same instance is applied to every element regardless of whether it was
    still deferred, had already been accessed, or arrived via a copied dataset,
    so one approval governs the whole written file.
    """

    approved_tags: frozenset[BaseTag]
    blocked_tags: frozenset[BaseTag] = BLOCKED_TAGS
    uid_tags: frozenset[BaseTag] = UID_TAGS
    file_meta_allowed: frozenset[BaseTag] = FILE_META_ALLOWED
    retain_pixel_data: bool = True
    method_label: str = DEIDENTIFICATION_METHOD
    _approved_lookup: frozenset[BaseTag] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        # A blocked identity tag can never be approved, even if mis-listed.
        resolved = frozenset(self.approved_tags - self.blocked_tags)
        if not self.retain_pixel_data:
            resolved = frozenset(resolved - {Tag(0x7FE00010)})
        object.__setattr__(self, "_approved_lookup", resolved)

    @classmethod
    def review_export(cls) -> DeidentificationStrategy:
        """Return the standard allow-list policy used for external review."""
        return cls(approved_tags=frozenset(APPROVED_TAGS))

    def allows(self, tag: BaseTag) -> bool:
        """Return whether `tag` is approved for the export (blocked wins)."""
        if tag in self.blocked_tags:
            return False
        if tag.group % 2 == 1:  # private (odd group) elements are never allowed
            return False
        return tag in self._approved_lookup


def _is_raw(element: Any) -> bool:
    return isinstance(element, RawDataElement)


def materialize_dataset(dataset: Dataset) -> None:
    """Convert every deferred :class:`RawDataElement` in `dataset` in place.

    Recurses into sequence items. Conversion forces pydicom to re-open the
    original file for any deferred value, so a missing/moved source raises
    :class:`SourceUnavailableError` here -- before any output file is created.
    """

    def _resolve(ds: Dataset, path: str) -> None:
        for base_tag in list(ds._dict.keys()):
            element = ds._dict[base_tag]
            tag_path = f"{path}/{base_tag}"
            if _is_raw(element):
                try:
                    # Attribute access triggers the deferred read and replaces
                    # the raw entry with a native DataElement in-place.
                    _ = ds[base_tag].value
                except (OSError, EOFError) as exc:
                    raise SourceUnavailableError(
                        f"deferred element {tag_path} could not be resolved "
                        f"from its source: {exc}"
                    ) from exc
                element = ds._dict[base_tag]
            if not isinstance(element, DataElement):
                continue
            if element.VR == "SQ" and isinstance(element.value, pydicom.Sequence):
                for index, item in enumerate(element.value):
                    _resolve(item, f"{tag_path}[{index}]")

    _resolve(dataset, "")


def _new_uid_for(source_uid: str, uid_map: dict[str, str]) -> str:
    if source_uid not in uid_map:
        uid_map[source_uid] = generate_uid()
    return uid_map[source_uid]


def _filter_dataset(
    dataset: Dataset, strategy: DeidentificationStrategy, uid_map: dict[str, str]
) -> Dataset:
    """Return a new dataset containing only strategy-approved elements."""
    filtered = Dataset()
    filtered.set_original_encoding(*dataset.original_encoding)

    for base_tag in list(dataset._dict.keys()):
        element = dataset._dict[base_tag]
        tag = Tag(base_tag)
        if not strategy.allows(tag):
            continue
        if _is_raw(element):  # materialize_dataset() should have prevented this
            raise DeidentificationError(
                f"unexpected deferred element {tag} reached the filter"
            )
        if tag in strategy.uid_tags:
            element = DataElement(
                tag, element.VR, _new_uid_for(str(element.value), uid_map)
            )
        elif element.VR == "SQ" and isinstance(element.value, pydicom.Sequence):
            items = [_filter_dataset(item, strategy, uid_map) for item in element.value]
            element = DataElement(tag, "SQ", pydicom.Sequence(items))
        filtered[tag] = element
    return filtered


def _filter_file_meta(
    meta: FileMetaDataset | None,
    strategy: DeidentificationStrategy,
    uid_map: dict[str, str],
) -> FileMetaDataset:
    result = FileMetaDataset()
    if meta is None:
        return result
    for base_tag in list(meta._dict.keys()):
        tag = Tag(base_tag)
        if tag not in strategy.file_meta_allowed:
            continue
        element = meta._dict[base_tag]
        if tag == Tag(0x00020003) and not _is_raw(element):
            element = DataElement(
                tag, element.VR, _new_uid_for(str(element.value), uid_map)
            )
        result[tag] = element
    return result


def _stamp_deidentification(
    dataset: Dataset, strategy: DeidentificationStrategy
) -> None:
    dataset.PatientIdentityRemoved = PATIENT_IDENTITY_REMOVED
    dataset.DeidentificationMethod = strategy.method_label


@dataclass
class PreparedDataset:
    """An in-memory, fully resolved and de-identified dataset ready to write.

    It holds no reference to the original file: all deferred values were
    resolved during preparation, so the source can be moved or deleted without
    affecting the commit.
    """

    dataset: FileDataset
    uid_map: dict[str, str]
    source_filename: str | None
    removed_tags: tuple[BaseTag, ...]
    strategy: DeidentificationStrategy

    def commit(self, output_path: str | os.PathLike[str]) -> Path:
        """Atomically write the prepared dataset. Return the finished path."""
        return _atomic_write(self.dataset, Path(output_path))


def prepare_deidentified(
    dataset: Dataset, strategy: DeidentificationStrategy
) -> PreparedDataset:
    """Resolve and de-identify `dataset` in memory without touching the disk.

    A deep copy is used so the caller's original (possibly still-lazy) dataset
    is never mutated. Preparation fails closed if a deferred value's source is
    unavailable; no partial output is produced because no file is opened here.
    """
    if not isinstance(strategy, DeidentificationStrategy):
        raise DeidentificationError(
            "an explicit DeidentificationStrategy is required; refusing to "
            "export without an approved policy"
        )

    source_filename = getattr(dataset, "filename", None)
    working = copy.deepcopy(dataset)

    # One approval for everything: resolving deferred elements does not change
    # which tags survive, because filtering happens afterwards for all elements.
    materialize_dataset(working)

    removed = tuple(
        sorted(Tag(t) for t in working._dict if not strategy.allows(Tag(t)))
    )

    uid_map: dict[str, str] = {}
    filtered = _filter_dataset(working, strategy, uid_map)
    _stamp_deidentification(filtered, strategy)

    meta = _filter_file_meta(getattr(working, "file_meta", None), strategy, uid_map)

    preamble = getattr(working, "preamble", b"\0" * 128) or b"\0" * 128
    out = FileDataset(
        filename_or_obj=None,
        dataset=filtered._dict,
        preamble=preamble,
        file_meta=meta,
        is_implicit_VR=False,
        is_little_endian=True,
    )
    # Detach from the source: the prepared object must be self-contained.
    out.filename = None
    out.buffer = None
    out.timestamp = None
    out.fileobj_type = None
    out.set_original_encoding(False, True, working._read_charset)

    return PreparedDataset(
        dataset=out,
        uid_map=uid_map,
        source_filename=source_filename,
        removed_tags=removed,
        strategy=strategy,
    )


def _atomic_write(dataset: FileDataset, destination: Path) -> Path:
    """Write to a temp file in the same directory, then atomically replace."""
    destination = destination.resolve() if destination.parent.exists() else destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp_handle, tmp_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".part", dir=str(destination.parent)
    )
    tmp_path = Path(tmp_name)
    os.close(tmp_handle)
    try:
        dataset.save_as(str(tmp_path), enforce_file_format=True, overwrite=True)
        # Re-open the bytes we actually wrote to prove they are readable before
        # promoting the temp file to the official output.
        pydicom.dcmread(str(tmp_path))
        os.replace(str(tmp_path), str(destination))
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise
    return destination


def export_deidentified(
    dataset: Dataset,
    output_path: str | os.PathLike[str],
    strategy: DeidentificationStrategy,
) -> Path:
    """Prepare and atomically export `dataset`, returning the finished path.

    Either a complete, readable de-identified file appears at `output_path` or
    an exception is raised and no official output file is left behind.
    """
    prepared = prepare_deidentified(dataset, strategy)
    return prepared.commit(output_path)
