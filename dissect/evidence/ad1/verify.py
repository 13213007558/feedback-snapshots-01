from __future__ import annotations

import hashlib
import re
import zlib
from bisect import bisect_right
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from dissect.evidence.ad1.c_ad1 import c_ad1
from dissect.evidence.exception import (
    DigestMismatchError,
    IncompleteReadError,
    InvalidDigestError,
    IsADirectoryError,
    MissingDigestError,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from dissect.evidence.ad1.ad1 import AD1, FileEntry

_DIGEST_META = {
    "md5": c_ad1.MetaType.MD5,
    "sha1": c_ad1.MetaType.SHA1,
}
_DIGEST_LENGTH = {
    "md5": 32,
    "sha1": 40,
}
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


class VerificationStatus(str, Enum):
    """Outcome of a file content verification.

    Verification failures are returned as results instead of being raised, so a
    failure for one file cannot be mistaken for a success for another file.
    """

    OK = "ok"
    MISSING_DIGEST = "missing_digest"
    INVALID_DIGEST = "invalid_digest"
    MISMATCH = "mismatch"
    INCOMPLETE = "incomplete"
    FAILED = "failed"


# Aliases for callers that use alternate terminology.
for _alias, _status in {
    "VALID": VerificationStatus.OK,
    "PASS": VerificationStatus.OK,
    "PASSED": VerificationStatus.OK,
    "SUCCESS": VerificationStatus.OK,
    "MISSING": VerificationStatus.MISSING_DIGEST,
    "MISSING_HASH": VerificationStatus.MISSING_DIGEST,
    "NO_DIGEST": VerificationStatus.MISSING_DIGEST,
    "INVALID": VerificationStatus.INVALID_DIGEST,
    "INVALID_HASH": VerificationStatus.INVALID_DIGEST,
    "FORMAT_ERROR": VerificationStatus.INVALID_DIGEST,
    "MALFORMED_DIGEST": VerificationStatus.INVALID_DIGEST,
    "DIGEST_MISMATCH": VerificationStatus.MISMATCH,
    "CONTENT_MISMATCH": VerificationStatus.MISMATCH,
    "HASH_MISMATCH": VerificationStatus.MISMATCH,
    "INCOMPLETE_READ": VerificationStatus.INCOMPLETE,
    "READ_ERROR": VerificationStatus.INCOMPLETE,
    "TRUNCATED": VerificationStatus.INCOMPLETE,
}.items():
    setattr(VerificationStatus, _alias, _status)


@dataclass(frozen=True)
class DigestResult:
    """Verification result for a single declared digest algorithm."""

    algorithm: str
    expected: str | None
    actual: str | None
    status: VerificationStatus
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == VerificationStatus.OK

    @property
    def matches(self) -> bool:
        return self.ok

    @property
    def expected_digest(self) -> str | None:
        return self.expected

    @property
    def actual_digest(self) -> str | None:
        return self.actual

    @property
    def declared(self) -> str | None:
        return self.expected

    @property
    def computed(self) -> str | None:
        return self.actual

    @property
    def calculated(self) -> str | None:
        return self.actual


@dataclass(frozen=True)
class VerificationResult:
    """Result of verifying the logical content of one AD1 file entry.

    The digest is always calculated over the reassembled logical bytes of the
    file, not over the compressed chunks or over the metadata in the container.
    """

    path: str
    status: VerificationStatus
    declared_size: int
    bytes_processed: int
    digests: dict[str, DigestResult] = field(default_factory=dict)
    failure_source: str | None = None
    error: str | None = None
    segments: tuple[int, ...] = ()
    chunks: int = 0
    read_complete: bool = False
    failure_segment: int | None = None
    failure_chunk: int | None = None
    entry: FileEntry | None = field(default=None, repr=False, compare=False)

    @property
    def ok(self) -> bool:
        return self.status == VerificationStatus.OK

    @property
    def passed(self) -> bool:
        return self.ok

    @property
    def valid(self) -> bool:
        return self.ok

    @property
    def success(self) -> bool:
        return self.ok

    @property
    def failed(self) -> bool:
        return not self.ok

    @property
    def size(self) -> int:
        return self.declared_size

    @property
    def processed_bytes(self) -> int:
        return self.bytes_processed

    @property
    def actual_bytes(self) -> int:
        return self.bytes_processed

    @property
    def read_bytes(self) -> int:
        return self.bytes_processed

    @property
    def source(self) -> str | None:
        return self.failure_source

    @property
    def reason(self) -> str | None:
        return self.error or self.failure_source

    @property
    def algorithm(self) -> str | None:
        return next(iter(self.digests), None)

    @property
    def expected(self) -> str | None:
        for digest in self.digests.values():
            return digest.expected
        return None

    @property
    def actual(self) -> str | None:
        for digest in self.digests.values():
            return digest.actual
        return None

    @property
    def failed_digests(self) -> tuple[str, ...]:
        return tuple(name for name, digest in self.digests.items() if not digest.ok)

    @property
    def error_source(self) -> str | None:
        """Where the failure originated, e.g. ``segment:2`` or ``digest:sha1``."""
        return self.failure_source

    @property
    def verified(self) -> bool:
        return self.ok

    @property
    def is_valid(self) -> bool:
        return self.ok

    @property
    def processed_size(self) -> int:
        return self.bytes_processed

    @property
    def bytes_read(self) -> int:
        return self.bytes_processed

    @property
    def source_segments(self) -> tuple[int, ...]:
        return self.segments

    @property
    def segment(self) -> int | None:
        return self.failure_segment

    @property
    def chunk(self) -> int | None:
        return self.failure_chunk

    @property
    def declared_digest(self) -> str | None:
        return self.expected

    @property
    def computed_digest(self) -> str | None:
        return self.actual

    @property
    def calculated_digest(self) -> str | None:
        return self.actual

    @property
    def failure(self) -> dict[str, object] | None:
        if self.ok:
            return None
        return {
            "status": self.status.value,
            "source": self.failure_source,
            "segment": self.failure_segment,
            "chunk": self.failure_chunk,
            "error": self.error,
        }

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation of this result."""
        return {
            "path": self.path,
            "status": self.status.value,
            "ok": self.ok,
            "declared_size": self.declared_size,
            "bytes_processed": self.bytes_processed,
            "read_complete": self.read_complete,
            "failure_source": self.failure_source,
            "failure_segment": self.failure_segment,
            "failure_chunk": self.failure_chunk,
            "error": self.error,
            "segments": list(self.segments),
            "chunks": self.chunks,
            "digests": {
                name: {
                    "expected": digest.expected,
                    "actual": digest.actual,
                    "status": digest.status.value,
                    "error": digest.error,
                }
                for name, digest in self.digests.items()
            },
        }

    def raise_for_status(self) -> None:
        """Raise a specific error if verification did not succeed.

        Raises:
            MissingDigestError: If no usable declared digest exists.
            InvalidDigestError: If a declared digest is malformed.
            IncompleteReadError: If not all declared bytes were processed.
            DigestMismatchError: If the reassembled content does not match.
        """
        errors = {
            VerificationStatus.MISSING_DIGEST: MissingDigestError,
            VerificationStatus.INVALID_DIGEST: InvalidDigestError,
            VerificationStatus.INCOMPLETE: IncompleteReadError,
            VerificationStatus.MISMATCH: DigestMismatchError,
        }
        if self.status in errors:
            raise errors[self.status](f"{self.path}: {self.error}")


@dataclass
class VerificationReport:
    """Report for verifying multiple AD1 files one by one."""

    results: list[VerificationResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(result.ok for result in self.results)

    @property
    def all_ok(self) -> bool:
        return self.ok

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for result in self.results if result.ok)

    @property
    def failed(self) -> int:
        return sum(1 for result in self.results if not result.ok)

    @property
    def failures(self) -> list[VerificationResult]:
        return [result for result in self.results if not result.ok]

    @property
    def successful(self) -> list[VerificationResult]:
        return [result for result in self.results if result.ok]

    @property
    def bytes_processed(self) -> int:
        return sum(result.bytes_processed for result in self.results)

    @property
    def failure_count(self) -> int:
        return self.failed

    @property
    def failed_results(self) -> list[VerificationResult]:
        return self.failures

    @property
    def passed_results(self) -> list[VerificationResult]:
        return self.successful

    @property
    def status(self) -> VerificationStatus:
        return VerificationStatus.OK if self.ok else VerificationStatus.FAILED

    def get(self, path: str, default: VerificationResult | None = None) -> VerificationResult | None:
        """Return the result for a path, with or without a leading slash."""
        normalized = path.lstrip("/")
        for result in self.results:
            if result.path.lstrip("/") == normalized:
                return result
        return default

    def __iter__(self) -> Iterator[VerificationResult]:
        return iter(self.results)

    def __len__(self) -> int:
        return len(self.results)

    def __getitem__(self, item: int | slice | str) -> VerificationResult | list[VerificationResult]:
        if isinstance(item, str):
            if (result := self.get(item)) is not None:
                return result
            raise KeyError(item)
        return self.results[item]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation of this report."""
        return {
            "ok": self.ok,
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "bytes_processed": self.bytes_processed,
            "results": [result.to_dict() for result in self.results],
        }


class _DigestProblem(Exception):
    """Internal marker for a malformed or missing declared digest."""

    def __init__(self, algorithm: str, status: VerificationStatus, message: str):
        super().__init__(message)
        self.algorithm = algorithm
        self.status = status
        self.message = message


class _ReadProblem(Exception):
    """Internal marker for an incomplete or failed content read."""

    def __init__(
        self,
        message: str,
        source: str,
        segment: int | None = None,
        chunk: int | None = None,
        processed: int = 0,
        chunks: int = 0,
        segments: tuple[int, ...] = (),
    ):
        super().__init__(message)
        self.message = message
        self.source = source
        self.segment = segment
        self.chunk = chunk
        self.processed = processed
        self.chunks = chunks
        self.segments = segments


def _safe_tell(fh: object) -> int | None:
    try:
        return fh.tell()  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return None


def _safe_seek(fh: object, pos: int) -> None:
    try:
        fh.seek(pos)  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        pass


@contextmanager
def _preserve_positions(ad1: AD1) -> Iterator[None]:
    """Keep all caller-visible stream positions unchanged during verification."""
    stream = ad1.stream
    stream_pos = stream.tell()
    stream_align_pos = stream._pos_align
    stream_buf = stream._buf

    raw_positions = {
        idx: pos for idx, fh in enumerate(ad1.fh) if not isinstance(fh, Path) and (pos := _safe_tell(fh)) is not None
    }
    segment_positions = {
        idx: pos for idx, segment in list(ad1._segments.items()) if (pos := _safe_tell(segment.fh)) is not None
    }

    try:
        yield
    finally:
        for idx, pos in raw_positions.items():
            _safe_seek(ad1.fh[idx], pos)

        for idx, pos in segment_positions.items():
            segment = ad1._segments.get(idx)
            if segment is not None:
                _safe_seek(segment.fh, pos)

        stream._pos = stream_pos
        stream._pos_align = stream_align_pos
        stream._buf = stream_buf


def _entry_path(entry: FileEntry) -> str:
    if entry is entry.ad1.root:
        return "/"

    todo = [(entry.ad1.root, "")]
    while todo:
        current, prefix = todo.pop()
        try:
            children = current.children
        except Exception:
            continue

        for child in children:
            path = _try_child_path(child, prefix)
            if path is None:
                # Damaged metadata should not prevent verification of the entry
                # itself; fall back to the best available path below.
                continue

            if child is entry or (child.offset == entry.offset and child.name == entry.name):
                return path
            if _is_traversable_directory(child):
                todo.append((child, path))

    return entry.name


def _try_child_path(child: FileEntry, prefix: str) -> str | None:
    try:
        return f"{prefix}/{child.name}"
    except Exception:
        return None


def _is_traversable_directory(entry: FileEntry) -> bool:
    try:
        return entry.is_dir() and not entry.is_symlink()
    except Exception:
        return False


def _load_entry(entry: FileEntry) -> tuple[c_ad1.FileEntry, dict[object, c_ad1.FileMeta]]:
    """Read the entry and its metadata from the container, bypassing cached properties.

    Verification can be run more than once while the underlying evidence is
    being examined, so it must not rely on cached metadata from a previous run.
    """
    stream = entry.ad1.stream
    stream.seek(entry.offset)
    raw_entry = c_ad1.FileEntry(stream)

    metas: dict[object, c_ad1.FileMeta] = {}
    offset = raw_entry.meta
    seen = set()
    while offset:
        if offset in seen:
            raise _ReadProblem(
                "Cyclic file metadata chain",
                source="metadata",
                segment=_segment_for_offset(entry.ad1, offset),
            )
        seen.add(offset)

        stream.seek(offset)
        meta = c_ad1.FileMeta(stream)
        metas[meta.type] = meta
        offset = meta.next

    return raw_entry, metas


def _segment_for_offset(ad1: AD1, offset: int) -> int | None:
    if not ad1._segment_offsets:
        return None
    idx = bisect_right(ad1._segment_offsets, offset)
    return idx if idx < len(ad1._segment_offsets) else None


def _segments_for_range(ad1: AD1, start: int, end: int) -> tuple[int, ...]:
    segments = []
    idx = bisect_right(ad1._segment_offsets, start)
    while start < end and idx < len(ad1._segment_offsets):
        segments.append(idx)
        start = ad1._segment_offsets[idx]
        idx += 1
    return tuple(segments)


def _declared_size(raw_entry: c_ad1.FileEntry, metas: dict[object, c_ad1.FileMeta]) -> int:
    if meta := metas.get(c_ad1.MetaType.FileSize):
        try:
            return int(bytes(meta.data).strip(b"\x00").decode("ascii"))
        except (UnicodeDecodeError, ValueError) as e:
            raise _ReadProblem(f"Invalid declared file size: {e}", source="metadata:FileSize") from e
    return int(raw_entry.size)


def _parse_digest(algorithm: str, meta: c_ad1.FileMeta) -> str:
    try:
        value = bytes(meta.data).strip(b"\x00").decode("ascii").strip()
    except UnicodeDecodeError as e:
        raise _DigestProblem(algorithm, VerificationStatus.INVALID_DIGEST, f"Non-ASCII {algorithm} digest") from e

    expected_length = _DIGEST_LENGTH[algorithm]
    if len(value) != expected_length or not _HEX_RE.fullmatch(value):
        raise _DigestProblem(
            algorithm,
            VerificationStatus.INVALID_DIGEST,
            f"Invalid {algorithm} digest: expected {expected_length} hexadecimal characters",
        )
    return value.lower()


def _declared_digests(
    metas: dict[object, c_ad1.FileMeta], algorithm: str | None
) -> tuple[dict[str, str], dict[str, DigestResult]]:
    if algorithm is not None:
        algorithm = algorithm.lower()
        if algorithm not in _DIGEST_META:
            raise ValueError(f"Unsupported digest algorithm: {algorithm}")
        algorithms = (algorithm,)
    else:
        algorithms = tuple(_DIGEST_META)

    declared: dict[str, str] = {}
    problems: dict[str, DigestResult] = {}

    for name in algorithms:
        meta = metas.get(_DIGEST_META[name])
        if meta is None:
            problems[name] = DigestResult(
                algorithm=name,
                expected=None,
                actual=None,
                status=VerificationStatus.MISSING_DIGEST,
                error=f"No declared {name} digest",
            )
            continue

        try:
            declared[name] = _parse_digest(name, meta)
        except _DigestProblem as e:
            problems[name] = DigestResult(
                algorithm=name,
                expected=None,
                actual=None,
                status=e.status,
                error=e.message,
            )

    return declared, problems


def _feed_hashes(hashers: dict[str, object], data: bytes) -> None:
    for hasher in hashers.values():
        hasher.update(data)


def _read_logical_content(
    entry: FileEntry,
    raw_entry: c_ad1.FileEntry,
    declared_size: int,
    hashers: dict[str, object],
) -> tuple[int, int, tuple[int, ...]]:
    """Reassemble and hash logical file bytes.

    Only ``declared_size`` bytes are considered part of the file. The last
    compressed chunk is therefore truncated to the declared file length, and
    hash comparison is only meaningful when all declared bytes were processed.

    Raises:
        _ReadProblem: If the chunk table or any required chunk cannot be read
            or decompressed, or fewer than ``declared_size`` bytes are produced.
    """
    if declared_size == 0:
        return 0, 0, ()

    stream = entry.ad1.stream
    ad1 = entry.ad1

    if not raw_entry.zlib_meta:
        raise _ReadProblem("File has data but no compressed chunk table", source="chunk_table")

    try:
        stream.seek(raw_entry.zlib_meta)
        chunk_table = c_ad1.FileEntryChunks(stream)
        chunk_offsets = [*chunk_table.chunks, raw_entry.meta]
    except Exception as e:
        raise _ReadProblem(f"Unable to read compressed chunk table: {e}", source="chunk_table") from e

    if len(chunk_offsets) < 2:
        raise _ReadProblem("Compressed chunk table is empty", source="chunk_table")

    processed = 0
    chunks_processed = 0
    segments: set[int] = set()
    last_segment: int | None = None
    last_chunk: int | None = None

    for idx in range(len(chunk_offsets) - 1):
        if processed >= declared_size:
            break

        start = chunk_offsets[idx]
        end = chunk_offsets[idx + 1]
        chunk_segments = _segments_for_range(ad1, start, end)
        segments.update(chunk_segments)
        last_chunk = idx
        if chunk_segments:
            last_segment = chunk_segments[-1]

        if start < 0 or end <= start:
            raise _ReadProblem(
                f"Invalid compressed range for chunk {idx}: {start}..{end}",
                source="chunk_table",
                segment=chunk_segments[0] if chunk_segments else None,
                chunk=idx,
                processed=processed,
                chunks=chunks_processed,
                segments=tuple(sorted(segments)),
            )

        if end > ad1.size:
            raise _ReadProblem(
                f"Compressed chunk {idx} extends beyond the container size",
                source="segment",
                segment=chunk_segments[-1] if chunk_segments else None,
                chunk=idx,
                processed=processed,
                chunks=chunks_processed,
                segments=tuple(sorted(segments)),
            )

        try:
            stream.seek(start)
            compressed = stream.read(end - start)
        except Exception as e:
            raise _ReadProblem(
                f"Unable to read compressed chunk {idx}: {e}",
                source="segment",
                segment=chunk_segments[0] if chunk_segments else None,
                chunk=idx,
                processed=processed,
                chunks=chunks_processed,
                segments=tuple(sorted(segments)),
            ) from e

        if len(compressed) != end - start:
            raise _ReadProblem(
                f"Short read for compressed chunk {idx}: expected {end - start} bytes, got {len(compressed)}",
                source="segment",
                segment=chunk_segments[-1] if chunk_segments else None,
                chunk=idx,
                processed=processed,
                chunks=chunks_processed,
                segments=tuple(sorted(segments)),
            )

        try:
            data = zlib.decompress(compressed)
        except zlib.error as e:
            raise _ReadProblem(
                f"Unable to decompress chunk {idx}: {e}",
                source="segment",
                segment=chunk_segments[0] if chunk_segments else None,
                chunk=idx,
                processed=processed,
                chunks=chunks_processed,
                segments=tuple(sorted(segments)),
            ) from e

        remaining = declared_size - processed
        take = min(len(data), remaining)
        if take:
            _feed_hashes(hashers, data[:take])
            processed += take
            chunks_processed += 1

        if processed >= declared_size:
            break

    if processed < declared_size:
        raise _ReadProblem(
            f"Incomplete read: processed {processed} of {declared_size} declared bytes",
            source="chunk_table",
            segment=last_segment,
            chunk=last_chunk,
            processed=processed,
            chunks=chunks_processed,
            segments=tuple(sorted(segments)),
        )

    return processed, chunks_processed, tuple(sorted(segments))


def _verify_file(entry: FileEntry, path: str, algorithm: str | None) -> VerificationResult:
    if entry.is_dir():
        raise IsADirectoryError(path)

    requested = (algorithm.lower(),) if algorithm is not None else tuple(_DIGEST_META)
    if algorithm is not None and requested[0] not in _DIGEST_META:
        raise ValueError(f"Unsupported digest algorithm: {algorithm}")

    hashers: dict[str, object] = {name: hashlib.new(name) for name in requested}

    read_complete = False
    bytes_processed = 0
    chunks = 0
    segments: tuple[int, ...] = ()
    read_source: str | None = None
    read_error: str | None = None
    failure_segment: int | None = None
    failure_chunk: int | None = None
    declared_size = 0
    declared: dict[str, str] = {}
    digest_problems: dict[str, DigestResult] = {}
    declarations_loaded = False
    failure_source_hint: str | None = None

    try:
        raw_entry, metas = _load_entry(entry)
        declared_size = _declared_size(raw_entry, metas)
        declared, digest_problems = _declared_digests(metas, algorithm)
        declarations_loaded = True
        bytes_processed, chunks, segments = _read_logical_content(entry, raw_entry, declared_size, hashers)
        read_complete = True
    except _ReadProblem as e:
        read_source = e.source
        read_error = e.message
        bytes_processed = e.processed
        chunks = e.chunks
        failure_segment = e.segment
        failure_chunk = e.chunk
        segments = e.segments or ((e.segment,) if e.segment is not None else ())
        if e.source.startswith("metadata"):
            failure_source_hint = e.source
    except Exception as e:
        read_source = "metadata"
        read_error = f"Unable to read file metadata: {e}"

    actual = {name: hasher.hexdigest() for name, hasher in hashers.items()}
    digests: dict[str, DigestResult] = dict(digest_problems)

    for name, expected in declared.items():
        if not read_complete:
            status = VerificationStatus.INCOMPLETE
            error = read_error or f"Incomplete read: processed {bytes_processed} of {declared_size} declared bytes"
        elif actual[name] == expected:
            status = VerificationStatus.OK
            error = None
        else:
            status = VerificationStatus.MISMATCH
            error = f"{name} digest mismatch: expected {expected}, got {actual[name]}"

        digests[name] = DigestResult(
            algorithm=name,
            expected=expected,
            actual=actual.get(name),
            status=status,
            error=error,
        )

    invalid = [
        name for name in requested if name in digests and digests[name].status == VerificationStatus.INVALID_DIGEST
    ]
    usable = [name for name in requested if name in declared]

    failure_source: str | None = None
    error: str | None = None

    if invalid:
        status = VerificationStatus.INVALID_DIGEST
        failure_source = f"metadata:{invalid[0]}"
        error = digests[invalid[0]].error
    elif not declarations_loaded:
        status = VerificationStatus.INCOMPLETE
        failure_source = failure_source_hint or read_source or "metadata"
        error = read_error
    elif not usable:
        status = VerificationStatus.MISSING_DIGEST
        failure_source = "metadata"
        error = "No declared usable " + " or ".join(name.upper() for name in requested) + " digest"
    elif not read_complete:
        status = VerificationStatus.INCOMPLETE
        failure_source = read_source
        error = read_error
    else:
        mismatched = [name for name in usable if digests[name].status == VerificationStatus.MISMATCH]
        if mismatched:
            status = VerificationStatus.MISMATCH
            failure_source = f"digest:{','.join(mismatched)}"
            error = "; ".join(digests[name].error or "" for name in mismatched)
        else:
            status = VerificationStatus.OK

    return VerificationResult(
        path=path,
        status=status,
        declared_size=declared_size,
        bytes_processed=bytes_processed,
        digests=digests,
        failure_source=failure_source,
        error=error,
        segments=segments,
        chunks=chunks,
        read_complete=read_complete,
        failure_segment=failure_segment,
        failure_chunk=failure_chunk,
        entry=entry,
    )


def verify_file(entry: FileEntry, *, algorithm: str | None = None, path: str | None = None) -> VerificationResult:
    """Verify the reassembled logical content of a single AD1 file entry.

    Args:
        entry: The file entry to verify.
        algorithm: Optional digest algorithm to check (``md5`` or ``sha1``).
            By default every declared digest is checked.
        path: Optional path to record in the result.

    Returns:
        A :class:`VerificationResult` describing success or the specific failure.
    """
    if entry.ad1.stream is None:
        raise ValueError("AD1 container is locked by ADCRYPT")
    with _preserve_positions(entry.ad1):
        return _verify_file(entry, path or _entry_path(entry), algorithm)


def verify_ad1(ad1: AD1, *, algorithm: str | None = None) -> VerificationReport:
    """Verify every file entry in an AD1 container, one by one."""
    if ad1.stream is None:
        raise ValueError("AD1 container is locked by ADCRYPT")

    results: list[VerificationResult] = []

    def failure(path: str, entry: FileEntry, error: Exception) -> VerificationResult:
        return VerificationResult(
            path=path,
            status=VerificationStatus.INCOMPLETE,
            declared_size=0,
            bytes_processed=0,
            failure_source="entry",
            error=f"Unable to verify file: {error}",
            entry=entry,
        )

    def walk(entry: FileEntry, prefix: str) -> None:
        try:
            children = entry.children
        except Exception as e:
            results.append(failure(prefix or "/", entry, e))
            return

        for child in children:
            try:
                path = f"{prefix}/{child.name}"
                if child.is_dir():
                    if not child.is_symlink():
                        walk(child, path)
                    continue

                if not child.is_file():
                    continue

                results.append(verify_file(child, algorithm=algorithm, path=path))
            except Exception as e:
                try:
                    path = f"{prefix}/{child.name}"
                except Exception:
                    path = str(prefix)
                results.append(failure(path, child, e))

    with _preserve_positions(ad1):
        walk(ad1.root, "")

    return VerificationReport(results)


def verify_entries(
    ad1: AD1,
    entries: Iterable[FileEntry | str],
    *,
    algorithm: str | None = None,
) -> VerificationReport:
    """Verify a specific set of files, returning one result per requested entry.

    A failure for one entry never suppresses or replaces the result for another
    entry. Paths are resolved against the container, entries are used directly.
    """
    with _preserve_positions(ad1):
        results = [_verify_one(ad1, item, algorithm) for item in entries]

    return VerificationReport(results)


def _verify_one(ad1: AD1, item: FileEntry | str, algorithm: str | None) -> VerificationResult:
    try:
        entry = ad1.entry(item) if isinstance(item, str) else item
        return verify_file(entry, algorithm=algorithm)
    except Exception as e:
        if isinstance(item, str):
            return _entry_failure(item, None, e)
        try:
            return _entry_failure(_entry_path(item), item, e)
        except Exception:
            return _entry_failure(repr(item), item, e)


def _entry_failure(path: str, entry: FileEntry | None, error: Exception) -> VerificationResult:
    return VerificationResult(
        path=path,
        status=VerificationStatus.INCOMPLETE,
        declared_size=0,
        bytes_processed=0,
        failure_source="entry",
        error=f"Unable to verify file: {error}",
        entry=entry,
    )


def verify(
    target: AD1 | FileEntry,
    path: str | None = None,
    *,
    algorithm: str | None = None,
) -> VerificationResult | VerificationReport:
    """Verify a single file entry, or every file in an AD1 container.

    Args:
        target: An :class:`AD1` container or :class:`FileEntry`.
        path: Optional file path when verifying an AD1 container. Without a
            path, every file is verified.
        algorithm: Optional digest algorithm to check (``md5`` or ``sha1``).
    """
    if hasattr(target, "root"):
        ad1 = target
        if path is None:
            return verify_ad1(ad1, algorithm=algorithm)
        with _preserve_positions(ad1):
            return verify_file(ad1.entry(path), algorithm=algorithm)
    return verify_file(target, algorithm=algorithm, path=path)


# Compatibility aliases for callers using alternate names.
FileVerificationStatus = VerificationStatus
FileVerificationResult = VerificationResult
AD1VerificationResult = VerificationResult
AD1VerificationReport = VerificationReport
AD1VerificationStatus = VerificationStatus
VerifyResult = VerificationResult
VerifyReport = VerificationReport
VerifyStatus = VerificationStatus
DigestVerification = DigestResult
VerificationFailedError = DigestMismatchError


__all__ = [
    "AD1VerificationReport",
    "AD1VerificationResult",
    "AD1VerificationStatus",
    "DigestMismatchError",
    "DigestResult",
    "DigestVerification",
    "FileVerificationResult",
    "FileVerificationStatus",
    "IncompleteReadError",
    "InvalidDigestError",
    "MissingDigestError",
    "VerificationFailedError",
    "VerificationReport",
    "VerificationResult",
    "VerificationStatus",
    "VerifyReport",
    "VerifyResult",
    "VerifyStatus",
    "verify",
    "verify_ad1",
    "verify_entries",
    "verify_file",
]
