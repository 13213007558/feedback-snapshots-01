from __future__ import annotations

import hashlib
import re
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, BinaryIO

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.evidence.ad1.ad1 import AD1, FileEntry

READ_SIZE = 1024 * 1024

HASH_ALGORITHMS = ("md5", "sha1")
HASH_HEX_LENGTH = {"md5": 32, "sha1": 40}


class VerifyStatus(Enum):
    """Outcome of a single file content verification."""

    OK = "ok"
    MISSING_HASH = "missing-hash"
    INVALID_HASH = "invalid-hash"
    MISMATCH = "mismatch"
    INCOMPLETE_READ = "incomplete-read"


@dataclass
class VerifyResult:
    """Result of verifying the declared hash of a single file entry against its logical content.

    The digest is always computed over the reassembled logical bytes of the entry, i.e. the
    decompressed chunks stitched together, with the final chunk truncated to the declared file
    size. ``bytes_processed`` reflects how many logical bytes were actually read, and ``source``
    identifies where a failure originated.
    """

    name: str
    algorithm: str | None
    status: VerifyStatus
    size: int
    bytes_processed: int = 0
    expected: str | None = None
    actual: str | None = None
    source: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is VerifyStatus.OK

    def __str__(self) -> str:
        parts = [f"{self.name}: {self.algorithm or '-'} {self.status.value}"]
        parts.append(f"bytes={self.bytes_processed}/{self.size}")
        if self.expected is not None:
            parts.append(f"expected={self.expected}")
        if self.actual is not None:
            parts.append(f"actual={self.actual}")
        if self.source is not None:
            parts.append(f"source={self.source}")
        return " ".join(parts)


def _is_valid_hash(algorithm: str, value: str) -> bool:
    length = HASH_HEX_LENGTH[algorithm]
    return re.fullmatch(rf"[0-9a-fA-F]{{{length}}}", value) is not None


@contextmanager
def _preserve_positions(ad1: AD1) -> Iterator[None]:
    """Restore the positions of the AD1 stream and all involved file objects on exit.

    Verification seeks all over the stitched stream and segment file handles. Callers may hold
    their own positions on these streams, so save and restore them.
    """
    streams = []
    seen = set()

    def add(fh: BinaryIO | None) -> None:
        if fh is not None and id(fh) not in seen and hasattr(fh, "tell") and hasattr(fh, "seek"):
            seen.add(id(fh))
            streams.append(fh)

    add(ad1.stream)
    for segment in ad1._segments.values():
        add(segment.fh)
    for fh in ad1.fh:
        if not isinstance(fh, (str, bytes)):
            add(fh)

    positions = {}
    for fh in streams:
        try:
            positions[id(fh)] = (fh, fh.tell())
        except Exception:
            pass

    try:
        yield
    finally:
        for fh, pos in positions.values():
            try:
                fh.seek(pos)
            except Exception:
                pass


def verify_entry(
    entry: FileEntry, path: str | None = None, algorithms: tuple[str, ...] = HASH_ALGORITHMS
) -> list[VerifyResult]:
    """Verify the declared hashes of a single :class:`FileEntry` against its logical content.

    Returns one :class:`VerifyResult` per declared hash algorithm. A missing declared hash, a
    malformed declared hash, a content mismatch and an incomplete read each produce a distinct
    status. A partial read never produces an ``OK`` result, even if the digest of the bytes that
    could be read happens to match the declared hash.
    """
    name = path or entry.name
    size = entry.size

    declared: dict[str, str] = {}
    results: list[VerifyResult] = []

    for algorithm in algorithms:
        value = getattr(entry, algorithm, None)
        if value is None:
            continue
        if not _is_valid_hash(algorithm, value):
            results.append(
                VerifyResult(
                    name=name,
                    algorithm=algorithm,
                    status=VerifyStatus.INVALID_HASH,
                    size=size,
                    expected=value,
                    source=f"declared {algorithm} metadata",
                )
            )
        else:
            declared[algorithm] = value.lower()

    if not declared:
        if not results:
            results.append(
                VerifyResult(
                    name=name,
                    algorithm=None,
                    status=VerifyStatus.MISSING_HASH,
                    size=size,
                    source="no hash metadata",
                )
            )
        return results

    contexts = {algorithm: hashlib.new(algorithm) for algorithm in declared}
    processed = 0
    error: Exception | None = None

    with _preserve_positions(entry.ad1):
        try:
            fh = entry.open()
            while buf := fh.read(READ_SIZE):
                for ctx in contexts.values():
                    ctx.update(buf)
                processed += len(buf)
        except Exception as exc:
            error = exc

    if error is not None or processed != size:
        if error is not None:
            source = f"read error after {processed} bytes: {error}"
        else:
            source = f"read {processed} of {size} declared bytes"
        for algorithm, expected in declared.items():
            results.append(
                VerifyResult(
                    name=name,
                    algorithm=algorithm,
                    status=VerifyStatus.INCOMPLETE_READ,
                    size=size,
                    bytes_processed=processed,
                    expected=expected,
                    actual=contexts[algorithm].hexdigest(),
                    source=source,
                )
            )
        return results

    for algorithm, expected in declared.items():
        actual = contexts[algorithm].hexdigest()
        ok = actual == expected
        results.append(
            VerifyResult(
                name=name,
                algorithm=algorithm,
                status=VerifyStatus.OK if ok else VerifyStatus.MISMATCH,
                size=size,
                bytes_processed=processed,
                expected=expected,
                actual=actual,
                source=None if ok else f"declared {algorithm} metadata",
            )
        )
    return results


def _iter_file_entries(entry: FileEntry, path: str = "") -> Iterator[tuple[str, FileEntry]]:
    for child in entry.children:
        child_path = f"{path}/{child.name}" if path else child.name
        if child.is_file():
            yield child_path, child
        elif child.is_dir():
            yield from _iter_file_entries(child, child_path)


def verify(ad1: AD1, algorithms: tuple[str, ...] = HASH_ALGORITHMS) -> list[VerifyResult]:
    """Verify every file entry in an AD1 logical image against its declared hashes.

    Each entry is verified independently: a failure on one entry is reported for that entry only
    and never affects, skips or masks the results of the remaining entries.
    """
    results = []
    with _preserve_positions(ad1):
        for path, entry in _iter_file_entries(ad1.root):
            try:
                results.extend(verify_entry(entry, path=path, algorithms=algorithms))
            except Exception as exc:
                results.append(
                    VerifyResult(
                        name=path,
                        algorithm=None,
                        status=VerifyStatus.INCOMPLETE_READ,
                        size=0,
                        source=f"verification error: {exc}",
                    )
                )
    return results
