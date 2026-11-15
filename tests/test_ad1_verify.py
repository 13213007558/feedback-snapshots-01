from __future__ import annotations

import hashlib
import shutil
import zlib
from typing import TYPE_CHECKING

import pytest

from dissect.evidence.ad1 import (
    AD1,
    DigestMismatchError,
    IncompleteReadError,
    InvalidDigestError,
    MissingDigestError,
    VerificationStatus,
    verify_file,
)
from dissect.evidence.ad1.c_ad1 import c_ad1
from dissect.evidence.ad1.verify import _entry_path
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path


CROSS_SEGMENT_FILE = "C:/Users/pcbje/Desktop/Data/Pictures/2-0-826-Desert.jpg"
CROSS_SEGMENT_SHA1 = "30420d1a9afb2bcb60335812569af4435a59ce17"


def _read_metadata(fs: AD1, entry: object) -> tuple[c_ad1.FileEntry, dict[object, tuple[int, int, bytes]]]:
    """Return the raw entry and (record offset, data offset, data) for each metadata item."""
    stream = fs.stream
    stream.seek(entry.offset)
    raw_entry = c_ad1.FileEntry(stream)

    result = {}
    offset = raw_entry.meta
    while offset:
        stream.seek(offset)
        meta = c_ad1.FileMeta(stream)
        result[meta.type] = (offset, stream.tell() - len(meta.data), bytes(meta.data))
        offset = meta.next
    return raw_entry, result


def _write_at(paths: list[Path], segment_offsets: list[int], offset: int, data: bytes) -> None:
    segment_idx = next(idx for idx, end in enumerate(segment_offsets) if offset < end)
    segment_start = 0 if segment_idx == 0 else segment_offsets[segment_idx - 1]
    with paths[segment_idx].open("r+b") as fh:
        fh.seek(512 + offset - segment_start)
        fh.write(data)


def _chunk_offsets(fs: AD1, entry: object) -> list[int]:
    stream = fs.stream
    stream.seek(entry.entry.zlib_meta)
    return list(c_ad1.FileEntryChunks(stream).chunks)


@pytest.fixture
def segmented_copy(tmp_path: Path) -> list[Path]:
    """A writable copy of the segmented sample so tests can tamper with it."""
    paths = []
    for idx in range(1, 5):
        src = absolute_path(f"_data/ad1/pcbje/text-and-pictures.ad{idx}")
        dst = tmp_path / src.name
        shutil.copyfile(src, dst)
        paths.append(dst)
    return paths


def test_ad1_verify_cross_segment_cross_chunk(segmented_copy: list[Path]) -> None:
    """A file spanning segments and many zlib chunks verifies against logical bytes."""
    fs = AD1(segmented_copy)
    entry = fs.get(CROSS_SEGMENT_FILE)

    result = entry.verify()

    assert result.ok, result.error
    assert result.status == VerificationStatus.OK
    assert result.declared_size == entry.size == 845941
    assert result.bytes_processed == entry.size
    assert result.read_complete
    assert result.segments == (0, 1)
    assert result.chunks > 1
    assert result.digests["sha1"].expected == CROSS_SEGMENT_SHA1
    assert result.digests["sha1"].actual == CROSS_SEGMENT_SHA1
    assert result.failure_source is None
    assert result.error is None

    expected = hashlib.sha1(entry.open().read()).hexdigest()
    assert result.digests["sha1"].actual == expected


def test_ad1_verify_does_not_move_caller_stream(segmented_copy: list[Path]) -> None:
    fs = AD1(segmented_copy)
    entry = fs.get(CROSS_SEGMENT_FILE)

    fs.stream.seek(12345)
    segment = fs.segment(1)
    segment.fh.seek(6789)

    assert entry.verify().ok

    assert fs.stream.tell() == 12345
    assert segment.fh.tell() == 6789


def test_ad1_verify_preserves_caller_file_stream(segmented_copy: list[Path]) -> None:
    """Verification must not disturb an already-open logical file stream."""
    fs = AD1(segmented_copy)
    entry = fs.get(CROSS_SEGMENT_FILE)
    caller = entry.open()
    head = caller.read(1000)
    position = caller.tell()

    assert entry.verify().ok

    assert caller.tell() == position
    assert caller.read(1000) == entry.open().read()[1000:2000]
    assert head == entry.open().read()[:1000]


def test_ad1_verify_container_path_lookup_preserves_stream(segmented_copy: list[Path]) -> None:
    fs = AD1(segmented_copy)
    fs.stream.seek(4321)

    assert fs.verify(CROSS_SEGMENT_FILE).ok
    assert fs.stream.tell() == 4321

    report = fs.verify_entries([CROSS_SEGMENT_FILE])
    assert report.ok
    assert fs.stream.tell() == 4321


def test_ad1_verify_corrupt_compressed_content(segmented_copy: list[Path]) -> None:
    """Changing compressed bytes must not be reported as a digest match."""
    fs = AD1(segmented_copy)
    entry = fs.get(CROSS_SEGMENT_FILE)
    chunks = _chunk_offsets(fs, entry)
    target = chunks[len(chunks) // 2] + 10

    segment_idx = next(idx for idx, end in enumerate(fs._segment_offsets) if target < end)
    segment_start = 0 if segment_idx == 0 else fs._segment_offsets[segment_idx - 1]
    with segmented_copy[segment_idx].open("r+b") as fh:
        fh.seek(512 + target - segment_start)
        byte = fh.read(1)
        fh.seek(-1, 1)
        fh.write(bytes([byte[0] ^ 0xFF]))

    result = entry.verify()

    assert not result.ok
    assert result.status in (VerificationStatus.MISMATCH, VerificationStatus.INCOMPLETE)
    assert not any(digest.status == VerificationStatus.OK for digest in result.digests.values())
    assert result.failure_source is not None
    assert result.failure_segment == segment_idx
    assert result.failure_chunk is not None
    assert result.bytes_processed < result.declared_size


def test_ad1_verify_compressed_content_mismatch_after_recompression(tmp_path: Path) -> None:
    """A self-consistent but altered logical file must be reported as a mismatch."""
    path = tmp_path / "test.ad1"
    shutil.copyfile(absolute_path("_data/ad1/test.ad1"), path)

    fs = AD1(path)
    entry = fs.get("E:/AD1_test/doc2.txt")
    raw_entry = entry.entry
    fs.stream.seek(raw_entry.zlib_meta)
    chunk_offset = c_ad1.FileEntryChunks(fs.stream).chunks[0]
    compressed = fs.stream.readoffset(chunk_offset, raw_entry.meta - chunk_offset)
    data = bytearray(zlib.decompress(compressed))
    data[5] ^= 0xFF

    replacement = zlib.compress(bytes(data))
    assert len(replacement) <= len(compressed)
    replacement += b"\x00" * (len(compressed) - len(replacement))

    with path.open("r+b") as fh:
        fh.seek(512 + chunk_offset)
        fh.write(replacement)

    fs = AD1(path)
    result = fs.get("E:/AD1_test/doc2.txt").verify()

    assert result.status == VerificationStatus.MISMATCH
    assert result.read_complete
    assert result.bytes_processed == result.declared_size == 142
    assert result.digests["md5"].status == VerificationStatus.MISMATCH
    assert result.digests["sha1"].status == VerificationStatus.MISMATCH
    assert result.failure_source == "digest:md5,sha1"


def test_ad1_verify_modified_declared_size(segmented_copy: list[Path]) -> None:
    """The last chunk is cut to the declared length, so a larger declared size must fail."""
    fs = AD1(segmented_copy)
    entry = fs.get(CROSS_SEGMENT_FILE)
    _, metas = _read_metadata(fs, entry)

    _, size_offset, original = metas[c_ad1.MetaType.FileSize]
    _write_at(segmented_copy, fs._segment_offsets, size_offset, str(entry.size + 1).encode())

    result = entry.verify()

    assert not result.ok
    assert result.declared_size == entry.size + 1
    assert result.bytes_processed < result.declared_size
    assert result.status == VerificationStatus.INCOMPLETE
    assert "Incomplete read" in (result.error or "")
    assert not result.read_complete
    assert result.failure_source is not None

    _write_at(segmented_copy, fs._segment_offsets, size_offset, original)

    assert entry.verify().ok


def test_ad1_verify_modified_declared_digest(segmented_copy: list[Path]) -> None:
    fs = AD1(segmented_copy)
    entry = fs.get(CROSS_SEGMENT_FILE)
    _, metas = _read_metadata(fs, entry)

    _, sha1_offset, original = metas[c_ad1.MetaType.SHA1]
    replacement = hashlib.sha1(b"not the file").hexdigest().encode()
    _write_at(segmented_copy, fs._segment_offsets, sha1_offset, replacement)

    result = entry.verify()

    assert not result.ok
    assert result.status == VerificationStatus.MISMATCH
    assert result.digests["sha1"].status == VerificationStatus.MISMATCH
    assert result.digests["sha1"].expected == replacement.decode()
    assert result.digests["sha1"].actual == CROSS_SEGMENT_SHA1
    assert result.failure_source == "digest:sha1"
    assert result.bytes_processed == entry.size

    with pytest.raises(DigestMismatchError):
        result.raise_for_status()

    _write_at(segmented_copy, fs._segment_offsets, sha1_offset, original)

    assert entry.verify().ok


def test_ad1_verify_missing_digest(segmented_copy: list[Path]) -> None:
    fs = AD1(segmented_copy)
    entry = fs.get(CROSS_SEGMENT_FILE)
    raw_entry, metas = _read_metadata(fs, entry)

    # Unlink both digest metadata records from the chain so they are not declared.
    digest_offsets = {metas[c_ad1.MetaType.MD5][0], metas[c_ad1.MetaType.SHA1][0]}
    stream = fs.stream
    offset = raw_entry.meta
    while offset:
        stream.seek(offset)
        meta = c_ad1.FileMeta(stream)
        if meta.next in digest_offsets:
            _write_at(segmented_copy, fs._segment_offsets, offset, (0).to_bytes(8, "little"))
            break
        offset = meta.next
    else:
        raise AssertionError("digest metadata pointer not found")

    result = entry.verify()

    assert result.status == VerificationStatus.MISSING_DIGEST
    assert not result.ok
    assert result.failure_source == "metadata"
    assert result.bytes_processed == result.declared_size

    with pytest.raises(MissingDigestError):
        result.raise_for_status()


def test_ad1_verify_broken_metadata_is_not_missing_digest(segmented_copy: list[Path]) -> None:
    """A damaged metadata chain is an incomplete read, not evidence of an absent digest."""
    fs = AD1(segmented_copy)
    entry = fs.get(CROSS_SEGMENT_FILE)
    raw_entry, _ = _read_metadata(fs, entry)

    # Point the first metadata record beyond the container.
    _write_at(segmented_copy, fs._segment_offsets, raw_entry.meta, (fs.size + 1).to_bytes(8, "little"))

    result = entry.verify()

    assert not result.ok
    assert result.status == VerificationStatus.INCOMPLETE
    assert result.failure_source == "metadata"
    assert not any(digest.status == VerificationStatus.MISSING_DIGEST for digest in result.digests.values())


def test_ad1_verify_invalid_declared_size(segmented_copy: list[Path]) -> None:
    """A malformed declared size is an incomplete read, never a missing digest."""
    fs = AD1(segmented_copy)
    entry = fs.get(CROSS_SEGMENT_FILE)
    _, metas = _read_metadata(fs, entry)

    _, size_offset, original = metas[c_ad1.MetaType.FileSize]
    _write_at(segmented_copy, fs._segment_offsets, size_offset, b"84594x")

    result = entry.verify()

    assert not result.ok
    assert result.status == VerificationStatus.INCOMPLETE
    assert result.failure_source == "metadata:FileSize"
    assert result.bytes_processed == 0
    assert not result.read_complete

    _write_at(segmented_copy, fs._segment_offsets, size_offset, original)

    assert entry.verify().ok


def test_ad1_verify_invalid_digest(segmented_copy: list[Path]) -> None:
    fs = AD1(segmented_copy)
    entry = fs.get(CROSS_SEGMENT_FILE)
    _, metas = _read_metadata(fs, entry)

    _, md5_offset, original = metas[c_ad1.MetaType.MD5]
    replacement = b"not-a-valid-md5-digest-value-000"

    assert len(replacement) == 32
    _write_at(segmented_copy, fs._segment_offsets, md5_offset, replacement)

    result = entry.verify()

    assert result.status == VerificationStatus.INVALID_DIGEST
    assert not result.ok
    assert result.failure_source == "metadata:md5"
    assert result.digests["md5"].status == VerificationStatus.INVALID_DIGEST

    with pytest.raises(InvalidDigestError):
        result.raise_for_status()

    _write_at(segmented_copy, fs._segment_offsets, md5_offset, original)

    assert entry.verify().ok


def test_ad1_verify_incomplete_does_not_claim_match(
    segmented_copy: list[Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    fs = AD1(segmented_copy)
    entry = fs.get(CROSS_SEGMENT_FILE)

    original_read = fs.stream.read
    shortened = False

    def short_read(length: int = -1) -> bytes:
        nonlocal shortened
        if not shortened and length > 1024:
            shortened = True
            return original_read(length - 1)
        return original_read(length)

    monkeypatch.setattr(fs.stream, "read", short_read)

    result = entry.verify()

    assert not result.ok
    assert result.status == VerificationStatus.INCOMPLETE
    assert not any(digest.status == VerificationStatus.OK for digest in result.digests.values())
    assert not result.read_complete
    assert result.bytes_processed < result.declared_size
    assert result.failure_source is not None

    with pytest.raises(IncompleteReadError):
        result.raise_for_status()


def test_ad1_verify_missing_digest_algorithm_specific(segmented_copy: list[Path]) -> None:
    fs = AD1(segmented_copy)
    entry = fs.get(CROSS_SEGMENT_FILE)

    assert entry.verify(algorithm="sha1").ok
    assert entry.verify(algorithm="md5").ok

    with pytest.raises(ValueError, match="Unsupported digest algorithm"):
        entry.verify(algorithm="sha256")


def test_ad1_verify_algorithm_specific_missing(segmented_copy: list[Path]) -> None:
    """Requesting an unsupported-by-declaration algorithm must not pass via another digest."""
    fs = AD1(segmented_copy)
    entry = fs.get(CROSS_SEGMENT_FILE)
    raw_entry, metas = _read_metadata(fs, entry)

    # Unlink the SHA1 record only; MD5 remains declared.
    sha1_offset = metas[c_ad1.MetaType.SHA1][0]
    stream = fs.stream
    offset = raw_entry.meta
    while offset:
        stream.seek(offset)
        meta = c_ad1.FileMeta(stream)
        if meta.next == sha1_offset:
            _write_at(segmented_copy, fs._segment_offsets, offset, (0).to_bytes(8, "little"))
            break
        offset = meta.next
    else:
        raise AssertionError("SHA1 pointer not found")

    assert entry.verify(algorithm="md5").ok
    result = entry.verify(algorithm="sha1")

    assert not result.ok
    assert result.status == VerificationStatus.MISSING_DIGEST
    assert "md5" not in result.digests


def test_ad1_verify_report_isolates_failures(segmented_copy: list[Path]) -> None:
    fs = AD1(segmented_copy)

    report = fs.verify_all()

    assert report.ok
    assert report.total == 8
    assert report.failed == 0

    # Corrupt one file's declared SHA1, leave the rest intact.
    entry = fs.get(CROSS_SEGMENT_FILE)
    _, metas = _read_metadata(fs, entry)
    _, sha1_offset, _ = metas[c_ad1.MetaType.SHA1]
    _write_at(segmented_copy, fs._segment_offsets, sha1_offset, b"0" * 40)

    report = fs.verify_all()

    assert not report.ok
    assert report.total == 8
    assert report.failed == 1
    assert report.passed == 7
    assert report[f"/{CROSS_SEGMENT_FILE}"].status == VerificationStatus.MISMATCH
    assert all(result.ok for result in report if result.path != f"/{CROSS_SEGMENT_FILE}")


def test_ad1_verify_entries_reports_each_file(segmented_copy: list[Path]) -> None:
    fs = AD1(segmented_copy)
    paths = [
        "C:/Users/pcbje/Desktop/Data/Pictures/2-0-826-Desert.jpg",
        "C:/Users/pcbje/Desktop/Data/Pictures/5-0-762-Koala.jpg",
    ]

    report = fs.verify_entries(paths)

    assert report.total == 2
    assert report.ok
    assert {result.path for result in report} == {f"/{path}" for path in paths}
    assert sum(result.bytes_processed for result in report) == 845941 + 780831

    # A bad path must not turn the other entry into a failure.
    report = fs.verify_entries([paths[0], "C:/does/not/exist"])

    assert report.total == 2
    assert not report.ok
    assert report.passed == 1
    assert report.failed == 1
    assert report.results[0].ok


def test_ad1_verify_entries_type() -> None:
    fs = AD1(absolute_path("_data/ad1/test.ad1"))
    entry = fs.get("E:/AD1_test/doc1.txt")

    report = fs.verify_entries([entry])

    assert report.total == 1
    assert report[0].ok
    assert report[0].path == "/E:/AD1_test/doc1.txt"


def test_ad1_verify_empty_file_and_directory(segmented_copy: list[Path]) -> None:
    fs = AD1(segmented_copy)
    pictures = fs.get("C:/Users/pcbje/Desktop/Data/Pictures")

    with pytest.raises(IsADirectoryError):
        pictures.verify()


def test_ad1_verify_result_shape(segmented_copy: list[Path]) -> None:
    fs = AD1(segmented_copy)
    result = verify_file(fs.get(CROSS_SEGMENT_FILE))

    payload = result.to_dict()
    assert payload["status"] == "ok"
    assert payload["bytes_processed"] == 845941
    assert payload["segments"] == [0, 1]
    assert payload["digests"]["sha1"]["actual"] == CROSS_SEGMENT_SHA1
    assert isinstance(payload["chunks"], int)
    assert payload["failure_source"] is None


def test_ad1_verify_paths_are_stable(segmented_copy: list[Path]) -> None:
    fs = AD1(segmented_copy)
    entry = fs.get(CROSS_SEGMENT_FILE)
    assert _entry_path(entry) == f"/{CROSS_SEGMENT_FILE}"

    report = fs.verify_all()
    assert f"/{CROSS_SEGMENT_FILE}" in [result.path for result in report]
