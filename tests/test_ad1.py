from __future__ import annotations

import hashlib
import zlib
from datetime import datetime, timezone
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

import pytest

from dissect.evidence.ad1 import ad1
from dissect.evidence.ad1.ad1 import EntryType, MetaType, find_files
from dissect.evidence.ad1.verify import VerifyStatus, verify, verify_entry
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path


def test_ad1(ad1_basic: BinaryIO) -> None:
    """Test if we can parse a basic non-segmented AD1 file with no file hierarchy."""
    fs = ad1.AD1(ad1_basic)
    assert fs.segment(0).header.magic == b"ADSEGMENTEDFILE\x00"

    assert fs.root.is_dir()
    assert fs.root.listdir() == ["E:"]

    file = fs.get("E:/AD1_test/doc1.txt")
    assert file.is_file()
    assert file.size == 17
    assert file.atime == datetime(2017, 3, 31, 18, 2, 31, 189682, tzinfo=timezone.utc)
    assert file.open().read() == b"Inhoud document 1"


def test_ad1_long(ad1_long: BinaryIO) -> None:
    """Test if we can parse a basic non-segmented AD1 file with long file names."""
    fs = ad1.AD1(ad1_long)

    assert fs.segment(0).header.magic == b"ADSEGMENTEDFILE\x00"
    assert fs.root.is_dir()

    assert [file.name for file in fs.root.children] == ["E:"]

    assert [file.name for file in fs.get("E:").children] == [
        "testdatamap 2 met spaties en een heel stuk langer",
    ]

    assert [file.name for file in fs.get("E:/testdatamap 2 met spaties en een heel stuk langer").iterdir()] == [
        "een lange filenaam 1 met spaties.txt",
        "Een nog langere bestandsnaam met nog meer tekens en 12345.txt",
    ]

    entry = fs.get("E:/testdatamap 2 met spaties en een heel stuk langer").children[0]
    assert entry.name == "een lange filenaam 1 met spaties.txt"
    assert entry.open().read() == (
        b"masdhdslkfjasdfjlksadjflkjsda;lfj\r\nasdflk\r\na;lsdkf\r\n"
        b";lasdklf;lkasd\r\n;lk\r\nfask;ldkf\r\n;lka\r\nsd;lkf\r\n"
        b"asdfasdaflkjsd;lkg;dfshglkdksfhg;ljsdflgjs;dlkkjg'qwjer'pgtoks\r\n"
        b"ddasd'dgkls'dfkjg\r\nsd'g;lkksd'f';gkjsd\r\n[fkgli'erjrg';ksd\r\n"
        b"'g'asldjg';askg\r\nkqe\r\n-["
    )
    md5sum = hashlib.md5(entry.open().read())
    assert md5sum.hexdigest() == entry.md5


def test_ad1_compressed(ad1_compressed: BinaryIO) -> None:
    """Test if we can parse a non-segmented AD1 file with standard zlib compression."""
    fs = ad1.AD1(ad1_compressed)

    assert fs.segment(0).header.magic == b"ADSEGMENTEDFILE\x00"

    assert fs.get("/").listdir() == ["E:"]
    assert fs.get("E:/AD1_test").listdir() == ["doc1.txt", "doc2.txt"]
    assert fs.get("E:/AD1_test/doc1.txt").open().read() == b"Inhoud document 1"


@pytest.mark.parametrize(
    ("path", "expected_files"),
    [
        pytest.param(
            "_data/ad1/pcbje/text-and-pictures.ad1",
            [
                "text-and-pictures.ad1",
                "text-and-pictures.ad2",
                "text-and-pictures.ad3",
                "text-and-pictures.ad4",
            ],
            id="segmented-simple",
        ),
        pytest.param(
            "_data/ad1/encrypted-passphrase/encrypted.ad1",
            [
                "encrypted.ad1",
                "encrypted.ad2",
                "encrypted.ad3",
                "encrypted.ad4",
                "encrypted.ad5",
                "encrypted.ad6",
                "encrypted.ad7",
                "encrypted.ad8",
                "encrypted.ad9",
                "encrypted.ad10",
                "encrypted.ad11",
                "encrypted.ad12",
                "encrypted.ad13",
            ],
            id="segmented-natural-sorting",
        ),
    ],
)
def test_ad1_find_files(path: str, expected_files: list[str]) -> None:
    """Test if we correctly find and order segmented AD1 files and do not find .txt or .csv artifact files."""
    files = find_files(absolute_path(path))
    assert [file.name for file in files] == expected_files


def test_ad1_segmented(ad1_segmented: list[Path]) -> None:
    """Test if we can parse segmented AD1 files.

    References:
        - https://github.com/pcbje/pyad1/tree/master/test_data
    """
    fs = ad1.AD1(ad1_segmented)

    assert len(fs.fh) == 4
    assert fs.segment(0).number == 1
    assert fs.segment(0).count == 4
    assert fs.segment(0).size == 0x200000 - 512

    assert fs.logical_image.version == 4
    assert fs.logical_image.name == "C:\\Users\\pcbje\\Desktop\\Data"

    dir = fs.get("C:/Users/pcbje/Desktop/Data/Pictures")
    assert dir.is_dir()
    assert not dir.is_symlink()
    assert not dir.is_file()
    assert dir.name == "Pictures"
    assert dir.type == EntryType.Directory
    assert dir.size == 0
    assert dir.btime == datetime(2018, 5, 2, 7, 34, 11, 284926, tzinfo=timezone.utc)
    assert dir.mtime == datetime(2018, 5, 2, 7, 42, 39, 841574, tzinfo=timezone.utc)
    assert dir.ctime == datetime(2018, 5, 2, 7, 42, 39, 841574, tzinfo=timezone.utc)
    assert dir.atime == datetime(2018, 5, 2, 7, 46, 59, 164650, tzinfo=timezone.utc)
    assert dir.listdir() == [
        "0-0-581-Hydrangeas.jpg",
        "1-0-858-Chrysanthemum.jpg",
        "2-0-826-Desert.jpg",
        "4-0-757-Jellyfish.jpg",
        "5-0-762-Koala.jpg",
        "6-0-548-Lighthouse.jpg",
        "7-0-759-Penguins.jpg",
    ]

    picture = fs.get("C:/Users/pcbje/Desktop/Data/Pictures/5-0-762-Koala.jpg")
    assert picture.is_file()
    assert not picture.is_dir()
    assert not picture.is_symlink()
    assert picture.btime == datetime(2018, 1, 28, 7, 18, 0, tzinfo=timezone.utc)
    assert picture.mtime == datetime(2018, 5, 2, 7, 42, 34, 287014, tzinfo=timezone.utc)
    assert picture.ctime == datetime(2018, 5, 2, 7, 42, 34, 287014, tzinfo=timezone.utc)
    assert picture.atime == datetime(2018, 5, 2, 7, 42, 35, 611785, tzinfo=timezone.utc)

    buf = picture.open().read()
    assert picture.name == "5-0-762-Koala.jpg"
    assert picture.size == 780831
    assert len(buf) == 780831
    assert picture.sha1 == "9c3dcb1f9185a314ea25d51aed3b5881b32f420c"
    assert hashlib.sha1(buf).hexdigest() == "9c3dcb1f9185a314ea25d51aed3b5881b32f420c"


def test_ad1_segmented_find_files(ad1_segmented: list[Path]) -> None:
    """Test that providing a single segment file finds all segments in the same directory."""
    fs = ad1.AD1(ad1_segmented[0])

    assert fs.fh == ad1_segmented


def test_ad1_close_with_fh(ad1_basic: BinaryIO) -> None:
    """Verify that AD1 does not close file-like objects passed to it."""
    fs = ad1.AD1(ad1_basic)
    assert len(fs._segments) == 1
    assert fs._segment_lru == [0]

    fs.close()
    assert fs._segments == {}
    assert fs._segment_lru == []

    # The file-like object passed to AD1 should not be closed by AD1
    assert not ad1_basic.closed


def test_ad1_close_with_paths(ad1_segmented: list[Path]) -> None:
    """Verify that AD1 closes file handles opened from paths."""
    fs = ad1.AD1(ad1_segmented)

    num_segments = len(fs._segments)
    assert num_segments > 0

    # Store references to all file handles
    fhs = [fs._segments[idx].fh for idx in range(num_segments)]

    fs.close()

    # Verify all file handles are closed
    for fh in fhs:
        assert fh.closed
    assert fs._segments == {}
    assert fs._segment_lru == []


def test_ad1_context_manager_with_fh(ad1_basic: BinaryIO) -> None:
    """Verify context manager closes AD1 but not the file-like object passed to it."""
    with ad1.AD1(ad1_basic) as fs:
        assert isinstance(fs, ad1.AD1)

    assert fs._segments == {}
    assert fs._segment_lru == []

    # The file-like object should not be closed by AD1's context manager
    assert not ad1_basic.closed


def test_adcrypt_passphrase(ad1_encrypted_passphrase: list[Path]) -> None:
    """Test if we can decrypt ADCRYPT AD1 images, in this example a segmented AD1 logical image."""
    fs = ad1.AD1(ad1_encrypted_passphrase)

    assert fs.is_adcrypt()
    assert fs.is_locked()

    with pytest.raises(ValueError, match="AD1 container is locked by ADCRYPT"):
        fs.get("/")

    with pytest.raises(ValueError, match="Unable to unlock: HMAC verification of passphrase failed"):
        fs.unlock(passphrase="asdf")

    fs.unlock(passphrase="password")

    assert fs.adcrypt.key.hex() == "9030a43f29689a045e815cf4f0ad82b68850063b414f2797f0897e188f98d7b4"

    assert fs.get("C:/Users/User/Downloads").listdir() == [
        "7z2501-x64.exe",
        "desktop.ini",
        "Exterro_FTK_Imager_(x64)-4.7.3.81.exe",
        "hans-veth-8y--BAFlC9c-unsplash.jpg",
        "marc-olivier-jodoin-tauPAnOIGvE-unsplash.jpg",
        "marek-szturc-8Ou3EZmTMWA-unsplash.jpg",
        "milo-weiler-1AIYdIb3O5M-unsplash.jpg",
    ]

    for file in fs.get("C:/Users/User/Downloads").iterdir():
        buf = file.open().read()
        assert len(buf) == file.size
        assert hashlib.sha1(buf).hexdigest() == file.sha1


def test_adcrypt_certificate(ad1_encrypted_certificate: list[Path]) -> None:
    """Test if we can decrypt ADCRYPT AD1 images, in this example a segmented AD1 logical image."""
    fs = ad1.AD1(ad1_encrypted_certificate)

    assert fs.is_adcrypt()
    assert fs.is_locked()

    with pytest.raises(ValueError, match="AD1 container is locked by ADCRYPT"):
        fs.get("/")

    with pytest.raises(ValueError, match="Unable to unlock: HMAC verification of passphrase failed"):
        fs.unlock(passphrase="asdf")

    fs.unlock(private_key=absolute_path("_data/ad1/encrypted-certificate/key"))

    assert fs.adcrypt.key.hex() == "6cc0a9f94f944381cc51be474e5da6178059324bb457a87e0035b80f80ff9d4b"

    assert fs.get("C:/Users/User/Downloads").listdir() == [
        "desktop.ini",
        "hans-veth-8y--BAFlC9c-unsplash.jpg",
        "key.pem",
        "marc-olivier-jodoin-tauPAnOIGvE-unsplash.jpg",
        "marek-szturc-8Ou3EZmTMWA-unsplash.jpg",
        "milo-weiler-1AIYdIb3O5M-unsplash.jpg",
        "programs",
    ]

    for file in fs.get("C:/Users/User/Downloads").iterdir():
        if file.is_dir():
            continue

        buf = file.open().read()
        assert len(buf) == file.size
        assert hashlib.sha1(buf).hexdigest() == file.sha1

    assert fs.get("C:/Users/User/Downloads/programs").listdir() == [
        "7z2501-x64.exe",
        "Exterro_FTK_Imager_(x64)-4.7.3.81.exe",
    ]


def test_ad1_segment_lru(ad1_segmented: list[Path], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ad1, "MAX_OPEN_SEGMENTS", 2)

    fs = ad1.AD1(ad1_segmented)
    assert fs._segment_lru == [3, 0]

    fs.segment(2)
    assert fs._segment_lru == [0, 2]

    fs.segment(1)
    assert fs._segment_lru == [2, 1]

    picture = fs.get("C:/Users/pcbje/Desktop/Data/Pictures/5-0-762-Koala.jpg")
    assert hashlib.sha1(picture.open().read()).hexdigest() == "9c3dcb1f9185a314ea25d51aed3b5881b32f420c"


def _tamper_ad1(data: bytes, offset: int, old: bytes, new: bytes) -> BytesIO:
    """Return a new AD1 file-like object with ``old`` at ``offset`` replaced by ``new``."""
    assert len(old) == len(new)
    assert data[offset : offset + len(old)] == old
    patched = bytearray(data)
    patched[offset : offset + len(old)] = new
    return BytesIO(bytes(patched))


def test_ad1_verify_multi_chunk(ad1_segmented: list[Path]) -> None:
    """Verify a file spanning multiple segments and compressed chunks against its declared hashes."""
    fs = ad1.AD1(ad1_segmented)

    entry = fs.get("C:/Users/pcbje/Desktop/Data/Text/norvig-big.txt")
    assert entry.size == 6488666
    assert entry.size > fs.logical_image.chunk_size
    assert entry.size > fs.segment(0).size

    results = verify_entry(entry)
    assert len(results) == 2
    assert {result.algorithm for result in results} == {"md5", "sha1"}
    for result in results:
        assert result.status is VerifyStatus.OK
        assert result.ok
        assert result.bytes_processed == entry.size
        assert result.actual == result.expected

    results = verify(fs)
    assert len(results) == 16
    assert all(result.ok for result in results)


def test_ad1_verify_preserves_stream_positions(ad1_basic: BinaryIO) -> None:
    """Verification must not disturb the caller's existing stream positions."""
    fs = ad1.AD1(ad1_basic)

    ad1_basic.seek(123)
    fs.stream.seek(456)

    results = verify(fs)
    assert results and all(result.ok for result in results)

    assert ad1_basic.tell() == 123
    assert fs.stream.tell() == 456


def test_ad1_verify_tampered_compressed_content() -> None:
    """Tampered compressed content must produce a content mismatch, not a copied-metadata pass."""
    data = absolute_path("_data/ad1/compressed.ad1").read_bytes()

    fs = ad1.AD1(BytesIO(data))
    entry = fs.get("E:/AD1_test/doc1.txt")
    stream = entry.open()
    chunk_start, chunk_end = stream.chunks[0], stream.chunks[1]

    # Segment 0 data starts after the 512 byte segment header
    compressed = data[512 + chunk_start : 512 + chunk_end]
    content = zlib.decompress(compressed)
    tampered = zlib.compress(b"Inhoud document X", 9).ljust(len(compressed), b"\x00")

    fh = _tamper_ad1(data, 512 + chunk_start, compressed, tampered)
    fs = ad1.AD1(fh)

    results = verify_entry(fs.get("E:/AD1_test/doc1.txt"))
    assert {result.status for result in results} == {VerifyStatus.MISMATCH}
    for result in results:
        assert not result.ok
        assert result.bytes_processed == result.size == len(content)
        assert result.actual != result.expected
        assert "declared" in result.source

    # The failure of doc1.txt must not affect the independent result of doc2.txt
    results = verify(fs)
    by_name = {}
    for result in results:
        by_name.setdefault(result.name, []).append(result)
    assert all(result.status is VerifyStatus.MISMATCH for result in by_name["E:/AD1_test/doc1.txt"])
    assert all(result.ok for result in by_name["E:/AD1_test/doc2.txt"])

    # Corrupt the compressed stream itself: the read error must surface as an incomplete read
    fh = _tamper_ad1(data, 512 + chunk_end - 1, compressed[-1:], bytes([compressed[-1] ^ 0xFF]))
    results = verify_entry(ad1.AD1(fh).get("E:/AD1_test/doc1.txt"))
    assert {result.status for result in results} == {VerifyStatus.INCOMPLETE_READ}
    assert all("read error" in result.source for result in results)


def test_ad1_verify_tampered_file_size() -> None:
    """A declared file size larger than the readable content must yield an incomplete read.

    The declared hashes still match the readable prefix exactly, so a partial read must never be
    reported as a hash match.
    """
    data = absolute_path("_data/ad1/compressed.ad1").read_bytes()

    fs = ad1.AD1(BytesIO(data))
    entry = fs.get("E:/AD1_test/doc1.txt")

    # FileMeta data starts 20 bytes into the record; segment 0 data starts after the 512 byte header
    size_offset = 512 + entry.meta[MetaType.FileSize].offset + 20
    fh = _tamper_ad1(data, size_offset, b"17", b"18")
    fs = ad1.AD1(fh)

    entry = fs.get("E:/AD1_test/doc1.txt")
    assert entry.size == 18

    results = verify_entry(entry)
    assert {result.status for result in results} == {VerifyStatus.INCOMPLETE_READ}
    for result in results:
        assert not result.ok
        assert result.size == 18
        assert result.bytes_processed == 17
        # The digest of the 17 readable bytes equals the declared hash, but the read is incomplete
        assert result.actual == result.expected


def test_ad1_verify_tampered_declared_hash() -> None:
    """Tampered declared hashes must be reported as mismatch, format error or missing."""
    data = absolute_path("_data/ad1/compressed.ad1").read_bytes()

    fs = ad1.AD1(BytesIO(data))
    entry = fs.get("E:/AD1_test/doc1.txt")
    md5_offset = 512 + entry.meta[MetaType.MD5].offset
    sha1_offset = 512 + entry.meta[MetaType.SHA1].offset

    # Declared hash no longer matches the content
    fh = _tamper_ad1(data, md5_offset + 20, b"8", b"0")
    results = verify_entry(ad1.AD1(fh).get("E:/AD1_test/doc1.txt"))
    by_algorithm = {result.algorithm: result for result in results}
    assert by_algorithm["md5"].status is VerifyStatus.MISMATCH
    assert by_algorithm["md5"].bytes_processed == 17
    assert by_algorithm["sha1"].status is VerifyStatus.OK

    # Declared hash with an invalid format
    fh = _tamper_ad1(data, md5_offset + 20, b"8", b"z")
    results = verify_entry(ad1.AD1(fh).get("E:/AD1_test/doc1.txt"))
    by_algorithm = {result.algorithm: result for result in results}
    assert by_algorithm["md5"].status is VerifyStatus.INVALID_HASH
    assert by_algorithm["md5"].bytes_processed == 0
    assert by_algorithm["sha1"].status is VerifyStatus.OK

    # No declared hashes at all: mask out the MD5 and SHA1 meta types
    fh = _tamper_ad1(data, md5_offset + 12, b"\x01\x50", b"\x99\x99")
    fh = _tamper_ad1(fh.getvalue(), sha1_offset + 12, b"\x02\x50", b"\x99\x99")
    results = verify_entry(ad1.AD1(fh).get("E:/AD1_test/doc1.txt"))
    assert len(results) == 1
    assert results[0].status is VerifyStatus.MISSING_HASH
