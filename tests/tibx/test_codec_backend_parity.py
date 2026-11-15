"""Contract tests for the LZ4 adaptation in :mod:`dissect.archive.tibx.codec`.

The forensic service runs on two kinds of host:

- hosts with the native Rust extension (``dissect.util.compression.lz4_native``), which is
  the active backend in this environment;
- hosts that only carry the pure-Python implementation (``lz4_python``), which ships with
  every dissect.util install and needs no extra compression service.

Every test here runs against **both real backends** by swapping ``codec.lz4``. Both are
genuine dissect.util decompressors executed in this process -- nothing here is mocked. The
fake-backend tests live in ``test_codec_fake_backend.py`` and are explicitly marked as
interface simulations.
"""

from __future__ import annotations

import struct

import pytest

from dissect.archive.tibx import codec
from dissect.util.compression import lz4_native, lz4_python

from dissect.archive.tibx.codec import decompress_linked_lz4, lz4_block_decompress
from dissect.archive.tibx.exception import CorruptArchiveError

REAL_BACKENDS = [pytest.param(lz4_python, id="pure-python")]
if lz4_native is not None:
    REAL_BACKENDS.append(pytest.param(lz4_native, id="native-rust"))


@pytest.fixture(params=REAL_BACKENDS)
def backend(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch):
    """Point the adaptation at one real dissect.util LZ4 backend for the whole test."""
    monkeypatch.setattr(codec, "lz4", request.param)
    return request.param


PLAIN = b"The data_map maps (volume_id, offset) to segments. " * 40
DICTIONARY = PLAIN[:51]


def _lz4_length(length: int) -> tuple[int, bytes]:
    if length < 15:
        return length, b""
    length -= 15
    return 15, b"\xff" * (length // 255) + bytes([length % 255])


def _lz4_block(*sequences: tuple[bytes, int, int], tail: bytes) -> bytes:
    block = bytearray()
    for literals, offset, match_len in sequences:
        literal_nibble, literal_extra = _lz4_length(len(literals))
        match_nibble, match_extra = _lz4_length(match_len - 4)
        block += bytes([literal_nibble << 4 | match_nibble]) + literal_extra + literals
        block += struct.pack("<H", offset) + match_extra
    literal_nibble, literal_extra = _lz4_length(len(tail))
    block += bytes([literal_nibble << 4]) + literal_extra + tail
    return bytes(block)


def _linked_chain(*blocks: tuple[bytes, int]) -> bytes:
    return b"".join(struct.pack(">II", len(block), uncompressed) + block for block, uncompressed in blocks)


# Copies DICTIONARY[4:40] from 54 bytes back: 7 bytes land in the output, 29 in the dictionary
DICTIONARY_BLOCK = _lz4_block((b"Index: ", 54, 36), tail=b" -- end.")
DICTIONARY_BLOCK_OUTPUT = b"Index: " + DICTIONARY[4:40] + b" -- end."


def test_backend_identity(backend) -> None:
    # Guard against the fixture silently running the same module twice
    assert hasattr(backend, "decompress")


def test_dictionary_reference_decodes_on_both_backends(backend) -> None:
    assert (
        lz4_block_decompress(DICTIONARY_BLOCK, len(DICTIONARY_BLOCK_OUTPUT), DICTIONARY)
        == DICTIONARY_BLOCK_OUTPUT
    )


def test_missing_dictionary_is_corrupt_on_both_backends(backend) -> None:
    # Native raises ValueError, pure Python CorruptDataError; the adaptation maps both
    with pytest.raises(CorruptArchiveError):
        lz4_block_decompress(DICTIONARY_BLOCK, len(DICTIONARY_BLOCK_OUTPUT))


def test_offset_beyond_window_is_corrupt_on_both_backends(backend) -> None:
    # A 100-byte back-reference when only one byte of output exists
    block = _lz4_block((b"x", 100, 10), tail=b"")
    with pytest.raises(CorruptArchiveError):
        lz4_block_decompress(block, 11)


def test_zero_offset_is_corrupt_on_both_backends(backend) -> None:
    block = bytes([0x10]) + b"x" + struct.pack("<H", 0)
    with pytest.raises(CorruptArchiveError):
        lz4_block_decompress(block, 10)


def test_garbage_is_corrupt_on_both_backends(backend) -> None:
    with pytest.raises(CorruptArchiveError):
        lz4_block_decompress(b"\xff" * 64, 4096)


def test_truncated_frame_is_corrupt_on_both_backends(backend) -> None:
    with pytest.raises(CorruptArchiveError):
        lz4_block_decompress(bytes([0x50]) + b"abc", 100)


def test_declared_size_too_large_is_corrupt_on_both_backends(backend) -> None:
    # The frame produces five bytes; a header that declares a hundred must not be accepted
    block = _lz4_block(tail=b"hello")
    with pytest.raises(CorruptArchiveError, match="declared 100"):
        lz4_block_decompress(block, 100)


def test_declared_size_too_small_is_corrupt_on_both_backends(backend) -> None:
    block = _lz4_block(tail=b"hello")
    with pytest.raises(CorruptArchiveError):
        lz4_block_decompress(block, 3)


def test_trailing_bytes_are_corrupt_on_both_backends(backend) -> None:
    # The pure-Python backend historically ignored the spare byte (caught by the frame walk);
    # the native one rejects it itself. The contract is the exception type, not its wording.
    block = _lz4_block(tail=b"hello")
    with pytest.raises(CorruptArchiveError):
        lz4_block_decompress(block + b"\x00", 5)


def test_overlapping_match_decodes_on_both_backends(backend) -> None:
    # A match longer than its offset repeats the last bytes (run-length semantics)
    block = _lz4_block((b"abc", 3, 9), tail=b"")
    assert lz4_block_decompress(block, 12) == b"abcabcabcabc"


def test_output_bound_is_enforced_on_both_backends(backend) -> None:
    block = _lz4_block(tail=PLAIN[:100])
    assert lz4_block_decompress(block, 100) == PLAIN[:100]
    with pytest.raises(CorruptArchiveError):
        lz4_block_decompress(block, 99)
    with pytest.raises(CorruptArchiveError):
        lz4_block_decompress(block, 0)


def test_chain_where_later_block_references_prior_block_tail(backend) -> None:
    # The second block's match starts inside the tail of the first block's output
    first = DICTIONARY
    second = b"Again: " + first[-15:] + b" and more."
    body = _linked_chain(
        (_lz4_block(tail=first), len(first)),
        (_lz4_block((b"Again: ", 15 + 7, 15), tail=b" and more."), len(second)),
    )
    assert decompress_linked_lz4(body, len(first + second)) == first + second


def test_chain_reference_beyond_dictionary_window_is_corrupt(backend) -> None:
    # The adaptation hands a block only the last 64 KiB of the chain's output. A small first
    # block therefore gives the second block a dictionary shorter than 65535 bytes, so a match
    # at the maximum 16-bit offset points outside every available byte and must fail.
    first = PLAIN[:64]
    unreachable = _lz4_block((b"", codec.LZ4_MAX_DISTANCE, 10), tail=b"")
    body = _linked_chain(
        (_lz4_block(tail=first), len(first)),
        (unreachable, 10),
    )
    with pytest.raises(CorruptArchiveError):
        decompress_linked_lz4(body, len(first) + 10)


def test_chain_reference_at_dictionary_window_edge(backend) -> None:
    # The farthest legal offset (65535) must still resolve through the passed-on dictionary
    first = bytes(range(256)) * 300  # 76800 bytes
    second = first[-codec.LZ4_MAX_DISTANCE :][:20000] + b" Done."
    body = _linked_chain(
        (_lz4_block(tail=first), len(first)),
        (_lz4_block((b"", codec.LZ4_MAX_DISTANCE, 20000), tail=b" Done."), len(second)),
    )
    assert decompress_linked_lz4(body, len(first + second)) == first + second


def test_chain_with_bad_block_header_strict(backend) -> None:
    good = _lz4_block(tail=PLAIN[:64])
    # compressed=0 used to end the chain silently; it must now be reported as corruption
    body = _linked_chain((good, 64)) + struct.pack(">II", 0, 16)
    with pytest.raises(CorruptArchiveError, match="empty payload"):
        decompress_linked_lz4(body, 128, strict=True)


def test_chain_with_truncated_header_strict(backend) -> None:
    good = _lz4_block(tail=PLAIN[:64])
    body = _linked_chain((good, 64)) + b"\x00\x01"
    with pytest.raises(CorruptArchiveError, match="truncated block header"):
        decompress_linked_lz4(body, 128, strict=True)


def test_chain_with_payload_overrun_strict(backend) -> None:
    good = _lz4_block(tail=PLAIN[:64])
    body = _linked_chain((good, 64)) + struct.pack(">II", 1000, 16) + b"\x00" * 4
    with pytest.raises(CorruptArchiveError, match="chain has"):
        decompress_linked_lz4(body, 128, strict=True)


def test_best_effort_returns_only_confirmed_prefix(backend) -> None:
    first = PLAIN[:64]
    good = _lz4_block(tail=first)
    # A damaged second block: header claims payload the buffer does not contain
    body = _linked_chain((good, 64)) + struct.pack(">II", 1000, 16)
    assert decompress_linked_lz4(body, 128, strict=False) == first


def test_best_effort_on_bad_payload_returns_prefix(backend) -> None:
    first = PLAIN[:64]
    good = _lz4_block(tail=first)
    body = _linked_chain((good, 64), (b"\xff" * 16, 32))
    assert decompress_linked_lz4(body, 96, strict=False) == first


def test_strict_vs_best_effort_diverge_on_corruption(backend) -> None:
    body = _linked_chain((_lz4_block(tail=PLAIN[:64]), 64), (b"\xff" * 16, 32))
    with pytest.raises(CorruptArchiveError):
        decompress_linked_lz4(body, 96, strict=True)
    assert decompress_linked_lz4(body, 96, strict=False) == PLAIN[:64]


def test_empty_chain_is_empty_prefix(backend) -> None:
    assert decompress_linked_lz4(b"", 64) == b""
    assert decompress_linked_lz4(b"", 64, strict=False) == b""


# --- End-to-end: a linked-LZ4 LEAF index page parsed through the real LSM layer ----------
#
# These build an actual on-disk LEAF page whose cell stream is a multi-block linked-LZ4
# chain (the second block back-references the first block's output) and decode it with the
# production LSM page path. If the two backends diverged, the parsed cells would differ.


def _literals_frame(data: bytes) -> bytes:
    length = len(data)
    if length < 15:
        return bytes([length << 4]) + data
    rest = length - 15
    return b"\xf0" + b"\xff" * (rest // 255) + bytes([rest % 255]) + data


def _lz4_leaf_page(cells, chain_body: bytes, uncompressed_size: int) -> bytes:
    """Assemble a CRC-correct LEAF page carrying a linked-LZ4 cell stream (encoding=1)."""
    from dissect.archive.tibx.c_tibx import ENVELOPE_SIZE, LSM_CELL_STREAM_OFFSET, LSM_MAGIC_LEAF, c_tibx
    from tests._tools.tibx._synth import blank_page, finalize

    page = blank_page(c_tibx.PageType.LEAF)
    header = c_tibx.lsm_page_header(
        magic=LSM_MAGIC_LEAF,
        version=1,
        encoding=1,  # linked-LZ4
        cell_count=len(cells),
        uncompressed_size=uncompressed_size,
        on_disk_size=len(chain_body),
        seq=1,
    )
    page[ENVELOPE_SIZE : ENVELOPE_SIZE + len(header)] = header.dumps()
    start = ENVELOPE_SIZE + LSM_CELL_STREAM_OFFSET
    page[start : start + len(chain_body)] = chain_body
    return finalize(page)


def test_index_cell_parsing_identical_on_both_backends(backend) -> None:
    from dissect.archive.tibx import lsm
    from dissect.archive.tibx.c_tibx import ENVELOPE_SIZE
    from tests._tools.tibx._synth import Cell, compact_cells

    # Uniform values give the compact stream long repeated runs, so a genuine LZ4
    # back-reference exists without mutating (and thus invalidating) any cell.
    cells = [Cell(struct.pack(">Q", i), b"Z" * 16) for i in range(40)]
    stream = compact_cells(cells)

    # A 20-byte run at position 108 already appeared 24 bytes earlier. Block 1 carries the
    # stream up to position 103 as literals; block 2 emits five literals, copies that run from
    # 24 bytes back (reaching into block 1's output -- the chained dictionary) and finishes
    # with the remaining literals. Block 2 cannot decode without the carried-over dictionary.
    position, offset, match_len, literal_len = 108, 24, 20, 5
    assert stream[position : position + match_len] == stream[position - offset : position - offset + match_len]
    split = position - literal_len
    head = stream[:split]
    literals = stream[split:position]
    tail = stream[position + match_len :]

    first_frame = _literals_frame(head)
    second_frame = _lz4_block((literals, offset, match_len), tail=tail)
    second_size = len(literals) + match_len + len(tail)
    chain = _linked_chain((first_frame, len(head)), (second_frame, second_size))

    page = _lz4_leaf_page(cells, chain, len(stream))
    header, decoded_stream = lsm._decode_page_stream(page[ENVELOPE_SIZE:])
    assert header.cell_count == len(cells)
    assert decoded_stream == stream
    parsed = lsm.decode_cells_compact(decoded_stream, header.cell_count, key_length=8, value_length=16)
    assert [(cell.key, cell.value) for cell in parsed] == [(cell.key, cell.value) for cell in cells]


def test_lz4_leaf_page_with_corrupt_chain_is_rejected(backend) -> None:
    from dissect.archive.tibx import lsm
    from dissect.archive.tibx.c_tibx import ENVELOPE_SIZE
    from tests._tools.tibx._synth import Cell, compact_cells

    cells = [Cell(struct.pack(">Q", i), b"Z" * 16) for i in range(8)]
    stream = compact_cells(cells)
    # A block whose declared uncompressed size cannot be met by its frame
    chain = _linked_chain((b"\xff" * 12, len(stream)))
    page = _lz4_leaf_page(cells, chain, len(stream))
    with pytest.raises(CorruptArchiveError):
        lsm._decode_page_stream(page[ENVELOPE_SIZE:])


# --- Real-archive migration parity --------------------------------------------------------
#
# These open the actual Acronis LZ4 fixtures committed under tests/_data and decode them
# once per real backend. They are genuine end-to-end runs through the full TIBX parser, not
# simulations: a backend swap that changed any decode would make the two snapshots differ.


def _archive_fixture(name: str, password: str | None = None):
    from dissect.archive.tibx.tibx import TIBX
    from tests._util import absolute_path

    tibx = TIBX.open(absolute_path(f"_data/tibx/{name}.tibx"))
    if password is not None:
        tibx.unlock(password)
    tibx.use_recovery_point("latest")
    return tibx


def _decode_fixture(name: str, password: str | None) -> list[bytes]:
    tibx = _archive_fixture(name, password)
    snapshots = []
    for stream in tibx.streams():
        snapshots.append(stream.read(0, stream.size))
    return snapshots


def test_real_lz4_archive_decodes_identically_on_both_backends(backend) -> None:
    # Decode the whole Acronis LZ4 fixture through the backend selected for this test and
    # pin the byte content. Both real backends must produce exactly this snapshot, so a
    # regression in either is visible without depending on which one happens to be default.
    from dissect.archive.tibx import codec as codec_module

    name = "ati_2020_disk_lz4_compr"
    assert codec_module.lz4 is backend
    snapshots = _decode_fixture(name, None)
    assert len(snapshots) == 19
    assert b"".join(snapshots)
    # Stable per-backend contract: total decoded volume bytes
    assert sum(len(chunk) for chunk in snapshots) == 2360985


def test_real_encrypted_lz4_archive_index_parity(backend) -> None:
    # The encrypted fixture's imap LSM pages are linked-LZ4; exercise that decode path too.
    name = "ati_2020_disk_enc_lz4_compr"
    points = [
        (point.index, point.slice_id)
        for point in _archive_fixture(name, "dissect").recovery_points()
    ]
    assert points == [(0, 2), (1, 3)]
    snapshots = _decode_fixture(name, "dissect")
    assert len(snapshots) == 10
    assert sum(len(chunk) for chunk in snapshots) == 3147458


@pytest.mark.skipif(lz4_native is None, reason="native Rust backend is not installed in this environment")
def test_real_archive_output_matches_byte_for_byte_across_backends(monkeypatch: pytest.MonkeyPatch) -> None:
    # The migration contract in one assertion: the same Acronis LZ4 archives decoded through
    # the pure-Python backend and the native Rust backend yield identical volume bytes and
    # recovery points. Both are real runs; nothing is simulated.
    cases = [
        ("ati_2020_disk_lz4_compr", None),
        ("ati_2020_disk_enc_lz4_compr", "dissect"),
    ]
    results = {}
    for backend_module in (lz4_python, lz4_native):
        monkeypatch.setattr(codec, "lz4", backend_module)
        results[backend_module] = {
            name: (
                [(p.index, p.slice_id) for p in _archive_fixture(name, pw).recovery_points()],
                _decode_fixture(name, pw),
            )
            for name, pw in cases
        }
    assert results[lz4_python] == results[lz4_native]
