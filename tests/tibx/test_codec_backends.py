"""Contract tests for the LZ4 adapter in :mod:`dissect.archive.tibx.codec`.

``dissect.util`` ships two interchangeable LZ4 backends -- a native Rust module and a
pure-Python one -- and a deployment has whichever its platform got. They disagree on
malformed input: the exception type they raise, whether they stop at the declared size or
run to the end of the stream, and whether bytes after a complete block are an error. The
adapter must hide all of that.

These tests exercise the contract three ways:

* against each **real** backend present in this environment, monkeypatched into
  ``codec.lz4`` so the adapter path is what runs;
* against a **simulated** backend that implements only the documented interface and
  deliberately behaves unlike either real one. It is not a decoder and proves nothing
  about real LZ4 output; it only checks that the adapter neither depends on a backend's
  judgement nor passes malformed blocks to it;
* against the committed Acronis fixtures, pinning the normal index cells so an adapter
  change cannot silently alter what a valid archive parses to.

Nothing here needs a network or an external compression service: the only implementations
used are the two modules ``dissect.util`` already provides.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

import pytest

from dissect.archive.tibx import codec
from dissect.archive.tibx.c_tibx import LZ4_BLOCK_HEADER_SIZE
from dissect.archive.tibx.exception import CorruptArchiveError
from dissect.archive.tibx.lsm import iter_tree_cells
from dissect.archive.tibx.tibx import TIBX
from dissect.util.compression import lz4_native, lz4_python

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.archive.tibx.page import PageStore


PLAIN = b"The data_map maps (volume_id, offset) to segments. " * 40
DICTIONARY = PLAIN[:51]


# --- block encoders: the format's own vocabulary, so a test states what it means ---------


def _lz4_length(length: int) -> tuple[int, bytes]:
    """Split an LZ4 length into its token nibble and extension bytes."""
    if length < 15:
        return length, b""
    length -= 15
    return 15, b"\xff" * (length // 255) + bytes([length % 255])


class Sequence(NamedTuple):
    """One LZ4 sequence: literals, then a match of ``match_len`` bytes at ``offset``."""

    literals: bytes
    offset: int
    match_len: int


def _block(*sequences: Sequence, tail: bytes) -> bytes:
    """Encode a raw LZ4 block: sequences followed by the final, literal-only sequence."""
    block = bytearray()
    for sequence in sequences:
        literal_nibble, literal_extra = _lz4_length(len(sequence.literals))
        match_nibble, match_extra = _lz4_length(sequence.match_len - 4)
        block += bytes([literal_nibble << 4 | match_nibble]) + literal_extra + sequence.literals
        block += struct.pack("<H", sequence.offset) + match_extra
    literal_nibble, literal_extra = _lz4_length(len(tail))
    return bytes(block) + bytes([literal_nibble << 4]) + literal_extra + tail


def _chain(*blocks: tuple[bytes, int]) -> bytes:
    """Frame ``(payload, uncompressed_size)`` pairs as a linked-LZ4 chain."""
    return b"".join(struct.pack(">II", len(payload), size) + payload for payload, size in blocks)


# A block that starts with literals, then copies DICTIONARY[4:40] from 54 bytes back:
# 7 bytes from the output so far and 47 from the dictionary
DICTIONARY_BLOCK = _block(Sequence(b"Index: ", 54, 36), tail=b" -- end.")
DICTIONARY_OUTPUT = b"Index: " + DICTIONARY[4:40] + b" -- end."


def _real_backends() -> list[object]:
    return [(name, module) for name, module in (("native", lz4_native), ("python", lz4_python)) if module]


REAL_BACKENDS = pytest.mark.parametrize(
    ("backend_name", "backend"),
    _real_backends(),
    ids=[name for name, _ in _real_backends()],
)


@pytest.fixture()
def use_backend(monkeypatch: pytest.MonkeyPatch) -> Iterator[object]:
    """Return a function that makes ``codec`` use the given backend."""

    def select(backend: object) -> object:
        monkeypatch.setattr(codec, "lz4", backend)
        return backend

    return select


# --- the contract every backend must present ---------------------------------------------


class Case(NamedTuple):
    """One decode input and the exact result the adapter must produce."""

    args: tuple[bytes, int]
    kwargs: dict[str, bytes]
    output: bytes | type[CorruptArchiveError]


def _cases() -> list[Case]:
    return [
        # Valid blocks, with and without a window
        Case((_block(tail=b"abc"), 3), {}, b"abc"),
        Case((DICTIONARY_BLOCK, len(DICTIONARY_OUTPUT)), {"dictionary": DICTIONARY}, DICTIONARY_OUTPUT),
        # The declaration is larger than the block produces
        Case((_block(tail=b"abc"), 4), {}, CorruptArchiveError),
        # The declaration is smaller than the block produces
        Case((_block(tail=b"abc"), 2), {}, CorruptArchiveError),
        # Trailing bytes after a complete block are not part of it
        Case((_block(tail=b"abc") + b"\x00", 3), {}, CorruptArchiveError),
        Case((_block(tail=b"abc") + b"\x30def", 3), {}, CorruptArchiveError),
        # Truncation, at every point a sequence can be cut: after a match, inside a literal
        # run, before any token, and inside a length extension
        Case((_block(Sequence(b"abc", 3, 4), tail=b"")[:-1], 7), {}, CorruptArchiveError),
        Case((_block(tail=b"abcdef")[:3], 6), {}, CorruptArchiveError),
        Case((_block(tail=b"abcdef")[:1], 6), {}, CorruptArchiveError),
        Case((b"\xf0", 15), {}, CorruptArchiveError),
        # Illegal sequences
        Case((_block(Sequence(b"", 0, 4), tail=b"z"), 5), {}, CorruptArchiveError),
        Case((_block(Sequence(b"", 5, 4), tail=b"z"), 5), {}, CorruptArchiveError),
        Case((b"\x30\x00\x00", 5), {}, CorruptArchiveError),  # offset 0
        # A match that reaches further back than the supplied window
        Case((_block(Sequence(b"", 6, 4), tail=b"z"), 5), {"dictionary": b"abcde"}, CorruptArchiveError),
        # Empty and size-less declarations are refused before any backend is involved
        Case((b"", 1), {}, CorruptArchiveError),
        Case((_block(tail=b"abc"), 0), {}, CorruptArchiveError),
    ]


@REAL_BACKENDS
def test_block_contract_holds_for_each_real_backend(backend_name: str, backend: object, use_backend: object) -> None:
    """Both installed backends must produce the same result for every case, valid or not."""
    use_backend(backend)
    for case in _cases():
        src, size = case.args
        if isinstance(case.output, bytes):
            assert codec.lz4_block_decompress(src, size, **case.kwargs) == case.output, (backend_name, case)
        else:
            with pytest.raises(case.output):
                codec.lz4_block_decompress(src, size, **case.kwargs)


@pytest.mark.skipif(lz4_native is None or lz4_python is None, reason="needs both backends installed")
def test_real_backends_do_disagree() -> None:
    """Guard the premise: the raw backends really do differ, so the adapter is not a no-op.

    This asserts on the backend modules directly, not through the adapter. Both differences
    below were measured in this environment:

    * a block that declares one byte more than it holds: native refuses, Python returns the
      short result when the stream ends cleanly;
    * a complete block followed by a trailing byte: native refuses, Python accepts it at the
      declared size.

    If a future ``dissect.util`` makes them agree, this test says the normalization can be
    simplified; it is not the adapter that would need changing.
    """
    short_declaration = _block(tail=b"abc"), 4
    trailing_byte = _block(tail=b"abc") + b"\x00", 3

    def accepts(module: object, src: bytes, size: int) -> bool:
        try:
            module.decompress(src, size)
        except Exception:
            return False
        return True

    disagreeing = [
        (src, size)
        for src, size in (short_declaration, trailing_byte)
        if accepts(lz4_native, src, size) != accepts(lz4_python, src, size)
    ]
    assert disagreeing, "the backends agree now; the adapter's normalization may be simplifiable"


# --- linked chains: dictionary, window, strictness ---------------------------------------


@REAL_BACKENDS
def test_chain_uses_the_previous_blocks_tail_as_dictionary(
    backend_name: str, backend: object, use_backend: object
) -> None:
    use_backend(backend)
    first = DICTIONARY
    second = b"Again: " + first[:20] + b" and more."
    second_block = _block(Sequence(b"Again: ", len(first) + 7, 20), tail=b" and more.")
    body = _chain((_block(tail=first), len(first)), (second_block, len(second)))
    assert codec.decompress_linked_lz4(body, len(first + second)) == first + second


@REAL_BACKENDS
def test_chain_window_is_the_last_64_kib_only(backend_name: str, backend: object, use_backend: object) -> None:
    """A longer chain is still decodable: only the last 64 KiB is ever a dictionary."""
    use_backend(backend)
    first = bytes(range(256)) * 300  # 75 KiB
    # Reach exactly the farthest byte a 16-bit offset can address
    second = first[-codec.LZ4_MAX_DISTANCE :][:20000] + b" Done."
    body = _chain(
        (_block(tail=first), len(first)),
        (_block(Sequence(b"", codec.LZ4_MAX_DISTANCE, 20000), tail=b" Done."), len(second)),
    )
    assert codec.decompress_linked_lz4(body, len(first + second)) == first + second


@REAL_BACKENDS
def test_reference_past_the_window_is_rejected(backend_name: str, backend: object, use_backend: object) -> None:
    """A block cannot reach past the preceding output plus 64 KiB, whatever the backend says."""
    use_backend(backend)
    # A 16-bit offset cannot name more than 65535, so a chain's window is never longer
    # than that. The failure mode is the other way round: a block that reaches back
    # further than the output it is given, which includes the previous blocks' tail.
    first = b"A" * 100
    body = _chain(
        (_block(tail=first), len(first)),
        # Offset 60000 with only 100 bytes of prior output: beyond the reachable window
        (_block(Sequence(b"", 60000, 4), tail=b"BB"), len(b"BB") + 4),
    )
    with pytest.raises(CorruptArchiveError):
        codec.decompress_linked_lz4(body, len(first) + 6)


@REAL_BACKENDS
def test_declared_length_mismatch_is_not_accepted(backend_name: str, backend: object, use_backend: object) -> None:
    use_backend(backend)
    # Header says 1000 but the payload produces 1000 - the control
    payload = PLAIN[:1000]
    good = _chain((_block(tail=payload), len(payload)))
    assert codec.decompress_linked_lz4(good, 1000) == payload
    # Header overstates the block's output
    overstated = struct.pack(">II", len(_block(tail=payload)), 1001) + _block(tail=payload)
    with pytest.raises(CorruptArchiveError):
        codec.decompress_linked_lz4(overstated, 1001)
    # Header understates it
    understated = struct.pack(">II", len(_block(tail=payload)), 999) + _block(tail=payload)
    with pytest.raises(CorruptArchiveError):
        codec.decompress_linked_lz4(understated, 999)
    # The target bound forbids more output than the caller asked for
    with pytest.raises(CorruptArchiveError):
        codec.decompress_linked_lz4(good, 999)


@REAL_BACKENDS
def test_strict_and_best_effort_differ_only_in_raising(backend_name: str, backend: object, use_backend: object) -> None:
    use_backend(backend)
    first = b"first block"
    good_block, good_size = _block(tail=first), len(first)
    bad_block, bad_size = b"\xff" * 8, 8  # structurally impossible
    third = b"third block"
    body = _chain((good_block, good_size), (bad_block, bad_size), (_block(tail=third), len(third)))

    with pytest.raises(CorruptArchiveError):
        codec.decompress_linked_lz4(body, len(first + third), strict=True)
    # Best effort returns the prefix confirmed before the bad block, and does not resume
    # after it: skipping a bad block would invent a gap the archive never had
    assert codec.decompress_linked_lz4(body, len(first + third), strict=False) == first


@REAL_BACKENDS
def test_a_bad_block_is_never_treated_as_empty(backend_name: str, backend: object, use_backend: object) -> None:
    """A block with a payload but a zero size (or the reverse) is corruption, not a terminator."""
    use_backend(backend)
    good = _chain((_block(tail=b"abc"), 3))
    for malformed_header in (struct.pack(">II", 5, 3), struct.pack(">II", 0, 3), struct.pack(">II", 5, 0)):
        # Keep the payload so the framing has the length it claims
        body = good + malformed_header + b"abcde"
        with pytest.raises(CorruptArchiveError):
            codec.decompress_linked_lz4(body, 100)
        # Best effort stops and keeps only what was confirmed
        assert codec.decompress_linked_lz4(body, 100, strict=False) == b"abc"


@REAL_BACKENDS
def test_chain_with_non_zero_trailing_bytes_is_rejected(
    backend_name: str, backend: object, use_backend: object
) -> None:
    use_backend(backend)
    good = _chain((_block(tail=b"abc"), 3))
    # A zero header terminates the chain; zero padding after it is tolerated
    assert codec.decompress_linked_lz4(good + b"\x00" * LZ4_BLOCK_HEADER_SIZE, 3) == b"abc"
    # Any other byte is unaccounted-for damage
    with pytest.raises(CorruptArchiveError):
        codec.decompress_linked_lz4(good + b"\x00" * (LZ4_BLOCK_HEADER_SIZE - 1) + b"\x01", 3)
    with pytest.raises(CorruptArchiveError):
        codec.decompress_linked_lz4(good + b"\x00\x00\x00\x01\x00\x00\x00\x00", 3)


# --- a simulated backend: interface only, not a decoder -----------------------------------


class StandInBackend:
    """A backend stand-in implementing only ``decompress``, deliberately unlike the real ones.

    This is **interface simulation**: ``decompress`` ignores LZ4 semantics and returns a
    fixed byte string of the requested size. It exists to prove two things about the
    adapter, neither of which needs a real decoder:

    * malformed blocks never reach the backend -- the adapter's own validation decides;
    * only the documented call shape is used: ``decompress(src, size, dictionary=...)``
      with ``src`` as ``bytes`` and ``dictionary`` as ``bytes`` or ``None``.

    Its output is intentionally not valid decompressed data; no test compares it to a real
    decode.
    """

    def __init__(self, *, fail: Exception | None = None, short_by: int = 0) -> None:
        self.calls: list[dict[str, object]] = []
        self.fail = fail
        self.short_by = short_by

    def decompress(
        self,
        src: bytes,
        uncompressed_size: int = -1,
        return_bytearray: bool = False,
        dictionary: bytes | None = None,
    ) -> bytes:
        self.calls.append(
            {
                "src": src,
                "src_type": type(src),
                "size": uncompressed_size,
                "dictionary": dictionary,
                "dictionary_type": type(dictionary),
            }
        )
        if self.fail is not None:
            raise self.fail
        return b"\xaa" * max(0, uncompressed_size - self.short_by)


def test_stand_in_sees_only_validated_blocks(use_backend: object) -> None:
    stand_in = StandInBackend()
    use_backend(stand_in)
    # Valid: the adapter validates, then delegates exactly once
    assert codec.lz4_block_decompress(_block(tail=b"abc"), 3) == b"\xaa\xaa\xaa"
    assert len(stand_in.calls) == 1
    call = stand_in.calls[0]
    assert call["src_type"] is bytes
    assert call["size"] == 3
    assert call["dictionary"] is None

    # Corrupt: the adapter decides, and the stand-in is not consulted
    stand_in.calls.clear()
    for src, size in (
        (b"\xff" * 8, 8),
        (_block(tail=b"abc"), 4),
        (_block(tail=b"abc") + b"x", 3),
        (b"", 1),
    ):
        with pytest.raises(CorruptArchiveError):
            codec.lz4_block_decompress(src, size)
    assert stand_in.calls == []


def test_stand_in_dictionary_is_the_truncated_window(use_backend: object) -> None:
    stand_in = StandInBackend()
    use_backend(stand_in)
    long_dictionary = bytes(range(256)) * 400  # 102400 bytes
    src = _block(Sequence(b"", codec.LZ4_MAX_DISTANCE, 4), tail=b"")
    assert codec.lz4_block_decompress(src, 4, long_dictionary) == b"\xaa" * 4
    call = stand_in.calls[0]
    assert call["dictionary_type"] is bytes
    assert len(call["dictionary"]) == codec.LZ4_MAX_DISTANCE
    assert call["dictionary"] == long_dictionary[-codec.LZ4_MAX_DISTANCE :]


def test_stand_in_failures_are_normalized(use_backend: object) -> None:
    """Whatever exception style a backend uses, callers see our error type."""
    for failure in (ValueError("nope"), EOFError("nope")):
        stand_in = StandInBackend(fail=failure)
        use_backend(stand_in)
        with pytest.raises(CorruptArchiveError):
            codec.lz4_block_decompress(_block(tail=b"abc"), 3)


def test_stand_in_short_output_is_caught(use_backend: object) -> None:
    """A backend that silently under-delivers cannot turn into silent truncation."""
    use_backend(StandInBackend(short_by=1))
    with pytest.raises(CorruptArchiveError):
        codec.lz4_block_decompress(_block(tail=b"abc"), 3)


def test_stand_in_chain_dictionary_is_the_confirmed_prefix(use_backend: object) -> None:
    stand_in = StandInBackend()
    use_backend(stand_in)
    first = b"1234567890"
    body = _chain((_block(tail=first), len(first)), (_block(Sequence(b"", 10, 4), tail=b""), 4))
    assert codec.decompress_linked_lz4(body, len(first) + 4) == b"\xaa" * (len(first) + 4)
    assert [call["size"] for call in stand_in.calls] == [len(first), 4]
    assert stand_in.calls[0]["dictionary"] is None
    assert stand_in.calls[1]["dictionary"] == b"\xaa" * len(first)
    # The window handed on is never longer than the format can address
    stand_in.calls.clear()
    long_prefix = bytes(range(256)) * 300
    body = _chain((_block(tail=long_prefix), len(long_prefix)), (_block(Sequence(b"", 65535, 4), tail=b""), 4))
    codec.decompress_linked_lz4(body, len(long_prefix) + 4)
    assert len(stand_in.calls[1]["dictionary"]) == codec.LZ4_MAX_DISTANCE


def test_adapter_needs_no_external_service() -> None:
    """The adapter is dissect.util plus the standard library, not a subprocess or a socket."""
    import ast

    tree = ast.parse(Path(codec.__file__).read_text())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert not {name for name in imported if name.split(".")[0] in {"subprocess", "socket", "urllib", "http"}}
    assert "dissect.util.compression" in imported


# --- migration parity: normal index cells must not change --------------------------------


# sha256 over every cell of every LSM tree, in tree order: alive flag + 4-byte lengths and
# the bytes of each key and value. Captured before the adapter change and re-verified after.
INDEX_DIGESTS = {
    "ati_2020_disk_enc_lz4_compr.tibx": "47b7c9dbee275254f76d8bc9f54a962695708cadcb26c31d391da699415dde4e",
    "ati_2020_disk_lz4_compr.tibx": "1923da2f0ef3a4f4c8d1d5e810885e1590fe7a029f71aecf42c072703ac121d0",
    "t1_chain_diff.tibx": "4c18bce8c1cf78de7882469d7a0fdee7f777c57ad2756ffdfc90426ac7684f0e",
    "t1_chain_inc.tibx": "72088e74d809a8a5577f3c54c6513ee41c9c375d2109876bddb5def8a549b35b",
    "t1_disk_gpt.tibx": "b7f201e5b04476cbd4100f66fed544f5f0664d5f2253810b0c65852da5f8ede6",
    "t1_disk_mbr.tibx": "8ef2d8db0e02011f2719e4c1ab880b967872fe36f6b13ba0d8328d2b3f8f65f8",
    "t1_empty_ntfs.tibx": "c9411ace36c59416137c3748d89b1c1ac4e7a4132cb5ca73241fe4f9329847f0",
    "t1_enc_aes.tibx": "a05f9d08b687e112358b7207c73cd60a1dd5c9b00eabd122dd6d78efaa5e0d89",
    "t1_legacy_tib.tibx": "0b4bc3014aff2ea980d27ffa2362793c50d1f5251c1afb2d08c4f1ec37cc954d",
    "t1_multivol.tibx": "6356d3bbc399b0496d8b63559666f23f68e5795369fb3bb2237c365ceb706381",
    "t1_simple_ntfs.tibx": "874592d1524d37ca4b5dde8183f4486c1334354badc0f8ca95f5291a3f00a6c1",
    "t1_stored.tibx": "9c34540559ce9da5cb5c77c5a94b81654429720c1eb91bd81a5e297a87ade497",
}


def _index_digest(name: str) -> str:
    with TIBX.open(f"tests/_data/tibx/{name}") as tibx:
        if tibx.password_protected:
            tibx.unlock("dissect")
        digest = hashlib.sha256()
        for index in sorted(tibx.header.lsm_trees):
            for cell in iter_tree_cells(tibx.store, tibx.header.lsm_trees[index], tibx._data_key):
                digest.update(b"\x01" if cell.alive else b"\x00")
                digest.update(len(cell.key).to_bytes(4, "big"))
                digest.update(cell.key)
                digest.update(len(cell.value).to_bytes(4, "big"))
                digest.update(cell.value)
    return digest.hexdigest()


@REAL_BACKENDS
@pytest.mark.parametrize("name", sorted(INDEX_DIGESTS))
def test_normal_index_cells_parse_identically(
    name: str, backend_name: str, backend: object, use_backend: object
) -> None:
    """A valid archive's index cells are byte-for-byte what the parser produced before.

    The expected digests were captured from the pre-migration tree, and each fixture is
    re-parsed with the adapter forced onto every backend installed here.
    """
    use_backend(backend)
    assert _index_digest(name) == INDEX_DIGESTS[name]


def test_damaged_index_chain_exposes_only_the_confirmed_prefix() -> None:
    """A corrupt cell stream raises; best effort would expose the prefix, never a gap."""
    # A chain whose second block declares more than it produces is damage, not a short stream
    first = PLAIN[:64]
    second = PLAIN[64:128]
    blocks = _chain((_block(tail=first), len(first)), (_block(tail=second), len(second)))
    assert codec.decompress_linked_lz4(blocks, 128) == first + second

    damaged = bytearray(blocks)
    # Inflate the second block's declared size by one byte
    start = LZ4_BLOCK_HEADER_SIZE + len(_block(tail=first))
    damaged[start : start + 4] = struct.pack(">I", len(_block(tail=second)) + 1)
    with pytest.raises(CorruptArchiveError):
        codec.decompress_linked_lz4(bytes(damaged), 128)
    assert codec.decompress_linked_lz4(bytes(damaged), 128, strict=False) == first
    # And the cell-stream entry point, which is strict, refuses it
    with pytest.raises(CorruptArchiveError):
        codec.decompress_cell_stream(bytes(damaged), 1, 128)


@REAL_BACKENDS
def test_damaged_chain_fails_the_same_way_on_each_backend(
    backend_name: str, backend: object, use_backend: object
) -> None:
    """One corrupt input, both backends: the same exception and the same best-effort prefix."""
    first = b"first block"
    body = _chain(
        (_block(tail=first), len(first)),
        # Declares 8 bytes, produces 7: a length mismatch, not a short block
        (b"\x70abcdefg", 8),
        (_block(tail=b"never reached"), 12),
    )
    use_backend(backend)
    with pytest.raises(CorruptArchiveError):
        codec.decompress_linked_lz4(body, 64, strict=True)
    assert codec.decompress_linked_lz4(body, 64, strict=False) == first


def test_damaged_real_index_page_exposes_only_the_confirmed_prefix(use_backend: object) -> None:
    """Damage a real LZ4 index page and check the boundary of what is exposed.

    ``t1_disk_gpt`` stores its smallest trees in LZ4 cell streams. Overwriting the second
    block's header with a size larger than the page can hold is damage no writer produces;
    the strict reader must raise, and best effort must stop before the bad block.
    """
    from dissect.archive.tibx.page import PageStore

    path = "tests/_data/tibx/t1_disk_gpt.tibx"
    # PageStore keeps reading from the handle, so hold it open for the whole scan
    with Path(path).open("rb") as fh:
        store = PageStore(fh)
        assert _damage_first_multiblock_page(store)


def _damage_first_multiblock_page(store: PageStore) -> bool:
    """Overwrite the second block's header on the first multi-block LZ4 page, and check the prefix."""
    from dissect.archive.tibx.c_tibx import LSM_CELL_STREAM_OFFSET, c_tibx

    for index in range(store.page_count):
        page = store.page(index)
        if c_tibx.page_header(page).type not in (c_tibx.PageType.LEAF, c_tibx.PageType.LDIR):
            continue
        body = page[8:]
        if body[:4] not in (b"LEAF", b"LDIR"):
            continue
        header = c_tibx.lsm_page_header(body)
        if header.encoding & 0x7F != 1 or header.encoding & 0x80:
            continue
        stream = body[LSM_CELL_STREAM_OFFSET : LSM_CELL_STREAM_OFFSET + header.on_disk_size]
        compressed, uncompressed = struct.unpack_from(">II", stream, 0)
        second = LZ4_BLOCK_HEADER_SIZE + compressed
        if second + LZ4_BLOCK_HEADER_SIZE > len(stream):
            continue  # single block
        # The first block is confirmed; the second's declared size is now impossible
        damaged = bytearray(stream)
        damaged[second : second + 4] = struct.pack(">I", len(stream) + 1)
        first_block = codec.decompress_linked_lz4(stream[:second], uncompressed)
        with pytest.raises(CorruptArchiveError):
            codec.decompress_cell_stream(bytes(damaged), 1, header.uncompressed_size)
        assert codec.decompress_linked_lz4(bytes(damaged), header.uncompressed_size, strict=False) == first_block
        return True
    return False
