"""Decompression codecs used by TIBX.

- Data segments: a single zstd frame, or LZ4, zlib or stored, per the segment header.
- LSM cell streams and mem-tree blobs: **linked-LZ4** -- a chain of blocks
  ``[compressed BE u32][uncompressed BE u32][payload]`` where each block may
  back-reference previously decompressed output as its LZ4 dictionary
  (``LZ4_decompress_safe_continue`` semantics).

LZ4 comes from :mod:`dissect.util.compression`, which has two interchangeable backends:
a native Rust module and a pure-Python implementation. A deployment has one or the
other, and they disagree on malformed input -- the exception type they raise, whether
they stop at a declared size or follow the stream to its end, and whether bytes after a
complete block are an error. :func:`_lz4_decompress` is the only code here that talks to
them; it validates a block's structure itself before handing the block over, so a damaged
block produces the same :class:`CorruptArchiveError` either way.

A ``.tibx`` is untrusted input: every decode is bounded by the caller-supplied output
size so malformed on-disk sizes can't drive unbounded allocations.

The linked-LZ4 chain framing is ported from ``acronis-tibx`` (MIT License, Copyright (c)
2026 mniedermaier).
"""

from __future__ import annotations

import struct
import sys
import zlib

from dissect.archive.tibx.c_tibx import LZ4_BLOCK_HEADER_SIZE
from dissect.archive.tibx.exception import CorruptArchiveError, UnsupportedFormatError
from dissect.util.compression import lz4
from dissect.util.exceptions import CorruptDataError

# Generous ceiling for a single decompressed unit; real segments are a few MiB
MAX_DECOMPRESSED = 2 << 30

# LZ4 back-references reach at most this far, so a longer dictionary is never read
LZ4_MAX_DISTANCE = 0xFFFF

# c_tibx.lz4_block_header as a precompiled struct (a test keeps the two in step): an index
# page chains six to eight blocks, and cstruct's ~3 us a header was a quarter of the time
# spent decoding the index's LZ4 with dissect.util's native module
_LZ4_BLOCK_HEADER = struct.Struct(">II")


def decompress_zstd(data: bytes, max_output: int) -> bytes:
    """Decompress one zstd frame, ignoring trailing padding, bounded by ``max_output``.

    zstd is imported here, as :mod:`dissect.archive.tibx.crypto` imports pycryptodome: below
    Python 3.14 it comes from ``backports.zstd``, which only the ``full`` extra installs, and
    opening an archive and listing what it holds needs no zstd.
    """
    try:
        if sys.version_info >= (3, 14):
            from compression import zstd  # novermin
        else:
            from backports import zstd
    except ImportError:
        # An Error, so that what tolerates an unreadable segment (TIBX.volumes()) does here too.
        # Python 3.14 itself may be built without zstd.
        raise UnsupportedFormatError(
            "reading zstd-compressed TIBX segments needs zstd support: install dissect.archive[full]"
        )

    try:
        decompressor = zstd.ZstdDecompressor()
        out = decompressor.decompress(data, max_output + 1)
    except zstd.ZstdError as e:
        raise CorruptArchiveError(f"zstd: {e}")
    if len(out) > max_output:
        raise CorruptArchiveError(f"zstd output exceeds {max_output}-byte cap (malformed frame?)")
    return out


def decompress_zlib(data: bytes, max_output: int) -> bytes:
    """Decompress one zlib stream, bounded by ``max_output``."""
    try:
        decompressor = zlib.decompressobj()
        out = decompressor.decompress(data, max_output + 1)
    except zlib.error as e:
        raise CorruptArchiveError(f"zlib: {e}")
    if len(out) > max_output:
        raise CorruptArchiveError(f"zlib output exceeds {max_output}-byte cap (malformed stream?)")
    return out


def _lz4_block_size(src: bytes, dictionary_size: int) -> int:
    """Walk a raw LZ4 block's sequences and return the output size it produces.

    This is the backend-independent definition of a well-formed block: every literal run
    and match fits the input, no match uses offset 0, a match may reach back at most
    ``dictionary_size`` bytes before the start of the output, the block ends on a
    literal-only sequence, and a length extension byte is never cut off. An LZ4 block always
    ends with literals (the format's last sequence), so a block that stops right after a
    match, or whose last token still announces one, is truncated. The native backend enforces
    this; the pure-Python one accepts both when the declared size happens to be reached, so
    the rule has to live here for the two to agree.

    Raises:
        ~dissect.archive.tibx.exception.CorruptArchiveError: If the block is malformed.
    """
    pos = 0
    size = 0
    length = len(src)
    while True:
        if pos >= length:
            raise CorruptArchiveError("LZ4: block ends without a final literal token")
        token = src[pos]
        pos += 1

        literals = token >> 4
        if literals == 0xF:
            while True:
                if pos >= length:
                    raise CorruptArchiveError("LZ4: block ends inside a literal length")
                byte = src[pos]
                pos += 1
                literals += byte
                if byte != 0xFF:
                    break
        if literals > length - pos:
            raise CorruptArchiveError("LZ4: literal run runs past the end of the block")
        pos += literals
        size += literals

        if pos == length:
            if token & 0xF:
                # The last sequence must be literals only: a match nibble with no offset
                # bytes after it is a truncated block, whichever size was declared
                raise CorruptArchiveError("LZ4: block ends on a match, without its final literal sequence")
            return size

        if pos + 2 > length:
            raise CorruptArchiveError("LZ4: block ends inside a match offset")
        offset = src[pos] | src[pos + 1] << 8
        pos += 2
        if offset == 0:
            raise CorruptArchiveError("LZ4: match offset is 0")
        if offset > dictionary_size + size:
            raise CorruptArchiveError(
                f"LZ4: match offset {offset} reaches past the {dictionary_size + size} bytes decoded so far"
            )

        matches = token & 0xF
        if matches == 0xF:
            while True:
                if pos >= length:
                    raise CorruptArchiveError("LZ4: block ends inside a match length")
                byte = src[pos]
                pos += 1
                matches += byte
                if byte != 0xFF:
                    break
        size += matches + 4


def _lz4_decompress(src: bytes, uncompressed_size: int, dictionary: bytes) -> bytes:
    """Validate one raw LZ4 block for its declared size, then decode it with the backend.

    ``dictionary`` is the reachable window (at most :data:`LZ4_MAX_DISTANCE` bytes) and
    ``uncompressed_size`` is the exact size the block must produce. Validation first makes
    a malformed block fail identically on both backends; the decode itself is only reached
    by a block whose framing and size are already known to be right.
    """
    produced = _lz4_block_size(src, len(dictionary))
    if produced != uncompressed_size:
        raise CorruptArchiveError(f"LZ4: block declares {uncompressed_size} bytes but produces {produced}")
    try:
        # ``dictionary=... or None``: the empty window is the same as no window, and the
        # native backend rejects a ``memoryview``, so hand over exactly ``bytes``
        out = lz4.decompress(src, uncompressed_size, dictionary=dictionary or None)
    except (CorruptDataError, ValueError, TypeError, EOFError) as e:
        # Only a backend bug or an input its validator accepts but its decoder rejects
        # should get here; normalize it rather than let the backend's type through
        raise CorruptArchiveError(f"LZ4: {e}")
    if len(out) != uncompressed_size:
        raise CorruptArchiveError(f"LZ4: backend decoded {len(out)} bytes, expected {uncompressed_size}")
    return out


def lz4_block_decompress(src: bytes, uncompressed_size: int, dictionary: bytes = b"") -> bytes:
    """Decompress one raw LZ4 block whose matches may reach back into ``dictionary``.

    Raises:
        ~dissect.archive.tibx.exception.CorruptArchiveError: If the block is malformed, if it
            does not produce exactly ``uncompressed_size`` bytes, or if it references bytes
            outside the output and the last :data:`LZ4_MAX_DISTANCE` bytes of ``dictionary``.
    """
    if uncompressed_size <= 0:
        # Every TIBX LZ4 block records its size; without one the output would be unbounded
        raise CorruptArchiveError(f"LZ4: invalid uncompressed size {uncompressed_size}")
    if not src:
        raise CorruptArchiveError("LZ4: empty block")
    return _lz4_decompress(src, uncompressed_size, bytes(dictionary[-LZ4_MAX_DISTANCE:] if dictionary else b""))


def decompress_linked_lz4(body: bytes, max_output: int, *, strict: bool = True) -> bytes:
    """Decompress a linked-LZ4 block chain, bounded by ``max_output``.

    Each block is ``[compressed BE u32][uncompressed BE u32][payload]`` and may use the
    output of the blocks before it as its LZ4 dictionary, truncated to the last
    :data:`LZ4_MAX_DISTANCE` bytes -- which is all a 16-bit match offset can reach.

    ``strict=True`` raises :class:`CorruptArchiveError` for a block that is malformed,
    produces a different size than its header declares, or claims more than ``max_output``
    allows, and for trailing bytes that do not form a block. ``strict=False`` (best-effort
    scans over untrusted input) stops at the first such block and returns only the prefix
    that decoded cleanly. A malformed block is never treated as an empty one: strict raises,
    best-effort truncates, and both discard the rest of the chain rather than skip the block.

    Returns:
        The decompressed prefix. In strict mode this is the whole chain.
    """
    out = bytearray()
    pos = 0
    body_len = len(body)
    while pos + LZ4_BLOCK_HEADER_SIZE <= body_len:
        compressed, uncompressed = _LZ4_BLOCK_HEADER.unpack_from(body, pos)
        if compressed == 0 and uncompressed == 0:
            # The chain terminator: a zero header, which Acronis leaves after the last block
            pos += LZ4_BLOCK_HEADER_SIZE
            break
        if compressed == 0 or uncompressed == 0:
            # A header that claims a payload on one side but not the other is damage, not a
            # terminator. Continuation would be treating a bad block as an empty one.
            if not strict:
                break
            raise CorruptArchiveError(
                f"linked-LZ4 block at offset {pos} claims compressed={compressed}, uncompressed={uncompressed}"
            )
        if compressed > body_len - pos - LZ4_BLOCK_HEADER_SIZE:
            if strict:
                raise CorruptArchiveError(
                    f"linked-LZ4 block at offset {pos} claims {compressed} compressed bytes; "
                    f"only {body_len - pos - LZ4_BLOCK_HEADER_SIZE} remain"
                )
            break
        if uncompressed > max_output - len(out):
            if not strict:
                break
            raise CorruptArchiveError(
                f"linked-LZ4 block at offset {pos} claims {uncompressed} bytes; "
                f"only {max_output - len(out)} remain of the {max_output}-byte target"
            )
        payload_start = pos + LZ4_BLOCK_HEADER_SIZE
        try:
            out += _lz4_decompress(
                body[payload_start : payload_start + compressed],
                uncompressed,
                bytes(out[-LZ4_MAX_DISTANCE:]) if out else b"",
            )
        except CorruptArchiveError:
            if not strict:
                break
            raise
        pos = payload_start + compressed

    if strict and pos < body_len and any(body[pos:]):
        # Zero bytes after the last block are the padding Acronis leaves; anything else is
        # loss, and a chain that leaves bytes unexplained must not pass as complete
        raise CorruptArchiveError(f"linked-LZ4 chain has {body_len - pos} trailing bytes after its last block")
    return bytes(out)


def decompress_cell_stream(body: bytes, codec: int, uncompressed_size: int) -> bytes:
    """Decompress a LEAF/LDIR cell stream or mem-tree blob (codec 0 = raw, 1 = linked-LZ4)."""
    if codec == 0:
        if len(body) < uncompressed_size:
            raise CorruptArchiveError(f"raw cell stream is {len(body)} bytes, expected {uncompressed_size}")
        return bytes(body[:uncompressed_size])
    if codec != 1:
        raise CorruptArchiveError(f"unknown LSM cell codec {codec}")
    out = decompress_linked_lz4(body, uncompressed_size, strict=True)
    if len(out) != uncompressed_size:
        raise CorruptArchiveError(f"cell stream decoded {len(out)} bytes, expected {uncompressed_size}")
    return out
