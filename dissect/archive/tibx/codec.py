"""Decompression codecs used by TIBX.

- Data segments: a single zstd frame, or LZ4, zlib or stored, per the segment header.
- LSM cell streams and mem-tree blobs: **linked-LZ4** -- a chain of blocks
  ``[compressed BE u32][uncompressed BE u32][payload]`` where each block may
  back-reference previously decompressed output as its LZ4 dictionary
  (``LZ4_decompress_safe_continue`` semantics).

A ``.tibx`` is untrusted input: every decode is bounded by the caller-supplied output
size so malformed on-disk sizes can't drive unbounded allocations.

The linked-LZ4 chain framing is ported from ``acronis-tibx`` (MIT License, Copyright (c)
2026 mniedermaier).
"""

from __future__ import annotations

import struct
import sys
import zlib

from dissect.util.compression import lz4
from dissect.util.exceptions import CorruptDataError

from dissect.archive.tibx.c_tibx import LZ4_BLOCK_HEADER_SIZE
from dissect.archive.tibx.exception import CorruptArchiveError, UnsupportedFormatError

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


def lz4_block_decompress(src: bytes, uncompressed_size: int, dictionary: bytes = b"") -> bytes:
    """Decompress one raw LZ4 block whose matches may reach back into ``dictionary``.

    This is the one place the two ``dissect.util`` LZ4 backends are normalized so a
    deployment with the Rust extension and one with only the pure-Python module behave
    identically:

    - the Rust backend raises :class:`ValueError`, the pure-Python one
      :class:`~dissect.util.exceptions.CorruptDataError` (not a ``ValueError``) -- both
      become :class:`CorruptArchiveError`;
    - the pure-Python backend silently ignores bytes left over after the block is
      complete, while Rust rejects them -- trailing bytes are an error here too;
    - both backends return short output when the block decodes fewer bytes than
      ``uncompressed_size`` declares -- a declared length that does not match is an error.
    """
    if uncompressed_size <= 0:
        # Every TIBX LZ4 block records its size; without one the output would be unbounded
        raise CorruptArchiveError(f"LZ4: invalid uncompressed size {uncompressed_size}")
    try:
        out = lz4.decompress(src, uncompressed_size, dictionary=dictionary)
    except (CorruptDataError, ValueError) as e:
        # The Rust backend raises ValueError, the pure-Python one CorruptDataError, which is not a ValueError
        raise CorruptArchiveError(f"LZ4: {e}") from e
    if len(out) != uncompressed_size:
        raise CorruptArchiveError(
            f"LZ4: block decoded {len(out)} bytes, header declared {uncompressed_size}"
        )
    block_end = _lz4_block_end(src, uncompressed_size, len(dictionary))
    if block_end != len(src):
        raise CorruptArchiveError("LZ4: trailing bytes after the end of the block")
    return bytes(out)


def _lz4_block_end(src: bytes, uncompressed_size: int, dictionary_len: int) -> int:
    """Walk one raw LZ4 block's framing and return the offset just past its last byte.

    A structural walk only -- matches are not copied, their lengths are still bounded by the
    same token/length encoding a decoder reads. It exists because the pure-Python backend
    stops as soon as the declared output is full and never reports how much of ``src`` it
    consumed, whereas the Rust backend rejects an over-long frame outright. Walking the frame
    here gives both backends the same "a block ends exactly at its buffer" rule.

    Returns ``-1`` when ``src`` is not a complete, self-consistent frame for
    ``uncompressed_size`` output bytes.
    """
    pos = 0
    produced = 0
    src_len = len(src)
    while True:
        if pos >= src_len:
            return -1
        token = src[pos]
        pos += 1

        literal_len = token >> 4
        if literal_len == 0xF:
            while True:
                if pos >= src_len:
                    return -1
                extension = src[pos]
                pos += 1
                literal_len += extension
                if extension != 0xFF:
                    break
        if pos + literal_len > src_len:
            return -1
        pos += literal_len
        produced += literal_len
        if produced >= uncompressed_size:
            # Output complete: a block ends here with a final (match-less) literals sequence
            return pos if produced == uncompressed_size else -1

        if pos + 2 > src_len:
            return -1
        offset = src[pos] | (src[pos + 1] << 8)
        pos += 2
        if offset == 0 or offset > dictionary_len + produced:
            return -1

        match_len = token & 0xF
        if match_len == 0xF:
            while True:
                if pos >= src_len:
                    return -1
                extension = src[pos]
                pos += 1
                match_len += extension
                if extension != 0xFF:
                    break
        match_len += 4
        produced += match_len
        if produced > uncompressed_size:
            return -1
        if produced == uncompressed_size:
            # A block ending on a full match may carry one zero literal-length token as a
            # terminator (the Rust backend requires it, pure Python tolerates its absence).
            if pos == src_len:
                return pos
            if pos == src_len - 1 and src[pos] == 0:
                return src_len
            return -1


def decompress_linked_lz4(body: bytes, max_output: int, *, strict: bool = True) -> bytes:
    """Decompress a linked-LZ4 block chain, bounded by ``max_output``.

    ``strict=True`` raises :class:`CorruptArchiveError` on any malformed block or framing;
    ``strict=False`` (best-effort scans over untrusted input) stops at the first malformed
    block and returns only the prefix that decoded cleanly. A malformed block header is
    corruption in both modes, never an implicit empty block or end of chain: a chain ends
    cleanly only when its buffer is exactly consumed.
    """
    out = bytearray()
    pos = 0
    body_len = len(body)
    while pos < body_len and len(out) < max_output:
        if body_len - pos < LZ4_BLOCK_HEADER_SIZE:
            return _chain_endpoint(out, pos, body_len, strict, "truncated block header")
        compressed, uncompressed = _LZ4_BLOCK_HEADER.unpack_from(body, pos)
        pos += LZ4_BLOCK_HEADER_SIZE
        if compressed == 0:
            # A zero-length payload is never a valid block: treating it as end-of-chain would
            # silently swallow whatever the damaged header was meant to introduce.
            if not strict:
                return bytes(out)
            raise CorruptArchiveError("linked-LZ4 chain is corrupt: block declares an empty payload")
        if compressed > body_len - pos:
            return _chain_endpoint(
                out,
                pos,
                body_len,
                strict,
                f"block declares {compressed} payload bytes but the chain has {body_len - pos}",
            )
        if uncompressed > max_output - len(out):
            if not strict:
                break
            raise CorruptArchiveError(
                f"linked-LZ4 block claims {uncompressed} bytes; "
                f"only {max_output - len(out)} remain of the {max_output}-byte target"
            )
        try:
            dictionary = bytes(out[-LZ4_MAX_DISTANCE:])
            decoded = lz4_block_decompress(body[pos : pos + compressed], uncompressed, dictionary=dictionary)
        except CorruptArchiveError:
            if not strict:
                break
            raise
        out += decoded
        pos += compressed
    # The loop also ends once ``max_output`` bytes are confirmed. Real pages pad the stream
    # past that point, so leftover bytes with the target full are padding, not a broken chain;
    # a partial header or an over-long block declaration with room left in the target is not.
    if pos < body_len and len(out) < max_output:
        return _chain_endpoint(out, pos, body_len, strict, "chain ends before the declared output was produced")
    return bytes(out)


def _chain_endpoint(out: bytearray, pos: int, body_len: int, strict: bool, reason: str) -> bytes:
    """Handle a chain whose buffer does not end on a block boundary.

    A fully consumed buffer is a clean end; any leftover bytes are a damaged chain because
    nothing can parse them. In best-effort mode the confirmed prefix is returned instead.
    """
    if pos == body_len:
        return bytes(out)
    if not strict:
        return bytes(out)
    raise CorruptArchiveError(f"linked-LZ4 chain is corrupt: {reason}")


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
