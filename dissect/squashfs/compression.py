from __future__ import annotations

import importlib
import io
import sys
from typing import TYPE_CHECKING

from dissect.squashfs.c_squashfs import c_squashfs
from dissect.squashfs.exceptions import CompressionError

if TYPE_CHECKING:
    from collections.abc import Callable


def _lzo_consumed(decompress: Callable[..., bytes], data: bytes, expected: int) -> int:
    """Return the length of the shortest prefix that decodes as a complete LZO block.

    The native LZO binding does not expose how many input bytes it consumed. A
    complete LZO block is the shortest prefix that decodes successfully; anything
    after it is trailing input.

    Removing the last byte only breaks decoding when that byte is part of the
    stream, so the common case (no trailing input) needs a single probe. If the
    shortened input still decodes, trailing input exists and the exact boundary is
    found with a binary search; acceptance is monotonic because the native binding
    ignores everything after a complete block.
    """
    if not data:
        return 0

    try:
        decompress(data[:-1], False, expected + 1)
    except Exception:  # noqa: BLE001
        return len(data)

    low, high = 0, len(data) - 1
    while low < high:
        middle = (low + high) // 2
        try:
            decompress(data[:middle], False, expected + 1)
        except Exception:  # noqa: BLE001
            low = middle + 1
        else:
            high = middle
    return low


def _lz4_block_length(data: bytes, expected: int) -> int:
    """Return the exact output length of one raw LZ4 block, bounded by ``expected``.

    Raw LZ4 blocks have no frame header; a block ends after its final literal run.
    The structure is parsed to locate that end and to reject input whose decoded
    size exceeds the SquashFS block bound. This is also what prevents a second raw
    block from being silently accepted as part of the first when it would exceed
    the bound.
    """
    length = len(data)
    pos = 0
    produced = 0

    while True:
        if pos >= length:
            raise CompressionError("Truncated LZ4 block")

        token = data[pos]
        pos += 1

        literals = token >> 4
        if literals == 15:
            while True:
                if pos >= length:
                    raise CompressionError("Truncated LZ4 literal length")
                part = data[pos]
                pos += 1
                literals += part
                if part != 255:
                    break

        if pos + literals > length:
            raise CompressionError("LZ4 literal run exceeds stored block")

        pos += literals
        produced += literals
        if produced > expected:
            raise CompressionError(f"Decompressed LZ4 block exceeds {expected} bytes")

        if pos == length:
            # A block always ends after a literal run; nothing may follow it.
            return produced

        if pos + 2 > length:
            raise CompressionError("Truncated LZ4 match offset")

        offset = data[pos] | (data[pos + 1] << 8)
        pos += 2
        if offset == 0:
            raise CompressionError("LZ4 match offset can't be 0")
        if offset > produced:
            raise CompressionError("LZ4 match offset exceeds decoded data")

        match_length = token & 0x0F
        if match_length == 15:
            while True:
                if pos >= length:
                    raise CompressionError("Truncated LZ4 match length")
                part = data[pos]
                pos += 1
                match_length += part
                if part != 255:
                    break
        match_length += 4

        produced += match_length
        if produced > expected:
            raise CompressionError(f"Decompressed LZ4 block exceeds {expected} bytes")


def initialize(id: int, options: bytes | None) -> Compression:
    # Options have no effect on decompression, so ignore for now
    modules = {
        c_squashfs.ZLIB_COMPRESSION: (NativeZlib,),
        c_squashfs.LZMA_COMPRESSION: (NativeLZMA,),
        c_squashfs.LZO_COMPRESSION: (AvailableLZO,),
        c_squashfs.XZ_COMPRESSION: (NativeXZ,),
        c_squashfs.LZ4_COMPRESSION: (AvailableLZ4,),
        c_squashfs.ZSTD_COMPRESSION: (NativeZSTD,),
    }

    try:
        for mod in modules[id]:
            try:
                return mod()
            except ModuleNotFoundError:  # noqa: PERF203
                pass
        else:
            raise ImportError(f"No modules available ({modules[id]})")  # noqa: TRY301
    except ImportError:
        raise ValueError(f"Compression ID {id} requested but module ({modules[id]}) is not available") from None
    except KeyError:
        raise NotImplementedError(f"Unsupported compression ID: {id}") from None


class Compression:
    """Decompression backend for one SquashFS block.

    The block contract is identical for every backend:

    * ``data`` contains exactly one compressed stream/frame. The backend must consume
      all of it; trailing bytes and concatenated streams/frames are invalid.
    * ``expected`` is the uncompressed upper bound for the block. It is
      ``SQUASHFS_METADATA_SIZE`` for metadata blocks and the filesystem block size
      for file data blocks.
    * The output is never sliced to hide excess data. If a backend produces more
      than ``expected`` bytes, decompression fails.
    """

    module: str | None = None

    def __init__(self) -> None:
        self._module = self._load_module()

    def _load_module(self) -> object:
        if self.module is None:
            raise NotImplementedError("Compression backend does not define a module")
        return importlib.import_module(self.module)

    def compress(self, data: bytes) -> bytes:
        raise NotImplementedError

    def decompress(self, data: bytes, expected: int) -> bytes:
        """Decompress a single block, rejecting truncated, trailing or oversized data."""
        if expected < 0:
            raise ValueError(f"Expected block size must not be negative: {expected}")

        try:
            result = self._decompress(data, expected)
        except CompressionError:
            raise
        except Exception as e:
            raise CompressionError(f"{type(self).__name__}: {e}") from e

        if len(result) > expected:
            raise CompressionError(
                f"{type(self).__name__}: decompressed block is {len(result)} bytes, expected at most {expected}"
            )

        return result

    def _decompress(self, data: bytes, expected: int) -> bytes:
        raise NotImplementedError


class NativeZlib(Compression):
    module = "zlib"

    def _decompress(self, data: bytes, expected: int) -> bytes:
        decompressor = self._module.decompressobj()
        result = decompressor.decompress(data, expected + 1)

        if len(result) > expected:
            raise CompressionError(f"Decompressed zlib block exceeds {expected} bytes")

        if not decompressor.eof:
            raise CompressionError("Truncated zlib block")

        if decompressor.unused_data or decompressor.unconsumed_tail:
            raise CompressionError("Trailing data after zlib block")

        return result


class NativeLZMA(Compression):
    module = "lzma"

    def _decompress(self, data: bytes, expected: int) -> bytes:
        # FORMAT_AUTO accepts both legacy .lzma and XZ streams, matching the
        # historical behavior of lzma.decompress().
        decompressor = self._module.LZMADecompressor(format=self._module.FORMAT_AUTO)
        result = decompressor.decompress(data, max_length=expected + 1)

        if len(result) > expected:
            raise CompressionError(f"Decompressed LZMA block exceeds {expected} bytes")

        if not decompressor.eof:
            raise CompressionError("Truncated or oversized LZMA block")

        if decompressor.unused_data:
            raise CompressionError("Trailing data after LZMA block")

        return result


class AvailableLZO(Compression):
    # ``dissect.util.compression`` selects the native implementation when it is
    # available and the pure Python one otherwise. The native binding only accepts
    # bytes and does not report its consumed length, so trailing input is detected
    # by finding the shortest prefix that still decodes. The Python implementation
    # reports the consumed length through the file-like source.
    module = "dissect.util.compression"

    def _load_module(self) -> object:
        compression = importlib.import_module(self.module)
        self._native = compression.lzo is getattr(compression, "lzo_native", None)
        return compression.lzo

    def _decompress(self, data: bytes, expected: int) -> bytes:
        if self._native:
            result = self._module.decompress(data, False, expected + 1)
        else:
            source = io.BytesIO(data)
            result = self._module.decompress(source, False, expected + 1)

        if len(result) > expected:
            raise CompressionError(f"Decompressed LZO block exceeds {expected} bytes")

        consumed = _lzo_consumed(self._module.decompress, data, expected) if self._native else source.tell()
        if consumed != len(data):
            raise CompressionError(f"Trailing data after LZO block ({len(data) - consumed} bytes)")

        return result


class NativeXZ(Compression):
    module = "lzma"

    def _decompress(self, data: bytes, expected: int) -> bytes:
        decompressor = self._module.LZMADecompressor(format=self._module.FORMAT_AUTO)
        result = decompressor.decompress(data, max_length=expected + 1)

        if len(result) > expected:
            raise CompressionError(f"Decompressed XZ block exceeds {expected} bytes")

        if not decompressor.eof:
            raise CompressionError("Truncated or oversized XZ block")

        if decompressor.unused_data:
            raise CompressionError("Trailing data after XZ block")

        return result


class AvailableLZ4(Compression):
    # The native LZ4 binding accepts a raw block appended to another raw block
    # (there is no frame marker to stop at) and exposes no consumed length. Parse
    # the block structure ourselves to determine the exact output length and to
    # reject input that is not one complete raw LZ4 block. The decoder is then used
    # with that exact size, so the native and pure Python implementations agree.
    module = "dissect.util.compression"

    def _load_module(self) -> object:
        compression = importlib.import_module(self.module)
        self._native = compression.lz4 is getattr(compression, "lz4_native", None)
        return compression.lz4

    def _decompress(self, data: bytes, expected: int) -> bytes:
        output_size = _lz4_block_length(data, expected)

        if self._native:
            try:
                result = self._module.decompress(data, output_size)
            except Exception as e:
                raise CompressionError(f"Invalid LZ4 block: {e}") from e
        else:
            source = io.BytesIO(data)
            result = self._module.decompress(source, uncompressed_size=output_size)
            if source.tell() != len(data):
                raise CompressionError("Trailing data after LZ4 block")

        if len(result) != output_size:
            raise CompressionError(f"LZ4 block decoded to {len(result)} bytes, expected {output_size}")

        return result


class NativeZSTD(Compression):
    @property
    def module(self) -> str:
        if sys.version_info >= (3, 14):
            return "compression.zstd"
        return "backports.zstd"

    def _decompress(self, data: bytes, expected: int) -> bytes:
        # The module-level decompress() joins concatenated frames; use a decompressor
        # object so that a second frame is visible as unused_data and rejected.
        decompressor = self._module.ZstdDecompressor()
        result = decompressor.decompress(data, max_length=expected + 1)

        if len(result) > expected:
            raise CompressionError(f"Decompressed ZSTD block exceeds {expected} bytes")

        if not decompressor.eof:
            raise CompressionError("Truncated or oversized ZSTD block")

        if decompressor.unused_data:
            raise CompressionError("Trailing data after ZSTD block")

        return result
