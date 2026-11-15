from __future__ import annotations

import hashlib
import io
import struct
from typing import TYPE_CHECKING, BinaryIO
from zlib import compressobj, crc32

if TYPE_CHECKING:
    from collections.abc import Callable


def write_all(fh: BinaryIO, b: bytes | bytearray | memoryview) -> int:
    """Write all of ``b`` to ``fh``, retrying short writes.

    Args:
        fh: The file-like object to write to.
        b: The bytes to write.

    Returns:
        The number of bytes written, which is always ``len(b)``.

    Raises:
        OSError: If the file-like object does not accept any data.
    """
    view = memoryview(b)
    if not len(view):
        return 0

    total = 0
    while total < len(view):
        written = fh.write(view[total:])
        if written is None or written <= 0:
            raise OSError("write() did not accept any data")
        total += min(written, len(view) - total)

    return total


def _tell(fh: BinaryIO) -> int | None:
    """Return the current position of ``fh``, or ``None`` if it can't be determined."""
    try:
        pos = fh.tell()
    except (AttributeError, OSError, ValueError):
        return None

    return pos if isinstance(pos, int) else None


def _accepted_since(fh: BinaryIO, start: int | None, limit: int) -> int:
    """Return how many bytes ``fh`` accepted since ``start``, capped at ``limit``."""
    if start is None:
        return 0

    end = _tell(fh)
    if end is None:
        return 0

    return max(0, min(end - start, limit))


def write_hashed(
    fh: BinaryIO, b: bytes | bytearray | memoryview, update: Callable[[memoryview], None]
) -> int:
    """Write all of ``b`` to ``fh``, updating a digest with only the accepted bytes.

    Short writes are retried. If the underlying write raises, the digest is still
    updated with whatever was accepted before the failure, after which the
    exception is re-raised.

    Args:
        fh: The file-like object to write to.
        b: The bytes to write.
        update: Callable that is invoked with the bytes that were accepted.

    Returns:
        The number of bytes written, which is always ``len(b)``.
    """
    view = memoryview(b)
    if not len(view):
        return 0

    total = 0
    while total < len(view):
        start = _tell(fh)
        try:
            written = fh.write(view[total:])
        except BaseException:
            accepted = _accepted_since(fh, start, len(view) - total)
            if accepted:
                update(view[total : total + accepted])
            raise

        accepted = written if written is not None and written > 0 else 0
        if not accepted:
            raise OSError("write() did not accept any data")

        accepted = min(accepted, len(view) - total)
        update(view[total : total + accepted])
        total += accepted

    return total


class SubStreamBase(io.RawIOBase):
    """Convenience class for easy sub stream subclassing.

    Additionally adds the `finalize` method.

    Args:
        fh: The file-like object to wrap.
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh

    def write(self, b: bytes) -> int:
        return write_all(self.fh, b)

    def flush(self) -> None:
        self.fh.flush()

    def tell(self) -> int:
        return self.fh.tell()

    def seek(self, pos: int, whence: int = io.SEEK_CUR) -> int:
        return self.fh.seek(pos, whence)

    def close(self) -> None:
        super().close()

    def finalize(self) -> None:
        self.fh.flush()
        if hasattr(self.fh, "finalize"):
            self.fh.finalize()


class WriteAllStream(SubStreamBase):
    """Write all data to the wrapped file-like object, retrying short writes.

    Useful underneath a wrapper (like :class:`gzip.GzipFile`) that doesn't handle
    short writes itself.

    Args:
        fh: The file-like object to wrap.
    """

    def write(self, b: bytes) -> int:
        return write_all(self.fh, b)


class Crc32Stream(SubStreamBase):
    """Compute a CRC32 over all written data.

    This assumes that all data is written as a continuous stream. The CRC is
    only updated with the bytes that the wrapped file-like object actually
    accepted, so it also stays correct across short writes.

    Args:
        fh: The file-like object to wrap.
    """

    def __init__(self, fh: BinaryIO):
        super().__init__(fh)
        self.crc = 0

    def write(self, b: bytes) -> int:
        def update(data: memoryview) -> None:
            self.crc = crc32(data, self.crc) & 0xFFFFFFFF

        return write_hashed(self.fh, b, update)

    def digest(self) -> bytes:
        return struct.pack("<I", self.crc)

    def finalize(self) -> None:
        write_all(self.fh, self.digest())
        super().finalize()


class HashedStream(SubStreamBase):
    """Compute a hash over all written data.

    This assumes that all data is written as a continuous stream. The hash is
    only updated with the bytes that the wrapped file-like object actually
    accepted, so it also stays correct across short writes.

    Args:
        fh: The file-like object to wrap.
        alg: The hashing algorithm to use. Must be supported by hashlib.
    """

    def __init__(self, fh: BinaryIO, alg: str = "sha256"):
        super().__init__(fh)
        self.ctx = hashlib.new(alg)

    def write(self, b: bytes) -> int:
        return write_hashed(self.fh, b, self.ctx.update)

    def digest(self) -> bytes:
        return self.ctx.digest()

    def hexdigest(self) -> str:
        return self.ctx.hexdigest()

    def close(self) -> None:
        super().close()
        self.fh.close()


class CompressedStream(SubStreamBase):
    """Compress data as it's being written.

    This assumes that all data is written as a continuous stream.

    Args:
        fh: The file-like object to wrap.
    """

    def __init__(self, fh: BinaryIO):
        super().__init__(fh)
        self.cobj = compressobj()

    def write(self, b: bytes) -> int:
        # Return the amount of input consumed, not the amount of compressed output
        write_all(self.fh, self.cobj.compress(b))
        return len(b)

    def finalize(self) -> None:
        write_all(self.fh, self.cobj.flush())
        super().finalize()
