from __future__ import annotations

import hashlib
import io
import struct
from typing import BinaryIO
from zlib import compressobj, crc32


def _write_all(fh: BinaryIO, b: bytes) -> int:
    """Write all of ``b`` to ``fh``, retrying on short writes.

    File-like objects are allowed to accept fewer bytes than offered. Callers
    such as ``shutil.copyfileobj`` and cstruct ignore the return value of
    ``write``, so a short write would silently truncate the snapshot. This
    helper keeps writing until every byte is accepted or the underlying object
    raises.

    Args:
        fh: The file-like object to write to.
        b: The bytes to write.

    Returns:
        The amount of bytes written, which is always ``len(b)``.
    """
    view = memoryview(b)
    total = 0
    if not view:
        return total
    while view:
        written = fh.write(view)
        if written is None:
            # Buffered file objects may return None, in which case we cannot
            # tell how many bytes were accepted and cannot safely retry.
            written = len(view)
        elif written <= 0:
            raise OSError("write failed, no bytes were accepted")
        total += written
        view = view[written:]
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
        return _write_all(self.fh, b)

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


class Crc32Stream(SubStreamBase):
    """Compute a CRC32 over all written data.

    This assumes that all data is written as a continuous stream.

    Args:
        fh: The file-like object to wrap.
    """

    def __init__(self, fh: BinaryIO):
        super().__init__(fh)
        self.crc = 0

    def write(self, b: bytes) -> int:
        # Only fold the bytes that the underlying file actually accepts into
        # the checksum, retrying the remainder on short writes.
        view = memoryview(b)
        total = 0
        if not view:
            return total
        while view:
            written = self.fh.write(view)
            if written is None:
                written = len(view)
            elif written <= 0:
                raise OSError("write failed, no bytes were accepted")
            accepted = view[:written]
            self.crc = crc32(accepted, self.crc) & 0xFFFFFFFF
            total += written
            view = view[written:]
        return total

    def digest(self) -> bytes:
        return struct.pack("<I", self.crc)

    def finalize(self) -> None:
        self.fh.write(self.digest())
        super().finalize()


class HashedStream(SubStreamBase):
    """Compute a hash over all written data.

    This assumes that all data is written as a continuous stream.

    Args:
        fh: The file-like object to wrap.
        alg: The hashing algorithm to use. Must be supported by hashlib.
    """

    def __init__(self, fh: BinaryIO, alg: str = "sha256"):
        super().__init__(fh)
        self.ctx = hashlib.new(alg)

    def write(self, b: bytes) -> int:
        # Only hash the bytes that the underlying file actually accepts,
        # retrying the remainder on short writes.
        view = memoryview(b)
        total = 0
        if not view:
            return total
        while view:
            written = self.fh.write(view)
            if written is None:
                written = len(view)
            elif written <= 0:
                raise OSError("write failed, no bytes were accepted")
            self.ctx.update(view[:written])
            total += written
            view = view[written:]
        return total

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
        if not b:
            return 0
        compressed = self.cobj.compress(b)
        if compressed:
            self.fh.write(compressed)
        return len(b)

    def finalize(self) -> None:
        tail = self.cobj.flush()
        if tail:
            self.fh.write(tail)
        super().finalize()
