from __future__ import annotations

from io import BytesIO
from pathlib import Path

# Read bounds are recorded so tests can assert on offsets and sizes, not wall-clock time.


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent.joinpath(filename).resolve()


class CountingIO:
    """An in-memory backup that counts the reads made on it, and the bytes they read.

    Mirrors the helper TIBX's tests use, so VBK cache assertions measure real read calls
    rather than wall-clock time.
    """

    def __init__(self, data: bytes):
        self._fh = BytesIO(data)
        self.reads = 0
        self.bytes = 0
        self.max_read = 0
        self.read_bounds: list[tuple[int, int]] = []

    def read(self, size: int | None = -1) -> bytes:
        offset = self._fh.tell()
        data = self._fh.read(size)
        self.reads += 1
        self.bytes += len(data)
        self.max_read = max(self.max_read, len(data))
        self.read_bounds.append((offset, len(data)))
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        return self._fh.seek(offset, whence)

    def tell(self) -> int:
        return self._fh.tell()

    def close(self) -> None:
        self._fh.close()

    def __getattr__(self, name: str):
        return getattr(self._fh, name)

    def reset(self) -> None:
        self.reads = 0
        self.bytes = 0
        self.max_read = 0
        self.read_bounds = []
