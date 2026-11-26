"""Tiny helper to build deterministic wheels for the demo/tests.

The wheels produced here have a correct ``RECORD`` (real sha256/size values),
so :meth:`installer.sources.WheelFile.validate_record` and the plan's
"declared facts" are meaningful.  One member can be arbitrarily large, which
lets the demo prove that large wheels are streamed in fixed-size chunks rather
than buffered whole.
"""

from __future__ import annotations

import base64
import hashlib
import io
import zipfile
from pathlib import Path


def _b64_sha256(data: bytes) -> tuple[str, int]:
    digest = hashlib.sha256(data).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("="), len(data)


def deterministic_blob(size: int, *, seed: int = 0) -> bytes:
    """Return ``size`` pseudo-random but deterministic bytes.

    Generated in chunks so constructing a multi-megabyte blob does not go
    through a slow Python-level byte-by-byte loop.
    """
    if size < 0:
        raise ValueError("size must be non-negative")
    chunks: list[bytes] = []
    remaining = size
    counter = seed
    while remaining > 0:
        block = hashlib.sha256(counter.to_bytes(8, "big")).digest()
        if len(block) >= remaining:
            chunks.append(block[:remaining])
            break
        chunks.append(block)
        remaining -= len(block)
        counter += 1
    return b"".join(chunks)


def build_demo_wheel(
    wheel_path: str | Path,
    *,
    distribution: str = "demopkg",
    version: str = "1.0.0",
    big_size: int = 300_000,
    with_entrypoint: bool = True,
) -> Path:
    """Write a wheel containing a package, a large blob and valid RECORD."""
    wheel_path = Path(wheel_path)
    wheel_path.parent.mkdir(parents=True, exist_ok=True)

    dist_info = f"{distribution}-{version}.dist-info"
    data_dir = f"{distribution}-{version}.data"

    files: dict[str, bytes] = {}
    files[f"{distribution}/__init__.py"] = (
        f"def main():\n    print('hello from {distribution}')\n"
    ).encode("utf-8")
    if big_size:
        files[f"{distribution}/blob.bin"] = deterministic_blob(big_size)

    files[f"{dist_info}/WHEEL"] = (
        "Wheel-Version: 1.0\n"
        "Generator: deploy-demo-reference\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    ).encode("utf-8")
    files[f"{dist_info}/METADATA"] = (
        "Metadata-Version: 2.1\n"
        f"Name: {distribution}\n"
        f"Version: {version}\n"
        "Summary: wheel used by the deployment safety demo\n"
    ).encode("utf-8")
    if with_entrypoint:
        files[f"{dist_info}/entry_points.txt"] = (
            "[console_scripts]\n" f"{distribution} = {distribution}:main\n"
        ).encode("utf-8")
    files[f"{dist_info}/top_level.txt"] = f"{distribution}\n".encode()
    files[f"{data_dir}/data/{distribution}/note.txt"] = b"data-scheme payload\n"

    record_rows: list[str] = []
    for name, data in files.items():
        hash_value, size = _b64_sha256(data)
        record_rows.append(f"{name},sha256={hash_value},{size}")
    record_rows.append(f"{dist_info}/RECORD,,")
    files[f"{dist_info}/RECORD"] = ("\n".join(record_rows) + "\n").encode("utf-8")

    with zipfile.ZipFile(wheel_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)

    return wheel_path


def hash_stream_sha256(stream: io.BufferedIOBase) -> tuple[str, int]:
    """Chunk-hash a binary stream without reading it all into memory."""
    hasher = hashlib.sha256()
    size = 0
    while True:
        chunk = stream.read(64 * 1024)
        if not chunk:
            break
        hasher.update(chunk)
        size += len(chunk)
    return base64.urlsafe_b64encode(hasher.digest()).decode("ascii").rstrip("="), size
