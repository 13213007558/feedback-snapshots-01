"""Demonstrate bytecode admission and post-install verification.

Runs the same wheel twice against an isolated ``--destdir`` layout:

1. a full install, with an unrelated ``.pyc`` pre-seeded in the target cache;
2. an install of a wheel whose second module fails to compile.

For each run it prints the state derived from the artifacts on disk, not from
in-memory bookkeeping, so the result can be re-checked in a separate process.

Usage::

    python examples/bytecode-admission.py
"""

import sys
import tempfile
import zipfile
from pathlib import Path

from installer import install
from installer.destinations import (
    SchemeDictionaryDestination,
    inspect_installation,
)
from installer.exceptions import BytecodeCompilationError
from installer.sources import WheelFile
from installer.utils import SCHEME_NAMES

WHEEL_NAME = "demo-1.0.0-py3-none-any.whl"


def _build_wheel(directory: Path, *, broken_second_module: bool) -> Path:
    wheel = directory / WHEEL_NAME
    second = b"def broken(:\n" if broken_second_module else b"def ok():\n    return 2\n"
    files = {
        "demo/__init__.py": b"VALUE = 1\n",
        "demo/second.py": second,
        "demo-1.0.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        "demo-1.0.0.dist-info/METADATA": (
            b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0.0\n"
        ),
        "demo-1.0.0.dist-info/RECORD": b"",
    }
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return wheel


def _scheme_dict(dest: Path) -> dict[str, str]:
    return {scheme: str(dest / scheme) for scheme in SCHEME_NAMES}


def _seed_decoy(dest: Path) -> None:
    """Pre-place unrelated bytecode where the real cache will live."""
    cache = dest / str(dest).lstrip("/") / "purelib" / "demo" / "__pycache__"
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "decoy.cpython-312.pyc").write_bytes(b"from an older install")


def _installed_cache(dest: Path) -> Path:
    """Locate the module cache in a ``--destdir`` install."""
    return dest / str(dest).lstrip("/") / "purelib" / "demo" / "__pycache__"


def _run(wheel: Path, dest: Path, levels: list[int]) -> str:
    schemes = _scheme_dict(dest)
    destination = SchemeDictionaryDestination(
        schemes,
        sys.executable,
        "posix",
        bytecode_optimization_levels=levels,
        destdir=str(dest),
    )
    try:
        with WheelFile.open(wheel) as source:
            install(source, destination, {})
    except BytecodeCompilationError as exc:
        print(f"installation refused: {exc}\n")

    report = inspect_installation(
        schemes,
        "demo-1.0.0.dist-info/RECORD",
        bytecode_optimization_levels=levels,
        destdir=str(dest),
    )
    print(f"status:          {report.status}")
    print(f"distribution:    {report.distribution} {report.version}")
    print(f"official files:  {sorted(report.official_files)}")
    for artifact in report.bytecode:
        print(
            f"bytecode:        {artifact.source} "
            f"opt={artifact.optimization_level} -> {artifact.state}"
        )
    print(
        "unexpected pyc:  " f"{[p.name for p in report.unexpected_bytecode] or 'none'}"
    )
    print(f"issues:          {list(report.issues) or 'none'}\n")
    return report.status


def main() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        levels = [0, 1]

        good_dest = root / "good"
        _seed_decoy(good_dest)
        print("== full install (unrelated cache pre-seeded) ==")
        _run(_build_wheel(root, broken_second_module=False), good_dest, levels)

        bad_dest = root / "bad"
        _seed_decoy(bad_dest)
        print("== install where the second module fails to compile ==")
        _run(_build_wheel(root, broken_second_module=True), bad_dest, levels)


if __name__ == "__main__":
    main()
