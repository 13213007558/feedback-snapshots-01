"""Build the offline wheelhouse that stands in for the build platform baseline.

The cloud build portal only allows dependencies that the platform has already
vetted and cached. In an offline sandbox we cannot reach an index, so we seed
the wheelhouse from the wheels bundled with virtualenv and record every wheel
as part of the approved baseline manifest.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
WHEELHOUSE = HERE / "wheelhouse"
BASELINE = HERE / "baseline.json"

import virtualenv

_VIRTUALENV_PACKAGE = Path(virtualenv.__file__).resolve().parent
VIRTUALENV_EMBED = _VIRTUALENV_PACKAGE / "seed" / "wheels" / "embed"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    WHEELHOUSE.mkdir(exist_ok=True)
    if not VIRTUALENV_EMBED.is_dir():
        msg = f"virtualenv embedded wheel directory not found: {VIRTUALENV_EMBED}"
        raise SystemExit(msg)

    copied: list[str] = []
    for wheel in VIRTUALENV_EMBED.glob("*.whl"):
        target = WHEELHOUSE / wheel.name
        if not target.exists():
            target.write_bytes(wheel.read_bytes())
            copied.append(wheel.name)

    wheels = sorted(WHEELHOUSE.glob("*.whl"))
    manifest = {
        "source": "virtualenv bundled seed wheels (offline stand-in for the platform index mirror)",
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "wheels": [
            {"file": wheel.name, "sha256": _sha256(wheel), "bytes": wheel.stat().st_size} for wheel in wheels
        ],
    }
    BASELINE.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wheelhouse: {len(wheels)} wheel(s) at {WHEELHOUSE}")
    for name in copied:
        print(f"  copied {name}")
    print(f"baseline manifest: {BASELINE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
