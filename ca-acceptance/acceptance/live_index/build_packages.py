"""Build minimal offline packages for the live-index acceptance run.

Outputs into the artifact root:

* ``corpdemo-1.0-py3-none-any.whl`` - a pure-Python wheel installable without
  a build step;
* ``seabuild-0.1-py3-none-any.whl`` - the PEP 517 build backend package that
  must be fetched into the isolated build environment;
* ``needbuild-2.0.tar.gz`` - an sdist whose build-system.requires pulls
  ``seabuild`` from the authenticated index, exercising the nested
  build-dependency network path.

Only the standard library is used so the fixtures stay self-contained.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path


def _wheel(path: Path, distribution: str, version: str, payload: dict[str, str]) -> Path:
    dist_info = f"{distribution}-{version}.dist-info"
    metadata = (
        f"Metadata-Version: 2.1\n"
        f"Name: {distribution}\n"
        f"Version: {version}\n"
        f"Summary: local acceptance fixture\n"
    )
    wheel_meta = "Wheel-Version: 1.0\nGenerator: ca-acceptance\nRoot-Is-Purelib: true\n\n"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in payload.items():
            zf.writestr(name, content)
        zf.writestr(f"{dist_info}/METADATA", metadata)
        zf.writestr(f"{dist_info}/WHEEL", wheel_meta)
        zf.writestr(f"{dist_info}/RECORD", "")
    return path


def build(artifact_root: Path) -> dict[str, Path]:
    artifact_root.mkdir(parents=True, exist_ok=True)
    wheel_path = _wheel(
        artifact_root / "corpdemo-1.0-py3-none-any.whl",
        "corpdemo",
        "1.0",
        {"corpdemo/__init__.py": "__version__ = '1.0'\n"},
    )
    backend_path = _wheel(
        artifact_root / "seabuild-0.1-py3-none-any.whl",
        "seabuild",
        "0.1",
        {
            "seabuild/__init__.py": (
                "import tarfile, zipfile\n"
                "def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):\n"
                "    name = 'needbuild-2.0-py3-none-any.whl'\n"
                "    with zipfile.ZipFile(__import__('pathlib').Path(wheel_directory) / name, 'w') as zf:\n"
                "        zf.writestr('needbuild/__init__.py', \"__version__ = '2.0'\\n\")\n"
                "        zf.writestr('needbuild-2.0.dist-info/METADATA', 'Metadata-Version: 2.1\\nName: needbuild\\nVersion: 2.0\\n')\n"
                "        zf.writestr('needbuild-2.0.dist-info/WHEEL', 'Wheel-Version: 1.0\\nGenerator: seabuild\\n\\n')\n"
                "        zf.writestr('needbuild-2.0.dist-info/RECORD', '')\n"
                "    return name\n"
            )
        },
    )

    sdist_path = artifact_root / "needbuild-2.0.tar.gz"
    files = {
        "needbuild-2.0/pyproject.toml": (
            "[build-system]\n"
            "requires = ['seabuild==0.1']\n"
            "build-backend = 'seabuild'\n"
        ),
        "needbuild-2.0/needbuild/__init__.py": "__version__ = '2.0'\n",
        "needbuild-2.0/PKG-INFO": "Metadata-Version: 2.1\nName: needbuild\nVersion: 2.0\n",
    }
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tf:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    sdist_path.write_bytes(buffer.getvalue())
    return {"wheel": wheel_path, "backend_wheel": backend_path, "sdist": sdist_path}
