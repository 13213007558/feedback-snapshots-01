"""Tests for the optional safe-update flow."""

import base64
import hashlib
import os
import sys
import zipfile
from pathlib import Path
from unittest import mock

import pytest
from installer import install
from installer.destinations import SchemeDictionaryDestination
from installer.exceptions import UpdateConflictError, UpdateFailedError
from installer.records import RecordEntry, parse_record_file
from installer.sources import WheelFile
from installer.update import update, verify_installation
from installer.utils import SCHEME_NAMES

FANCY_ENTRY_POINTS = b"[console_scripts]\nfancy = fancy:main\n"

OLD_MODULES = {
    "fancy/__init__.py": b"def main():\n    print('old')\n",
    "fancy/legacy.py": b"OLD = True\n",
}
NEW_MODULES = {
    "fancy/__init__.py": b"def main():\n    print('new')\n",
    "fancy/modern.py": b"NEW = True\n",
}
INDEPENDENT_MODULES = {
    "independent/__init__.py": b"INDEPENDENT = True\n",
    "shared.py": b"SHARED = True\n",
}


def _hash(data):
    digest = hashlib.sha256(data).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def build_wheel(tmp_path, name, version, modules, entry_points=None):
    dist_info = f"{name}-{version}.dist-info"
    files = dict(modules)
    files[f"{dist_info}/METADATA"] = (
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode()
    )
    files[f"{dist_info}/WHEEL"] = (
        b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\n"
        b"Tag: py3-none-any\n"
    )
    if entry_points is not None:
        files[f"{dist_info}/entry_points.txt"] = entry_points

    record_rows = sorted(
        f"{path},sha256={_hash(content)},{len(content)}"
        for path, content in files.items()
    )
    record_rows.append(f"{dist_info}/RECORD,,")
    files[f"{dist_info}/RECORD"] = ("\n".join(record_rows) + "\n").encode()

    wheel_path = tmp_path / f"{name}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel_path, "w") as archive:
        for path, content in files.items():
            archive.writestr(path, content)
    return wheel_path


def install_wheel(wheel_path, destination):
    with WheelFile.open(wheel_path) as source:
        return install(source, destination, {})


def snapshot(scheme_dict):
    """Digest every installed file, keyed by (scheme, relative path)."""
    result = {}
    for scheme, root in scheme_dict.items():
        for path in sorted(Path(root).rglob("*")):
            if path.is_file():
                result[(scheme, str(path.relative_to(root)))] = _hash(path.read_bytes())
    return result


@pytest.fixture
def scheme_dict(tmp_path):
    return {scheme: str(tmp_path / scheme) for scheme in SCHEME_NAMES}


@pytest.fixture
def destination(scheme_dict):
    return SchemeDictionaryDestination(
        scheme_dict, interpreter=sys.executable, script_kind="posix"
    )


@pytest.fixture
def previous_records(tmp_path, destination):
    """Old version of fancy, plus an independent distribution, installed."""
    old_wheel = build_wheel(tmp_path, "fancy", "1.0.0", OLD_MODULES, FANCY_ENTRY_POINTS)
    independent_wheel = build_wheel(
        tmp_path, "independent", "1.0.0", INDEPENDENT_MODULES
    )
    records = install_wheel(old_wheel, destination)
    install_wheel(independent_wheel, destination)
    return records


def test_update_refuses_files_of_another_distribution(
    tmp_path, destination, scheme_dict, previous_records
):
    # The new version wants a landing point that overlaps the independent
    # distribution's `shared.py`.
    new_modules = dict(NEW_MODULES)
    new_modules["shared.py"] = b"SHARED = 'taken over'\n"
    new_wheel = build_wheel(tmp_path, "fancy", "2.0.0", new_modules, FANCY_ENTRY_POINTS)

    before = snapshot(scheme_dict)
    with WheelFile.open(new_wheel) as source, pytest.raises(
        UpdateConflictError
    ) as exc_info:
        update(source, destination, previous_records)

    assert [(c.scheme, c.path, c.reason) for c in exc_info.value.conflicts] == [
        ("purelib", "shared.py", "foreign")
    ]
    # Nothing was modified.
    assert snapshot(scheme_dict) == before


def test_update_detects_divergence_from_approved_record(
    tmp_path, destination, scheme_dict, previous_records
):
    # The installed file no longer matches the approved record.
    target = Path(scheme_dict["purelib"]) / "fancy" / "__init__.py"
    target.write_bytes(b"def main():\n    print('tampered')\n")

    new_wheel = build_wheel(tmp_path, "fancy", "2.0.0", NEW_MODULES, FANCY_ENTRY_POINTS)

    before = snapshot(scheme_dict)
    with WheelFile.open(new_wheel) as source, pytest.raises(
        UpdateConflictError
    ) as exc_info:
        update(source, destination, previous_records)

    assert [(c.scheme, c.path, c.reason) for c in exc_info.value.conflicts] == [
        ("purelib", "fancy/__init__.py", "modified")
    ]
    assert snapshot(scheme_dict) == before


def test_failed_update_restores_previous_install_then_retry(
    tmp_path, destination, scheme_dict, previous_records
):
    new_wheel = build_wheel(tmp_path, "fancy", "2.0.0", NEW_MODULES, FANCY_ENTRY_POINTS)

    # Inject a failure just before the final RECORD would be written.
    with (
        WheelFile.open(new_wheel) as source,
        mock.patch.object(
            destination,
            "finalize_installation",
            side_effect=RuntimeError("injected failure"),
        ),
        pytest.raises(UpdateFailedError),
    ):
        update(source, destination, previous_records)

    # The old version can still be proven intact against its approved record.
    assert verify_installation(destination, previous_records) == []

    # The launcher of the old version is still in place and executable.
    launcher = Path(scheme_dict["scripts"]) / "fancy"
    assert launcher.exists()
    assert os.access(launcher, os.X_OK)

    # Rolled back: no new module, the removed old module is back.
    purelib = Path(scheme_dict["purelib"])
    assert not (purelib / "fancy" / "modern.py").exists()
    assert (purelib / "fancy" / "legacy.py").exists()

    # The independent distribution is untouched.
    independent_init = purelib / "independent" / "__init__.py"
    assert (
        independent_init.read_bytes() == INDEPENDENT_MODULES["independent/__init__.py"]
    )
    assert (purelib / "shared.py").read_bytes() == INDEPENDENT_MODULES["shared.py"]

    # No backup files were left behind.
    leftovers = [
        path
        for scheme in scheme_dict.values()
        for path in Path(scheme).rglob("*~installer-*")
    ]
    assert leftovers == []

    # Retry the approved update; this time it succeeds.
    with WheelFile.open(new_wheel) as source:
        report = update(source, destination, previous_records)

    # The report explains additions, removals and where the scripts went.
    assert ("purelib", "fancy/modern.py") in [(s, r.path) for s, r in report.added]
    assert ("purelib", "fancy/legacy.py") in [(s, r.path) for s, r in report.removed]
    assert any(scheme == "scripts" for scheme, _ in report.records)

    # The old version is gone, the new files are in place.
    assert not (purelib / "fancy" / "legacy.py").exists()
    assert not (purelib / "fancy-1.0.0.dist-info" / "METADATA").exists()
    assert (purelib / "fancy" / "__init__.py").read_bytes() == NEW_MODULES[
        "fancy/__init__.py"
    ]
    assert (purelib / "fancy" / "modern.py").read_bytes() == NEW_MODULES[
        "fancy/modern.py"
    ]

    # The new RECORD on disk matches the actual files, scripts included.
    record_path = purelib / "fancy-2.0.0.dist-info" / "RECORD"
    rows = list(parse_record_file(record_path.read_text().splitlines()))
    paths = [row[0] for row in rows]
    assert "fancy/modern.py" in paths
    assert "fancy/legacy.py" not in paths
    assert any(path.endswith("scripts/fancy") for path in paths)
    for path, hash_, size in rows:
        if path == "fancy-2.0.0.dist-info/RECORD":
            continue
        entry = RecordEntry.from_elements(path, hash_, size)
        # RECORD paths for other schemes are relative to the root scheme.
        target = (purelib / path).resolve()
        with target.open("rb") as stream:
            assert entry.validate_stream(stream), path

    # The independent distribution is still untouched.
    assert (
        independent_init.read_bytes() == INDEPENDENT_MODULES["independent/__init__.py"]
    )
    assert (purelib / "shared.py").read_bytes() == INDEPENDENT_MODULES["shared.py"]
