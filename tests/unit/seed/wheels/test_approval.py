from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from virtualenv.app_data import AppDataDiskFolder
from virtualenv.seed.wheels.approval import (
    Approval,
    ApprovalIntegrityError,
    ApprovalLedger,
    ApprovedWheel,
)
from virtualenv.seed.wheels.periodic_update import UpdateLog, trigger_update


def make_stub_wheel(folder: Path, version: str, distribution: str = "setuptools") -> Path:
    """Create a minimal but really installable pure-Python wheel double."""
    filename = f"{distribution}-{version}-py3-none-any.whl"
    path = folder / filename
    files = {
        f"{distribution}/__init__.py": f"__version__ = {version!r}\n",
        f"{distribution}-{version}.dist-info/METADATA": (
            "Metadata-Version: 2.1\n"
            f"Name: {distribution}\n"
            f"Version: {version}\n"
        ),
        f"{distribution}-{version}.dist-info/WHEEL": (
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        f"{distribution}-{version}.dist-info/top_level.txt": f"{distribution}\n",
    }
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
        archive.writestr(
            f"{distribution}-{version}.dist-info/RECORD",
            "".join(f"{name},,\n" for name in files),
        )
    return path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def seed_cli(venv: Path, app_data: Path, approval: str, version: str = "bundle") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "virtualenv",
            str(venv),
            "--app-data",
            str(app_data),
            "--seeder",
            "app-data",
            "--activators",
            "",
            "--no-periodic-update",
            "--no-pip",
            "--no-wheel",
            "--setuptools",
            version,
            "--seed-approval",
            approval,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def installed_version(venv: Path) -> str:
    process = subprocess.run(
        [
            str(venv_python(venv)),
            "-c",
            "from importlib.metadata import version; print(version('setuptools'))",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 0, process.stderr
    return process.stdout.strip()


def test_approval_ledger_is_shared_between_app_data_instances(tmp_path: Path) -> None:
    wheel_dir = tmp_path / "wheels"
    wheel_dir.mkdir()
    wheel = make_stub_wheel(wheel_dir, "90.0")
    app_data = tmp_path / "app-data"

    first = ApprovalLedger(AppDataDiskFolder(str(app_data)))
    committed = first.record_update("APR-1", "3.12", [wheel])

    second = ApprovalLedger(AppDataDiskFolder(str(app_data)))
    selected = second.select("3.12", "APR-1")

    assert selected is not None
    assert (selected.approval_id, selected.set.id, selected.stale) == ("APR-1", committed.id, False)
    assert selected.path_for("setuptools") == app_data / "wheel" / "house" / wheel.name
    assert selected.path_for("setuptools").read_bytes() == wheel.read_bytes()


def test_tightened_approval_enforces_digest(tmp_path: Path) -> None:
    wheel_dir = tmp_path / "wheels"
    wheel_dir.mkdir()
    wheel = make_stub_wheel(wheel_dir, "91.0")
    approval = Approval(
        id="APR-TIGHT",
        wheels={
            "setuptools": ApprovedWheel(
                distribution="setuptools",
                filename=wheel.name,
                version="91.0",
                sha256="0" * 64,
            ),
        },
    )
    ledger = ApprovalLedger(tmp_path / "app-data")

    with pytest.raises(ApprovalIntegrityError, match="SHA-256"):
        ledger.record_update(approval, "3.12", [wheel])

    assert ledger.latest_ready("3.12") is None


def test_update_log_round_trips_approval_identity() -> None:
    log = UpdateLog(None, None, [], True, approval_id="APR-7")

    restored = UpdateLog.from_dict(log.to_dict())

    assert log.to_dict()["approval_id"] == "APR-7"
    assert log.to_dict()["approval"] == "APR-7"
    assert restored.approval_id == "APR-7"


def test_interleaved_update_tightening_offline_create_and_recovery(tmp_path: Path) -> None:
    wheel_dir = tmp_path / "wheels"
    wheel_dir.mkdir()
    wheel_a = make_stub_wheel(wheel_dir, "90.0")
    wheel_b = make_stub_wheel(wheel_dir, "91.0")

    app_data = tmp_path / "app-data"
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    ledger = ApprovalLedger(AppDataDiskFolder(str(app_data)))
    approval_a = Approval(id="APR-A", index_url="https://approved.example/simple/a")
    approval_b_document = tmp_path / "approval-b.json"
    approval_b = Approval(
        id="APR-B",
        index_url="https://approved.example/simple/b",
        wheels={
            "setuptools": ApprovedWheel.from_path(wheel_b),
        },
    )
    approval_b_document.write_text(json.dumps(approval_b.to_dict()), encoding="utf-8")

    ready_a = ledger.record_update(approval_a, py_version, [wheel_a])

    # An independent process sees the last ready approval in the shared cache.
    visibility = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json, sys; "
                "from virtualenv.seed.wheels.approval import ApprovalLedger; "
                "from virtualenv.app_data import AppDataDiskFolder; "
                "sel = ApprovalLedger(AppDataDiskFolder(sys.argv[1])).select(sys.argv[2], sys.argv[3]); "
                "print(json.dumps({'approval_id': sel.approval_id, 'stale': sel.stale}))"
            ),
            str(app_data),
            py_version,
            "APR-A",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert visibility.returncode == 0, visibility.stderr
    assert json.loads(visibility.stdout) == {"approval_id": "APR-A", "stale": False}

    first_venv = tmp_path / "venv-a"
    result_a = seed_cli(first_venv, app_data, "APR-A")
    assert result_a.returncode == 0, result_a.stderr
    assert installed_version(first_venv) == "90.0"
    receipt_a = json.loads((first_venv / "seed-approval.json").read_text(encoding="utf-8"))
    assert (receipt_a["approval_id"], receipt_a["stale"], receipt_a["installed_versions"]["setuptools"]) == (
        "APR-A",
        False,
        "90.0",
    )
    images = list((app_data / "wheel" / py_version / "image" / "1").glob("*/*setuptools-90.0*"))
    assert images, "the expanded wheel image must be visible in shared AppData"

    # A background attempt has frozen APR-B but has not committed its wheel set.
    attempt_b = ledger.begin("APR-B", py_version)

    second_venv = tmp_path / "venv-while-b-pending"
    result_b = seed_cli(second_venv, app_data, str(approval_b_document))
    assert result_b.returncode == 0, result_b.stderr
    assert installed_version(second_venv) == "90.0"
    receipt_b = json.loads((second_venv / "seed-approval.json").read_text(encoding="utf-8"))
    assert receipt_b["approval_id"] == "APR-A"
    assert receipt_b["requested_approval_id"] == "APR-B"
    assert receipt_b["stale"] is True
    assert receipt_b["installed_versions"]["setuptools"] == "90.0"
    assert "seed-approval-stale = true" in (second_venv / "pyvenv.cfg").read_text(encoding="utf-8")

    # The queued update fails; the active pointer still names APR-A.
    failed_b = ledger.fail(attempt_b.id, RuntimeError("local mirror returned 500"))
    assert failed_b.status == "failed"
    assert ledger.latest_ready(py_version).id == ready_a.id

    third_venv = tmp_path / "venv-after-failure"
    result_failure = seed_cli(third_venv, app_data, str(approval_b_document))
    assert result_failure.returncode == 0, result_failure.stderr
    assert installed_version(third_venv) == "90.0"
    receipt_failure = json.loads((third_venv / "seed-approval.json").read_text(encoding="utf-8"))
    assert receipt_failure["approval_id"] == "APR-A"

    # Recovery commits the tightened APR-B set; new offline processes use it.
    ready_b = ledger.record_update(approval_b, py_version, [wheel_b])
    assert ready_b.approval_id == "APR-B"

    recovered_venv = tmp_path / "venv-recovered"
    result_recovered = seed_cli(recovered_venv, app_data, str(approval_b_document))
    assert result_recovered.returncode == 0, result_recovered.stderr
    assert installed_version(recovered_venv) == "91.0"
    receipt_recovered = json.loads((recovered_venv / "seed-approval.json").read_text(encoding="utf-8"))
    assert receipt_recovered["approval_id"] == "APR-B"
    assert receipt_recovered["stale"] is False
    assert receipt_recovered["installed_versions"]["setuptools"] == "91.0"
    assert ledger.select(py_version, "APR-B").set.id == ready_b.id

    # The failed attempt is retained, but exactly one ready B set is active.
    assert [item.approval_id for item in ledger.sets(py_version, status="failed")] == ["APR-B"]
    assert wheel_b.exists()


def test_background_trigger_freezes_approval_id(tmp_path: Path, mocker) -> None:
    process = mocker.create_autospec(subprocess.Popen, instance=True, pid=4321)
    popen = mocker.patch("virtualenv.seed.wheels.periodic_update.Popen", autospec=True, return_value=process)
    app_data = AppDataDiskFolder(str(tmp_path / "app-data"))

    trigger_update(
        "pip",
        "3.12",
        None,
        [],
        app_data,
        {},
        True,
        approval_id="APR-FROZEN",
    )

    code = popen.call_args.args[0][2]
    assert "approval_id='APR-FROZEN'" in code
    compile(code, "<approval-trigger>", "exec")
