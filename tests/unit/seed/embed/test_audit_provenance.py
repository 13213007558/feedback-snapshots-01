from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import zipfile
from base64 import urlsafe_b64encode
from typing import TYPE_CHECKING, Any, Final

import pytest
from python_discovery import PythonInfo
from python_discovery import (
    _cached_py_info as cached_py_info,  # ruff:ignore[import-private-name]  # test cache  # fmt: skip
)
from virtualenv import cli_run
from virtualenv.app_data import AppDataDiskFolder
from virtualenv.seed.wheels.periodic_update import UnverifiedWheelError, do_update

if TYPE_CHECKING:
    from pathlib import Path

    from pytest_mock import MockerFixture

_DISTRIBUTION: Final[str] = "setuptools"
_APPROVED_VERSION: Final[str] = "900.0"
_ATTEMPTED_VERSION: Final[str] = "901.0"
_PY_TAG: Final[str] = "py3-none-any"
_SCHEMA: Final[str] = "virtualenv.offline-audit-evidence/v1"

_PROBE_CODE: Final[str] = """
import hashlib
import json
from importlib.metadata import distribution
from pathlib import Path

import _audit_provenance_seed

dist = distribution("setuptools")
metadata_path = dist.locate_file(f"setuptools-{dist.version}.dist-info/METADATA")
print(json.dumps({
    "implementation": __import__("sys").implementation.name,
    "cache_tag": __import__("sys").implementation.cache_tag,
    "running_version": __import__("sys").version.split()[0],
    "seed_version": dist.version,
    "content_marker": _audit_provenance_seed.MARKER,
    "metadata_sha256": hashlib.sha256(Path(metadata_path).read_bytes()).hexdigest(),
}))
"""


def test_offline_audit_evidence_distinguishes_discovery_attempt_and_adoption(  # noqa: PLR0915
    tmp_path: Path,
    mocker: MockerFixture,
) -> None:
    approved_dir = tmp_path / "approved-wheels"
    approved_dir.mkdir()
    approved_wheel = _make_seed_wheel(approved_dir, _APPROVED_VERSION, "approved-audit-material")
    attempted_wheel = _make_seed_wheel(tmp_path / "attempted-wheels", _ATTEMPTED_VERSION, "attempted-audit-material")
    approved_digest = _sha256_file(approved_wheel)
    attempted_digest = _sha256_file(attempted_wheel)
    approved_metadata_digest = _wheel_metadata_digest(approved_wheel, _APPROVED_VERSION)

    app_data_dir = tmp_path / "app-data"
    first_env = tmp_path / "envs" / "first"
    second_env = tmp_path / "envs" / "second"
    creation_env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"VIRTUALENV_NO_PERIODIC_UPDATE", "VIRTUALENV_OVERRIDE_APP_DATA"}
    }
    creation_env["VIRTUALENV_NO_DOWNLOAD"] = "1"
    creation_env["_VIRTUALENV_PERIODIC_UPDATE_INLINE"] = "1"
    creation_args = [
        "--python",
        sys.executable,
        "--app-data",
        str(app_data_dir),
        "--seeder",
        "app-data",
        "--activators",
        "",
        "--no-pip",
        "--setuptools",
        _APPROVED_VERSION,
        "--extra-search-dir",
        str(approved_dir),
    ]

    first_session = cli_run([str(first_env), *creation_args, "--no-periodic-update"], env=creation_env)
    first_runtime = _probe_installed_environment(first_session.creator.exe)
    release = first_session.interpreter.version_release_str
    app_data = AppDataDiskFolder(str(app_data_dir))
    update_store = app_data.embed_update_log(_DISTRIBUTION, release)

    _assert_approved_runtime(first_runtime, approved_metadata_digest)
    assert not update_store.exists()

    discovery_files = _python_info_digests(app_data_dir)
    discovery_digest = _discovery_digest(discovery_files)
    discovered_marker = _interpreter_marker(app_data_dir, first_runtime)

    download_calls, update_failures = _install_update_doubles(mocker, attempted_wheel.name, attempted_digest)
    PythonInfo._cache_exe_discovery.clear()  # ruff:ignore[private-member-access]
    cached_py_info._CACHE.clear()  # ruff:ignore[private-member-access]
    interpreter_probe = mocker.patch(
        "python_discovery._cached_py_info.Popen",
        autospec=True,
        side_effect=AssertionError("second creation probed the interpreter instead of using its information"),
    )

    second_session = cli_run([str(second_env), *creation_args], env=creation_env)
    second_runtime = _probe_installed_environment(second_session.creator.exe)

    interpreter_probe.assert_not_called()
    second_discovery_files = _python_info_digests(app_data_dir)
    assert second_discovery_files == discovery_files
    assert _discovery_digest(second_discovery_files) == discovery_digest
    _assert_approved_runtime(second_runtime, approved_metadata_digest)
    assert second_runtime["running_version"] == first_runtime["running_version"]
    assert second_runtime["implementation"] == first_runtime["implementation"]

    update_log = update_store.read()
    update_log_digest = _sha256_file(update_store.file)
    app_data.close()

    _assert_failed_update_record(update_log, download_calls, update_failures, release)
    assert download_calls[0]["candidate_filename"] == attempted_wheel.name
    assert download_calls[0]["candidate_digest"] == attempted_digest
    assert len({discovery_digest, attempted_digest, approved_digest, approved_metadata_digest}) == 4

    evidence = {
        "schema": _SCHEMA,
        "discovered": {
            "source_marker": "python-info-disk-cache",
            "interpreter_marker": discovered_marker,
            "material_digest": discovery_digest,
        },
        "update_attempt": {
            "source_marker": f"failing-download-double:{attempted_wheel.name}",
            "candidate_digest": attempted_digest,
            "update_log_digest": update_log_digest,
            "outcome_marker": "started-without-completion:not-adopted",
        },
        "adopted": {
            "source_marker": f"local-approved-wheel:{approved_wheel.name}",
            "interpreter_marker": discovered_marker,
            "installed_marker": f"{_DISTRIBUTION}-{second_runtime['seed_version']}.dist-info/METADATA",
            "material_digest": approved_digest,
            "installed_metadata_digest": second_runtime["metadata_sha256"],
        },
    }

    report_text = json.dumps(evidence, sort_keys=True)
    assert json.loads(report_text) == evidence
    _assert_shareable_markers_and_digests_only(evidence)
    _assert_report_omits_machine_configuration(report_text, tmp_path, app_data_dir)
    _assert_report_matches_physical_environment(evidence, second_runtime, approved_metadata_digest)

    wrong_report = _OverclaimedAdoptionReport(attempted_wheel.name, attempted_digest, evidence).shareable()
    with pytest.raises(AssertionError, match="physical environment says"):
        _assert_report_matches_physical_environment(wrong_report, second_runtime, approved_metadata_digest)
    assert _ATTEMPTED_VERSION in json.dumps(wrong_report)
    _assert_report_omits_machine_configuration(json.dumps(wrong_report, sort_keys=True), tmp_path, app_data_dir)


class _OverclaimedAdoptionReport:
    """Report double that promotes a failed update candidate to the adopted seed."""

    def __init__(self, attempted_filename: str, attempted_digest: str, evidence: dict[str, Any]) -> None:
        self.attempted_filename = attempted_filename
        self.attempted_digest = attempted_digest
        self.evidence = evidence

    def shareable(self) -> dict[str, Any]:
        return {
            "schema": _SCHEMA,
            "discovered": self.evidence["discovered"],
            "update_attempt": self.evidence["update_attempt"],
            "adopted": {
                "source_marker": f"download-double:{self.attempted_filename}",
                "interpreter_marker": self.evidence["discovered"]["interpreter_marker"],
                "installed_marker": f"{_DISTRIBUTION}-{_ATTEMPTED_VERSION}.dist-info/METADATA",
                "material_digest": self.attempted_digest,
                "installed_metadata_digest": hashlib.sha256(b"report-double-has-no-installed-file").hexdigest(),
            },
        }


def _install_update_doubles(
    mocker: MockerFixture,
    attempted_filename: str,
    attempted_digest: str,
) -> tuple[list[dict[str, Any]], list[Exception]]:
    download_calls: list[dict[str, Any]] = []
    update_failures: list[Exception] = []

    def download_double(**kwargs: Any) -> None:
        kwargs["candidate_filename"] = attempted_filename
        kwargs["candidate_digest"] = attempted_digest
        download_calls.append(kwargs)
        raise UnverifiedWheelError(f"offline download double refuses {_ATTEMPTED_VERSION}")

    def trigger_double(  # noqa: PLR0913  # ruff:ignore[too-many-arguments]
        distribution: str,
        for_py_version: str,
        wheel: Any,
        search_dirs: list[Path],
        app_data: AppDataDiskFolder,
        env: dict[str, str],
        periodic: bool,
    ) -> None:
        del env
        try:
            do_update(
                distribution,
                for_py_version,
                None if wheel is None else str(wheel.path),
                app_data,
                search_dirs,
                periodic,
            )
        except Exception as exception:  # noqa: BLE001  # ruff:ignore[blind-except]
            # The real update runs in a detached process, whose failed return code also cannot fail creation.
            update_failures.append(exception)

    mocker.patch("virtualenv.seed.wheels.acquire.download_wheel", side_effect=download_double)
    mocker.patch("virtualenv.seed.wheels.periodic_update.trigger_update", side_effect=trigger_double)
    return download_calls, update_failures


def _probe_installed_environment(executable: Path) -> dict[str, str]:
    completed = subprocess.run(
        [str(executable), "-c", _PROBE_CODE],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    result: dict[str, str] = json.loads(completed.stdout)
    return result


def _assert_approved_runtime(runtime: dict[str, str], approved_metadata_digest: str) -> None:
    assert runtime["running_version"] == ".".join(str(part) for part in sys.version_info[:3])
    assert runtime["seed_version"] == _APPROVED_VERSION
    assert runtime["content_marker"] == "approved-audit-material"
    assert runtime["metadata_sha256"] == approved_metadata_digest


def _assert_failed_update_record(
    update_log: dict[str, Any],
    download_calls: list[dict[str, Any]],
    update_failures: list[Exception],
    release: str,
) -> None:
    assert update_log["started"] is not None
    assert update_log["completed"] is None
    assert update_log["periodic"] is True
    assert update_log["versions"] == []
    assert len(download_calls) == 1
    assert download_calls[0]["distribution"] == _DISTRIBUTION
    assert download_calls[0]["for_py_version"] == release
    assert download_calls[0]["version_spec"] is None
    assert len(update_failures) == 1
    assert isinstance(update_failures[0], UnverifiedWheelError)


def _make_seed_wheel(folder: Path, version: str, material_marker: str) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    stem = f"{_DISTRIBUTION}-{version}"
    dist_info = f"{stem}.dist-info"
    package = "_audit_provenance_seed"
    files: dict[str, bytes] = {
        f"{package}/__init__.py": f"MARKER = {material_marker!r}\n".encode(),
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.1\n"
            f"Name: {_DISTRIBUTION}\n"
            f"Version: {version}\n"
            "Summary: offline supply-chain audit fixture\n"
        ).encode(),
        f"{dist_info}/WHEEL": f"""Wheel-Version: 1.0
Generator: offline-audit-test
Root-Is-Purelib: true
Tag: {_PY_TAG}
""".encode(),
    }
    rows = []
    for name, content in files.items():
        digest = urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode("ascii")
        rows.append(f"{name},sha256={digest},{len(content)}")
    files[f"{dist_info}/RECORD"] = ("\n".join([*rows, f"{dist_info}/RECORD,,"]) + "\n").encode()

    wheel_path = folder / f"{stem}-{_PY_TAG}.whl"
    with zipfile.ZipFile(wheel_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return wheel_path


def _wheel_metadata_digest(wheel_path: Path, version: str) -> str:
    metadata_name = f"{_DISTRIBUTION}-{version}.dist-info/METADATA"
    with zipfile.ZipFile(wheel_path) as archive:
        return hashlib.sha256(archive.read(metadata_name)).hexdigest()


def _python_info_digests(app_data_dir: Path) -> dict[str, str]:
    return {path.name: _sha256_file(path) for path in sorted((app_data_dir / "py_info" / "5").glob("*.json"))}


def _discovery_digest(files: dict[str, str]) -> str:
    digest = hashlib.sha256()
    for filename, file_digest in sorted(files.items()):
        digest.update(filename.encode("utf-8"))
        digest.update(file_digest.encode("ascii"))
    return digest.hexdigest()


def _interpreter_marker(app_data_dir: Path, runtime: dict[str, str]) -> str:
    for probe_path in sorted((app_data_dir / "py_info" / "5").glob("*.json")):
        probe = json.loads(probe_path.read_text(encoding="utf-8"))
        if probe.get("path") == sys.executable:
            architecture = probe["content"]["architecture"]
            return f"{runtime['implementation']}-{runtime['running_version']}-{architecture}"
    probe = json.loads(next((app_data_dir / "py_info" / "5").glob("*.json")).read_text(encoding="utf-8"))
    return f"{runtime['implementation']}-{runtime['running_version']}-{probe['content']['architecture']}"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _assert_shareable_markers_and_digests_only(evidence: dict[str, Any]) -> None:
    assert set(evidence) == {"schema", "discovered", "update_attempt", "adopted"}
    expected_keys = {
        "discovered": {"source_marker", "interpreter_marker", "material_digest"},
        "update_attempt": {"source_marker", "candidate_digest", "update_log_digest", "outcome_marker"},
        "adopted": {
            "source_marker",
            "interpreter_marker",
            "installed_marker",
            "material_digest",
            "installed_metadata_digest",
        },
    }
    for section, keys in expected_keys.items():
        assert set(evidence[section]) == keys
        for key, value in evidence[section].items():
            assert isinstance(value, str) and value
            if key.endswith("digest"):
                assert len(value) == 64
                int(value, 16)


def _assert_report_matches_physical_environment(
    report: dict[str, Any], runtime: dict[str, str], approved_metadata_digest: str
) -> None:
    adopted = report["adopted"]
    actual_marker = f"{_DISTRIBUTION}-{runtime['seed_version']}.dist-info/METADATA"
    errors = []
    if adopted["installed_marker"] != actual_marker:
        errors.append(f"installed marker is {actual_marker}")
    if adopted["installed_metadata_digest"] != runtime["metadata_sha256"]:
        errors.append(f"installed metadata digest is {runtime['metadata_sha256']}")
    if runtime["metadata_sha256"] != approved_metadata_digest:
        errors.append("installed metadata does not match the locally approved wheel")
    if errors:
        message = "report adoption claim is wrong; physical environment says: " + "; ".join(errors)
        raise AssertionError(message)


def _assert_report_omits_machine_configuration(report_text: str, tmp_path: Path, app_data_dir: Path) -> None:
    assert str(tmp_path) not in report_text
    assert sys.executable not in report_text
    for probe_file in sorted((app_data_dir / "py_info" / "5").glob("*.json")):
        probe = json.loads(probe_file.read_text(encoding="utf-8"))
        for key in ("path",):
            value = probe.get(key)
            if isinstance(value, str) and value:
                assert value not in report_text, key
        content = probe["content"]
        for key in ("executable", "original_executable", "system_executable", "prefix", "base_prefix"):
            value = content.get(key)
            if isinstance(value, str) and value:
                assert value not in report_text, key
        assert json.dumps(content.get("sysconfig", {}), sort_keys=True) not in report_text
