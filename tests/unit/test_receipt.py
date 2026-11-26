from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from virtualenv.activation.bash import BashActivator
from virtualenv.run import cli_run, session_via_cli

if TYPE_CHECKING:
    from pytest_mock import MockerFixture

_SYNTHETIC_FAILURE: Final[str] = "activation scripts would point at /private/synthetic-tenant/never"


def raising_activator_failure(*_args, **_kwargs) -> None:
    raise RuntimeError(_SYNTHETIC_FAILURE)


def _receipts(folder: Path) -> list[dict[str, object]]:
    return [json.loads(path.read_text(encoding="utf-8")) for path in sorted(folder.glob("receipt-*.json"))]


def _diagnostics(folder: Path) -> list[dict[str, object]]:
    return [json.loads(path.read_text(encoding="utf-8")) for path in sorted(folder.glob("diagnostic-*.json"))]


def _shared(tmp_path: Path) -> Path:
    shared: Final[Path] = tmp_path / "managed"
    shared.mkdir()
    return shared


def test_successful_creation_writes_shareable_receipt(tmp_path: Path) -> None:
    public: Final[Path] = tmp_path / "public"
    private: Final[Path] = tmp_path / "private"
    arguments: Final[list[str]] = [
        str(tmp_path / "env"),
        "--no-seed",
        "--activators",
        "python",
        "--receipt-dir",
        str(public),
        "--diagnostic-dir",
        str(private),
    ]
    session = cli_run(arguments, setup_logging=False)
    receipt: Final[dict[str, object]] = _receipts(public)[0]
    diagnostic: Final[dict[str, object]] = _diagnostics(private)[0]
    assert (
        receipt["outcome"],
        receipt["error"],
        receipt["handoff"],
        receipt["steps"],
        receipt["cleanup"],
    ) == (
        "succeeded",
        None,
        "not_required",
        {"create": "succeeded", "seed": "skipped", "activate": "succeeded", "finalize": "succeeded"},
        {"state": "not_required", "cleaned": True, "removed_entries": 0},
    )
    assert receipt["job"] == diagnostic["job"]
    assert str(session.creator.dest) not in json.dumps(receipt)
    assert str(public) not in json.dumps(receipt)
    assert str(private) not in json.dumps(receipt)


def test_public_receipt_carries_no_paths_or_cache_markers(tmp_path: Path) -> None:
    public: Final[Path] = tmp_path / "public"
    private: Final[Path] = tmp_path / "private"

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(BashActivator, "generate", raising_activator_failure)
        with pytest.raises(RuntimeError, match="synthetic-tenant"):
            cli_run(
                [
                    str(tmp_path / "env"),
                    "--no-seed",
                    "--activators",
                    "bash",
                    "--receipt-dir",
                    str(public),
                    "--diagnostic-dir",
                    str(private),
                ],
                setup_logging=False,
            )

    text: Final[str] = json.dumps(_receipts(public)[0])
    for leaked in (str(tmp_path), "/private/synthetic-tenant", "never", "receipt-", "diagnostic-", "report"):
        assert leaked not in text, leaked
    assert _receipts(public)[0]["error"] == {"kind": "RuntimeError"}
    assert "/private/synthetic-tenant" in json.dumps(_diagnostics(private)[0])


def test_failed_job_reclaims_only_its_own_materials(tmp_path: Path, mocker: MockerFixture) -> None:
    shared: Final[Path] = _shared(tmp_path)
    public: Final[Path] = tmp_path / "public"
    # job A starts from an existing destination that already holds content it did not create
    job_a: Final[Path] = shared / "job-a"
    job_a.mkdir()
    (job_a / "keep.txt").write_text("keep", encoding="utf-8")
    # job B finishes beside A, while A is still being built
    session: Final = cli_run([str(shared / "job-b"), "--no-seed", "--activators="], setup_logging=False)
    assert (shared / "job-b" / "pyvenv.cfg").is_file()

    patched: Final = mocker.patch.object(
        BashActivator, "generate", autospec=True, side_effect=RuntimeError(_SYNTHETIC_FAILURE)
    )
    try:
        with pytest.raises(RuntimeError, match="synthetic-tenant"):
            cli_run(
                [str(job_a), "--no-seed", "--activators", "bash", "--receipt-dir", str(public)],
                setup_logging=False,
            )
    finally:
        mocker.stop(patched)

    # A's own half-built tree and its .venv redirect are gone, its original content remains
    assert sorted(path.name for path in job_a.iterdir()) == ["keep.txt"]
    # B's finished environment and the shared parent's pre-existing content are untouched
    assert (session.creator.dest / "pyvenv.cfg").is_file()
    assert (shared / "job-a" / "keep.txt").read_text(encoding="utf-8") == "keep"


def test_two_interleaved_jobs_cleanup_and_retry(tmp_path: Path, mocker: MockerFixture) -> None:
    shared: Final[Path] = _shared(tmp_path)
    public: Final[Path] = tmp_path / "tickets"
    private: Final[Path] = tmp_path / "evidence"
    # job A has a pre-existing destination while job B, beside it, finishes
    job_a: Final[Path] = shared / "job-a"
    job_a.mkdir()
    (job_a / "keep.txt").write_text("keep", encoding="utf-8")
    job_b: Final[Path] = shared / "job-b"
    assert not job_b.exists()
    cli_run([str(job_b), "--activators", "bash", "--pip", "embed", "--no-periodic-update"], setup_logging=False)

    patched: Final = mocker.patch.object(
        BashActivator, "generate", autospec=True, side_effect=RuntimeError(_SYNTHETIC_FAILURE)
    )
    try:
        with pytest.raises(RuntimeError, match="synthetic-tenant"):
            cli_run(
                [
                    str(job_a),
                    "--activators",
                    "bash",
                    "--pip",
                    "embed",
                    "--no-periodic-update",
                    "--receipt-dir",
                    str(public),
                    "--diagnostic-dir",
                    str(private),
                ],
                setup_logging=False,
            )
    finally:
        mocker.stop(patched)

    receipt: Final[dict[str, object]] = _receipts(public)[0]
    diagnostic: Final[dict[str, object]] = _diagnostics(private)[0]
    # the ticket distinguishes the four facts without naming where anything is
    assert (receipt["outcome"], receipt["steps"]["seed"], receipt["steps"]["activate"]) == (
        "failed",
        "succeeded",
        "failed",
    )
    assert (receipt["cleanup"]["cleaned"], receipt["cleanup"]["state"], receipt["handoff"]) == (
        True,
        "preserved",
        "not_required",
    )
    assert str(tmp_path) not in json.dumps(receipt)
    assert "/private/synthetic-tenant" not in json.dumps(receipt)
    # the diagnostic links to the ticket and shows the actual retained content
    assert diagnostic["job"] == receipt["job"]
    assert Path(str(diagnostic["destination"])) == job_a.resolve()
    assert diagnostic["seeded"]
    # the disk matches: A keeps its old file, B keeps its finished environment
    assert sorted(path.name for path in job_a.iterdir()) == ["keep.txt"]
    assert (job_b / "pyvenv.cfg").is_file()

    session = cli_run(
        [str(job_a), "--activators", "bash", "--pip", "embed", "--no-periodic-update", "--receipt-dir", str(public)],
        setup_logging=False,
    )
    assert (job_a / "bin" / "activate").is_file()
    assert (job_a / "pyvenv.cfg").is_file()
    assert (job_a / "keep.txt").read_text(encoding="utf-8") == "keep"
    assert session.creator.dest == job_a
    assert (job_b / "pyvenv.cfg").is_file()


def test_failed_job_reports_seeded_cleanup_and_handoff(tmp_path: Path, mocker: MockerFixture) -> None:
    public: Final[Path] = tmp_path / "public"
    job: Final[Path] = tmp_path / "job"

    patched: Final = mocker.patch.object(
        BashActivator, "generate", autospec=True, side_effect=RuntimeError(_SYNTHETIC_FAILURE)
    )
    try:
        with pytest.raises(RuntimeError, match="synthetic-tenant"):
            cli_run(
                [
                    str(job),
                    "--activators",
                    "bash",
                    "--no-periodic-update",
                    "--pip",
                    "embed",
                    "--receipt-dir",
                    str(public),
                ],
                setup_logging=False,
            )
    finally:
        mocker.stop(patched)

    receipt: Final[dict[str, object]] = _receipts(public)[0]
    assert (receipt["outcome"], receipt["steps"]["seed"], receipt["steps"]["activate"]) == (
        "failed",
        "succeeded",
        "failed",
    )
    assert receipt["cleanup"]["cleaned"] is True
    assert receipt["cleanup"]["state"] == "completed"
    assert receipt["handoff"] == "not_required"
    assert receipt["steps"]["finalize"] == "not_started"


def test_incomplete_cleanup_needs_an_operator(tmp_path: Path, mocker: MockerFixture) -> None:
    public: Final[Path] = tmp_path / "public"
    job: Final[Path] = tmp_path / "job"

    patched: Final = mocker.patch.object(
        BashActivator, "generate", autospec=True, side_effect=RuntimeError(_SYNTHETIC_FAILURE)
    )
    refused: Final = mocker.patch(
        "virtualenv.run.receipt.safe_delete", autospec=True, side_effect=PermissionError("in use")
    )
    try:
        with pytest.raises(RuntimeError, match="synthetic-tenant"):
            cli_run([str(job), "--no-seed", "--activators", "bash", "--receipt-dir", str(public)], setup_logging=False)
    finally:
        mocker.stop(patched)
        mocker.stop(refused)

    receipt: Final[dict[str, object]] = _receipts(public)[0]
    diagnostic: Final[dict[str, object]] = _diagnostics(public)[0]
    assert (receipt["cleanup"]["cleaned"], receipt["handoff"]) == (False, "required")
    assert diagnostic["cleanup"]["retained"] == [str(job)]


def test_failed_job_retries_to_a_working_environment(tmp_path: Path, mocker: MockerFixture) -> None:
    public: Final[Path] = tmp_path / "public"
    job: Final[Path] = tmp_path / "job"
    job.mkdir()
    (job / "keep.txt").write_text("keep", encoding="utf-8")

    patched: Final = mocker.patch.object(
        BashActivator, "generate", autospec=True, side_effect=RuntimeError(_SYNTHETIC_FAILURE)
    )
    try:
        with pytest.raises(RuntimeError, match="synthetic-tenant"):
            cli_run([str(job), "--no-seed", "--activators", "bash", "--receipt-dir", str(public)], setup_logging=False)
    finally:
        mocker.stop(patched)

    session = cli_run(
        [str(job), "--no-seed", "--activators", "bash", "--receipt-dir", str(public)], setup_logging=False
    )
    assert (job / "bin" / "activate").is_file()
    assert (job / "pyvenv.cfg").is_file()
    assert (job / "keep.txt").read_text(encoding="utf-8") == "keep"
    assert any(receipt["outcome"] == "succeeded" for receipt in _receipts(public))
    assert session.creator.dest == job


def test_redirect_of_another_job_is_kept(tmp_path: Path, mocker: MockerFixture) -> None:
    shared: Final[Path] = _shared(tmp_path)
    (shared / "pyproject.toml").write_text("", encoding="utf-8")
    job_b: Final[Path] = cli_run(
        [str(shared / "job-b"), "--no-seed", "--activators=", "--venv-redirect"],
        setup_logging=False,
    ).creator.dest
    assert (shared / ".venv").read_text(encoding="utf-8") == "job-b\n"

    patched: Final = mocker.patch.object(
        BashActivator, "generate", autospec=True, side_effect=RuntimeError(_SYNTHETIC_FAILURE)
    )
    try:
        with pytest.raises(RuntimeError, match="synthetic-tenant"):
            cli_run(
                [str(shared / "job-a"), "--no-seed", "--activators", "bash", "--venv-redirect"],
                setup_logging=False,
            )
    finally:
        mocker.stop(patched)

    assert (shared / ".venv").read_text(encoding="utf-8") == "job-b\n"
    assert (job_b / "pyvenv.cfg").is_file()


def test_no_receipt_keeps_the_creation_summary_unchanged(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    session: Final = session_via_cli([str(tmp_path / "env"), "--no-seed", "--activators="])
    assert session.scope is not None
    assert session.scope.receipt_dir is None
    assert session.scope.diagnostic_dir is None
    assert capsys.readouterr().err == ""


def test_receipt_inside_environment_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="must not be inside the environment"):
        session_via_cli([str(tmp_path / "env"), "--receipt-dir", str(tmp_path / "env")])


def test_diagnostic_defaults_beside_receipt(tmp_path: Path) -> None:
    public: Final[Path] = tmp_path / "public"
    cli_run([str(tmp_path / "env"), "--no-seed", "--activators=", "--receipt-dir", str(public)], setup_logging=False)
    assert len(_receipts(public)) == 1
    assert len(_diagnostics(public)) == 1
    assert _receipts(public)[0]["evidence_retained"] is True


def test_receipt_is_written_after_creation(tmp_path: Path) -> None:
    public: Final[Path] = tmp_path / "public"
    session = cli_run(
        [str(tmp_path / "env"), "--no-seed", "--activators=", "--receipt-dir", str(public)], setup_logging=False
    )
    assert session.scope.receipt_path is not None
    assert session.scope.receipt_path.is_file()
    perms: Final[int] = session.scope.receipt_path.stat().st_mode & 0o777
    assert perms == 0o644
