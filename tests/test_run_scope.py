from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from tox.run_scope import (
    CONFIGURE_HOLD,
    PLAN_FILE,
    PREPARE_HOLD,
    SCOPE_FILE,
    SCOPE_FILE_ENV,
    RunScope,
    read_scope,
    write_scope,
)

if TYPE_CHECKING:
    from pytest_mock import MockerFixture

    from tox.pytest import MonkeyPatch, ToxProject, ToxProjectCreator, ToxRunOutcome


def _project(tox_project: ToxProjectCreator, envs: str = "alpha,beta,gamma") -> ToxProject:
    listed = ", ".join(f'"{name}"' for name in envs.split(","))
    return tox_project({
        "tox.toml": f"""
            env_list = [{listed}]

            [env_run_base]
            package = "skip"
            commands = [["python", "-c", "print('ran {{env_name}}')"]]
        """,
    })


def _plans(project: ToxProject) -> list[dict[str, object]]:
    path = project.path / ".tox" / PLAN_FILE
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _write_scope(project: ToxProject, scope: RunScope) -> Path:
    path = project.path / ".tox" / SCOPE_FILE
    write_scope(path, scope)
    return path


def _inherit(monkeypatch: MonkeyPatch, path: Path) -> None:
    monkeypatch.setenv(SCOPE_FILE_ENV, str(path))


def test_scope_off_by_default_runs_normally(tox_project: ToxProjectCreator) -> None:
    project = _project(tox_project)

    outcome: ToxRunOutcome = project.run("r", "-e", "alpha", "-q")

    outcome.assert_success()
    assert not (project.path / ".tox" / SCOPE_FILE).exists()
    assert _plans(project) == []
    assert "ran alpha" in outcome.out


def test_scope_records_the_run_selection_and_the_command_that_started(tox_project: ToxProjectCreator) -> None:
    project = _project(tox_project)

    outcome = project.run("r", "--run-scope", "-e", "alpha", "-q")

    outcome.assert_success()
    assert read_scope(project.path / ".tox" / SCOPE_FILE).envs == ("alpha",)
    plans = _plans(project)
    assert [(entry["role"], entry["stage"]) for entry in plans] == [("outer", "configure"), ("outer", "execute")]
    assert plans[0]["environments"] == ["alpha"]
    assert plans[0]["launched"] is None  # nothing started while configuring
    assert plans[1]["launched"] == ["python", "-c", "print('ran alpha')"]


def test_scope_subset_keeps_the_rest_of_the_env_list_out(tox_project: ToxProjectCreator) -> None:
    project = _project(tox_project)

    outcome = project.run("r", "--run-scope", "-e", "alpha", "-q")

    outcome.assert_success()
    assert "ran alpha" in outcome.out
    assert "ran beta" not in outcome.out
    assert "ran gamma" not in outcome.out


def test_inherited_scope_ignores_the_default_selection(
    tox_project: ToxProjectCreator, monkeypatch: MonkeyPatch
) -> None:
    project = _project(tox_project)
    _inherit(monkeypatch, _write_scope(project, RunScope(envs=("alpha",))))

    # naming no environment would select the whole env_list without the inherited record
    outcome = project.run("r", "-q")

    outcome.assert_success()
    assert "ran alpha" in outcome.out
    assert "ran beta" not in outcome.out
    assert "ran gamma" not in outcome.out


def test_inherited_scope_refuses_an_environment_outside_it(
    tox_project: ToxProjectCreator, monkeypatch: MonkeyPatch
) -> None:
    project = _project(tox_project)
    _inherit(monkeypatch, _write_scope(project, RunScope(envs=("alpha",))))

    outcome = project.run("r", "-e", "gamma", "-q")

    outcome.assert_failed(-2)
    assert "gamma cannot run in this invocation" in outcome.out
    assert "ran gamma" not in outcome.out


def test_inherited_scope_withdrawn_approval_stops_before_the_command(
    tox_project: ToxProjectCreator, monkeypatch: MonkeyPatch
) -> None:
    project = _project(tox_project)
    _inherit(monkeypatch, _write_scope(project, RunScope(envs=("alpha",), approved=frozenset())))

    outcome = project.run("r", "-q")

    outcome.assert_failed()
    assert "refusing to run alpha" in outcome.out
    assert "approve it again to continue" in outcome.out
    assert "ran alpha" not in outcome.out


def test_inherited_scope_keeps_a_still_approved_environment_running(
    tox_project: ToxProjectCreator, monkeypatch: MonkeyPatch
) -> None:
    project = _project(tox_project)
    _inherit(monkeypatch, _write_scope(project, RunScope(envs=("alpha", "beta"), approved=frozenset({"beta"}))))

    outcome = project.run("r", "-q")

    outcome.assert_failed()  # alpha is refused, beta still runs
    assert "refusing to run alpha" in outcome.out
    assert "ran alpha" not in outcome.out
    assert "ran beta" in outcome.out


def test_inherited_scope_withdrawn_preparation_approval_stops_before_install(
    tox_project: ToxProjectCreator, monkeypatch: MonkeyPatch, mocker: MockerFixture
) -> None:
    project = tox_project({
        "tox.toml": """
            requires = ["demo-pkg-missing"]

            [env_run_base]
            package = "skip"
            commands = [["python", "-c", "print('ran {env_name}')"]]
        """,
    })
    scope_path = project.path / ".tox" / SCOPE_FILE
    write_scope(scope_path, RunScope(envs=("py",), prepare=True))
    monkeypatch.setenv(SCOPE_FILE_ENV, str(scope_path))
    def _withdraw(name: str) -> None:  # noqa: ARG001 - the seam passes the stage name
        data = json.loads(scope_path.read_text())
        data["prepare"] = False
        scope_path.write_text(json.dumps(data))

    mocker.patch("tox.run_scope._run_hold", side_effect=_withdraw)

    outcome = project.run("r", "-q")

    outcome.assert_failed(-2)
    assert "refusing to prepare tox" in outcome.out
    assert "approve it again to continue" in outcome.out
    assert "demo-pkg-missing" not in outcome.out  # nothing tried to install it


def test_scope_reports_an_unreadable_record(tox_project: ToxProjectCreator, monkeypatch: MonkeyPatch) -> None:
    project = _project(tox_project)
    bad = project.path / ".tox" / SCOPE_FILE
    bad.parent.mkdir(parents=True, exist_ok=True)
    bad.write_text("not json", encoding="utf-8")
    _inherit(monkeypatch, bad)

    outcome = project.run("r", "-q")

    outcome.assert_failed(-2)
    assert "cannot read the run scope" in outcome.out


def test_scope_names_are_the_public_contract() -> None:
    # a caller withdraws an approval by editing the record, or pauses a stage with these environment variables
    assert SCOPE_FILE_ENV == "TOX_RUN_SCOPE_FILE"
    assert SCOPE_FILE == "run.scope.json"
    assert CONFIGURE_HOLD == "TOX_RUN_SCOPE_CONFIGURE_HOLD"
    assert PREPARE_HOLD == "TOX_RUN_SCOPE_PREPARE_HOLD"


def test_scope_round_trips_through_json(tmp_path: Path) -> None:
    scope = RunScope(
        envs=("alpha", "beta"),
        labels=("lint",),
        factors=(("py312", "coverage"),),
        approved=frozenset({"alpha"}),
        prepare=False,
        parent="/tmp/outer.json",
    )
    path = tmp_path / "scope.json"

    write_scope(path, scope)

    assert read_scope(path) == scope


def test_scope_honors_a_custom_work_dir(tox_project: ToxProjectCreator) -> None:
    project = _project(tox_project)
    work_dir = project.path / "custom"

    outcome = project.run("r", "--run-scope", "-e", "alpha", "--workdir", str(work_dir), "-q")

    outcome.assert_success()
    assert (work_dir / SCOPE_FILE).is_file()
    assert not (project.path / ".tox" / SCOPE_FILE).exists()


def test_inner_scope_withdrawal_during_configure_stops_that_environment(
    tox_project: ToxProjectCreator, monkeypatch: MonkeyPatch
) -> None:
    project = _project(tox_project)
    scope_path = project.path / ".tox" / SCOPE_FILE
    write_scope(scope_path, RunScope(envs=("alpha", "beta"), approved=frozenset({"alpha", "beta"})))
    withdrawal = (
        "from json import load, dump; from pathlib import Path; "
        "p = Path('" + str(scope_path) + "'); d = load(p.open()); "
        "d['approved'] = [n for n in d['approved'] if n != 'alpha']; dump(d, p.open('w'))"
    )
    monkeypatch.setenv(SCOPE_FILE_ENV, str(scope_path))
    monkeypatch.setenv(CONFIGURE_HOLD, f'"{sys.executable}" -c "{withdrawal}"')

    outcome = project.run("r", "-q")

    outcome.assert_failed()  # alpha is refused, beta still runs
    assert "refusing to run alpha" in outcome.out
    assert "ran alpha" not in outcome.out
    assert "ran beta" in outcome.out


def test_scope_hold_runs_the_command_from_the_environment(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    from tox.run_scope import _run_hold  # ruff:ignore[import-outside-top-level]  # exercise the seam directly

    marker = tmp_path / "hold-ran"
    write = f"from pathlib import Path; Path({str(marker)!r}).write_text('1')"
    monkeypatch.setenv(PREPARE_HOLD, f'"{sys.executable}" -c "{write}"')

    _run_hold(PREPARE_HOLD)

    assert marker.read_text() == "1"


def test_scope_provision_child_receives_the_record_path(
    tox_project: ToxProjectCreator, mocker: MockerFixture
) -> None:
    from tox.provision import _setup_and_execute  # ruff:ignore[import-outside-top-level]  # exercise the seam directly

    project = _project(tox_project)
    state = _setup_state(project, "r", "--run-scope", "-e", "alpha")
    from tox import run_scope  # ruff:ignore[import-outside-top-level]  # the scope binds before provisioning

    run_scope.register_config(state.conf.core)
    run_scope.prepare(state)
    state.envs._mark_provision(True, ".tox")  # ruff:ignore[private-member-access]  # mark the provision env
    captured: dict[str, dict[str, str]] = {}

    def _execute(*, cmd: object, stdin: object, show: object, run_id: object, cwd: object, env: object) -> object:
        captured["env"] = env  # type: ignore[assignment]
        outcome = mocker.MagicMock()
        outcome.exit_code = 0
        return outcome

    tox_env = mocker.MagicMock()
    tox_env.conf = {"env_name": ".tox"}
    tox_env.environment_variables = {"PATH": "/usr/bin"}
    tox_env.base_python.version_info = (3, 12)
    tox_env.execute.side_effect = _execute
    mocker.patch("tox.tox_env.python.virtual_env.runner.VirtualEnvRunner.setup", autospec=True)
    _setup_and_execute(tox_env, Path(sys.executable), state)

    assert captured["env"][SCOPE_FILE_ENV] == str(state.conf.core["work_dir"] / SCOPE_FILE)
    assert captured["env"]["PATH"] == "/usr/bin"  # the environment variables of the provision environment survive


def _setup_state(project: ToxProject, *args: str) -> object:
    from tox.run import setup_state  # ruff:ignore[import-outside-top-level]  # avoid a module level cycle

    with project.chdir():
        return setup_state(args)


def test_inherited_scope_refuses_all_selection(tox_project: ToxProjectCreator, monkeypatch: MonkeyPatch) -> None:
    project = _project(tox_project)
    _inherit(monkeypatch, _write_scope(project, RunScope(envs=("alpha",))))

    outcome = project.run("r", "-e", "ALL", "-q")

    outcome.assert_failed(-2)
    assert "ALL cannot be used in this invocation" in outcome.out


