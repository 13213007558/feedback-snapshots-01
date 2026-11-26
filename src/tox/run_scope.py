"""Carry a run's environment selection and approvals across a provisioning re-exec.

tox can start a second tox process to install the version the project asks for. That process reads the project
configuration again and selects environments again. This module keeps both under the control of the process that was
invoked:

- before re-executing, the outer process records the environments it selected and the approvals it holds in a small
  JSON file inside the work directory and points the child at it with :data:`SCOPE_FILE_ENV`;
- the child selects exactly the recorded environments, so its own defaults, labels or factors cannot quietly add
  another one;
- the child checks the record again before each stage - preparing the tox version and its requirements, and starting
  a project command - so an approval withdrawn while the configuration is being read stops that stage, with a message
  saying how to continue;
- a run that needs no provisioning writes and checks the same record, so both paths follow one rule.

Every process also appends what it decided to a plan file, so the outer and inner arguments, environment selection and
the command that actually started can be compared. Both files are opt-in: pass ``--run-scope`` or set
``run_scope = true`` in the core configuration.
"""

from __future__ import annotations

__lazy_modules__ = [
    "json",
    "logging",
    "os",
    "pathlib",
    "subprocess",
    "tox.report",
    "tox.util.redact",
    f"{__spec__.parent}.report",  # ty: ignore[missing-union-attribute]  # imported modules have a spec
]

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

from .report import HandledError
from .util.redact import redact_argv

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .config.sets import CoreConfigSet
    from .session.state import State
    from .util.json_types import JsonValue

SCOPE_FILE_ENV: Final[str] = "TOX_RUN_SCOPE_FILE"
"""Environment variable that points the re-executed tox at the scope its outer process recorded."""

SCOPE_FILE: Final[str] = "run.scope.json"
"""Name of the scope record inside the work directory."""

PLAN_FILE: Final[str] = "run.scope.plan.ndjson"
"""Name of the append-only record of what each process decided, inside the work directory."""

PREPARE_HOLD: Final[str] = "TOX_RUN_SCOPE_PREPARE_HOLD"
"""Environment variable naming a command to run once after the preparation approval passes, before installing."""

CONFIGURE_HOLD: Final[str] = "TOX_RUN_SCOPE_CONFIGURE_HOLD"
"""Environment variable naming a command to run once in the child, after it read the configuration and before the
environments are selected, so an approval can be withdrawn while the child is still starting up."""

PREPARE: Final[str] = "prepare"
"""Stage of installing the tox version and its requirements."""

CONFIGURE: Final[str] = "configure"
"""Stage of reading the project configuration and selecting its environments."""

EXECUTE: Final[str] = "execute"
"""Stage of starting a project command."""

_REASONS: Final[dict[str, str]] = {
    PREPARE: "the approval to prepare the tox version and its requirements was withdrawn",
    EXECUTE: "the approval to run a project command in this environment was withdrawn",
}


@dataclass(frozen=True)
class RunScope:
    """The environments a run selected and the approvals that let it act.

    :param envs: the environment names the run selected, ``None`` when the run left the selection to the configuration
    :param all_envs: whether the run selected every environment
    :param labels: the labels the run selected
    :param factors: the factor groups the run selected
    :param approved: the environments that may start a project command, ``None`` when every selected one may
    :param prepare: whether preparing the tox version and its requirements is approved
    :param parent: the scope record this one was read from, ``None`` for the run that created it

    """

    envs: tuple[str, ...] | None = None
    all_envs: bool = False
    labels: tuple[str, ...] = ()
    factors: tuple[tuple[str, ...], ...] = ()
    approved: frozenset[str] | None = None
    prepare: bool = True
    parent: str | None = None

    def allows_prepare(self) -> bool:
        """:returns: whether preparing the tox version and its requirements is still approved"""
        return self.prepare

    def allows_command(self, name: str) -> bool:
        """:param name: the environment about to start a project command

        :returns: whether the environment may still start a project command

        """
        return self.approved is None or name in self.approved

    def to_json(self) -> dict[str, JsonValue]:
        """:returns: the scope as a JSON document"""
        return {
            "envs": list(self.envs) if self.envs is not None else None,
            "all": self.all_envs,
            "labels": list(self.labels),
            "factors": [list(group) for group in self.factors],
            "approved": sorted(self.approved) if self.approved is not None else None,
            "prepare": self.prepare,
            "parent": self.parent,
        }

    @classmethod
    def from_json(cls, data: JsonValue) -> RunScope:
        """Build a scope from the JSON document written by :meth:`to_json`.

        :param data: the JSON document

        :returns: the scope

        :raises ValueError: when the document is not a scope

        """
        if not isinstance(data, dict):
            msg = "the run scope is not a JSON object"
            raise ValueError(msg)
        envs = data.get("envs")
        approved = data.get("approved")
        labels = data.get("labels")
        factors = data.get("factors")
        parent = data.get("parent")
        return cls(
            envs=tuple(str(name) for name in envs) if isinstance(envs, list) else None,
            all_envs=bool(data.get("all", False)),
            labels=tuple(str(label) for label in labels) if isinstance(labels, list) else (),
            factors=tuple(tuple(str(part) for part in group) for group in factors) if isinstance(factors, list) else (),
            approved=frozenset(str(name) for name in approved) if isinstance(approved, list) else None,
            prepare=bool(data.get("prepare", True)),
            parent=parent if isinstance(parent, str) else None,
        )


@dataclass(frozen=True)
class RunPlan:
    """One process's decision at one stage.

    :param role: ``outer`` for the process tox was started as, ``inner`` for a re-executed tox
    :param stage: the stage the process reached
    :param command: the arguments the process was started with
    :param environments: the environments the process selected, in order
    :param approved: the environments that may start a project command at this stage
    :param launched: the project command actually started at this stage, ``None`` when none started
    :param scope: the scope record the process read or wrote

    """

    role: str
    stage: str
    command: tuple[str, ...]
    environments: tuple[str, ...]
    approved: tuple[str, ...]
    launched: tuple[str, ...] | None
    scope: str | None

    def to_json(self) -> dict[str, JsonValue]:
        """:returns: the plan as a JSON document"""
        return {
            "role": self.role,
            "stage": self.stage,
            "command": list(self.command),
            "environments": list(self.environments),
            "approved": list(self.approved),
            "launched": list(self.launched) if self.launched is not None else None,
            "scope": self.scope,
        }


@dataclass
class _Bound:
    state: State | None = None
    scope: RunScope | None = None
    path: Path | None = None
    role: str = "outer"


_BOUND: Final[_Bound] = _Bound()


def register_config(core: CoreConfigSet) -> None:
    """Register the core keys that turn the rule on and narrow the approvals.

    :param core: the core configuration

    """
    core.add_config(
        keys="run_scope",
        of_type=bool,
        default=False,
        desc="keep the selected environments and approvals when tox provisions a newer version",
    )
    core.add_config(
        keys="run_scope_approved",
        of_type=list[str],
        default=[],
        desc="environments that may start a project command when run_scope is set (unset means every selected one)",
    )


def enabled(state: State) -> bool:
    """Return whether the run keeps its selection and approvals.

    :param state: the state of the run

    :returns: whether the rule is on, either asked for directly or inherited from the outer process

    """
    if SCOPE_FILE_ENV in os.environ:
        return True
    if getattr(state.conf.options, "run_scope", False):
        return True
    return bool(state.conf.core.get("run_scope", bool))


def reset() -> None:
    """Forget the scope bound by a previous run in this process, so a new run starts clean."""
    _BOUND.state, _BOUND.scope, _BOUND.path, _BOUND.role = None, None, None, "outer"


def prepare(state: State) -> RunScope | None:
    """Read the scope from the outer process, or record it for this run, before the environments are selected.

    :param state: the state of the run

    :returns: the scope in force, ``None`` when the rule is off

    :raises tox.report.HandledError: when an inherited scope record cannot be read

    """
    reset()
    if not enabled(state):
        return None
    raw = os.environ.get(SCOPE_FILE_ENV)
    if raw:
        path = Path(raw)
        scope, role = _read(path), "inner"
    else:
        scope, role = _select(state), "outer"
        path = scope_path(state.conf.core)
        write_scope(path, scope)
    _BOUND.state, _BOUND.scope, _BOUND.path, _BOUND.role = state, scope, path, role
    record(state, CONFIGURE)
    if role == "inner":
        # let an operator withdraw an approval while the child has read the configuration but has not selected or run
        _run_hold(CONFIGURE_HOLD)
    return scope


def active() -> RunScope | None:
    """:returns: the scope in force, ``None`` when the rule is off"""
    return _BOUND.scope


def check_prepare(state: State) -> None:
    """Check the approval for preparation right before the tox version and its requirements are installed.

    :param state: the state of the run

    :raises tox.report.HandledError: when preparation is not approved

    """
    if _BOUND.scope is None:
        return
    if not _current().allows_prepare():
        raise HandledError(f"refusing to prepare tox: {_REASONS[PREPARE]}; approve it again to continue")
    record(state, PREPARE)
    _run_hold(PREPARE_HOLD)


def check_command(name: str) -> None:
    """Refuse to start a project command in an environment the current approvals exclude.

    The record is read again, so an approval withdrawn while the configuration was read applies here.

    :param name: the environment about to start a project command

    :raises tox.report.HandledError: when the environment may not start a command, with how to continue

    """
    scope = _BOUND.scope
    if scope is None:
        return
    if scope.envs is not None and name not in scope.envs:
        msg = f"refusing to run {name}: it is not one of the environments this run selected; approve it again to run it"
        raise HandledError(msg)
    if not _current().allows_command(name):
        raise HandledError(f"refusing to run {name}: {_REASONS[EXECUTE]}; approve it again to continue")


def record_launch(launched: Sequence[str]) -> None:
    """Record the project command that started, so the plan shows what really launched.

    :param launched: the command line that started

    """
    if _BOUND.state is not None:
        record(_BOUND.state, EXECUTE, launched)


def scope_path(core: CoreConfigSet) -> Path:
    """Return the scope record of a project.

    :param core: the core configuration

    :returns: the path of the record inside the work directory

    """
    return core.get("work_dir", Path) / SCOPE_FILE


def write_scope(path: Path, scope: RunScope) -> None:
    """Write a scope record so the next process can read it.

    :param path: the path to write to
    :param scope: the scope to write

    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(scope.to_json(), indent=2), encoding="utf-8")


def read_scope(path: Path) -> RunScope:
    """Read a scope record written by the outer process.

    :param path: the path to read

    :returns: the scope

    :raises tox.report.HandledError: when the record is missing or not a scope

    """
    return _read(path)


def record(state: State, stage: str, launched: Sequence[str] | None = None) -> None:
    """Append what this process decided to the plan file, and log it.

    :param state: the state of the run
    :param stage: the stage the process reached
    :param launched: the command actually started at this stage, ``None`` when none started

    """
    scope, path = _BOUND.scope, _BOUND.path
    if scope is None or path is None:
        return
    current = _current()
    plan = RunPlan(
        role=_BOUND.role,
        stage=stage,
        command=tuple(redact_argv(list(state.args))),
        environments=_selected(scope),
        approved=tuple(sorted(current.approved)) if current.approved is not None else _selected(scope),
        launched=tuple(redact_argv(list(launched))) if launched is not None else None,
        scope=str(path),
    )
    logging.info(
        "run scope plan: role=%s stage=%s selected=%s approved=%s launched=%s",
        plan.role,
        plan.stage,
        _join(plan.environments),
        _join(plan.approved),
        " ".join(plan.launched) if plan.launched else "-",
    )
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with (path.parent / PLAN_FILE).open("a", encoding="utf-8") as file_handler:
            file_handler.write(json.dumps(plan.to_json(), ensure_ascii=False))
            file_handler.write("\n")
    except OSError:  # pragma: no cover  # untested error path
        logging.warning("could not append to the run scope plan %s", path.parent / PLAN_FILE)


def _selected(scope: RunScope) -> tuple[str, ...]:
    return scope.envs or ()


def _read(path: Path) -> RunScope:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return RunScope.from_json(data)
    except (OSError, ValueError) as exception:
        msg = f"cannot read the run scope {path} passed by the outer tox process: {exception}"
        raise HandledError(msg) from exception


def _current() -> RunScope:
    path = _BOUND.path
    if path is not None and path.exists():
        try:
            return _read(path)
        except HandledError:  # an unreadable record means no approval survives
            return RunScope(envs=_BOUND.scope.envs if _BOUND.scope else None, approved=frozenset(), prepare=False)
    assert _BOUND.scope is not None  # ruff:ignore[assert]  # invariant, the caller checked it is set
    return _BOUND.scope


def _select(state: State) -> RunScope:
    options = state.conf.options
    cli = getattr(options, "env", None)
    labels = tuple(getattr(options, "labels", []))
    factors = tuple(tuple(group) for group in _factor_groups(getattr(options, "factors", [])))
    envs: tuple[str, ...] | None = None
    all_envs = False
    if not labels and not factors:
        if cli is not None and cli.is_all:
            all_envs = True
        elif cli is not None and not cli.is_default_list:
            envs = tuple(cli)
        else:
            envs = _configured_env_list(state)
    approved_cfg = tuple(state.conf.core.get("run_scope_approved", list[str]))
    approved = frozenset(approved_cfg) if approved_cfg else None
    return RunScope(envs=envs, all_envs=all_envs, labels=labels, factors=factors, approved=approved)


def _configured_env_list(state: State) -> tuple[str, ...]:
    from .config.types import EnvList  # ruff:ignore[import-outside-top-level]  # avoids an import cycle

    return tuple(state.conf.core.get("env_list", EnvList))


def _factor_groups(raw: Sequence[Sequence[str]]) -> list[set[str]]:
    return [{part for factor in group for part in factor.split("-")} for group in raw]


def _run_hold(name: str) -> None:
    hold = os.environ.get(name)
    if not hold:
        return
    from subprocess import run as run_process  # ruff:ignore[import-outside-top-level]  # only needed for a hold

    env = dict(os.environ)
    if _BOUND.path is not None:
        env[SCOPE_FILE_ENV] = str(_BOUND.path)
    run_process(hold, shell=True, check=False, env=env)  # noqa: S602 - the hold is an operator supplied seam


def _join(names: Sequence[str]) -> str:
    return ", ".join(names) if names else "none"


__all__ = [
    "CONFIGURE",
    "CONFIGURE_HOLD",
    "EXECUTE",
    "PLAN_FILE",
    "PREPARE",
    "PREPARE_HOLD",
    "SCOPE_FILE",
    "SCOPE_FILE_ENV",
    "RunPlan",
    "RunScope",
    "active",
    "check_command",
    "check_prepare",
    "enabled",
    "prepare",
    "read_scope",
    "record",
    "record_launch",
    "register_config",
    "reset",
    "scope_path",
    "write_scope",
]
