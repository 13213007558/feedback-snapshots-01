"""Check current artifact approvals for selected environments without installing."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from tox.plugin import impl
from tox.session.env_select import CliEnv, register_env_select_flags
from tox.tox_env.errors import Fail
from tox.tox_env.python.pip.pip_install import Pip
from tox.tox_env.python.pip.req_file import PythonDeps
from tox.tox_env.python.pylock import Pylock

if TYPE_CHECKING:
    from tox.config.cli.parser import ToxParser
    from tox.session.state import State


@impl
def tox_add_option(parser: ToxParser) -> None:
    """Add the ``approvals`` sub-command.

    :param parser: tox argument parser
    """
    our = parser.add_command(
        "approvals",
        [],
        "check current approval policy for resolved dependency artifacts",
        approvals_command,
    )
    our.add_argument("--json", action="store_true", help="print approval evidence as JSON", dest="approvals_json")
    register_env_select_flags(our, default=CliEnv())


def approvals_command(state: State) -> int:
    """Check approvals for selected environments.

    :param state: current tox state
    :returns: zero when every selected environment is approved
    """
    import json

    as_json = bool(state.conf.options.approvals_json)
    reports: list[dict[str, object]] = []
    failed = False
    for name in state.envs.iter():
        env = state.envs[name]
        installer = cast("Pip", env.installer)
        try:
            arguments = _install_arguments(env)
            evidence = installer.review_approvals(arguments, "ApprovalCommand.check")
        except Fail as exc:
            failed = True
            if not as_json:
                print(str(exc))  # noqa: T201 - command output
            reports.append({"env": name, "approved": False, "error": str(exc)})
            continue
        if evidence is None:
            if not as_json:
                print(f"{name}: no artifact approval policy configured")  # noqa: T201
            reports.append({"env": name, "enabled": False, "approved": True})
            continue
        if not evidence.approved:
            failed = True
        if not as_json:
            print(  # noqa: T201
                f"{name}: {'approved' if evidence.approved else 'blocked'} "
                f"{len(evidence.artifacts)} artifact(s) evidence={evidence.digest[:12]}",
            )
        reports.append({"env": name, **evidence.as_dict()})
    if as_json:
        print(json.dumps(reports, indent=2, sort_keys=True))  # noqa: T201
    return 1 if failed else 0


def _install_arguments(env: object) -> PythonDeps | Pylock:
    conf = env.conf  # type: ignore[attr-defined]
    pylock_name = conf.get("pylock", str)
    if pylock_name:
        package_root = env.core["package_root"]  # type: ignore[attr-defined]
        marker_environment = None
        target = getattr(env, "_target_marker_environment", None)
        if callable(target):
            try:
                marker_environment = target()
            except Fail:
                marker_environment = None
        return Pylock(
            path=package_root / pylock_name,
            extras=frozenset(conf.get("extras", set[str])),
            groups=frozenset(conf.get("dependency_groups", set[str])),
            marker_env=marker_environment or {},
        )
    return cast("PythonDeps", conf.get("deps", PythonDeps))


__all__ = ["approvals_command"]
