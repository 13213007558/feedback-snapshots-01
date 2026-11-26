"""Run tox environments in parallel."""

from __future__ import annotations

__lazy_modules__ = [
    "argparse",
    "tox.execute.input_arbiter",
    "tox.session.env_select",
    "tox.util.ci",
    "tox.util.cpu",
    f"{__spec__.parent}.common",  # ty: ignore[missing-union-attribute]  # imported modules have a spec
]

import logging
from argparse import ArgumentParser, ArgumentTypeError
from pathlib import Path
from typing import TYPE_CHECKING, Final

from tox.execute.input_arbiter import InputArbiter
from tox.plugin import impl
from tox.session.env_select import CliEnv, register_env_select_flags
from tox.util.ci import is_ci
from tox.util.cpu import auto_detect_cpus

from .common import env_run_create_flags, execute

if TYPE_CHECKING:
    from tox.config.cli.parser import ToxParser
    from tox.session.state import State

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)
"""Logger of the parallel run."""

ENV_VAR_KEY: Final[str] = "TOX_PARALLEL_ENV"
"""Environment variable that tells a parallel sub-process which environment it runs."""
OFF_VALUE: Final[int] = 0
"""Value of the parallel option that turns parallel runs off."""


@impl
def tox_add_option(parser: ToxParser) -> None:
    """Add the ``run-parallel`` sub-command to the command line parser.

    :param parser: the parser to add the sub-command to

    """
    our = parser.add_command("run-parallel", ["p"], "run environments in parallel", run_parallel)
    register_env_select_flags(our, default=CliEnv())
    env_run_create_flags(our, mode="run-parallel")
    parallel_flags(our, default_parallel="auto")


def run_parallel(state: State) -> int:
    """Here we'll just start parallel sub-processes.

    :param state: the state of the run

    :returns: the exit code of the run

    :raises SystemExit: when the run is interrupted

    """
    option = state.conf.options
    if option.no_capture:
        msg = "--no-capture cannot be used with parallel mode"
        raise SystemExit(msg)
    option.input_arbiter = build_input_arbiter(option)
    return execute(
        state,
        max_workers=1 if option.parallel == OFF_VALUE else option.parallel,
        has_spinner=option.parallel_no_spinner is False and option.parallel_live is False,
        live=option.parallel_live,
    )


def parallel_flags(
    our: ArgumentParser,
    default_parallel: int | str,
    # keeps the existing signature
    no_args: bool = False,  # ruff:ignore[boolean-type-hint-positional-argument, boolean-default-value-positional-argument]
) -> None:
    """Add the flags that control how many environments run in parallel.

    :param our: the parser to add the flags to
    :param default_parallel: the number of parallel processes when the flag is not given
    :param no_args: whether the parallel flag can be given without a value

    """
    our.add_argument(
        "-p",
        "--parallel",
        dest="parallel",
        help="run tox environments in parallel, the argument controls limit: all,"
        " auto - cpu count, some positive number, zero is turn off",
        action="store",
        type=parse_num_processes,
        default=default_parallel,
        metavar="VAL",
        nargs="?" if no_args else None,
    )
    our.add_argument(
        "-o",
        "--parallel-live",
        action="store_true",
        dest="parallel_live",
        help="connect to stdout while running environments",
    )
    our.add_argument(
        "--parallel-no-spinner",
        action="store_true",
        dest="parallel_no_spinner",
        default=is_ci(),
        help="disable the spinner when running in parallel, enabled by default in CI",
    )
    our.add_argument(
        "--terminal-input",
        dest="terminal_input",
        action="append",
        default=[],
        metavar="ENV:commands[INDEX]",
        help="explicitly allow one exact pre/main/post command to inherit the terminal input",
    )
    our.add_argument(
        "--fixed-input",
        dest="fixed_input",
        action="append",
        default=[],
        metavar="OWNER=TEXT|@FILE",
        help="give one exact command its own fixed stdin bytes without access to the terminal",
    )


def build_input_arbiter(option: object) -> InputArbiter:
    """Build the strict parallel stdin arbiter from parsed operator grants."""
    terminal_owners = tuple(getattr(option, "terminal_input", []) or [])
    fixed_inputs: dict[str, bytes | Path] = {}
    for grant in getattr(option, "fixed_input", []) or []:
        owner, separator, value = str(grant).partition("=")
        if not separator or not owner or not value:
            msg = f"invalid --fixed-input grant {grant!r}; expected OWNER=TEXT or OWNER=@FILE"
            raise SystemExit(msg)
        if value.startswith("@"):
            path = Path(value[1:]).expanduser()
            if not path.is_file():
                msg = f"fixed input file does not exist: {path}"
                raise SystemExit(msg)
            fixed_inputs[owner] = path
        else:
            fixed_inputs[owner] = value.encode()
    return InputArbiter(terminal_owners, fixed_inputs, strict=True)


def parse_num_processes(str_value: str) -> int | None:
    """Parse the number of parallel processes from a command line value.

    :param str_value: the value, ``all`` for no limit, ``auto`` for one process per CPU, or a number

    :returns: the number of processes, ``None`` for no limit

    :raises ArgumentTypeError: when the value is neither of those, or is negative

    """  # simplint: ignore[function-docstring] existing parser docs
    if str_value == "all":
        return None
    if str_value == "auto":
        return auto_detect_cpus()
    try:
        value = int(str_value)
    except ValueError as exc:
        msg = f"value must be a positive number, is {str_value!r}"
        raise ArgumentTypeError(msg) from exc
    if value < 0:
        msg = f"value must be positive, is {value!r}"
        raise ArgumentTypeError(msg)
    return value


__all__ = [
    "ENV_VAR_KEY",
    "OFF_VALUE",
    "parallel_flags",
    "run_parallel",
]
