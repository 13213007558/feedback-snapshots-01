from __future__ import annotations

__lazy_modules__ = [
    "json",
    "typing_extensions",
    "virtualenv.activation.batch",
    "virtualenv.config.cli.parser",
    f"{__spec__.parent}.receipt",  # ty: ignore[missing-union-attribute]  # imported modules have a spec
]

import json
import logging
import sys
from typing import TYPE_CHECKING, Callable, Final

from virtualenv.activation.batch import BatchActivator
from virtualenv.config.cli.parser import VirtualEnvOptions

from .receipt import (
    CLEANUP_NOT_REQUIRED,
    STEP_FAILED,
    STEP_SUCCEEDED,
    CreationRecord,
    CreationScope,
    CleanupReport,
    write_documents,
)

if TYPE_CHECKING:
    from types import TracebackType

    from python_discovery import PythonInfo

    from virtualenv.activation.activator import Activator
    from virtualenv.app_data.base import AppData
    from virtualenv.create.creator import Creator
    from virtualenv.seed.seeder import Seeder

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

LOGGER: Final[logging.Logger] = logging.getLogger(__name__)  # simplint: ignore[module-variable-prefix]  # existing name


class Session:
    """Represents a virtual environment creation session.

    :param verbosity: the verbosity level the creation runs with
    :param app_data: the application data folder
    :param interpreter: the host interpreter the environment is based on
    :param creator: the creator that builds the environment
    :param seeder: the seeder that installs the seed packages
    :param activators: the activators that generate the activation scripts
    :param scope: the materials this creation owns, for cleanup and the optional documents

    """

    # the session keeps each component of a creation as its own argument
    def __init__(  # ruff:ignore[too-many-arguments]
        self,
        verbosity: int,
        app_data: AppData,
        interpreter: PythonInfo,
        creator: Creator,
        seeder: Seeder,
        activators: list[Activator],
        scope: CreationScope | None = None,
    ) -> None:
        self._verbosity = verbosity
        self._app_data = app_data
        self._interpreter = interpreter
        self._creator = creator
        self._seeder = seeder
        self._activators = activators
        self._scope = scope

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self._app_data.close()

    @property
    def verbosity(self) -> int:
        """The verbosity of the run."""
        return self._verbosity

    def run(self) -> None:
        """Create the environment, seed it, activate it and write its configuration file."""
        # the scripted order is the public contract: a failure stops the creation where it happened, reclaims only the
        # materials this job owns, and only then propagates
        record = self._record()
        try:
            self._stage(record, "create", self._create)
            self._run_seed(record)
            self._run_activate(record)
            self._stage(record, "finalize", self.creator.pyenv_cfg.write)
        # any failure is reported through the receipt and the exception, never swallowed
        except BaseException as exception:  # ruff:ignore[blind-except]
            self._failed(record, exception)
            raise
        if record is not None:
            succeeded = CleanupReport()
            succeeded.state = CLEANUP_NOT_REQUIRED
            write_documents(record, succeeded)

    def _record(self) -> CreationRecord | None:
        if self._scope is None:
            return None
        return CreationRecord(self._scope, _interpreter_facts(self.interpreter), self.creator.env_name)

    def _stage(self, record: CreationRecord | None, stage: str, action: Callable[[], object]) -> None:
        if record is not None:
            record.begin(stage)
        action()
        if record is not None:
            record.finish(stage)

    def _run_seed(self, record: CreationRecord | None) -> None:
        if self.seeder is not None and self.seeder.enabled:
            LOGGER.info("add seed packages via %s", self.seeder)
            self._stage(record, "seed", self._seed)
        elif record is not None:
            record.skip("seed")

    def _run_activate(self, record: CreationRecord | None) -> None:
        removing_stale = BatchActivator.supports(self.interpreter) and not any(
            isinstance(i, BatchActivator) for i in self.activators
        )
        if self.activators or removing_stale:
            self._stage(record, "activate", self._activate)
        elif record is not None:
            record.skip("activate")

    def _failed(self, record: CreationRecord | None, exception: BaseException) -> None:
        if record is None:
            return
        record.fail(exception)
        # record the seed result while the environment still exists, since cleanup may reclaim it
        if record.steps["seed"] == STEP_SUCCEEDED:
            record.seeded = _seed_names(self.creator)
        cleanup = record.scope.reclaim()
        write_documents(record, cleanup)
        if cleanup.state == "incomplete":
            LOGGER.warning(
                "creation failed at %s, a controlled operator must reclaim what this job could not: %s",
                _failed_stage(record),
                exception,
            )

    def _create(self) -> None:
        LOGGER.info("create virtual environment via %s", self.creator)
        self.creator.run()
        LOGGER.debug(_DEBUG_MARKER)
        LOGGER.debug("%s", _Debug(self.creator))

    def _seed(self) -> None:
        self.seeder.run(self.creator)

    @property
    def seeder(self) -> Seeder:
        """The mechanism used to provide the seed packages (pip, setuptools, wheel)."""
        return self._seeder

    @property
    def scope(self) -> CreationScope | None:
        """The materials this creation owns, ``None`` when it was built without one."""
        return self._scope

    def _activate(self) -> None:
        if BatchActivator.supports(self.interpreter) and not any(
            isinstance(i, BatchActivator) for i in self.activators
        ):
            BatchActivator(VirtualEnvOptions(prompt=None)).remove_unsafe(self.creator, selected=False)
        if self.activators:
            active = ", ".join(type(i).__name__.replace("Activator", "") for i in self.activators)
            LOGGER.info("add activators for %s", active)
            self._activators = [activator for activator in self.activators if activator.generate(self.creator)]

    @property
    def interpreter(self) -> PythonInfo:
        """Create a virtual environment based on this reference interpreter."""
        return self._interpreter

    @property
    def activators(self) -> list[Activator]:
        """Activators used to generate activations scripts."""
        return self._activators

    @property
    def creator(self) -> Creator:
        """The creator used to build the virtual environment (must be compatible with the interpreter)."""
        return self._creator


def _failed_stage(record: CreationRecord) -> str:
    return next((stage for stage, state in record.steps.items() if state == STEP_FAILED), "create")


def _interpreter_facts(interpreter: PythonInfo) -> dict[str, str]:
    return {"implementation": interpreter.implementation, "version": interpreter.version_str}


def _seed_names(creator: Creator) -> list[str]:
    try:
        return sorted(
            "==".join(path.stem.split("-")) for path in creator.purelib.iterdir() if path.suffix == ".dist-info"
        )
    # the seeded packages are a diagnostic convenience, not required for the receipt
    except OSError:
        return []


class _Debug:
    def __init__(self, creator: Creator) -> None:
        self.creator = creator

    def __repr__(self) -> str:
        return json.dumps(self.creator.debug, indent=2)


_DEBUG_MARKER: Final[str] = f"{'=' * 30} target debug {'=' * 30}"


__all__ = [
    "Session",
]
