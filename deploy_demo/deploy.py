"""Recovery-oriented orchestration around stock ``installer.install``.

These helpers encode the recovery procedures described in the design note:

* staging target  -> discard the generation and retry (live tree untouched);
* write-once target -> never reuse a key; open a new generation and retry;
* persistent target death (strict one-shot double) -> replacement target.

Every attempt is recorded so a demo/operator can show exactly what happened.
"""

from __future__ import annotations

import uuid
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Callable

from installer._core import install
from installer.sources import WheelSource

from deploy_demo.staging import CommitReport, StagingWheelDestination
from deploy_demo.verify import (
    VerificationReport,
    verify_filesystem_installation,
    verify_worm_generation,
)
from deploy_demo.worm import WriteOnceDestination, WormStore

SourceFactory = Callable[[], AbstractContextManager[WheelSource]]


def default_metadata() -> dict[str, bytes]:
    """Platform metadata appended to ``.dist-info`` (like the installer CLI)."""
    return {"INSTALLER": b"deploy-demo-reference\n"}


@dataclass
class AttemptInfo:
    """What happened on one deployment attempt."""

    attempt: int
    generation: str
    succeeded: bool
    error_type: str | None = None
    error: str | None = None
    aborted: bool = False
    partial_key: str | None = None
    partial_bytes: int | None = None


@dataclass
class StagingOutcome:
    """Successful staging deployment result."""

    destination: StagingWheelDestination
    commit: CommitReport
    attempts: list[AttemptInfo]
    verification: VerificationReport


@dataclass
class WormOutcome:
    """Successful write-once deployment result."""

    destination: WriteOnceDestination
    generation: str
    manifest_key: str
    attempts: list[AttemptInfo]
    verification: VerificationReport


def _generation_names(count: int, prefix: str, names: list[str] | None) -> list[str]:
    if names is not None:
        if len(names) < count:
            raise ValueError("not enough generation names provided")
        return names
    return [f"{prefix}-{i + 1}-{uuid.uuid4().hex[:8]}" for i in range(count)]


def deploy_staging_with_retry(
    *,
    source_factory: SourceFactory,
    scheme_dict: dict[str, str],
    stage_root: str,
    root_scheme: str,
    record_file_path: str,
    max_attempts: int = 2,
    generation_names: list[str] | None = None,
    generation_prefix: str = "stage",
    interpreter: str = "/usr/bin/python3",
    additional_metadata: dict[str, bytes] | None = None,
    plan: "object | None" = None,
) -> StagingOutcome:
    """Install to staging, aborting and retrying the generation on failure."""
    names = _generation_names(max_attempts, generation_prefix, generation_names)
    attempts: list[AttemptInfo] = []
    last_error: BaseException | None = None

    for index in range(max_attempts):
        generation = names[index]
        destination = StagingWheelDestination(
            final_scheme_dict=scheme_dict,
            stage_root=stage_root,
            generation=generation,
            interpreter=interpreter,
        )
        info = AttemptInfo(index + 1, generation, False)
        try:
            with source_factory() as source:
                install(
                    source,
                    destination,
                    additional_metadata
                    if additional_metadata is not None
                    else default_metadata(),
                )
            commit = destination.commit()
            verification = verify_filesystem_installation(
                scheme_dict=scheme_dict,
                root_scheme=root_scheme,
                record_file_path=record_file_path,
                plan=plan,  # type: ignore[arg-type]
            )
            verification.raise_if_failed()
            info.succeeded = True
            attempts.append(info)
            return StagingOutcome(
                destination=destination,
                commit=commit,
                attempts=attempts,
                verification=verification,
            )
        except Exception as exc:  # recovery boundary: record, abort, maybe retry
            last_error = exc
            info.error_type = type(exc).__name__
            info.error = str(exc)
            try:
                destination.abort()
                info.aborted = True
            except Exception as abort_exc:  # pragma: no cover - defensive
                info.error = f"{info.error}; abort failed: {abort_exc!r}"
            attempts.append(info)
            if index == max_attempts - 1:
                raise

    assert last_error is not None  # pragma: no cover
    raise last_error  # pragma: no cover


def deploy_write_once(
    *,
    source_factory: SourceFactory,
    store: WormStore,
    scheme_dict: dict[str, str],
    root_scheme: str,
    record_file_path: str,
    max_attempts: int = 2,
    generation_names: list[str] | None = None,
    generation_prefix: str = "rel",
    interpreter: str = "/usr/bin/python3",
    additional_metadata: dict[str, bytes] | None = None,
    plan: "object | None" = None,
) -> WormOutcome:
    """Install to a write-once store using a fresh generation per attempt."""
    names = _generation_names(max_attempts, generation_prefix, generation_names)
    attempts: list[AttemptInfo] = []

    for index in range(max_attempts):
        generation = names[index]
        destination = WriteOnceDestination(
            store=store,
            generation=generation,
            scheme_dict=scheme_dict,
            interpreter=interpreter,
        )
        info = AttemptInfo(index + 1, generation, False)
        try:
            with source_factory() as source:
                install(
                    source,
                    destination,
                    additional_metadata
                    if additional_metadata is not None
                    else default_metadata(),
                )
            manifest_key = destination.commit_manifest()
            verification = verify_worm_generation(
                store,
                generation,
                scheme_dict=scheme_dict,
                root_scheme=root_scheme,
                record_file_path=record_file_path,
                plan=plan,  # type: ignore[arg-type]
            )
            verification.raise_if_failed()
            info.succeeded = True
            attempts.append(info)
            return WormOutcome(
                destination=destination,
                generation=generation,
                manifest_key=manifest_key,
                attempts=attempts,
                verification=verification,
            )
        except Exception as exc:
            info.error_type = type(exc).__name__
            info.error = str(exc)
            failed_keys = [
                key
                for key in store.keys("failed")
                if key.startswith(f"generations/{generation}/")
            ]
            if failed_keys:
                info.partial_key = failed_keys[0]
                partial_path = store.actual_path(info.partial_key)
                info.partial_bytes = (
                    partial_path.stat().st_size if partial_path.exists() else None
                )
            attempts.append(info)
            if index == max_attempts - 1:
                raise

    raise RuntimeError("unreachable")  # pragma: no cover


def wheel_source_factory(
    wheel_path: str,
    policy: "object | None" = None,
) -> SourceFactory:
    """Build a retry-safe context-manager factory for a real on-disk wheel.

    Every call reopens the :class:`installer.sources.WheelFile`, mirroring
    what a real retry should do (re-GET / reopen the source).  A shared
    :class:`~deploy_demo.flaky.FailurePolicy` makes the transport fail only on
    the first configured number of read passes.
    """
    from contextlib import contextmanager

    from installer.sources import WheelFile

    from deploy_demo.flaky import FailurePolicy, FlakyWheelSource

    shared_policy = policy

    @contextmanager
    def factory():
        with WheelFile.open(wheel_path) as wheel_file:
            if shared_policy is None:
                yield wheel_file
            else:
                assert isinstance(shared_policy, FailurePolicy)
                yield FlakyWheelSource(wheel_file, shared_policy)

    return factory  # type: ignore[return-value]
