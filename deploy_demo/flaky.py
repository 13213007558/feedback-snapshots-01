"""WheelSource wrapper that injects mid-stream read failures.

The real :class:`installer.sources.WheelSource` contract only promises
sequential access via ``get_contents()`` and explicitly allows multiple
iterations as long as each provides the same content.  This wrapper models a
source whose *transport* can reset after a number of bytes on one member
(remote object store, flaky HTTP response, ...).

The shared :class:`FailurePolicy` decides how many read passes actually fail,
so a fresh wrapper around a freshly opened wheel can model a successful retry
after a transient outage.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import BinaryIO

from installer.sources import WheelContentElement, WheelSource
from installer.utils import copyfileobj_with_hashing

from deploy_demo.errors import TransitReadError


@dataclass
class FailurePolicy:
    """When and how often a wrapped member stream fails.

    :param member_suffix: wheel member name (or suffix) to poison.
    :param fail_after: deliver exactly this many bytes, then fail the next read.
    :param times_to_fail: number of failing passes; ``None`` means always fail.
    """

    member_suffix: str
    fail_after: int = 64 * 1024
    times_to_fail: int | None = 1
    fires: int = 0

    def should_arm(self) -> bool:
        if self.times_to_fail is None:
            return True
        return self.fires < self.times_to_fail

    def record_fire(self) -> None:
        self.fires += 1


@dataclass
class StreamReport:
    """Observed read behaviour for one wrapped member stream."""

    member: str
    requested_sizes: list[int] = field(default_factory=list)
    delivered: int = 0
    fired: bool = False


class FlakyStream:
    """Binary stream proxy that fails after ``fail_after`` delivered bytes."""

    def __init__(
        self,
        raw: BinaryIO,
        report: StreamReport,
        policy: FailurePolicy | None,
    ) -> None:
        self._raw = raw
        self._report = report
        self._policy = policy
        self._delivered = 0

    def read(self, size: int = -1) -> bytes:
        self._report.requested_sizes.append(size)
        if self._policy is not None and self._policy.should_arm():
            if self._delivered >= self._policy.fail_after:
                self._report.fired = True
                self._policy.record_fire()
                raise TransitReadError(
                    f"simulated transport reset on {self._report.member!r} "
                    f"after {self._delivered} bytes"
                )
            if size is None or size < 0:
                size = self._policy.fail_after - self._delivered
            else:
                size = min(size, self._policy.fail_after - self._delivered)

        data = self._raw.read(size)
        self._delivered += len(data)
        self._report.delivered = self._delivered
        return data

    def __getattr__(self, name: str):
        # Delegate seek/tell/close/readline/... to the underlying wheel stream.
        return getattr(self._raw, name)


class FlakyWheelSource(WheelSource):
    """Wrap any :class:`WheelSource`, poisoning one member's stream."""

    def __init__(
        self,
        base: WheelSource,
        policy: FailurePolicy | None = None,
    ) -> None:
        super().__init__(base.distribution, base.version)
        self._base = base
        self._policy = policy
        self.stream_reports: list[StreamReport] = []

    @property
    def dist_info_filenames(self) -> list[str]:
        return self._base.dist_info_filenames

    def read_dist_info(self, filename: str) -> str:
        return self._base.read_dist_info(filename)

    def validate_record(self) -> None:
        self._base.validate_record()

    def get_contents(self) -> Iterator[WheelContentElement]:
        for elements, stream, is_executable in self._base.get_contents():
            member = elements[0]
            policy = self._policy
            if policy is not None and not member.endswith(policy.member_suffix):
                policy = None
            report = StreamReport(member=member)
            self.stream_reports.append(report)
            wrapped: BinaryIO = FlakyStream(stream, report, policy)  # type: ignore[assignment]
            yield elements, wrapped, is_executable


class _NullSink:
    def write(self, data: bytes) -> int:
        return len(data)

    def flush(self) -> None:
        return None


@dataclass
class PreflightEntry:
    """Result of fully reading one wheel member before touching targets."""

    member: str
    actual_hash: str
    size: int
    matches_record: bool | None


def preflight_read_all(
    source: WheelSource,
    *,
    hash_algorithm: str = "sha256",
) -> list[PreflightEntry]:
    """Read every member end-to-end, chunk-hashing it.

    This is the strongest pre-touch check available for an arbitrary
    :class:`WheelSource`: it proves every byte is *currently* readable and
    yields actual digests.  It uses constant-size buffers (the same
    ``copyfileobj_with_hashing`` loop as real installs), so large wheels stay
    bounded in memory.

    For a stock :class:`installer.sources.WheelFile`, prefer
    :meth:`WheelFile.validate_record` which additionally checks archive
    bookkeeping; this helper exists for custom/remote sources and shares the
    exact ``get_contents()`` path that installation uses, so injected transport
    failures are exercised.
    """
    results: list[PreflightEntry] = []
    null_sink = _NullSink()
    for record_elements, stream, _is_executable in source.get_contents():
        declared_path, declared_hash, _declared_size = record_elements
        actual_hash, size = copyfileobj_with_hashing(
            stream,  # type: ignore[arg-type]
            null_sink,  # type: ignore[arg-type]
            hash_algorithm,
        )
        matches: bool | None
        if declared_hash:
            expected = (
                declared_hash.split("=", 1)[1]
                if "=" in declared_hash
                else declared_hash
            )
            matches = expected == actual_hash
        else:
            matches = None
        results.append(
            PreflightEntry(
                member=declared_path,
                actual_hash=actual_hash,
                size=size,
                matches_record=matches,
            )
        )
    return results


def fsync_file(path: "os.PathLike[str]") -> None:
    """Best-effort fsync helper used by durable destination doubles."""
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
