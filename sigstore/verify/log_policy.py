# Copyright 2026 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
APIs for expressing transparency log deactivation ("sunset") policies.

A transparency log can be decommissioned while older archives that were
published to it still need to be verified. The types in this module let a
verifying caller describe that transition explicitly:

* a *deactivated* log only accepts entries whose authenticated entry time
  falls inside an approved historical window ending at the log's deactivation
  point;
* every other log known to the trust root is treated as a *current* log and
  is the only kind of log allowed to recognize materials produced after the
  deactivation point.

The same policy therefore works during the old/new log coexistence phase
(before the deactivation point) and after the old log has been retired.

All decisions are made against a caller-supplied reference time and the
materials' own authenticated times, so the policy is deterministic and safe
to use in fully offline verification.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from sigstore._internal.timestamp import (
    TimestampSource,
    TimestampVerificationResult,
)
from sigstore.errors import VerificationError
from sigstore.models import Bundle

__all__ = [
    "AcceptedMaterial",
    "LogDeactivation",
    "LogDeactivationPolicy",
    "LogMaterial",
    "VerificationReceipt",
]


class AcceptedMaterial(StrEnum):
    """
    The kind of transparency log material that a verification actually accepted.
    """

    CURRENT_LOG = "current_log"
    """
    The entry is on a log that is still active at the policy's reference time.
    """

    RETIRED_LOG_HISTORICAL = "retired_log_historical"
    """
    The entry is on a deactivated log, but its authenticated time falls inside
    the approved historical window preceding the deactivation point.
    """


@dataclass(frozen=True)
class LogDeactivation:
    """
    Describes the deactivation of a single transparency log.

    `log_id` is the raw (32-byte) key ID of the deactivated log, as it appears
    in bundle entries and in the trusted root's transparency log instances.

    `deactivated_at` is the fixed deactivation point: the log MUST NOT have
    accepted any entry at or after this time.

    `historical_window_start` optionally opens the approved historical window.
    When set, entries on the deactivated log whose authenticated time predates
    it are rejected. The window always closes at `deactivated_at`.
    """

    log_id: bytes
    deactivated_at: datetime
    historical_window_start: datetime | None = None

    def __post_init__(self) -> None:
        if self.deactivated_at.tzinfo is None:
            raise ValueError("deactivated_at must be timezone-aware")
        if (
            self.historical_window_start is not None
            and self.historical_window_start.tzinfo is None
        ):
            raise ValueError("historical_window_start must be timezone-aware")
        if (
            self.historical_window_start is not None
            and self.historical_window_start > self.deactivated_at
        ):
            raise ValueError(
                "historical_window_start must not be later than deactivated_at"
            )


@dataclass(frozen=True)
class LogMaterial:
    """
    The log-specific facts about a bundle entry that a policy evaluates.

    `entry_time` is the entry's authenticated time: the transparency log's
    integrated time for Rekor v1 entries, or a verified RFC 3161 timestamp for
    Rekor v2 entries (which carry no integrated time).
    """

    log_id: bytes
    log_version: int
    entry_kind: str
    entry_time: datetime

    @classmethod
    def from_bundle(
        cls,
        bundle: Bundle,
        verified_timestamps: list[TimestampVerificationResult],
    ) -> LogMaterial:
        """
        Build a `LogMaterial` from a verified bundle and its established times.

        Raises `VerificationError` if no authenticated entry time can be
        established for the entry's log version.
        """
        entry = bundle.log_entry._inner
        kind_version = entry.kind_version
        entry_kind = f"{kind_version.kind}/{kind_version.version}"

        if entry.integrated_time is not None:
            entry_time = datetime.fromtimestamp(entry.integrated_time, tz=UTC)
        else:
            tsa_times = [
                result.time
                for result in verified_timestamps
                if result.source is TimestampSource.TIMESTAMP_AUTHORITY
            ]
            if not tsa_times:
                raise VerificationError(
                    "log deactivation policy: cannot establish an authenticated "
                    f"entry time for {entry_kind} entry without an integrated time"
                )
            entry_time = min(tsa_times)

        return cls(
            log_id=entry.log_id.key_id,
            log_version=_log_version_from_kind(kind_version.version),
            entry_kind=entry_kind,
            entry_time=entry_time,
        )


@dataclass(frozen=True)
class VerificationReceipt:
    """
    A receipt describing the transparency log material actually accepted.

    Returned by the receipt-returning `Verifier` APIs; it is intentionally
    serializable through `dataclasses.asdict` for audit logging.
    """

    accepted_material: AcceptedMaterial
    log_id: str
    log_version: int
    entry_kind: str
    entry_time: datetime
    reference_time: datetime
    deactivated_at: datetime | None
    historical_window_start: datetime | None

    def describe(self) -> str:
        """
        Return a human-readable description of the accepted material.
        """
        log_id = self.log_id
        entry_time = _format_time(self.entry_time)
        reference_time = _format_time(self.reference_time)
        if self.accepted_material is AcceptedMaterial.RETIRED_LOG_HISTORICAL:
            window = _format_time(self.historical_window_start)
            return (
                f"accepted historical entry on deactivated Rekor v{self.log_version} "
                f"log {log_id} ({self.entry_kind}): entry time {entry_time} is within "
                f"the approved window [{window}, {_format_time(self.deactivated_at)}) "
                f"as of reference time {reference_time}"
            )
        return (
            f"accepted entry on current Rekor v{self.log_version} log {log_id} "
            f"({self.entry_kind}): entry time {entry_time}, log is not deactivated "
            f"as of reference time {reference_time}"
        )


class LogDeactivationPolicy:
    """
    A policy describing which transparency logs are deactivated and when.

    The policy holds one `LogDeactivation` per deactivated log and a fixed
    `reference_time` representing the trusted "now" at which verification is
    performed. Logs not listed in `deactivated_logs` are treated as current
    logs.

    During the old/new log coexistence phase, callers may pass a
    `reference_time` earlier than a log's deactivation point: the log is then
    still considered active and all of its entries are accepted as current
    material. Once the reference time reaches the deactivation point, only
    in-window historical entries on that log are accepted.
    """

    def __init__(
        self,
        deactivated_logs: list[LogDeactivation],
        *,
        reference_time: datetime | None = None,
    ) -> None:
        """
        Create a new `LogDeactivationPolicy`.

        `reference_time` defaults to the current UTC time, but offline and
        audit setups should pin it to a fixed trusted time.
        """
        if reference_time is None:
            reference_time = datetime.now(UTC)
        if reference_time.tzinfo is None:
            raise ValueError("reference_time must be timezone-aware")

        log_ids = [deactivation.log_id for deactivation in deactivated_logs]
        if len(log_ids) != len(set(log_ids)):
            raise ValueError("a log can only be deactivated once in a policy")

        self._deactivations = {
            deactivation.log_id: deactivation for deactivation in deactivated_logs
        }
        self._reference_time = reference_time

    @property
    def reference_time(self) -> datetime:
        """
        The fixed trusted time against which deactivation is evaluated.
        """
        return self._reference_time

    @property
    def deactivated_log_ids(self) -> list[bytes]:
        """
        The raw key IDs of the logs configured as deactivated.
        """
        return list(self._deactivations)

    def evaluate(self, material: LogMaterial) -> VerificationReceipt:
        """
        Evaluate `material` against this policy, returning a
        `VerificationReceipt` describing what was accepted.

        Raises `VerificationError` if the material must not be accepted:
        either because it was produced on or after a deactivated log's
        deactivation point, or because it predates the approved historical
        window.
        """
        deactivation = self._deactivations.get(material.log_id)
        if deactivation is None or self._reference_time < deactivation.deactivated_at:
            accepted = AcceptedMaterial.CURRENT_LOG
            deactivated_at = None
            window_start = None
        else:
            deactivated_at = deactivation.deactivated_at
            window_start = deactivation.historical_window_start
            if material.entry_time >= deactivated_at:
                raise VerificationError(
                    "log deactivation policy: entry on deactivated log "
                    f"{material.log_id.hex()} has entry time "
                    f"{_format_time(material.entry_time)} at or after the "
                    f"deactivation point {_format_time(deactivated_at)}; new "
                    "materials must be logged to a current log"
                )
            if window_start is not None and material.entry_time < window_start:
                raise VerificationError(
                    "log deactivation policy: entry on deactivated log "
                    f"{material.log_id.hex()} has entry time "
                    f"{_format_time(material.entry_time)} before the approved "
                    f"historical window start {_format_time(window_start)}"
                )
            accepted = AcceptedMaterial.RETIRED_LOG_HISTORICAL

        return VerificationReceipt(
            accepted_material=accepted,
            log_id=material.log_id.hex(),
            log_version=material.log_version,
            entry_kind=material.entry_kind,
            entry_time=material.entry_time,
            reference_time=self._reference_time,
            deactivated_at=deactivated_at,
            historical_window_start=window_start,
        )


def _log_version_from_kind(kind_version: str) -> int:
    """
    Map a bundle entry's kind version (e.g. "0.0.1", "0.0.2") to the Rekor
    major API version that produced it.
    """
    if kind_version == "0.0.1":
        return 1
    if kind_version == "0.0.2":
        return 2
    raise VerificationError(
        f"unsupported transparency log entry version {kind_version}"
    )


def _format_time(value: datetime | None) -> str:
    if value is None:
        return "unbounded"
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
