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
Policies for accepting a bundle's verified time materials.

A bundle can carry verified time from more than one kind of source: an
inclusion promise (or integrated time) from the transparency service, and one
or more signed timestamps from approved Timestamp Authorities. Different
artifacts can require different evidence: an ordinary build might only need
the transparency log's confirmation, while a more important build might also
need an approved timestamp.

Policies in this module operate on the *sources* of verified time, not on the
number of timestamp responses. Multiple responses from the same source are one
proof, no matter how many times they are repeated.

A source is a category of evidence (`TimestampSource`), not an individual
provider: every Timestamp Authority in the trusted root counts as the
`TIMESTAMP_AUTHORITY` source. This is deliberately conservative — several
timestamps from approved authorities are one category of proof — so a policy
can never be satisfied by padding a bundle with more copies of the same kind
of evidence.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from datetime import datetime, timedelta
from enum import StrEnum
from typing import overload

from sigstore._internal.timestamp import TimestampSource, TimestampVerificationResult
from sigstore.errors import VerificationError


class ArtifactLevel(StrEnum):
    """
    The assurance an artifact needs from its verified time materials.

    `ORDINARY` accepts any verified time source (for example, transparency log
    confirmation). `IMPORTANT` additionally requires timestamp evidence signed
    by an approved Timestamp Authority.
    """

    ORDINARY = "ordinary"
    IMPORTANT = "important"


class VerifiedTimeMaterials:
    """
    A bundle's verified time materials, grouped by their source.

    Grouping is what makes repeated material from one source count as a single
    proof: `sources` contains each `TimestampSource` at most once, regardless
    of how many responses the bundle carried.
    """

    def __init__(self, results: Iterable[TimestampVerificationResult]) -> None:
        """Group `results` by their source."""
        self._results = tuple(results)
        grouped: dict[TimestampSource, list[datetime]] = {}
        for result in self._results:
            grouped.setdefault(result.source, []).append(result.time)
        self._times_by_source = {
            source: tuple(times) for source, times in grouped.items()
        }

    @property
    def sources(self) -> frozenset[TimestampSource]:
        """The distinct sources that contributed verified time."""
        return frozenset(self._times_by_source)

    @property
    def source_count(self) -> int:
        """The number of distinct verified time sources."""
        return len(self._times_by_source)

    def times_for(self, source: TimestampSource) -> tuple[datetime, ...]:
        """Return every verified time contributed by `source`."""
        return self._times_by_source.get(source, ())

    @overload
    def __getitem__(self, index: int) -> TimestampVerificationResult: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[TimestampVerificationResult, ...]: ...

    def __getitem__(
        self, index: int | slice
    ) -> TimestampVerificationResult | tuple[TimestampVerificationResult, ...]:
        """Return the underlying result(s) at `index`."""
        return self._results[index]

    def __iter__(self) -> Iterator[TimestampVerificationResult]:
        """Iterate over the underlying results, including repeated sources."""
        return iter(self._results)

    def __len__(self) -> int:
        """Return the number of underlying results, including repeated sources."""
        return len(self._results)


def _format_sources(sources: Iterable[TimestampSource]) -> str:
    return ", ".join(sorted(source.name.lower() for source in sources))


class VerifiedTimePolicy:
    """
    A requirement on the verified time materials of a bundle.

    The policy expresses its requirement in two independent ways:

    * `required_sources` lists sources that must each contribute evidence;
    * `minimum_sources` requires at least that many *distinct* sources.

    Both are evaluated against `VerifiedTimeMaterials.sources`, so a source
    repeated many times satisfies the requirement only once.

    If `clock` is supplied, evidence that claims a time after the clock is
    rejected; `max_age`, if supplied, additionally rejects evidence older than
    the given duration relative to that clock. Supplying a clock lets an
    archival service evaluate a bundle against its own ingestion time instead
    of the host clock. `clock` must return a timezone-aware `datetime`.
    """

    def __init__(
        self,
        required_sources: Iterable[TimestampSource] = (),
        *,
        minimum_sources: int = 0,
        clock: Callable[[], datetime] | None = None,
        max_age: timedelta | None = None,
    ) -> None:
        """
        Create a new `VerifiedTimePolicy`.

        At least one of `required_sources` and `minimum_sources` must express a
        requirement, so that an accidentally empty policy cannot accept a
        bundle without any verified time.
        """
        sources = frozenset(TimestampSource(source) for source in required_sources)

        if minimum_sources < 0:
            raise ValueError("minimum_sources must be non-negative")
        if not sources and minimum_sources < 1:
            raise ValueError("a verified time policy must require at least one source")
        if max_age is not None and max_age < timedelta(0):
            raise ValueError("max_age must be non-negative")

        self._required_sources = sources
        self._minimum_sources = minimum_sources
        self._clock = clock
        self._max_age = max_age

    @property
    def required_sources(self) -> frozenset[TimestampSource]:
        """The sources that must each contribute at least one verified time."""
        return self._required_sources

    @property
    def minimum_sources(self) -> int:
        """The minimum number of distinct sources required."""
        return self._minimum_sources

    @classmethod
    def at_least(
        cls,
        minimum_sources: int,
        *,
        clock: Callable[[], datetime] | None = None,
        max_age: timedelta | None = None,
    ) -> VerifiedTimePolicy:
        """Require at least `minimum_sources` distinct sources of verified time."""
        return cls(minimum_sources=minimum_sources, clock=clock, max_age=max_age)

    @classmethod
    def ordinary(
        cls,
        *,
        clock: Callable[[], datetime] | None = None,
        max_age: timedelta | None = None,
    ) -> VerifiedTimePolicy:
        """
        The policy for ordinary builds: any verified time source is enough.

        In particular, transparency log confirmation (an inclusion promise
        covering the integrated time) satisfies this policy on its own.
        """
        return cls(minimum_sources=1, clock=clock, max_age=max_age)

    @classmethod
    def important(
        cls,
        *,
        clock: Callable[[], datetime] | None = None,
        max_age: timedelta | None = None,
    ) -> VerifiedTimePolicy:
        """
        The policy for important builds: approved timestamp evidence is
        required in addition to transparency log confirmation.

        Transparency log confirmation is always checked by the verifier
        (inclusion proof, checkpoint, and inclusion promise where present), for
        both ordinary and important artifacts. What `important` adds is a
        signed timestamp from a Timestamp Authority present in the trusted
        root; unapproved or unverifiable timestamps are discarded before this
        policy sees them.

        Using the Timestamp Authority source (rather than also requiring the
        transparency service's integrated time) keeps this policy meaningful
        for Rekor v2 bundles, which have no integrated time of their own.
        """
        return cls(
            required_sources=(TimestampSource.TIMESTAMP_AUTHORITY,),
            minimum_sources=1,
            clock=clock,
            max_age=max_age,
        )

    @classmethod
    def for_artifact_level(
        cls,
        level: ArtifactLevel | str,
        *,
        clock: Callable[[], datetime] | None = None,
        max_age: timedelta | None = None,
    ) -> VerifiedTimePolicy:
        """
        Return the policy corresponding to an artifact's assurance level.

        This is the entry point an archival service should use: it maps each
        artifact's level to a time material requirement once, and passes the
        result to `Verifier.verify_artifact` or `Verifier.verify_dsse`.
        """
        match ArtifactLevel(level):
            case ArtifactLevel.ORDINARY:
                return cls.ordinary(clock=clock, max_age=max_age)
            case ArtifactLevel.IMPORTANT:
                return cls.important(clock=clock, max_age=max_age)

    def verify(
        self,
        verified_times: VerifiedTimeMaterials | Iterable[TimestampVerificationResult],
    ) -> None:
        """
        Verify the given time materials against this policy.

        Raises `VerificationError` if a required source is absent or if the
        evidence is not acceptable at the policy's clock.
        """
        materials = (
            verified_times
            if isinstance(verified_times, VerifiedTimeMaterials)
            else VerifiedTimeMaterials(verified_times)
        )
        sources = materials.sources

        missing = self._required_sources - sources
        if missing:
            raise VerificationError(
                "verified time policy not satisfied: missing required source(s): "
                f"{_format_sources(missing)}; present source(s): "
                f"{_format_sources(sources) or 'none'}"
            )

        if len(sources) < self._minimum_sources:
            raise VerificationError(
                "not enough sources of verified time: "
                f"{len(sources)} distinct source(s) present, "
                f"{self._minimum_sources} required"
            )

        if self._clock is None:
            return

        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("the verification clock must return a timezone-aware time")

        for result in materials:
            if result.time > now:
                raise VerificationError(
                    "verified time policy not satisfied: evidence from "
                    f"{result.source.name.lower()} is after the verification "
                    f"clock ({result.time.isoformat()} > {now.isoformat()})"
                )
            if self._max_age is not None and now - result.time > self._max_age:
                raise VerificationError(
                    "verified time policy not satisfied: evidence from "
                    f"{result.source.name.lower()} is older than {self._max_age} "
                    f"({result.time.isoformat()} < "
                    f"{(now - self._max_age).isoformat()})"
                )
