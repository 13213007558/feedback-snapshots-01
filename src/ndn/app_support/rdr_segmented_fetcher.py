# -----------------------------------------------------------------------------
# Copyright (C) 2019-2022 The python-ndn authors
#
# This file is part of python-ndn.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------
r"""
Segmented object fetcher with a strict complete-object delivery contract.

This module hardens the RDR segmented fetch flow (see
``ndn.bin.tools.cmd_fetch_rdrcontent``) against cross-version mixing and
truncation attacks. A single valid Data packet only proves that one segment
is authentic; it does not prove that an assembled buffer belongs to one
version. This fetcher therefore guarantees:

- The trusted caller supplies the name scope and the validation policy
  (validator). Every segment is validated individually by that policy.
- The version is pinned by the first validated Data packet. No later
  segment may silently come from a different version (or any name outside
  the pinned prefix); otherwise the fetch fails.
- Every segment name must end in a typed segment component with the
  expected segment number.
- FinalBlockId, when present, must be a typed segment component and must
  agree across all segments. The final segment itself must confirm the
  FinalBlockId, so a truncated prefix can never masquerade as a complete
  object.
- Out-of-order arrivals, retries, missing segments and conflicting final
  segments are handled explicitly. Memory usage and in-flight Interests
  are bounded by ``FetchOptions``.
- On failure, only explicit partial evidence (pinned prefix, per-segment
  digests, final segment number) is exposed. Segment content is never
  released unless the whole object is complete and consistent.
"""
import asyncio as aio
import hashlib
import typing
from dataclasses import dataclass, field

from ..app import NDNApp, Validator
from ..encoding import Name, Component, FormalName, NonStrictName, BinaryStr
from ..encoding.ndn_format_0_3 import MetaInfo
from ..types import InterestNack, InterestTimeout, ValidationFailure

__all__ = [
    'FetchOptions',
    'FetchResult',
    'PartialEvidence',
    'SegmentEvidence',
    'SegmentedFetchError',
    'VersionConflictError',
    'FinalBlockConflictError',
    'MissingSegmentError',
    'SegmentStructureError',
    'SegmentValidationError',
    'ResourceLimitError',
    'SegmentedObjectFetcher',
]

ExpressFunc = typing.Callable[
    [FormalName, bool],
    typing.Coroutine[typing.Any, typing.Any, tuple[FormalName, BinaryStr | None, MetaInfo]]]
r"""
Async callable retrieving one Data packet.

Takes an Interest name and the CanBePrefix flag, and returns the validated
Data name, its Content value and its MetaInfo. It must raise
:any:`InterestTimeout` or :any:`InterestNack` when no Data arrives, and
:any:`ValidationFailure` when the validation policy rejects the packet.
"""


@dataclass
class FetchOptions:
    r"""Bounds and Interest parameters for a segmented fetch."""
    lifetime: int = 4000
    r"""Interest lifetime in milliseconds."""
    must_be_fresh: bool = False
    r"""MustBeFresh selector for all Interests."""
    retries: int = 3
    r"""Retries per segment after timeout or Nack before giving up."""
    max_in_flight: int = 8
    r"""Maximum number of simultaneously unanswered segment Interests."""
    max_segments: int = 1024
    r"""Maximum number of segments accepted for one object."""
    max_content_size: int = 4 * 1024 * 1024
    r"""Maximum buffered content bytes for one object."""


@dataclass
class SegmentEvidence:
    r"""Evidence that one segment was received and validated.

    Deliberately contains only a digest, never the segment content.
    """
    segment: int
    sha256: str


@dataclass
class PartialEvidence:
    r"""Explicit partial evidence exposed when a fetch fails.

    Contains no content bytes: only the pinned version prefix, the agreed
    final segment number and per-segment digests of validated segments.
    """
    scope: str
    pinned_prefix: str | None = None
    final_segment: int | None = None
    segments: list[SegmentEvidence] = field(default_factory=list)


@dataclass
class FetchResult:
    r"""A complete, version-consistent segmented object."""
    name: FormalName
    r"""Pinned object prefix, including the version component."""
    content: bytes
    r"""Segment contents concatenated in segment order."""
    segment_count: int
    r"""Number of segments assembled."""
    digest: bytes
    r"""SHA-256 digest of ``content``."""


class SegmentedFetchError(Exception):
    r"""Base class for fetch failures. Carries partial evidence only."""

    def __init__(self, message: str, evidence: PartialEvidence | None = None):
        super().__init__(message)
        self.evidence = evidence


class VersionConflictError(SegmentedFetchError):
    r"""A segment arrived from outside the version pinned by the first segment."""


class FinalBlockConflictError(SegmentedFetchError):
    r"""Segments disagree on FinalBlockId, or a segment lies beyond it."""


class MissingSegmentError(SegmentedFetchError):
    r"""A required segment could not be retrieved within the retry budget."""


class SegmentStructureError(SegmentedFetchError):
    r"""A segment name or FinalBlockId violates the typed-segment structure."""


class SegmentValidationError(SegmentedFetchError):
    r"""The validation policy rejected a segment."""


class ResourceLimitError(SegmentedFetchError):
    r"""The object exceeds the configured memory or segment bounds."""


class SegmentedObjectFetcher:
    r"""
    Fetcher delivering segmented objects only when they are complete and
    belong to a single pinned version.

    Use :meth:`from_app` to bind it to an :any:`NDNApp` and a validator,
    or pass a custom :any:`ExpressFunc` for testing.
    """

    def __init__(self, express: ExpressFunc, options: FetchOptions | None = None):
        self._express = express
        self.options = options if options is not None else FetchOptions()

    @classmethod
    def from_app(cls, app: NDNApp, validator: Validator,
                 options: FetchOptions | None = None) -> 'SegmentedObjectFetcher':
        opts = options if options is not None else FetchOptions()

        async def express(name: FormalName, can_be_prefix: bool):
            data_name, content, context = await app.express(
                name, validator, can_be_prefix=can_be_prefix,
                must_be_fresh=opts.must_be_fresh, lifetime=opts.lifetime)
            return data_name, content, context['meta_info']

        return cls(express, opts)

    async def fetch(self, name: NonStrictName) -> FetchResult:
        r"""
        Fetch the segmented object under ``name`` and return it only if it
        is complete and version-consistent.

        :param name: name scope of the object, with or without a version
            component. The first Data packet pins the exact version.
        :return: the assembled object with its digest.
        :raises SegmentedFetchError: on any inconsistency; the exception's
            ``evidence`` attribute carries partial evidence without content.
        """
        scope = Name.normalize(name)
        evidence = PartialEvidence(scope=Name.to_str(scope))
        try:
            return await self._fetch(scope, evidence)
        except ValidationFailure as e:
            raise SegmentValidationError(
                'a segment failed the validation policy', evidence) from e

    async def _fetch(self, scope: FormalName, evidence: PartialEvidence) -> FetchResult:
        opt = self.options
        # The first Interest doubles as version discovery: it is expressed
        # for the scope itself with CanBePrefix, and the first validated
        # Data packet pins the exact object version for the whole fetch.
        data_name, content, meta = await self._request(scope, True, None, evidence)
        data_name = Name.normalize(data_name)
        pinned, first_seg = self._pin(scope, data_name, evidence)
        final_seg = self._check_final(meta, first_seg, evidence)
        final_confirmed = final_seg is not None and first_seg == final_seg
        buffer: dict[int, bytes] = {}
        buffered_bytes = 0
        content = bytes(content) if content is not None else b''
        if len(content) > opt.max_content_size:
            raise ResourceLimitError(
                f'object exceeds {opt.max_content_size} buffered bytes', evidence)
        if final_seg is not None and final_seg + 1 > opt.max_segments:
            raise ResourceLimitError(
                f'object exceeds {opt.max_segments} segments', evidence)
        buffer[first_seg] = content
        buffered_bytes += len(content)
        evidence.segments.append(
            SegmentEvidence(first_seg, hashlib.sha256(content).hexdigest()))

        next_seg = 0
        in_flight: dict[aio.Task, int] = {}
        try:
            while True:
                if final_seg is not None and len(buffer) == final_seg + 1:
                    if not final_confirmed:
                        raise SegmentStructureError(
                            f'final segment {final_seg} does not confirm the '
                            f'FinalBlockId; refusing to deliver a possibly '
                            f'truncated object', evidence)
                    break
                while next_seg in buffer:
                    next_seg += 1
                while len(in_flight) < opt.max_in_flight and \
                        (final_seg is None or next_seg <= final_seg):
                    if next_seg >= opt.max_segments:
                        raise ResourceLimitError(
                            f'object exceeds {opt.max_segments} segments without a '
                            f'confirmed FinalBlockId', evidence)
                    seg_name = pinned + [Component.from_segment(next_seg)]
                    task = aio.ensure_future(self._request(seg_name, False, next_seg, evidence))
                    in_flight[task] = next_seg
                    next_seg += 1
                    while next_seg in buffer or next_seg in in_flight.values():
                        next_seg += 1
                if not in_flight:
                    raise SegmentStructureError(
                        'no progress possible but object is incomplete', evidence)
                done, _ = await aio.wait(in_flight.keys(), return_when=aio.FIRST_COMPLETED)
                for task in done:
                    seg = in_flight.pop(task)
                    data_name, content, meta = task.result()
                    data_name = Name.normalize(data_name)
                    self._check_segment(pinned, data_name, seg, evidence)
                    new_final = self._check_final(meta, seg, evidence)
                    if new_final is not None:
                        final_seg = new_final
                        if seg == new_final:
                            final_confirmed = True
                    if final_seg is not None and seg > final_seg:
                        raise FinalBlockConflictError(
                            f'segment {seg} lies beyond FinalBlockId segment {final_seg}',
                            evidence)
                    content = bytes(content) if content is not None else b''
                    buffered_bytes += len(content)
                    if buffered_bytes > opt.max_content_size:
                        raise ResourceLimitError(
                            f'object exceeds {opt.max_content_size} buffered bytes', evidence)
                    buffer[seg] = content
                    evidence.segments.append(
                        SegmentEvidence(seg, hashlib.sha256(content).hexdigest()))
        finally:
            for task in in_flight:
                task.cancel()

        if evidence.final_segment is None:
            raise SegmentStructureError(
                'no segment carried a FinalBlockId; completeness cannot be proven', evidence)
        content = b''.join(buffer[i] for i in range(final_seg + 1))
        return FetchResult(
            name=pinned,
            content=content,
            segment_count=final_seg + 1,
            digest=hashlib.sha256(content).digest())

    async def _request(self, name: FormalName, can_be_prefix: bool,
                       seg: int | None, evidence: PartialEvidence):
        attempts = 0
        while True:
            try:
                return await self._express(name, can_be_prefix)
            except (InterestTimeout, InterestNack) as e:
                attempts += 1
                if attempts > self.options.retries:
                    what = (f'segment {seg} of {Name.to_str(name[:-1])}'
                            if seg is not None else f'first segment of {Name.to_str(name)}')
                    raise MissingSegmentError(
                        f'{what} unreachable after {attempts} attempts', evidence) from e

    @staticmethod
    def _pin(scope: FormalName, data_name: FormalName,
             evidence: PartialEvidence) -> tuple[FormalName, int]:
        if not data_name:
            raise SegmentStructureError('first Data has an empty name', evidence)
        last = data_name[-1]
        if Component.get_type(last) != Component.TYPE_SEGMENT:
            raise SegmentStructureError(
                'first Data name does not end in a typed segment component', evidence)
        first_seg = Component.to_number(last)
        pinned = data_name[:-1]
        if not Name.is_prefix(scope, pinned):
            raise SegmentStructureError(
                f'first Data {Name.to_str(data_name)} is outside the requested scope '
                f'{Name.to_str(scope)}', evidence)
        evidence.pinned_prefix = Name.to_str(pinned)
        return pinned, first_seg

    @staticmethod
    def _check_segment(pinned: FormalName, data_name: FormalName, expected_seg: int,
                       evidence: PartialEvidence):
        if not data_name:
            raise SegmentStructureError('Data has an empty name', evidence)
        last = data_name[-1]
        if Component.get_type(last) != Component.TYPE_SEGMENT:
            raise SegmentStructureError(
                f'{Name.to_str(data_name)} does not end in a typed segment component',
                evidence)
        if Component.to_number(last) != expected_seg:
            raise SegmentStructureError(
                f'expected segment {expected_seg} but got {Name.to_str(data_name)}',
                evidence)
        if data_name[:-1] != pinned:
            raise VersionConflictError(
                f'segment {expected_seg} came from {Name.to_str(data_name[:-1])}, '
                f'outside the pinned version {Name.to_str(pinned)}', evidence)

    @staticmethod
    def _check_final(meta: MetaInfo, seg: int, evidence: PartialEvidence) -> int | None:
        final_block_id = meta.final_block_id
        if final_block_id is None:
            return None
        if Component.get_type(final_block_id) != Component.TYPE_SEGMENT:
            raise SegmentStructureError(
                'FinalBlockId is not a typed segment component', evidence)
        final_seg = Component.to_number(final_block_id)
        if final_seg < seg:
            raise FinalBlockConflictError(
                f'segment {seg} carries FinalBlockId for earlier segment {final_seg}',
                evidence)
        if evidence.final_segment is not None and evidence.final_segment != final_seg:
            raise FinalBlockConflictError(
                f'conflicting FinalBlockId: segment {evidence.final_segment} vs '
                f'segment {final_seg}', evidence)
        evidence.final_segment = final_seg
        return final_seg
