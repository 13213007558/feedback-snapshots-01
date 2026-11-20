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
Bounded batch verification for backend services.

`VerificationService` is the entry point for processes that receive more than
one artifact verification request at a time. Compared to calling
`Verifier.verify_artifact` directly, it:

* reads artifacts from caller-supplied streams, so large inputs are never
  buffered wholesale in memory;
* enforces a per-item and a whole-batch read budget (in bytes), so untrusted
  inputs cannot consume unbounded I/O;
* accepts cancellation tokens per request and per batch; and
* reports a status for every request, including requests that were not
  verified because a budget was exhausted or because they were cancelled.

The reported `status` is authoritative for completion, while `digest` is
authoritative for the summary: a digest is present exactly when the input was
read through EOF, even if verification itself was rejected or later cancelled.

A digest is only reported for an input that was read through EOF. Inputs that
were truncated by a budget or a cancellation never receive a digest, so a
consumer can safely treat a present digest as a summary of the complete input.

Example:
```python
import threading
from pathlib import Path

from sigstore.models import Bundle
from sigstore.verify.policy import Identity
from sigstore.verify.service import (
    ReadBudget,
    VerificationRequest,
    VerificationService,
)

service = VerificationService.production(
    policy=Identity(identity="foo@bar.com", issuer="https://accounts.google.com"),
)
requests = [
    VerificationRequest(
        name="foo.txt",
        artifact=Path("foo.txt"),
        bundle=Bundle.from_json(Path("foo.txt.sigstore.json").read_bytes()),
    ),
]
result = service.verify_batch(
    requests,
    budget=ReadBudget(per_item=64 * 1024 * 1024, batch=256 * 1024 * 1024),
)
for item in result.results:
    print(item.name, item.status, item.message)
```
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import threading
from collections.abc import Iterable, Sequence
from concurrent import futures
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import IO, TypeAlias

from sigstore_models.common.v1 import HashAlgorithm

from sigstore import dsse
from sigstore.errors import Error, VerificationError
from sigstore.hashes import Hashed
from sigstore.models import Bundle
from sigstore.verify.policy import VerificationPolicy
from sigstore.verify.verifier import Verifier

_logger = logging.getLogger(__name__)

_CHUNK_SIZE = 64 * 1024
_BUDGET_WAIT = 0.05

Artifact: TypeAlias = bytes | bytearray | memoryview | Path | IO[bytes]
"""
An artifact input: an in-memory buffer, a path, or an already-open binary stream.

Streams are never closed by `VerificationService`; the caller retains ownership.
"""

CancelToken: TypeAlias = threading.Event
"""
A cancellation token.

The caller sets the event to request cancellation. Cancellation is cooperative:
it is observed between reads and before verification, and an in-progress read
is only interrupted if the stream itself raises (for example, an interruptible
stream double used by a service).
"""


class VerificationStatus(StrEnum):
    """
    The outcome of a single verification request.
    """

    VERIFIED = "verified"
    """The input was read through EOF and its signature verified."""

    REJECTED = "rejected"
    """The input was read through EOF, but verification failed."""

    BUDGET_EXCEEDED = "budget_exceeded"
    """The input could not be read through EOF within the read budget."""

    CANCELLED = "cancelled"
    """The request was cancelled before verification completed."""

    ERROR = "error"
    """The input could not be read or verified due to an unexpected error."""


@dataclass(frozen=True)
class ReadBudget:
    """
    Read limits for a verification call, expressed in bytes.

    A value of `None` means "unlimited" for that dimension. Budgets are scoped
    to the artifact input; the bundle is not counted against them. Budgets
    apply per `verify_batch`/`verify_item` call and are not shared between
    calls.
    """

    per_item: int | None = None
    """The maximum number of artifact bytes a single item may contribute."""

    batch: int | None = None
    """The maximum number of artifact bytes all items in a call may read."""

    def __post_init__(self) -> None:
        """Validate that both budgets are non-negative integers or `None`."""
        for label, value in (("per_item", self.per_item), ("batch", self.batch)):
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(
                    f"{label} budget must be a non-negative int or None, got {value!r}"
                )


@dataclass(frozen=True)
class VerificationRequest:
    """
    A single artifact verification request.
    """

    name: str
    """
    A caller-chosen label, echoed back in the corresponding `ItemResult`.
    """

    artifact: Artifact
    """The artifact to verify."""

    bundle: Bundle
    """The Sigstore bundle to verify the artifact against."""

    cancel: CancelToken | None = None
    """An optional cancellation token for this request only."""


@dataclass(frozen=True)
class ItemResult:
    """
    The result of verifying one request.
    """

    index: int
    """The request's position in the input sequence."""

    name: str
    """The request's caller-chosen label."""

    status: VerificationStatus
    """The verification outcome."""

    bytes_read: int = 0
    """The number of artifact bytes read into the digest."""

    digest: Hashed | None = None
    """
    The artifact digest, if the artifact was read through EOF.

    This is `None` for inputs truncated by a budget or an I/O failure. A
    cancellation that arrives after the input was fully read still leaves the
    digest present, since it is a correct summary of the complete input.
    """

    message: str | None = None
    """Human-readable detail for non-verified outcomes."""

    @property
    def verified(self) -> bool:
        """Return whether this item's signature verified."""
        return self.status is VerificationStatus.VERIFIED

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable representation of this result.
        """
        return {
            "index": self.index,
            "name": self.name,
            "status": self.status.value,
            "verified": self.verified,
            "bytes_read": self.bytes_read,
            "digest": None
            if self.digest is None
            else {
                "algorithm": self.digest.algorithm.value,
                "hex": self.digest.digest.hex(),
            },
            "message": self.message,
        }


@dataclass(frozen=True)
class BatchResult:
    """
    The results of a batch verification call, in request order.
    """

    results: tuple[ItemResult, ...]
    """One result per request, in the same order as the requests."""

    @property
    def verified(self) -> tuple[ItemResult, ...]:
        """Return the items that completed verification."""
        return tuple(item for item in self.results if item.verified)

    @property
    def unfinished(self) -> tuple[ItemResult, ...]:
        """Return the items that did not complete verification."""
        return tuple(item for item in self.results if not item.verified)

    @property
    def bytes_read(self) -> int:
        """Return the total number of artifact bytes read in this batch."""
        return sum(item.bytes_read for item in self.results)

    @property
    def complete(self) -> bool:
        """Return whether every item in the batch verified."""
        return all(item.verified for item in self.results)

    def summary(self) -> dict[str, tuple[str, ...]]:
        """
        Group the request names by status.

        Every status is present, even if its tuple is empty, so callers can
        inspect the result without special-casing missing keys.
        """
        grouped: dict[str, list[str]] = {
            status.value: [] for status in VerificationStatus
        }
        for item in self.results:
            grouped[item.status.value].append(item.name)
        return {status: tuple(names) for status, names in grouped.items()}

    def to_dict(self) -> dict[str, object]:
        """
        Return a JSON-serializable representation of this batch result.
        """
        return {
            "complete": self.complete,
            "bytes_read": self.bytes_read,
            "summary": {
                status: list(names) for status, names in self.summary().items()
            },
            "results": [item.to_dict() for item in self.results],
        }


class _ReadAborted(Exception):
    def __init__(
        self, status: VerificationStatus, bytes_read: int, message: str
    ) -> None:
        super().__init__(message)
        self.status = status
        self.bytes_read = bytes_read
        self.message = message


class _BytePool:
    """
    A thread-safe byte budget shared by all items in a batch.

    Bytes are reserved before reading and refunded when a stream returns a
    short read, so the pool never accounts for more bytes than were actually
    hashed. A reservation that cannot be satisfied immediately waits while
    another item holds bytes in flight; this keeps the remaining budget
    available to items that can still make progress instead of handing it all
    to whichever items happen to run first.
    """

    def __init__(self, limit: int | None) -> None:
        self._limit = limit
        self._used = 0
        self._inflight = 0
        self._condition = threading.Condition()

    def reserve(self, wanted: int, tokens: Sequence[CancelToken]) -> int:
        """
        Reserve up to `wanted` bytes, returning the number reserved.

        Returns `0` only when the budget is exhausted and no other reservation
        is in flight. Returns `-1` if a cancellation token is set while waiting.
        """
        if wanted <= 0:
            return 0

        with self._condition:
            while True:
                if _cancelled(tokens):
                    return -1

                if self._limit is None:
                    self._used += wanted
                    self._inflight += wanted
                    return wanted

                available = self._limit - self._used
                if available > 0:
                    allowed = min(wanted, available)
                    self._used += allowed
                    self._inflight += allowed
                    return allowed

                if self._inflight == 0:
                    return 0

                # Another item is holding budget that may be refunded on a
                # short read. Wait briefly, but stay responsive to cancellation.
                self._condition.wait(timeout=_BUDGET_WAIT)

    def release(self, amount: int, *, consumed: bool) -> None:
        """
        Release an in-flight reservation.

        `consumed=False` refunds the bytes to the budget (short read or error);
        `consumed=True` keeps them accounted as used.
        """
        if amount <= 0:
            return
        with self._condition:
            self._inflight -= amount
            if not consumed:
                self._used -= amount
            self._condition.notify_all()

def _cancelled(tokens: Sequence[CancelToken]) -> bool:
    return any(token.is_set() for token in tokens)


def _read_probe(
    stream: IO[bytes], tokens: Sequence[CancelToken], consumed: int
) -> bool:
    """
    Read one probe byte to distinguish EOF from a truncated input.

    The probe is only performed once a budget is exhausted (or exactly met), so
    at most one byte per item is consumed outside the accounted input. A
    pending cancellation is observed before the probe blocks on the stream.
    """
    if _cancelled(tokens):
        raise _ReadAborted(
            VerificationStatus.CANCELLED, consumed, "cancelled by caller"
        )

    try:
        data: bytes | None = stream.read(1)
    except Exception as exc:  # noqa: BLE001
        if _cancelled(tokens):
            raise _ReadAborted(
                VerificationStatus.CANCELLED, consumed, "cancelled by caller"
            ) from exc
        raise

    if data is None:
        raise OSError(
            "artifact stream returned no data; non-blocking streams are not supported"
        )
    return not data


class VerificationService:
    """
    A bounded, concurrent verification entry point for backend services.

    A single service instance can be reused for many calls and from multiple
    threads. Each call gets its own byte budget and executor; completed items
    are never discarded because another request was cancelled or failed.

    `Verifier` keeps per-instance state that is not modified after
    construction, so sharing one `Verifier` across worker threads is safe.
    """

    def __init__(
        self,
        *,
        verifier: Verifier,
        policy: VerificationPolicy,
        max_workers: int | None = None,
    ) -> None:
        """
        Create a new `VerificationService`.

        `verifier` is shared by all requests and must be safe for concurrent
        use. `policy` is applied to every request. `max_workers` bounds how
        many artifacts are read concurrently; `None` selects a default based on
        the number of requests and CPUs.
        """
        if max_workers is not None and max_workers < 1:
            raise ValueError(f"max_workers must be at least 1, got {max_workers}")

        self._verifier = verifier
        self._policy = policy
        self._max_workers = max_workers

    @classmethod
    def production(
        cls,
        *,
        policy: VerificationPolicy,
        offline: bool = False,
        max_workers: int | None = None,
    ) -> VerificationService:
        """Return a service configured against Sigstore's production services."""
        return cls(
            verifier=Verifier.production(offline=offline),
            policy=policy,
            max_workers=max_workers,
        )

    @classmethod
    def staging(
        cls,
        *,
        policy: VerificationPolicy,
        offline: bool = False,
        max_workers: int | None = None,
    ) -> VerificationService:
        """Return a service configured against Sigstore's staging services."""
        return cls(
            verifier=Verifier.staging(offline=offline),
            policy=policy,
            max_workers=max_workers,
        )

    def verify_item(
        self,
        request: VerificationRequest,
        *,
        budget: ReadBudget | None = None,
        cancel: CancelToken | None = None,
    ) -> ItemResult:
        """
        Verify a single request.

        `budget.batch` still applies: it caps the bytes this one item may read.
        """
        budget = budget if budget is not None else ReadBudget()
        pool = _BytePool(budget.batch)
        return self._verify_one(0, request, budget, pool, (cancel,))

    def verify_batch(
        self,
        requests: Iterable[VerificationRequest],
        *,
        budget: ReadBudget | None = None,
        cancel: CancelToken | None = None,
    ) -> BatchResult:
        """
        Verify several requests concurrently.

        Returns one `ItemResult` per request, in input order. Budget exhaustion
        and cancellation affect only the items that hit them; items that have
        already completed keep their verified results.

        `cancel` cancels the whole batch. Individual requests may also carry
        their own tokens; a request is cancelled when either token is set.
        """
        budget = budget if budget is not None else ReadBudget()
        requests_ = tuple(requests)
        if not requests_:
            return BatchResult(())

        pool = _BytePool(budget.batch)
        workers = self._worker_count(len(requests_))
        results: list[ItemResult | None] = [None] * len(requests_)

        executor = futures.ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="sigstore-verify"
        )
        try:
            pending = {
                executor.submit(
                    self._verify_one,
                    index,
                    request,
                    budget,
                    pool,
                    (cancel,),
                ): index
                for index, request in enumerate(requests_)
            }

            for future in futures.as_completed(pending):
                index = pending[future]
                try:
                    results[index] = future.result()
                except Exception as exc:  # noqa: BLE001
                    # `_verify_one` handles expected failures itself; this is a
                    # last-resort guard so one bad item cannot abort the batch.
                    results[index] = ItemResult(
                        index,
                        requests_[index].name,
                        VerificationStatus.ERROR,
                        message=f"verification failed unexpectedly: {exc}",
                    )
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        return BatchResult(
            tuple(
                result
                if result is not None
                else ItemResult(
                    index,
                    request.name,
                    VerificationStatus.ERROR,
                    message="request was not executed",
                )
                for index, (request, result) in enumerate(
                    zip(requests_, results, strict=True)
                )
            )
        )

    def _worker_count(self, request_count: int) -> int:
        if self._max_workers is not None:
            return min(self._max_workers, request_count)
        default = min(32, (os.cpu_count() or 1) + 4)
        return min(default, request_count)

    def _verify_one(
        self,
        index: int,
        request: VerificationRequest,
        budget: ReadBudget,
        pool: _BytePool,
        extra_cancel: Sequence[CancelToken | None],
    ) -> ItemResult:
        tokens = tuple(
            token
            for token in (request.cancel, *extra_cancel)
            if token is not None
        )

        if _cancelled(tokens):
            return ItemResult(
                index,
                request.name,
                VerificationStatus.CANCELLED,
                message="cancelled before reading",
            )

        try:
            stream, owns_stream = _open_artifact(request.artifact)
        except Exception as exc:  # noqa: BLE001
            _logger.debug("failed to open artifact %r", request.name, exc_info=True)
            return ItemResult(
                index,
                request.name,
                VerificationStatus.ERROR,
                message=f"failed to open artifact: {exc}",
            )

        try:
            hashed, consumed = self._read_artifact(stream, budget, pool, tokens)
        except _ReadAborted as exc:
            return ItemResult(
                index,
                request.name,
                exc.status,
                bytes_read=exc.bytes_read,
                message=exc.message,
            )
        except Exception as exc:  # noqa: BLE001
            _logger.debug("failed to read artifact %r", request.name, exc_info=True)
            if _cancelled(tokens):
                return ItemResult(
                    index,
                    request.name,
                    VerificationStatus.CANCELLED,
                    message="cancelled while reading",
                )
            return ItemResult(
                index,
                request.name,
                VerificationStatus.ERROR,
                message=f"failed to read artifact: {exc}",
            )
        finally:
            if owns_stream:
                stream.close()

        if _cancelled(tokens):
            return ItemResult(
                index,
                request.name,
                VerificationStatus.CANCELLED,
                bytes_read=consumed,
                digest=hashed,
                message="cancelled before verification",
            )

        try:
            self._verify_bundle(hashed, request.bundle)
        except Error as exc:
            _logger.debug("verification rejected %r", request.name, exc_info=True)
            return ItemResult(
                index,
                request.name,
                VerificationStatus.REJECTED,
                bytes_read=consumed,
                digest=hashed,
                message=str(exc),
            )
        except Exception as exc:  # noqa: BLE001
            _logger.debug("verification errored %r", request.name, exc_info=True)
            return ItemResult(
                index,
                request.name,
                VerificationStatus.ERROR,
                bytes_read=consumed,
                digest=hashed,
                message=f"verification failed unexpectedly: {exc}",
            )

        _logger.debug(
            "verified %r (%d bytes, sha256:%s)",
            request.name,
            consumed,
            hashed.digest.hex(),
        )
        return ItemResult(
            index,
            request.name,
            VerificationStatus.VERIFIED,
            bytes_read=consumed,
            digest=hashed,
        )

    def _read_artifact(
        self,
        stream: IO[bytes],
        budget: ReadBudget,
        pool: _BytePool,
        tokens: Sequence[CancelToken],
    ) -> tuple[Hashed, int]:
        sha256 = hashlib.sha256()
        consumed = 0
        item_remaining = budget.per_item

        while True:
            if _cancelled(tokens):
                raise _ReadAborted(
                    VerificationStatus.CANCELLED, consumed, "cancelled by caller"
                )

            if item_remaining == 0:
                if _read_probe(stream, tokens, consumed):
                    break
                raise _ReadAborted(
                    VerificationStatus.BUDGET_EXCEEDED,
                    consumed,
                    f"exceeded per-item read budget of {budget.per_item} bytes",
                )

            wanted = (
                _CHUNK_SIZE
                if item_remaining is None
                else min(_CHUNK_SIZE, item_remaining)
            )
            allowed = pool.reserve(wanted, tokens)
            if allowed < 0:
                raise _ReadAborted(
                    VerificationStatus.CANCELLED, consumed, "cancelled by caller"
                )
            if allowed == 0:
                if _read_probe(stream, tokens, consumed):
                    break
                raise _ReadAborted(
                    VerificationStatus.BUDGET_EXCEEDED,
                    consumed,
                    f"exceeded batch read budget of {budget.batch} bytes",
                )

            try:
                data: bytes | None = stream.read(allowed)
            except Exception as exc:  # noqa: BLE001
                pool.release(allowed, consumed=False)
                if _cancelled(tokens):
                    raise _ReadAborted(
                        VerificationStatus.CANCELLED, consumed, "cancelled by caller"
                    ) from exc
                raise

            if data is None:
                pool.release(allowed, consumed=False)
                raise OSError(
                    "artifact stream returned no data; "
                    "non-blocking streams are not supported"
                )

            if not data:
                pool.release(allowed, consumed=False)
                break

            if len(data) > allowed:
                pool.release(allowed, consumed=False)
                raise OSError(
                    f"artifact stream returned {len(data)} bytes for a "
                    f"{allowed}-byte read"
                )

            if len(data) < allowed:
                pool.release(allowed - len(data), consumed=False)
            pool.release(len(data), consumed=True)
            sha256.update(data)
            consumed += len(data)
            if item_remaining is not None:
                item_remaining -= len(data)

        return (
            Hashed(digest=sha256.digest(), algorithm=HashAlgorithm.SHA2_256),
            consumed,
        )

    def _verify_bundle(self, hashed: Hashed, bundle: Bundle) -> None:
        if bundle._dsse_envelope is not None:
            type_, payload = self._verifier.verify_dsse(
                bundle=bundle, policy=self._policy
            )
            if type_ != dsse.Envelope._TYPE:
                raise VerificationError(
                    f"expected JSON payload for DSSE, got {type_}"
                )

            statement = dsse.Statement(payload)
            if not statement._matches_digest(hashed):
                raise VerificationError(
                    f"in-toto statement has no subject for digest "
                    f"{hashed.digest.hex()}"
                )
        else:
            self._verifier.verify_artifact(
                input_=hashed,
                bundle=bundle,
                policy=self._policy,
            )


def _open_artifact(artifact: Artifact) -> tuple[IO[bytes], bool]:
    """
    Return a binary stream for `artifact` and whether the caller owns it.
    """
    if isinstance(artifact, Path):
        return artifact.open("rb"), True
    if isinstance(artifact, (bytes, bytearray, memoryview)):
        return io.BytesIO(bytes(artifact)), True
    return artifact, False
