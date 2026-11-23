# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.


import threading
from enum import Enum
from typing import Any, Iterable, List, Union


class TransmissionBudget:
    """
    A measurable, shared budget of request transmissions for one import.

    Both the bulk helpers and the transport layer spend from the same
    instance, so every real request put on the wire - including retries
    issued internally by the transport - is charged exactly once against
    ``limit``. Operations that already succeeded are never retried and
    therefore never charged again.

    The same object may be shared between synchronous and asynchronous
    callers; spending is guarded by a lock.

    Cancelling a budget only prevents future transmissions. Cost that was
    already spent on requests that went out is never refunded.
    """

    def __init__(self, limit: int) -> None:
        if limit < 0:
            raise ValueError("limit must be >= 0")
        self._limit = limit
        self._spent = 0
        self._cancelled = False
        self._lock = threading.Lock()

    def spend(self, count: int = 1) -> bool:
        """
        Charge ``count`` transmissions to the budget. Returns ``True`` if the
        transmissions may proceed, ``False`` (charging nothing) if the budget
        is exhausted or cancelled.
        """
        if count < 0:
            raise ValueError("count must be >= 0")
        with self._lock:
            if self._cancelled or self._spent + count > self._limit:
                return False
            self._spent += count
            return True

    def cancel(self) -> None:
        """
        Prevent any further spending. Already spent transmissions keep their
        cost - cancellation never refunds requests that were already sent.
        """
        with self._lock:
            self._cancelled = True

    @property
    def limit(self) -> int:
        return self._limit

    @property
    def spent(self) -> int:
        with self._lock:
            return self._spent

    @property
    def remaining(self) -> int:
        with self._lock:
            return self._limit - self._spent

    @property
    def exhausted(self) -> bool:
        return self.remaining <= 0

    @property
    def cancelled(self) -> bool:
        with self._lock:
            return self._cancelled


class ReceiptStatus(str, Enum):
    """
    Outcome of a single action in a budgeted import.

    ``CONFIRMED_FAILURE`` and ``UNCONFIRMED`` are deliberately different
    receipts: the former means the server answered and rejected the action,
    the latter means the request was sent but no reply came back, so the
    action may or may not have been applied.
    """

    SUCCEEDED = "succeeded"
    CONFIRMED_FAILURE = "confirmed_failure"
    UNCONFIRMED = "unconfirmed"
    UNSENT = "unsent"


class TransmissionReceipt:
    """
    Receipt for one action of a budgeted import.

    ``action`` holds the expanded ``(action, data)`` pair (or ``(action,)``
    for deletes) exactly as it was going to be sent, so a recovery pass can
    resubmit it. ``attempts`` counts the helper-level attempts after which
    this receipt was emitted.
    """

    def __init__(
        self,
        action: Any,
        status: Union[ReceiptStatus, str],
        attempts: int = 0,
        info: Any = None,
    ) -> None:
        self.action = action
        self.status = ReceiptStatus(status)
        self.attempts = attempts
        self.info = info

    @property
    def ok(self) -> bool:
        return self.status is ReceiptStatus.SUCCEEDED

    @property
    def resumable(self) -> bool:
        """
        Whether this receipt explicitly allows a recovery pass to resend the
        action. Only failures the server confirmed and actions that were
        never transmitted qualify; actions sent without a reply do not,
        since resending them could apply them twice.
        """
        return self.status in (ReceiptStatus.CONFIRMED_FAILURE, ReceiptStatus.UNSENT)

    def __repr__(self) -> str:
        return f"TransmissionReceipt(status={self.status.value!r}, attempts={self.attempts!r}, action={self.action!r})"


def recoverable_actions(results: Iterable[Any]) -> List[Any]:
    """
    Collect the actions a recovery pass is allowed to resend from the results
    of a budgeted ``streaming_bulk``/``async_streaming_bulk`` run. Accepts
    either the yielded ``(ok, receipt)`` pairs or bare receipts and only
    returns actions whose receipt explicitly allows continuation.
    """
    actions = []
    for result in results:
        receipt = result[1] if isinstance(result, tuple) else result
        if receipt.resumable:
            actions.append(receipt.action)
    return actions
