#  BSD 3-Clause License
#
#  Copyright (c) 2019, Elasticsearch BV
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
#  * Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import functools
from types import TracebackType
from typing import Any, AsyncIterator, Awaitable, Callable, Optional, Type, TypeVar

from elasticapm.conf import constants
from elasticapm.conf.constants import LABEL_RE
from elasticapm.traces import SpanType, Transaction, capture_span, execution_context
from elasticapm.utils import get_name_from_func

FuncType = Callable[..., Awaitable[Any]]
_AnnotatedFunctionT = TypeVar("_AnnotatedFunctionT", bound=FuncType)


class async_capture_span(capture_span):
    def __call__(self, func: _AnnotatedFunctionT) -> _AnnotatedFunctionT:
        self.name = self.name or get_name_from_func(func)

        @functools.wraps(func)
        async def decorated(*args, **kwds):
            async with self:
                return await func(*args, **kwds)

        return decorated

    async def __aenter__(self) -> Optional[SpanType]:
        return self.handle_enter(False)

    async def __aexit__(
        self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]
    ) -> None:
        self.handle_exit(exc_type, exc_val, exc_tb)


async def set_context(data, key="custom") -> None:
    """
    Asynchronous copy of elasticapm.traces.set_context().
    Attach contextual data to the current transaction and errors that happen during the current transaction.

    If the transaction is not sampled, this function becomes a no-op.

    :param data: a dictionary, or a callable that returns a dictionary
    :param key: the namespace for this data
    """
    transaction = execution_context.get_transaction()
    if not (transaction and transaction.is_sampled):
        return
    if callable(data):
        data = await data()

    # remove invalid characters from key names
    for k in list(data.keys()):
        if LABEL_RE.search(k):
            data[LABEL_RE.sub("_", k)] = data.pop(k)

    if key in transaction.context:
        transaction.context[key].update(data)
    else:
        transaction.context[key] = data


def _resolve_client(client):
    """Return the explicit client or the process-wide singleton, if any."""
    if client is not None:
        return client
    try:
        from elasticapm.base import get_client

        return get_client()
    except Exception:
        return None


def _outcome_unset(transaction: Transaction) -> bool:
    """A transaction outcome is only terminal once it is success/failure."""
    return not transaction.outcome or transaction.outcome == constants.OUTCOME.UNKNOWN


class transaction_scope(object):
    """
    Async context manager that activates a specific transaction in the
    execution context and reliably restores the previous context on exit.

    A context token is used so activation is nesting/interleaving safe. This is
    the low-level building block for work that outlives the point where a
    response/stream is returned: activate the owning transaction while the late
    work (for example stream iteration) runs, and the context is detached again
    afterwards so the next request cannot inherit it.

    Exceptions raised inside the scope are (optionally) captured against the
    bound transaction. Cancellation (``asyncio.CancelledError``) is not treated
    as a request fault but still triggers context restoration.
    """

    def __init__(
        self,
        transaction: Optional[Transaction] = None,
        *,
        client=None,
        capture_exception: bool = True,
        end_transaction: bool = False,
        result: Optional[str] = None,
    ) -> None:
        self.transaction = transaction or execution_context.get_transaction()
        if self.transaction is None:
            raise ValueError("transaction_scope requires an active transaction or an explicit transaction")
        self.client = client
        self.capture_exception = capture_exception
        self.end_transaction = end_transaction
        self.result = result
        self._token = None
        self._ended = False

    async def __aenter__(self) -> Transaction:
        self._token = execution_context.set_transaction(self.transaction)
        return self.transaction

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> bool:
        try:
            if exc_val is not None and isinstance(exc_val, Exception):
                if self.capture_exception:
                    client = _resolve_client(self.client)
                    if client is not None:
                        client.capture_exception(exc_info=(exc_type, exc_val, exc_tb), handled=False)
                if _outcome_unset(self.transaction):
                    self.transaction.set_failure()
            if self.end_transaction:
                self._finish()
        finally:
            if self._token is not None:
                execution_context.reset_transaction(self._token)
        return False

    def _finish(self) -> None:
        if self._ended:
            return
        self._ended = True
        client = _resolve_client(self.client)
        if client is not None:
            client.end_transaction(result=self.result, transaction=self.transaction)


class AsyncTransactionStream(object):
    """
    Wrap an async iterable so each chunk is produced under its owning transaction.

    The transaction is (re)activated only for the duration of each
    ``__anext__`` call and the previous context is restored with a token
    afterwards. Therefore two streams belonging to different requests can be
    advanced alternately on the same event loop without either request's
    context leaking into the other's step:

    * a failure raised *after* the response/stream was returned (a "late"
      stream failure) is captured against, and linked to, the correct
      transaction;
    * once the stream terminates (exhaustion, failure or early close) the
      transaction is finalized exactly once;
    * no transaction remains active after a step or after the stream exits, so
      a subsequent request (or a newly spawned task) cannot inherit stale
      context.
    """

    def __init__(
        self,
        stream: AsyncIterator[Any],
        transaction: Optional[Transaction] = None,
        *,
        client=None,
        capture_exception: bool = True,
        end_transaction: bool = True,
        result: Optional[str] = None,
    ) -> None:
        self._stream = stream
        self._iterator: Optional[AsyncIterator[Any]] = None
        self.transaction = transaction or execution_context.get_transaction()
        if self.transaction is None:
            raise ValueError("bind_stream requires an active transaction or an explicit transaction")
        self.client = client
        self.capture_exception = capture_exception
        self.end_transaction = end_transaction
        self.result = result
        self._finished = False

    def __aiter__(self) -> "AsyncTransactionStream":
        if self._iterator is None:
            stream = self._stream
            # Tolerate an async-generator factory being passed instead of the
            # already-created async iterator.
            if not hasattr(stream, "__aiter__") and callable(stream):
                stream = stream()
            self._iterator = stream.__aiter__()
        return self

    async def __anext__(self) -> Any:
        if self._iterator is None:
            self.__aiter__()
        token = execution_context.set_transaction(self.transaction)
        try:
            try:
                chunk = await self._iterator.__anext__()
            except StopAsyncIteration:
                self._finish(constants.OUTCOME.SUCCESS)
                raise
            except BaseException as exc:
                if isinstance(exc, Exception):
                    if self.capture_exception:
                        client = _resolve_client(self.client)
                        if client is not None:
                            client.capture_exception(
                                exc_info=(type(exc), exc, exc.__traceback__), handled=False
                            )
                    self._finish(constants.OUTCOME.FAILURE)
                else:
                    # asyncio.CancelledError / GeneratorExit: terminal but not faults
                    self._finish(None)
                raise
            return chunk
        finally:
            execution_context.reset_transaction(token)
            # Once this stream has terminated, its transaction is finalized and
            # must not remain active. The token reset above restores the context
            # that preceded this step; only detach when that context is still
            # this transaction (e.g. the request started and finished within one
            # task/scope). Never clobber a different, still-active request.
            if self._finished and execution_context.get_transaction() is self.transaction:
                execution_context.set_transaction(None)

    async def aclose(self) -> None:
        """Close the underlying async generator and finalize the transaction."""
        iterator = self._iterator
        close = getattr(iterator if iterator is not None else self._stream, "aclose", None)
        token = execution_context.set_transaction(self.transaction)
        try:
            if close is not None:
                await close()
        finally:
            execution_context.reset_transaction(token)
            self._finish(None)
            if execution_context.get_transaction() is self.transaction:
                execution_context.set_transaction(None)

    async def __aenter__(self) -> "AsyncTransactionStream":
        self.__aiter__()
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> bool:
        if exc_val is not None and isinstance(exc_val, Exception) and not self._finished:
            if self.capture_exception:
                client = _resolve_client(self.client)
                if client is not None:
                    client.capture_exception(exc_info=(exc_type, exc_val, exc_tb), handled=False)
            self._finish(constants.OUTCOME.FAILURE)
        await self.aclose()
        return False

    def _finish(self, outcome: Optional[str]) -> None:
        if self._finished:
            return
        self._finished = True
        if outcome is not None and _outcome_unset(self.transaction):
            if outcome == constants.OUTCOME.SUCCESS:
                self.transaction.set_success()
            else:
                self.transaction.set_failure()
        if self.end_transaction:
            client = _resolve_client(self.client)
            if client is not None:
                client.end_transaction(result=self.result, transaction=self.transaction)


def bind_stream(
    stream: AsyncIterator[Any],
    transaction: Optional[Transaction] = None,
    *,
    client=None,
    capture_exception: bool = True,
    end_transaction: bool = True,
    result: Optional[str] = None,
) -> AsyncTransactionStream:
    """
    Bind an async stream to its owning request transaction.

    See :class:`AsyncTransactionStream` for the interleaving and context
    reclamation guarantees.
    """
    return AsyncTransactionStream(
        stream,
        transaction=transaction,
        client=client,
        capture_exception=capture_exception,
        end_transaction=end_transaction,
        result=result,
    )


# Alternative descriptive names kept as thin aliases for discoverability.
capture_stream = bind_stream
async_transaction_scope = transaction_scope
