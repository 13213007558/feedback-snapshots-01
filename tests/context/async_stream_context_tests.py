#  BSD 3-Clause License
#
#  Copyright (c) 2025, Elasticsearch BV
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

"""
Regression coverage for trace-context reclamation around streaming responses.

A endpoint can *return* a stream before the request's work is finished: chunks
(and a failure) may only be produced later, while two such streams are
interleaved on one event loop. These tests pin the three required properties:

* late stream failures are linked to the correct request transaction;
* two interleaved requests never steal each other's attribution;
* no transaction remains active after the streams exit, so the next request
  (or a newly spawned task) cannot inherit stale context.

The scenarios are dependency free: the asyncio event loop is driven through
:func:`asyncio.run` from ordinary synchronous pytest tests.
"""

import asyncio

import pytest

import elasticapm
from elasticapm.contrib.asyncio.traces import bind_stream
from elasticapm.traces import execution_context
from tests.fixtures import TempStoreClient


class LateStreamFailure(RuntimeError):
    pass


async def request_stream_a():
    yield b"a-part-1"
    await asyncio.sleep(0)
    yield b"a-part-2"
    raise LateStreamFailure("late failure produced by stream A")


async def request_stream_b():
    yield b"b-part-1"
    await asyncio.sleep(0)
    yield b"b-part-2"


async def current_transaction():
    return execution_context.get_transaction()


@pytest.fixture()
def apm_client():
    client = TempStoreClient(
        service_name="stream-context-tests",
        server_url="http://localhost:1",
        central_config=False,
        cloud_provider=False,
        metrics_interval="0ms",
        transaction_sample_rate=1.0,
    )
    try:
        yield client
    finally:
        client.close()
        execution_context.set_transaction(None)
        execution_context.unset_span(clear_all=True)
    assert not client._transport.validation_errors, dict(client._transport.validation_errors)


def test_late_failure_attributed_to_owning_request_and_context_reclaimed(apm_client):
    async def scenario():
        # Request A returns a stream, then its ambient request scope detaches
        # (without ending the transaction, which must stay root-able for the
        # late failure).
        transaction_a = apm_client.begin_transaction("request")
        transaction_a.name = "request-A"
        stream_a = bind_stream(request_stream_a(), client=apm_client, result="HTTP 2xx")
        execution_context.set_transaction(None)

        # Request B starts afterwards on the same loop.
        transaction_b = apm_client.begin_transaction("request")
        transaction_b.name = "request-B"
        stream_b = bind_stream(request_stream_b(), client=apm_client, result="HTTP 2xx")
        execution_context.set_transaction(None)

        # Advance the two local streams alternately. The ambient context must be
        # empty after every single step.
        assert await stream_a.__anext__() == b"a-part-1"
        assert execution_context.get_transaction() is None
        assert await stream_b.__anext__() == b"b-part-1"
        assert execution_context.get_transaction() is None

        assert await stream_a.__anext__() == b"a-part-2"
        assert execution_context.get_transaction() is None
        assert await stream_b.__anext__() == b"b-part-2"
        assert execution_context.get_transaction() is None

        # Stream B completes normally.
        with pytest.raises(StopAsyncIteration):
            await stream_b.__anext__()
        assert execution_context.get_transaction() is None

        # Stream A only fails *after* yielding part of its payload.
        with pytest.raises(LateStreamFailure):
            await stream_a.__anext__()
        assert execution_context.get_transaction() is None

        # A freshly spawned task copies the current context; it must see no
        # inherited transaction from either previous request.
        inherited = await asyncio.create_task(current_transaction())
        assert inherited is None

        # No stale active span, and the public context accessors are empty.
        assert execution_context.get_span() is None
        assert elasticapm.get_transaction_id() is None
        assert elasticapm.get_trace_id() is None

        # The next request starts from a clean slate and a fresh id/trace.
        transaction_c = apm_client.begin_transaction("request")
        transaction_c.name = "request-C"
        assert transaction_c.id not in (transaction_a.id, transaction_b.id)
        assert transaction_c.trace_parent.trace_id != transaction_a.trace_parent.trace_id
        apm_client.end_transaction("request", "HTTP 2xx", transaction=transaction_c)
        execution_context.set_transaction(None)

        return transaction_a, transaction_b, transaction_c

    transaction_a, transaction_b, transaction_c = asyncio.run(scenario())

    transactions = {event["id"]: event for event in apm_client.events["transaction"]}
    assert {transaction_a.id, transaction_b.id, transaction_c.id}.issubset(transactions)
    assert transactions[transaction_a.id]["name"] == "request-A"
    assert transactions[transaction_a.id]["outcome"] == "failure"
    assert transactions[transaction_b.id]["name"] == "request-B"
    assert transactions[transaction_b.id]["outcome"] == "success"

    errors = apm_client.events["error"]
    assert len(errors) == 1
    error = errors[0]
    assert error["exception"]["type"] == "LateStreamFailure"
    # Fault attribution: the late error belongs to request A and its trace.
    assert error["transaction_id"] == transaction_a.id
    assert error["trace_id"] == transaction_a.trace_parent.trace_id
    assert all(event.get("transaction_id") != transaction_b.id for event in errors)


def test_interleaved_streams_running_as_separate_tasks(apm_client):
    interleaving = []

    async def request_a():
        transaction = apm_client.begin_transaction("request")
        transaction.name = "task-A"
        stream = bind_stream(request_stream_a(), client=apm_client)
        with pytest.raises(LateStreamFailure):
            async for chunk in stream:
                interleaving.append(("A", chunk))
        assert execution_context.get_transaction() is None
        return transaction.id

    async def request_b():
        transaction = apm_client.begin_transaction("request")
        transaction.name = "task-B"
        stream = bind_stream(request_stream_b(), client=apm_client)
        async for chunk in stream:
            interleaving.append(("B", chunk))
        assert execution_context.get_transaction() is None
        return transaction.id

    async def scenario():
        id_a, id_b = await asyncio.gather(request_a(), request_b())
        # The driving context never saw the task-local transactions.
        assert execution_context.get_transaction() is None
        inherited = await asyncio.create_task(current_transaction())
        assert inherited is None
        return id_a, id_b

    id_a, id_b = asyncio.run(scenario())

    # Both streams produced at least one chunk and were advanced on one loop.
    assert ("A", b"a-part-1") in interleaving
    assert ("B", b"b-part-1") in interleaving

    errors = apm_client.events["error"]
    assert len(errors) == 1
    assert errors[0]["transaction_id"] == id_a

    transaction_ids = {event["id"] for event in apm_client.events["transaction"]}
    assert {id_a, id_b}.issubset(transaction_ids)


def test_token_attach_detach_restores_previous_transaction(apm_client):
    execution_context.set_transaction(None)
    assert execution_context.get_transaction() is None

    transaction_a = apm_client.begin_transaction("request", auto_activate=False)
    transaction_b = apm_client.begin_transaction("request", auto_activate=False)

    token_a = execution_context.set_transaction(transaction_a)
    assert execution_context.get_transaction() is transaction_a
    token_b = execution_context.set_transaction(transaction_b)
    assert execution_context.get_transaction() is transaction_b

    execution_context.reset_transaction(token_b)
    assert execution_context.get_transaction() is transaction_a
    execution_context.reset_transaction(token_a)
    assert execution_context.get_transaction() is None
