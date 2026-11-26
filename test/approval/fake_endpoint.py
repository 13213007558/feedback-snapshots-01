import asyncio

from openfga_sdk.client.models.batch_check_response import ClientBatchCheckResponse
from openfga_sdk.client.models.batch_check_single_response import (
    ClientBatchCheckSingleResponse,
)
from openfga_sdk.client.models.check_request import ClientCheckRequest


class InMemoryFgaEndpoint:
    """
    In-memory stand-in for the OpenFGA check/batch-check endpoints.

    It records the exact body of every request it receives so tests can assert
    which temporary tuples were actually sent. It also keeps a separate
    persistent tuple store that tests can inspect to prove contextual tuples
    are never persisted.
    """

    def __init__(self):
        self.received_checks: list[ClientCheckRequest] = []
        self.received_batches: list[list[dict]] = []
        self.persistent_tuples: list[dict] = []
        self._check_failures: dict[int, Exception] = {}
        self._failure_gate: asyncio.Event | None = None
        self._lock = asyncio.Lock()

    def fail_next_check(self, failure: Exception, gate: asyncio.Event | None = None):
        self._check_failures[len(self.received_checks)] = failure
        self._failure_gate = gate

    async def check(self, body, options=None):
        async with self._lock:
            attempt_index = len(self.received_checks)
            self.received_checks.append(body)
            failure = self._check_failures.pop(attempt_index, None)
            gate = self._failure_gate if failure is not None else None

        if failure is not None:
            # Hold the failed attempt until the test releases it, so callers
            # can deterministically interleave other work with the retry.
            if gate is not None:
                await gate.wait()

            raise failure

        allowed = self._evaluate(body)
        return _FakeCheckResponse(allowed=allowed)

    async def batch_check(self, body, options=None):
        rows = [self._serialize_item(item) for item in body.checks]

        async with self._lock:
            self.received_batches.append(rows)

        result = [
            ClientBatchCheckSingleResponse(
                allowed=self._evaluate_item(item),
                request=item,
                correlation_id=item.correlation_id,
                error=None,
            )
            for item in body.checks
        ]
        return ClientBatchCheckResponse(result=result)

    async def write(self, body, options=None):
        if body and body.writes:
            for tuple_key in body.writes:
                self.persistent_tuples.append(
                    {
                        "user": tuple_key.user,
                        "relation": tuple_key.relation,
                        "object": tuple_key.object,
                    }
                )

        return None

    def _evaluate(self, body: ClientCheckRequest) -> bool:
        contextual = body.contextual_tuples or []
        for tuple_key in contextual:
            if (
                tuple_key.user == body.user
                and tuple_key.relation == body.relation
                and tuple_key.object == body.object
            ):
                return True

        return any(
            stored["user"] == body.user
            and stored["relation"] == body.relation
            and stored["object"] == body.object
            for stored in self.persistent_tuples
        )

    def _evaluate_item(self, item) -> bool:
        for tuple_key in item.contextual_tuples or []:
            if (
                tuple_key.user == item.user
                and tuple_key.relation == item.relation
                and tuple_key.object == item.object
            ):
                return True

        return any(
            stored["user"] == item.user
            and stored["relation"] == item.relation
            and stored["object"] == item.object
            for stored in self.persistent_tuples
        )

    @staticmethod
    def _serialize_item(item) -> dict:
        return {
            "user": item.user,
            "relation": item.relation,
            "object": item.object,
            "correlation_id": item.correlation_id,
            "contextual_tuples": [
                {
                    "user": tuple_key.user,
                    "relation": tuple_key.relation,
                    "object": tuple_key.object,
                }
                for tuple_key in (item.contextual_tuples or [])
            ],
        }


class _FakeCheckResponse:
    def __init__(self, allowed: bool):
        self.allowed = allowed
