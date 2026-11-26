import asyncio
import uuid

from datetime import timedelta

from openfga_sdk.approval.approval import Approval, ApprovalExpiredError
from openfga_sdk.approval.registry import ApprovalRegistry
from openfga_sdk.approval.scope import ScopeViolation, TupleScope
from openfga_sdk.client.models.batch_check_item import ClientBatchCheckItem
from openfga_sdk.client.models.batch_check_request import ClientBatchCheckRequest
from openfga_sdk.client.models.check_request import ClientCheckRequest
from openfga_sdk.client.models.tuple import ClientTuple


class ApprovalService:
    """
    Layer on top of ``OpenFgaClient`` that lets a check carry temporary
    relationships only when they come from an approval issued for that check.

    The service never changes the SDK's ``check`` / ``batch_check`` signatures:
    approvals are passed alongside the existing requests. Each attempt pulls a
    fresh, independent copy of the approval's snapshot (re-checking validity),
    records exactly what was dispatched, and then hands a normal client request
    to the underlying client. Temporary tuples are never written persistently
    and never leak into another check.
    """

    def __init__(self, client, registry: ApprovalRegistry | None = None):
        self._client = client
        self._registry = registry or ApprovalRegistry()

    @property
    def registry(self) -> ApprovalRegistry:
        return self._registry

    def issue_approval(
        self,
        contextual_tuples: list[ClientTuple],
        scope: TupleScope | None = None,
        ttl: timedelta | None = None,
        approval_id: str | None = None,
    ) -> Approval:
        """
        Validate the temporary tuples against the optional scope, snapshot them
        inside an approval, and register the approval.
        """
        approval = Approval(
            contextual_tuples=contextual_tuples,
            scope=scope,
            ttl=ttl,
            approval_id=approval_id,
        )

        return self._registry.issue(approval)

    async def check(
        self,
        body: ClientCheckRequest,
        approval: Approval | None = None,
        options: dict | None = None,
    ):
        """
        Run a single check. When an approval is supplied, its scoped snapshot
        becomes the request's contextual tuples; otherwise the request is sent
        exactly as given (no temporary tuples are injected).
        """
        request, attempt_id = self._build_single_request(body, approval)
        return await self._client.check(request, options)

    async def check_with_retry(
        self,
        body: ClientCheckRequest,
        approval: Approval | None,
        is_transient,
        options: dict | None = None,
        max_attempts: int = 3,
        retry_delay: float = 0.0,
    ):
        """
        Run a single check, retrying only errors classified as transient.

        Between attempts the coroutine awaits ``retry_delay`` seconds, giving
        other checks a chance to run. Every attempt re-materializes the
        approval snapshot, so a retry cannot reuse tuples the caller mutated
        after the first attempt and cannot proceed once the approval has
        expired.
        """
        for attempt in range(1, max_attempts + 1):
            request, attempt_id = self._build_single_request(
                body, approval, attempt=attempt
            )

            try:
                return await self._client.check(request, options)
            except Exception as err:
                if not is_transient(err) or attempt == max_attempts:
                    raise

            if retry_delay > 0:
                await asyncio.sleep(retry_delay)

    async def batch_check(
        self,
        body: ClientBatchCheckRequest,
        approvals: dict[int, Approval] | None = None,
        options: dict | None = None,
    ):
        """
        Run a batch check. ``approvals`` maps a check's position in
        ``body.checks`` to the approval for that row. Rows without an approval
        keep their original contextual tuples (normally none).

        Each approval snapshot is materialized once per row and audited before
        the batch is sent through the existing ``batch_check`` interface.
        """
        approvals = approvals or {}
        checks: list[ClientBatchCheckItem] = []

        for index, item in enumerate(body.checks):
            approval = approvals.get(index)

            if approval is None:
                checks.append(self._clone_item(item, item.contextual_tuples))
                continue

            tuples = approval.materialize()
            attempt_id = str(uuid.uuid4())
            self._registry.record_dispatch(
                approval=approval,
                tuples=tuples,
                check_index=index,
                attempt_id=attempt_id,
                attempt=1,
            )
            checks.append(self._clone_item(item, tuples))

        request = ClientBatchCheckRequest(checks=checks)
        return await self._client.batch_check(request, options)

    def _build_single_request(
        self,
        body: ClientCheckRequest,
        approval: Approval | None,
        attempt: int = 1,
    ) -> tuple[ClientCheckRequest, str | None]:
        attempt_id = None

        if approval is None:
            contextual_tuples = body.contextual_tuples
        else:
            # Re-check expiry and copy the snapshot on every attempt.
            contextual_tuples = approval.materialize()
            attempt_id = str(uuid.uuid4())
            self._registry.record_dispatch(
                approval=approval,
                tuples=contextual_tuples,
                check_index=0,
                attempt_id=attempt_id,
                attempt=attempt,
            )

        request = ClientCheckRequest(
            user=body.user,
            relation=body.relation,
            object=body.object,
            contextual_tuples=contextual_tuples,
            context=body.context,
        )

        return request, attempt_id

    @staticmethod
    def _clone_item(
        item: ClientBatchCheckItem,
        contextual_tuples: list[ClientTuple] | None,
    ) -> ClientBatchCheckItem:
        return ClientBatchCheckItem(
            user=item.user,
            relation=item.relation,
            object=item.object,
            correlation_id=item.correlation_id,
            contextual_tuples=list(contextual_tuples) if contextual_tuples else None,
            context=item.context,
        )


__all__ = [
    "Approval",
    "ApprovalExpiredError",
    "ApprovalService",
    "ApprovalRegistry",
    "ScopeViolation",
    "TupleScope",
]
