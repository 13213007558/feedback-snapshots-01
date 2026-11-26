"""
Collect the data needed for an Expand forensics report from an OpenFGA API.

The collector issues the Expand request, records exactly which relationship
tuples were subsequently read as evidence, fetches the authorization model,
and then hands everything to :class:`ForensicsBuilder`. The raw Expand
response remains available on the returned :class:`InternalInvestigation` for
internal review, while the shareable report contains no internal accounts.
"""

from collections.abc import Callable
from datetime import datetime
from typing import Any

from openfga_sdk.forensics.builder import ForensicsBuilder
from openfga_sdk.forensics.models import InternalInvestigation
from openfga_sdk.models.expand_request import ExpandRequest
from openfga_sdk.models.read_request import ReadRequest
from openfga_sdk.models.read_request_tuple_key import ReadRequestTupleKey


class ExpandEvidenceCollector:
    """
    Collect Expand evidence through a low-level asynchronous ``OpenFgaApi``
    instance (or any object exposing the same ``expand``, ``read`` and
    ``read_authorization_model`` coroutines).
    """

    def __init__(
        self,
        api: Any,
        *,
        internal_types: tuple[str, ...] = ("user", "employee"),
        salt: str = "",
        display_name_resolver: Callable[[str], str | None] | None = None,
        page_size: int = 100,
    ) -> None:
        self.api = api
        self.internal_types = internal_types
        self.salt = salt
        self.display_name_resolver = display_name_resolver
        self.page_size = page_size
        self.relations_read: list[dict[str, Any]] = []

    async def collect(
        self,
        request: ExpandRequest,
        *,
        generated_at: datetime | None = None,
    ) -> InternalInvestigation:
        expand_response = await self.api.expand(request)

        model_id = request.authorization_model_id
        authorization_model = None
        if model_id:
            model_response = await self.api.read_authorization_model(model_id)
            authorization_model = getattr(
                model_response, "authorization_model", model_response
            )

        evidence_tuples = await self._read_evidence_tuples(request)

        builder = ForensicsBuilder(
            internal_types=self.internal_types,
            salt=self.salt,
            display_name_resolver=self.display_name_resolver,
            generated_at=generated_at,
        )
        return builder.build(
            request=request,
            expand_response=expand_response,
            evidence_tuples=evidence_tuples,
            authorization_model=authorization_model,
            relations_read=self.relations_read,
        )

    async def _read_evidence_tuples(self, request: ExpandRequest) -> list[Any]:
        tuple_key = request.tuple_key
        if tuple_key is None:
            return []

        reads: list[dict[str, Any]] = []
        tuples: list[Any] = []
        continuation_token = ""
        while True:
            read_request = ReadRequest(
                tuple_key=ReadRequestTupleKey(
                    object=tuple_key.object,
                    relation=None,
                    user=None,
                ),
                page_size=self.page_size,
                continuation_token=continuation_token or None,
                consistency=request.consistency,
            )
            response = await self.api.read(read_request)
            reads.append(
                {
                    "object": tuple_key.object,
                    "continuation_token_present": bool(continuation_token),
                    "tuples_returned": len(response.tuples or []),
                }
            )
            tuples.extend(response.tuples or [])
            continuation_token = response.continuation_token or ""
            if not continuation_token:
                break

        relations = sorted(
            {
                tuple_model.key.relation
                for tuple_model in tuples
                if getattr(tuple_model, "key", None) is not None
            }
        )
        self.relations_read = [
            {
                "object": tuple_key.object,
                "relations": relations,
                "read_count": len(reads),
                "tuple_count": len(tuples),
            }
        ]
        return tuples
