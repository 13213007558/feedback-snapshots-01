from datetime import datetime, timezone

import pytest

from openfga_sdk.forensics import ExpandEvidenceCollector
from openfga_sdk.forensics.identifiers import public_identifier
from openfga_sdk.models.authorization_model import AuthorizationModel
from openfga_sdk.models.expand_request import ExpandRequest
from openfga_sdk.models.expand_request_tuple_key import ExpandRequestTupleKey
from openfga_sdk.models.expand_response import ExpandResponse
from openfga_sdk.models.leaf import Leaf
from openfga_sdk.models.node import Node
from openfga_sdk.models.read_authorization_model_response import (
    ReadAuthorizationModelResponse,
)
from openfga_sdk.models.read_response import ReadResponse
from openfga_sdk.models.tuple import Tuple
from openfga_sdk.models.tuple_key import TupleKey
from openfga_sdk.models.users import Users
from openfga_sdk.models.userset_tree import UsersetTree


OBJECT = "document:collector-1"
INTERNAL = "user:morgan@internal.example.com"


class FakeApi:
    def __init__(self):
        self.calls = []

    async def expand(self, request):
        self.calls.append("expand")
        root = Node(
            name=f"{OBJECT}#viewer",
            leaf=Leaf(users=Users(users=[INTERNAL])),
        )
        return ExpandResponse(tree=UsersetTree(root=root))

    async def read(self, request):
        self.calls.append("read")
        assert request.tuple_key.object == OBJECT
        return ReadResponse(
            tuples=[
                Tuple(
                    key=TupleKey(user=INTERNAL, relation="viewer", object=OBJECT),
                    timestamp=datetime(2026, 11, 20, tzinfo=timezone.utc),
                )
            ],
            continuation_token="",
        )

    async def read_authorization_model(self, model_id):
        self.calls.append("read_authorization_model")
        return ReadAuthorizationModelResponse(
            authorization_model=AuthorizationModel(
                id=model_id, schema_version="1.1", type_definitions=[]
            )
        )


@pytest.mark.asyncio
async def test_collector_records_reads_and_redacts_report():
    api = FakeApi()
    collector = ExpandEvidenceCollector(api, internal_types=("user",), salt="incident")
    request = ExpandRequest(
        tuple_key=ExpandRequestTupleKey(relation="viewer", object=OBJECT),
        authorization_model_id="model-9",
    )

    investigation = await collector.collect(request)
    report = investigation.public_report()

    assert api.calls == ["expand", "read_authorization_model", "read"]
    assert report["authorization_model"]["id"] == "model-9"
    assert report["relations_read"] == [
        {
            "object": OBJECT,
            "relations": ["viewer"],
            "read_count": 1,
            "tuple_count": 1,
        }
    ]
    assert report["tree"]["root"]["leaf"]["status"] == "confirmed"
    assert INTERNAL not in str(report)
    assert INTERNAL in investigation.subject_mapping
    assert report["tree"]["root"]["leaf"]["members"][0][
        "public_user"
    ] == public_identifier(INTERNAL, salt="incident")


@pytest.mark.asyncio
async def test_collector_paginates_reads():
    class PagedApi(FakeApi):
        async def read(self, request):
            self.calls.append("read")
            page = request.continuation_token
            if page is None:
                return ReadResponse(
                    tuples=[
                        Tuple(
                            key=TupleKey(
                                user=INTERNAL, relation="viewer", object=OBJECT
                            ),
                            timestamp=datetime(2026, 11, 20, tzinfo=timezone.utc),
                        )
                    ],
                    continuation_token="next-page",
                )
            return ReadResponse(tuples=[], continuation_token="")

    collector = ExpandEvidenceCollector(PagedApi(), internal_types=("user",))
    request = ExpandRequest(
        tuple_key=ExpandRequestTupleKey(relation="viewer", object=OBJECT),
    )
    investigation = await collector.collect(request)

    assert collector.relations_read[0]["read_count"] == 2
    assert investigation.public_report()["relations_read"][0]["tuple_count"] == 1
