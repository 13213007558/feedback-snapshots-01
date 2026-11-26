"""
Local in-memory stand-in for the OpenFGA API used by the forensics demo.

It implements just the three coroutines the collector needs (``expand``,
``read`` and ``read_authorization_model``) and can return the same Expand
tree with sibling children in two different orders, proving that report
comparison does not depend on response ordering.

Scenario (object ``document:deal-memo``):

* chain A - direct ``viewer`` memberships, including one internal account that
  also appears through a group, and two distinct subjects sharing the display
  name "Jordan Lee";
* chain B - an ``editor`` relation feeding ``viewer`` through the model
  (``viewer includes editor``), sharing the internal account node with chain A;
* unconfirmed branch - a ``temp_contractor`` leaf whose backing tuple was never
  read, so it is exported as an unconfirmed branch rather than asserted.
"""

from datetime import datetime, timezone

from openfga_sdk.models.authorization_model import AuthorizationModel
from openfga_sdk.models.computed import Computed
from openfga_sdk.models.expand_request import ExpandRequest
from openfga_sdk.models.expand_response import ExpandResponse
from openfga_sdk.models.leaf import Leaf
from openfga_sdk.models.node import Node
from openfga_sdk.models.nodes import Nodes
from openfga_sdk.models.read_authorization_model_response import (
    ReadAuthorizationModelResponse,
)
from openfga_sdk.models.read_request import ReadRequest
from openfga_sdk.models.read_response import ReadResponse
from openfga_sdk.models.tuple import Tuple
from openfga_sdk.models.tuple_key import TupleKey
from openfga_sdk.models.users import Users
from openfga_sdk.models.userset_tree import UsersetTree


DOCUMENT = "document:deal-memo"
MODEL_ID = "01HMODELDEALMEMO000000000001"

# Internal account ids that must never appear in a shareable report.
INTERNAL_USERS = {
    "user:alice@internal.example.com": "Alice Zhang",
    "user:bob@internal.example.com": "Bob Martin",
    "user:jordan.li@internal.example.com": "Jordan Lee",
}
EXTERNAL_USERS = {
    "user:jordan.lee@partner.example.com": "Jordan Lee",
}
GROUPS = {
    "group:deal-advisors#member": "Deal Advisors",
}

DISPLAY_NAMES = {**INTERNAL_USERS, **EXTERNAL_USERS}

# Tuples actually stored in the stub. The temp_contractor tuple is
# deliberately absent: that branch has no evidence.
STORED_TUPLES: list[TupleKey] = [
    TupleKey(
        user="user:alice@internal.example.com",
        relation="viewer",
        object=DOCUMENT,
    ),
    TupleKey(
        user="user:jordan.li@internal.example.com",
        relation="viewer",
        object=DOCUMENT,
    ),
    TupleKey(
        user="user:jordan.lee@partner.example.com",
        relation="viewer",
        object=DOCUMENT,
    ),
    TupleKey(
        user="group:deal-advisors#member",
        relation="viewer",
        object=DOCUMENT,
    ),
    TupleKey(
        user="user:alice@internal.example.com",
        relation="member",
        object="group:deal-advisors",
    ),
    TupleKey(
        user="user:bob@internal.example.com",
        relation="editor",
        object=DOCUMENT,
    ),
    TupleKey(
        user="user:alice@internal.example.com",
        relation="editor",
        object=DOCUMENT,
    ),
]

# Claimed by the Expand tree but with no stored tuple to back it.
UNCONFIRMED_USER = "user:carol.temp@internal.example.com"
DISPLAY_NAMES[UNCONFIRMED_USER] = "Carol Temp"


def display_name_resolver(object_ref: str) -> str | None:
    return DISPLAY_NAMES.get(object_ref)


def _user_leaf(users: list[str]) -> Leaf:
    return Leaf(users=Users(users=list(users)))


def _computed_leaf(userset: str) -> Leaf:
    return Leaf(computed=Computed(userset=userset))


def _viewer_children() -> list[Node]:
    return [
        Node(
            name=f"{DOCUMENT}#viewer",
            leaf=_user_leaf(
                [
                    "user:alice@internal.example.com",
                    "user:jordan.li@internal.example.com",
                    "user:jordan.lee@partner.example.com",
                    "group:deal-advisors#member",
                ]
            ),
        ),
        Node(
            name=f"{DOCUMENT}#editor",
            leaf=_computed_leaf(f"{DOCUMENT}#editor"),
        ),
        Node(
            name=f"{DOCUMENT}#temp_contractor",
            leaf=_user_leaf([UNCONFIRMED_USER]),
        ),
    ]


def _editor_children() -> list[Node]:
    return [
        Node(
            name=f"{DOCUMENT}#editor",
            leaf=_user_leaf(
                [
                    "user:alice@internal.example.com",
                    "user:bob@internal.example.com",
                ]
            ),
        )
    ]


class LocalFgaStub:
    """In-memory API stub supporting the two Expand response orderings."""

    def __init__(self, order: str = "forward") -> None:
        if order not in ("forward", "reversed"):
            raise ValueError("order must be 'forward' or 'reversed'")
        self.order = order
        self.calls: list[str] = []

    async def expand(self, body: ExpandRequest) -> ExpandResponse:
        self.calls.append("expand")
        viewer_children = _viewer_children()
        editor_children = _editor_children()
        if self.order == "reversed":
            viewer_children = list(reversed(viewer_children))
            editor_children = list(reversed(editor_children))

        root = Node(
            name=f"{DOCUMENT}#viewer",
            union=Nodes(
                nodes=[
                    *viewer_children,
                    Node(
                        name=f"{DOCUMENT}#editor-branch",
                        union=Nodes(nodes=editor_children),
                    ),
                ]
            ),
        )
        return ExpandResponse(tree=UsersetTree(root=root))

    async def read(self, body: ReadRequest) -> ReadResponse:
        self.calls.append("read")
        filter_key = body.tuple_key
        tuples = []
        for key in STORED_TUPLES:
            if (
                filter_key is not None
                and filter_key.object
                and key.object != filter_key.object
            ):
                continue
            if (
                filter_key is not None
                and filter_key.relation
                and key.relation != filter_key.relation
            ):
                continue
            if (
                filter_key is not None
                and filter_key.user
                and key.user != filter_key.user
            ):
                continue
            tuples.append(
                Tuple(
                    key=key,
                    timestamp=datetime(2026, 11, 20, tzinfo=timezone.utc),
                )
            )
        return ReadResponse(tuples=tuples, continuation_token="")

    async def read_authorization_model(self, id: str) -> ReadAuthorizationModelResponse:
        self.calls.append("read_authorization_model")
        model = AuthorizationModel(
            id=id,
            schema_version="1.1",
            type_definitions=[],
        )
        return ReadAuthorizationModelResponse(authorization_model=model)
