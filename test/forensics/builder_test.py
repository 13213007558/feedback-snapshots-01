from datetime import datetime, timezone

import pytest

from openfga_sdk.forensics import build_forensics_report
from openfga_sdk.forensics.builder import ForensicsBuilder
from openfga_sdk.forensics.identifiers import public_identifier
from openfga_sdk.models.computed import Computed
from openfga_sdk.models.expand_request import ExpandRequest
from openfga_sdk.models.expand_request_tuple_key import ExpandRequestTupleKey
from openfga_sdk.models.expand_response import ExpandResponse
from openfga_sdk.models.leaf import Leaf
from openfga_sdk.models.node import Node
from openfga_sdk.models.nodes import Nodes
from openfga_sdk.models.tuple import Tuple
from openfga_sdk.models.tuple_key import TupleKey
from openfga_sdk.models.users import Users
from openfga_sdk.models.userset_tree import UsersetTree
from openfga_sdk.models.userset_tree_difference import UsersetTreeDifference
from openfga_sdk.models.userset_tree_tuple_to_userset import (
    UsersetTreeTupleToUserset,
)


DOCUMENT = "document:case-1"
SALT = "case-salt"
FIXED_TIME = datetime(2026, 11, 26, tzinfo=timezone.utc)

INTERNAL_ALICE = "user:alice@internal.example.com"
INTERNAL_BOB = "user:bob@internal.example.com"
INTERNAL_JORDAN = "user:jordan.li@internal.example.com"
PARTNER_JORDAN = "user:jordan.lee@partner.example.com"
UNCONFIRMED = "user:carol.temp@internal.example.com"


def _tuple(user, relation, obj=DOCUMENT):
    return Tuple(
        key=TupleKey(user=user, relation=relation, object=obj),
        timestamp=FIXED_TIME,
    )


def _request():
    return ExpandRequest(
        tuple_key=ExpandRequestTupleKey(relation="viewer", object=DOCUMENT),
        authorization_model_id="model-1",
    )


def _viewer_leaf_children():
    return [
        Node(
            name=f"{DOCUMENT}#viewer",
            leaf=Leaf(
                users=Users(
                    users=[
                        INTERNAL_ALICE,
                        INTERNAL_JORDAN,
                        PARTNER_JORDAN,
                    ]
                )
            ),
        ),
        Node(
            name=f"{DOCUMENT}#editor",
            leaf=Leaf(computed=Computed(userset=f"{DOCUMENT}#editor")),
        ),
        Node(
            name=f"{DOCUMENT}#temp_contractor",
            leaf=Leaf(users=Users(users=[UNCONFIRMED])),
        ),
    ]


def _editor_children():
    return [
        Node(
            name=f"{DOCUMENT}#editor",
            leaf=Leaf(users=Users(users=[INTERNAL_ALICE, INTERNAL_BOB])),
        )
    ]


def _expand(order="forward"):
    viewer_children = _viewer_leaf_children()
    editor_children = _editor_children()
    if order == "reversed":
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


def _evidence():
    return [
        _tuple(INTERNAL_ALICE, "viewer"),
        _tuple(INTERNAL_JORDAN, "viewer"),
        _tuple(PARTNER_JORDAN, "viewer"),
        _tuple(INTERNAL_ALICE, "editor"),
        _tuple(INTERNAL_BOB, "editor"),
    ]


def _display_name(ref):
    return {
        INTERNAL_ALICE: "Alice Zhang",
        INTERNAL_BOB: "Bob Martin",
        INTERNAL_JORDAN: "Jordan Lee",
        PARTNER_JORDAN: "Jordan Lee",
        UNCONFIRMED: "Carol Temp",
    }.get(ref)


def _build(order="forward"):
    return build_forensics_report(
        request=_request(),
        expand_response=_expand(order),
        evidence_tuples=_evidence(),
        internal_types=("user",),
        salt=SALT,
        display_name_resolver=_display_name,
        generated_at=FIXED_TIME,
    )


def test_orders_produce_identical_public_reports():
    forward = _build("forward").public_report()
    reversed_report = _build("reversed").public_report()

    assert forward == reversed_report


def test_internal_ids_never_appear_in_public_report():
    report = _build().public_report()
    text = str(report)

    for internal in (
        INTERNAL_ALICE,
        INTERNAL_BOB,
        INTERNAL_JORDAN,
        UNCONFIRMED,
    ):
        assert internal not in text


def test_same_subject_in_multiple_positions_shares_one_public_id():
    investigation = _build()
    report = investigation.public_report()
    expected = public_identifier(INTERNAL_ALICE, salt=SALT)

    occurrences = []

    def walk(value):
        if isinstance(value, dict):
            if value.get("public_user") == expected:
                occurrences.append(value)
            for nested in value.values():
                walk(nested)
        elif isinstance(value, list):
            for nested in value:
                walk(nested)

    walk(report["tree"])
    # alice appears in direct viewer and in editor chain
    assert len(occurrences) == 2
    assert expected in investigation.subject_mapping.values()


def test_equal_display_names_do_not_merge_subjects():
    report = _build().public_report()
    collisions = report["display_name_collisions"]

    assert len(collisions) == 1
    jordan_ids = collisions[0]["public_subject_ids"]
    assert len(jordan_ids) == 2
    assert jordan_ids == sorted(jordan_ids)
    assert public_identifier(INTERNAL_JORDAN, salt=SALT) in jordan_ids
    assert public_identifier(PARTNER_JORDAN, salt=SALT) in jordan_ids


def test_unconfirmed_branch_is_marked_with_expected_relation():
    report = _build().public_report()
    unconfirmed = report["unconfirmed_branches"]

    assert len(unconfirmed) == 1
    branch = unconfirmed[0]
    assert branch["reason"] == "missing_relationship_evidence"
    assert branch["expected_relation"]["relation"] == "temp_contractor"
    assert branch["expected_relation"]["users"] == [
        public_identifier(UNCONFIRMED, salt=SALT)
    ]

    leaf = report["tree"]["root"]["children"]
    temp_nodes = [node for node in leaf if node["userset"].endswith("#temp_contractor")]
    assert temp_nodes[0]["leaf"]["status"] == "unconfirmed"


def test_evidence_ids_are_stable_across_orders():
    first = [
        item["evidence_id"] for item in _build("forward").public_report()["evidence"]
    ]
    second = [
        item["evidence_id"] for item in _build("reversed").public_report()["evidence"]
    ]

    assert first == second
    assert first == sorted(first)


def test_raw_expand_and_mapping_remain_available_internally():
    investigation = _build()

    assert investigation.raw_expand["tree"]["root"]["name"] == (f"{DOCUMENT}#viewer")
    assert INTERNAL_ALICE in investigation.subject_mapping
    assert any(item["user"] == INTERNAL_ALICE for item in investigation.raw_evidence)


def test_relations_read_are_recorded_canonically():
    builder = ForensicsBuilder(internal_types=("user",), salt=SALT)
    investigation = builder.build(
        request=_request(),
        expand_response=_expand(),
        evidence_tuples=_evidence(),
        relations_read=[
            {"object": DOCUMENT, "relations": ["viewer", "editor"], "read_count": 1}
        ],
    )
    report = investigation.public_report()

    assert report["relations_read"] == [
        {"object": DOCUMENT, "relations": ["editor", "viewer"], "read_count": 1}
    ]


def test_leak_guard_refuses_export_on_internal_leak():
    builder = ForensicsBuilder(internal_types=("user",), salt=SALT)
    # Force the registry to hand back raw internal references.
    builder.registry.public_id = lambda object_ref: object_ref

    with pytest.raises(ValueError, match="internal references leaked"):
        builder.build(
            request=_request(),
            expand_response=_expand(),
            evidence_tuples=_evidence(),
        )


def test_tuple_to_userset_leaf_uses_tupleset_evidence():
    root = Node(
        name="folder:case#viewer",
        leaf=Leaf(
            tuple_to_userset=UsersetTreeTupleToUserset(
                tupleset="parent",
                computed=[Computed(userset="organization:hq#viewer")],
            )
        ),
    )
    expand = ExpandResponse(tree=UsersetTree(root=root))
    request = ExpandRequest(
        tuple_key=ExpandRequestTupleKey(relation="viewer", object="folder:case")
    )
    investigation = build_forensics_report(
        request=request,
        expand_response=expand,
        evidence_tuples=[_tuple("organization:hq", "parent", "folder:case")],
        internal_types=("user",),
        salt=SALT,
    )
    leaf = investigation.public_report()["tree"]["root"]["leaf"]

    assert leaf["kind"] == "tuple_to_userset"
    assert leaf["status"] == "confirmed"
    assert leaf["tupleset_relation"] == "parent"
    assert leaf["evidence_ids"]


def test_difference_node_is_walked_and_redacted():
    root = Node(
        name=f"{DOCUMENT}#viewer",
        difference=UsersetTreeDifference(
            base=Node(
                name=f"{DOCUMENT}#allowed",
                leaf=Leaf(users=Users(users=[INTERNAL_ALICE])),
            ),
            subtract=Node(
                name=f"{DOCUMENT}#denied",
                leaf=Leaf(users=Users(users=[INTERNAL_BOB])),
            ),
        ),
    )
    expand = ExpandResponse(tree=UsersetTree(root=root))
    investigation = build_forensics_report(
        request=_request(),
        expand_response=expand,
        evidence_tuples=[
            _tuple(INTERNAL_ALICE, "allowed"),
            _tuple(INTERNAL_BOB, "denied"),
        ],
        internal_types=("user",),
        salt=SALT,
    )
    report = investigation.public_report()
    node = report["tree"]["root"]

    assert node["operator"] == "difference"
    assert node["children"]["base"]["leaf"]["status"] == "confirmed"
    assert node["children"]["subtract"]["leaf"]["status"] == "confirmed"
    assert INTERNAL_ALICE not in str(report)


def test_empty_users_leaf_is_unconfirmed_without_claiming_members():
    root = Node(
        name=f"{DOCUMENT}#viewer",
        leaf=Leaf(users=Users(users=[])),
    )
    report = build_forensics_report(
        request=_request(),
        expand_response=ExpandResponse(tree=UsersetTree(root=root)),
        evidence_tuples=[],
        internal_types=("user",),
        salt=SALT,
    ).public_report()

    leaf = report["tree"]["root"]["leaf"]
    assert leaf["kind"] == "users"
    assert leaf["status"] == "unconfirmed"
    assert leaf["members"] == []
    # An empty leaf makes no membership claim, so no branch is recorded.
    assert report["unconfirmed_branches"] == []


def test_computed_leaf_without_evidence_is_unconfirmed():
    root = Node(
        name=f"{DOCUMENT}#viewer",
        leaf=Leaf(computed=Computed(userset=f"{DOCUMENT}#editor")),
    )
    report = build_forensics_report(
        request=_request(),
        expand_response=ExpandResponse(tree=UsersetTree(root=root)),
        evidence_tuples=[],
        internal_types=("user",),
        salt=SALT,
    ).public_report()

    leaf = report["tree"]["root"]["leaf"]
    assert leaf["kind"] == "computed"
    assert leaf["status"] == "unconfirmed"
    assert leaf["evidence_ids"] == []
    assert report["unconfirmed_branches"][0]["reason"] == (
        "no_evidence_for_computed_userset"
    )
