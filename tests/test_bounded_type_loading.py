from __future__ import annotations

from dataclasses import fields
from struct import pack
from types import SimpleNamespace
from typing import Any

import pytest

from asyncua import ua
from asyncua.common.structures104 import make_structure, new_struct_field
from asyncua.common.structures_bounded import (
    RejectionReason,
    TypeLoadLimits,
    load_data_type_definitions_bounded,
)
from asyncua.ua.ua_binary import (
    extensionobject_from_binary,
    get_safe_type_hints,
    nodeid_to_binary,
    type_from_optional,
)

pytestmark = pytest.mark.asyncio

NS = 2


class RecordedNode:
    def __init__(self, nodeid: ua.NodeId, name: str, sdef: ua.StructureDefinition | None = None) -> None:
        self.nodeid = nodeid
        self.name = name
        self.sdef = sdef
        self.children: list[RecordedNode] = []
        self.expansions = 0

    def link(self, child: RecordedNode) -> RecordedNode:
        self.children.append(child)
        return child

    async def get_children_descriptions(self, refs: ua.ObjectIds = ua.ObjectIds.HierarchicalReferences) -> list[Any]:
        self.expansions += 1
        descs = []
        for child in self.children:
            desc = ua.ReferenceDescription()
            desc.NodeId = child.nodeid
            desc.BrowseName = ua.QualifiedName(child.name, NS)
            descs.append(desc)
        return descs


class RecordedServer:
    def __init__(self) -> None:
        self.nodes: dict[ua.NodeId, RecordedNode] = {}
        self.read_attribute_calls = 0

    def add(self, node: RecordedNode) -> RecordedNode:
        self.nodes[node.nodeid] = node
        return node

    def get_node(self, nodeid: ua.NodeId) -> RecordedNode:
        return self.nodes[nodeid]

    async def read_attributes(self, nodes: list[RecordedNode], attr: ua.AttributeIds) -> list[Any]:
        self.read_attribute_calls += 1
        assert attr == ua.AttributeIds.DataTypeDefinition
        return [SimpleNamespace(Value=SimpleNamespace(Value=node.sdef)) for node in nodes]


def make_sdef(
    sdef_fields: list[ua.StructureField],
    structure_type: ua.StructureType = ua.StructureType.Structure,
    encoding: ua.NodeId | None = None,
) -> ua.StructureDefinition:
    sdef = ua.StructureDefinition()
    sdef.StructureType = structure_type
    sdef.Fields = sdef_fields
    sdef.DefaultEncodingId = encoding or ua.NodeId()
    return sdef


def make_server() -> tuple[RecordedServer, RecordedNode]:
    server = RecordedServer()
    base = server.add(RecordedNode(ua.NodeId(22, 0), "BaseStructureType"))
    return server, base


def int_struct(name: str, field_name: str = "Value", encoding: ua.NodeId | None = None) -> RecordedNode:
    node = RecordedNode(ua.NodeId(name, NS), name)
    node.sdef = make_sdef([new_struct_field(field_name, ua.VariantType.Int32)], encoding=encoding)
    return node


async def test_self_recursive_structure_loads_and_decodes(restore_ua_registry: Any) -> None:
    server, base = make_server()
    linked_nid = ua.NodeId("LinkedNode", NS)
    encoding = ua.NodeId("LinkedNodeEncoding", NS)
    linked = base.link(server.add(RecordedNode(ua.NodeId("LinkedNode", NS), "LinkedNode")))
    linked.sdef = make_sdef(
        [
            new_struct_field("Value", ua.VariantType.Int32),
            new_struct_field("Next", linked_nid, optional=True),
        ],
        ua.StructureType.StructureWithOptionalFields,
        encoding,
    )
    result = await load_data_type_definitions_bounded(server, base)
    assert result.failed == []
    assert list(result.loaded) == ["LinkedNode"]
    assert result.stats.nodes_visited == 2
    assert result.stats.edges_followed == 1
    assert result.stats.max_depth_reached == 1
    assert result.stats.types_registered == 1
    assert not result.stats.truncated
    assert base.expansions == 1
    assert linked.expansions == 1
    assert server.read_attribute_calls == 1
    assert ua.extension_objects_by_datatype[linked_nid] is result.loaded["LinkedNode"]
    body = pack("<I", 1) + pack("<i", 42) + pack("<I", 0) + pack("<i", 7)
    blob = nodeid_to_binary(encoding) + b"\x01" + pack("<i", len(body)) + body
    decoded = extensionobject_from_binary(ua.utils.Buffer(blob))
    assert type(decoded) is result.loaded["LinkedNode"]
    assert decoded.Value == 42
    assert type(decoded.Next) is result.loaded["LinkedNode"]
    assert decoded.Next.Value == 7
    assert decoded.Next.Next is None


async def test_mutually_recursive_group_loads_atomically(restore_ua_registry: Any) -> None:
    server, base = make_server()
    nid_a = ua.NodeId("PeerA", NS)
    nid_b = ua.NodeId("PeerB", NS)
    node_a = base.link(server.add(RecordedNode(nid_a, "PeerA")))
    node_b = base.link(server.add(RecordedNode(nid_b, "PeerB")))
    node_a.sdef = make_sdef(
        [new_struct_field("Peer", nid_b, optional=True)], ua.StructureType.StructureWithOptionalFields
    )
    node_b.sdef = make_sdef([new_struct_field("Other", nid_a)])
    result = await load_data_type_definitions_bounded(server, base)
    assert result.failed == []
    assert set(result.loaded) == {"PeerA", "PeerB"}
    assert result.stats.types_registered == 2
    cls_a = ua.extension_objects_by_datatype[nid_a]
    cls_b = ua.extension_objects_by_datatype[nid_b]
    assert cls_a is result.loaded["PeerA"]
    assert cls_b is result.loaded["PeerB"]
    assert get_safe_type_hints(cls_a, {"ua": ua})["Peer"] is not None
    hints_a = get_safe_type_hints(cls_a, {"ua": ua})
    hints_b = get_safe_type_hints(cls_b, {"ua": ua})
    assert hints_b["Other"] is cls_a
    assert type_from_optional(hints_a["Peer"]) is cls_b
    assert {f.name: f for f in fields(cls_b)}["Other"].default_factory is cls_a


async def test_inheritance_cycle_and_dependents_are_rejected(restore_ua_registry: Any) -> None:
    server, base = make_server()
    nid_a = ua.NodeId("CycA", NS)
    nid_b = ua.NodeId("CycB", NS)
    cyc_a = base.link(server.add(RecordedNode(nid_a, "CycA")))
    dep = base.link(server.add(int_struct("CycleUser", "Ref")))
    cyc_b = cyc_a.link(server.add(RecordedNode(nid_b, "CycB")))
    cyc_a.sdef = make_sdef([new_struct_field("AValue", ua.VariantType.Int32)])
    cyc_b.sdef = make_sdef([new_struct_field("BValue", ua.VariantType.Int32)])
    cyc_b.link(cyc_a)
    child_of_cycle = cyc_b.link(server.add(int_struct("CycleChild")))
    dep.sdef = make_sdef([new_struct_field("Ref", nid_a)])
    result = await load_data_type_definitions_bounded(server, base)
    assert result.loaded == {}
    assert result.stats.types_registered == 0
    assert result.stats.nodes_visited == 5
    assert result.stats.edges_followed == 5
    by_name = {pending.name: pending for pending in result.failed}
    assert set(by_name) == {"CycA", "CycB", "CycleChild", "CycleUser"}
    assert by_name["CycA"].reason is RejectionReason.InheritanceCycle
    assert by_name["CycB"].reason is RejectionReason.InheritanceCycle
    assert by_name["CycA"].pending_dependencies == [nid_b]
    assert by_name["CycB"].pending_dependencies == [nid_a]
    assert by_name["CycleChild"].reason is RejectionReason.UnresolvedDependency
    assert by_name["CycleChild"].pending_dependencies == [nid_b]
    assert by_name["CycleUser"].reason is RejectionReason.UnresolvedDependency
    assert by_name["CycleUser"].pending_dependencies == [nid_a]
    assert by_name["CycA"].raw_definition is cyc_a.sdef
    assert by_name["CycleUser"].raw_definition is dep.sdef
    assert child_of_cycle.sdef is by_name["CycleChild"].raw_definition
    for nid in (nid_a, nid_b, dep.nodeid, child_of_cycle.nodeid):
        assert nid not in ua.extension_objects_by_datatype


async def test_field_and_type_name_conflicts_are_explainable(restore_ua_registry: Any) -> None:
    server, base = make_server()
    colliding = base.link(server.add(RecordedNode(ua.NodeId("Colliding", NS), "Colliding")))
    colliding.sdef = make_sdef(
        [
            new_struct_field("My Field", ua.VariantType.Int32),
            new_struct_field("My-Field", ua.VariantType.Int32),
        ]
    )
    first = base.link(server.add(int_struct("My Type")))
    second = base.link(server.add(int_struct("My-Type")))
    result = await load_data_type_definitions_bounded(server, base)
    assert set(result.loaded) == {"My_Type"}
    assert result.stats.types_registered == 1
    by_name = {pending.name: pending for pending in result.failed}
    assert by_name["Colliding"].reason is RejectionReason.NameConflict
    assert by_name["Colliding"].raw_definition is colliding.sdef
    assert by_name["My_Type"].reason is RejectionReason.NameConflict
    field_conflict = next(conflict for conflict in result.name_conflicts if conflict.owner == colliding.nodeid)
    assert field_conflict.cleaned_name == "My_Field"
    assert set(field_conflict.original_names) == {"My Field", "My-Field"}
    type_conflict = next(conflict for conflict in result.name_conflicts if conflict.owner is None)
    assert type_conflict.cleaned_name == "My_Type"
    assert set(type_conflict.original_names) == {"My Type", "My-Type"}
    assert first.nodeid in ua.extension_objects_by_datatype
    assert second.nodeid not in ua.extension_objects_by_datatype


@pytest.mark.parametrize(
    "limits, expected_hit",
    [
        (TypeLoadLimits(max_nodes=2), "max_nodes"),
        (TypeLoadLimits(max_depth=1), "max_depth"),
        (TypeLoadLimits(max_edges=2), "max_edges"),
    ],
)
async def test_limits_truncate_traversal(restore_ua_registry: Any, limits: TypeLoadLimits, expected_hit: str) -> None:
    server, base = make_server()
    node1 = base.link(server.add(int_struct("Chain1")))
    node2 = node1.link(server.add(int_struct("Chain2")))
    node2.link(server.add(int_struct("Chain3")))
    result = await load_data_type_definitions_bounded(server, base, limits=limits)
    assert result.stats.truncated
    assert result.stats.limit_hit == expected_hit
    assert result.failed == []
    assert set(result.loaded) == {"Chain1", "Chain2"}
    if expected_hit == "max_edges":
        assert result.stats.edges_followed == 2
    else:
        assert result.stats.nodes_visited == 2


async def test_duplicate_encoding_ids_are_rejected(restore_ua_registry: Any) -> None:
    server, base = make_server()
    encoding = ua.NodeId("SharedEncoding", NS)
    first = base.link(server.add(int_struct("EncFirst", encoding=encoding)))
    second = base.link(server.add(int_struct("EncSecond", encoding=encoding)))
    result = await load_data_type_definitions_bounded(server, base)
    assert set(result.loaded) == {"EncFirst"}
    by_name = {pending.name: pending for pending in result.failed}
    assert by_name["EncSecond"].reason is RejectionReason.DuplicateEncodingId
    assert by_name["EncSecond"].raw_definition is second.sdef
    assert ua.extension_objects_by_typeid[encoding] is result.loaded["EncFirst"]
    assert second.nodeid not in ua.extension_objects_by_datatype
    assert first.nodeid in ua.extension_objects_by_datatype


async def test_existing_trusted_types_survive(restore_ua_registry: Any) -> None:
    trusted_nid = ua.NodeId("TrustedType", NS)
    trusted_encoding = ua.NodeId("TrustedEncoding", NS)
    trusted_sdef = make_sdef([new_struct_field("T", ua.VariantType.Int32)], encoding=trusted_encoding)
    trusted_cls = make_structure(trusted_nid, "TrustedType", trusted_sdef)["TrustedType"]
    ua.register_extension_object("TrustedType", trusted_encoding, trusted_cls, trusted_nid)
    server, base = make_server()
    evil = base.link(server.add(int_struct("EvilTwin", encoding=trusted_encoding)))
    good = base.link(server.add(int_struct("GoodOne")))
    result = await load_data_type_definitions_bounded(server, base)
    assert set(result.loaded) == {"GoodOne"}
    by_name = {pending.name: pending for pending in result.failed}
    assert by_name["EvilTwin"].reason is RejectionReason.DuplicateEncodingId
    assert ua.extension_objects_by_typeid[trusted_encoding] is trusted_cls
    assert ua.get_type(trusted_nid) is trusted_cls
    assert evil.nodeid not in ua.extension_objects_by_datatype
    assert good.nodeid in ua.extension_objects_by_datatype


async def test_supported_and_unknown_definition_variants(restore_ua_registry: Any) -> None:
    server, base = make_server()
    union_node = base.link(server.add(RecordedNode(ua.NodeId("MyUnion", NS), "MyUnion")))
    union_node.sdef = make_sdef(
        [new_struct_field("AsInt", ua.VariantType.Int32), new_struct_field("AsFloat", ua.VariantType.Double)],
        ua.StructureType.Union,
        ua.NodeId("MyUnionEncoding", NS),
    )
    optional_node = base.link(server.add(RecordedNode(ua.NodeId("MyOptional", NS), "MyOptional")))
    optional_node.sdef = make_sdef(
        [
            new_struct_field("Always", ua.VariantType.Int32),
            new_struct_field("Maybe", ua.VariantType.Int32, optional=True),
        ],
        ua.StructureType.StructureWithOptionalFields,
        ua.NodeId("MyOptionalEncoding", NS),
    )
    weird = base.link(server.add(RecordedNode(ua.NodeId("WeirdUnion", NS), "WeirdUnion")))
    weird.sdef = make_sdef([new_struct_field("X", ua.VariantType.Int32)], ua.StructureType.UnionWithSubtypedValues)
    enum_like = base.link(server.add(RecordedNode(ua.NodeId("AnEnum", NS), "AnEnum")))
    enum_def = ua.EnumDefinition()
    enum_def.Fields = [ua.EnumField(Name="One", Value=1)]
    enum_like.sdef = enum_def
    result = await load_data_type_definitions_bounded(server, base)
    assert set(result.loaded) == {"MyUnion", "MyOptional"}
    by_name = {pending.name: pending for pending in result.failed}
    assert by_name["WeirdUnion"].reason is RejectionReason.UnsupportedDefinition
    assert by_name["WeirdUnion"].raw_definition is weird.sdef
    assert by_name["AnEnum"].reason is RejectionReason.UnsupportedDefinition
    assert by_name["AnEnum"].raw_definition is enum_def
    assert result.stats.types_registered == 2
