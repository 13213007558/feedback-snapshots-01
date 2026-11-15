from __future__ import annotations

from typing import Any

import pytest

from dissect.database.ese.ntds.objects.object import Object
from dissect.database.ese.ntds.schema import (
    BOOTSTRAP_ATTRIBUTES,
    DeficiencyReason,
    Schema,
    SchemaSource,
)
from dissect.database.ese.ntds.util import UndecodedValue


class FakeRecord:
    """Minimal stand-in for :class:`dissect.database.ese.record.Record`.

    Stores values keyed by physical ESE column name, mirroring the only surface (``get`` / ``as_dict``) that
    the NTDS object layer touches.
    """

    def __init__(self, values: dict[str, Any]):
        self._values = values

    def get(self, column: str) -> Any:
        return self._values.get(column)

    def as_dict(self) -> dict[str, Any]:
        return dict(self._values)


class FakeDataTable:
    def __init__(self, schema: Schema):
        self.schema = schema


class FakeDatabase:
    """Minimal database exposing the schema the decode path requires."""

    def __init__(self, schema: Schema):
        self.data = FakeDataTable(schema)
        # decode_value only consults the schema for syntax deficiency reasons
        self.pek = None


def make_object(schema: Schema, values: dict[str, Any]) -> Object:
    return Object(FakeDatabase(schema), FakeRecord(values))


def extended_schema() -> Schema:
    """Build a schema that mimics an AD with an extended, partially documented schema.

    Contains:
      * a same-name collision (two definitions claiming the lDAPDisplayName ``cn``),
      * a custom multi-valued attribute with an unknown syntax,
      * a custom single-valued attribute with a known syntax,
      * a custom object class (subclass) that is registered and one that is not.
    """
    schema = Schema()

    # The database authoritatively redefines the bootstrapped "cn" attribute with a different ATTRTYP/syntax.
    schema._add_attribute(
        dnt=100,
        id=900001,
        name="cn",
        syntax=0x0008000C,
        om_syntax=None,
        om_object_class=None,
        is_single_valued=True,
        link_id=None,
        search_flags=None,
        source=SchemaSource.DATABASE,
    )

    # A second attribute reusing the same display name but with a distinct ATTRTYP: a genuine name collision.
    schema._add_attribute(
        dnt=101,
        id=900002,
        name="cn",
        syntax=0x00080009,
        om_syntax=None,
        om_object_class=None,
        is_single_valued=True,
        link_id=None,
        search_flags=None,
        source=SchemaSource.DATABASE,
    )

    # Custom multi-valued attribute backed by a syntax we have no decoder for (syntax 13, presentation-address).
    schema._add_attribute(
        dnt=102,
        id=900003,
        name="corp-MultiBlob",
        syntax=0x0008000D,
        om_syntax=None,
        om_object_class=None,
        is_single_valued=False,
        link_id=None,
        search_flags=None,
        source=SchemaSource.DATABASE,
    )

    # Custom single-valued attribute with a well-known syntax (9 = integer).
    schema._add_attribute(
        dnt=103,
        id=900004,
        name="corp-Score",
        syntax=0x00080009,
        om_syntax=None,
        om_object_class=None,
        is_single_valued=True,
        link_id=None,
        search_flags=None,
        source=SchemaSource.DATABASE,
    )

    # A registered custom subclass and an intentionally unregistered class id used on an object below.
    schema._add_class(dnt=200, id=0x00900001, name="corp-Widget", source=SchemaSource.DATABASE)

    return schema


def test_bootstrap_definition_is_overridden_by_database() -> None:
    """A database entry supersedes the bootstrap definition, and the replacement remains traceable."""
    schema = extended_schema()

    cn = schema.lookup_attribute(name="cn")
    assert cn.source == SchemaSource.DATABASE
    assert cn.id == 900002
    assert cn.dnt == 101

    override = next(item for item in schema.overrides if item.index == "attribute_name" and item.key == "cn")
    assert override.previous.source == SchemaSource.BOOTSTRAP_ATTRIBUTE
    assert override.current.id == 900001


def test_same_name_collision_is_reported_not_silently_masked() -> None:
    """Two database definitions sharing a display name produce an explicit, specific collision record."""
    schema = extended_schema()

    name_conflicts = schema.name_conflicts()
    assert len(name_conflicts) == 1
    conflict = name_conflicts[0]
    assert conflict.reason == DeficiencyReason.NAME_COLLISION
    assert conflict.key == "cn"
    assert conflict.previous.id == 900001
    assert conflict.current.id == 900002

    # Both colliding definitions remain retrievable by their distinct physical columns / ATTRTYPs.
    first = schema.lookup_attribute(id=900001)
    second = schema.lookup_attribute(id=900002)
    assert first.column != second.column
    assert schema.lookup_attribute(column=first.column).id == 900001
    assert schema.lookup_attribute(column=second.column).id == 900002


def test_known_fields_still_decode_with_extended_schema() -> None:
    """Known-syntax custom and built-in attributes decode to their normal Python types."""
    schema = extended_schema()
    score_column = schema.lookup_attribute(name="corp-Score").column
    instance_type_column = schema.lookup_attribute(name="instanceType").column
    obj = make_object(
        schema,
        {
            schema.lookup_attribute(id=900001).column: "widget-name",
            score_column: 42,
            instance_type_column: 1,  # bootstrap boolean
        },
    )

    assert obj.get("corp-Score") == 42
    assert isinstance(obj.get("corp-Score"), int)
    # The bootstrap instanceType attribute keeps its registered enum decoder.
    assert int(obj.get("instanceType")) == 1


def test_unknown_syntax_multivalue_is_lossless_and_explicit() -> None:
    """A multi-valued attribute with an unsupported syntax keeps every raw value with a precise reason."""
    schema = extended_schema()
    raw_values = [b"\x01\x00blob-a", b"\x02\x00blob-b"]
    column = schema.lookup_attribute(name="corp-MultiBlob").column
    obj = make_object(schema, {column: raw_values})

    decoded = obj.get("corp-MultiBlob")
    assert isinstance(decoded, list)
    assert len(decoded) == 2
    assert all(isinstance(item, UndecodedValue) for item in decoded)
    assert [item.raw for item in decoded] == raw_values
    assert all(item.reason == DeficiencyReason.NO_SYNTAX_DECODER for item in decoded)
    assert all(item.is_multi_valued for item in decoded)

    # The raw path must return the untouched bytes.
    assert obj.get_raw("corp-MultiBlob") == raw_values

    explanation = obj.explain("corp-MultiBlob")
    assert explanation["deficiency_reason"] == DeficiencyReason.NO_SYNTAX_DECODER
    assert explanation["is_single_valued"] is False
    assert explanation["source"] == SchemaSource.DATABASE


def test_unknown_column_without_schema_entry_is_synthesized_losslessly() -> None:
    """A physical column with no attributeSchema entry is reverse-mapped instead of being discarded."""
    schema = extended_schema()
    # ATTs123456: letter 's' -> syntax 18, an entirely unknown syntax number, multi-valued in storage.
    obj = make_object(schema, {"ATTs123456": [b"opaque", b"bytes"]})

    entry = schema.entry_for_column("ATTs123456")
    assert entry is not None
    assert entry.source == SchemaSource.SYNTHETIC
    assert entry.id == 123456
    assert entry.syntax == ord("s") - ord("a")

    # Accessible both through the physical column name and present in the object dictionary.
    decoded = obj.get("ATTs123456")
    assert isinstance(decoded, list)
    assert all(isinstance(item, UndecodedValue) for item in decoded)
    assert [item.raw for item in decoded] == [b"opaque", b"bytes"]
    assert all(item.reason == DeficiencyReason.UNKNOWN_SYNTAX for item in decoded)

    as_dict = obj.as_dict()
    assert "ATTs123456" in as_dict
    assert [item.raw for item in as_dict["ATTs123456"]] == [b"opaque", b"bytes"]

    assert obj.unknown_attributes()[0]["column"] == "ATTs123456"


def test_unregistered_object_class_ids_are_retained() -> None:
    """objectClass values with no classSchema entry stay as raw ATTRTYP integers alongside known names."""
    schema = extended_schema()
    top = schema.lookup_class(name="top")
    custom = schema.lookup_class(name="corp-Widget")
    unregistered_id = 0x00900099

    obj = make_object(schema, {"ATTc0": [top.id, custom.id, unregistered_id]})

    assert obj.object_class == ["top", "corp-Widget", unregistered_id]
    assert obj.unresolved_object_classes() == [unregistered_id]

    # The raw view still exposes the numeric ATTRTYPs losslessly.
    assert obj.get("objectClass", raw=True) == [top.id, custom.id, unregistered_id]

    # The unregistered class is named explicitly in the deficiency report.
    unknown_classes = schema.unknown_classes()
    assert unknown_classes == [{"reason": DeficiencyReason.UNKNOWN_CLASS, "attrtyp": unregistered_id, "oid": None}]
    assert any(item.get("reason") == DeficiencyReason.UNKNOWN_CLASS for item in schema.deficiencies())


def test_registered_custom_subclass_is_resolved_by_name() -> None:
    """A registered custom subclass resolves to its display name and does not pollute the unresolved list."""
    schema = extended_schema()
    custom = schema.lookup_class(name="corp-Widget")
    obj = make_object(schema, {"ATTc0": [custom.id]})

    assert obj.object_class == ["corp-Widget"]
    assert obj.unresolved_object_classes() == []


def test_deficiencies_name_the_insufficient_definition() -> None:
    """The deficiency report is specific: collisions, unknown attributes and unsupported syntaxes each named."""
    schema = extended_schema()
    # Touch the unknown column so it becomes part of the schema's synthetic index.
    schema.entry_for_column("ATTs123456")

    reasons = {item["reason"] for item in schema.deficiencies()}
    assert DeficiencyReason.NAME_COLLISION in reasons
    assert DeficiencyReason.UNKNOWN_ATTRIBUTE in reasons
    assert DeficiencyReason.NO_SYNTAX_DECODER in reasons

    unknown = next(item for item in schema.deficiencies() if item["reason"] == DeficiencyReason.UNKNOWN_ATTRIBUTE)
    assert unknown["column"] == "ATTs123456"
    assert unknown["attrtyp"] == 123456


def test_truly_unknown_attribute_name_still_raises() -> None:
    """A name that maps to neither a schema entry nor any physical column remains an explicit error."""
    schema = extended_schema()
    obj = make_object(schema, {})

    with pytest.raises(AttributeError, match="Attribute not found"):
        obj.get("does-Not-Exist")

    assert schema.explain_attribute("does-Not-Exist") is None


def test_bootstrap_attribute_set_remains_complete() -> None:
    """Guard the bootstrap contract: every essential bootstrapped attribute keeps a valid column mapping."""
    schema = Schema()
    for name, _id, attrtyp, _single in BOOTSTRAP_ATTRIBUTES:
        entry = schema.lookup_attribute(name=name)
        assert entry is not None
        assert entry.source == SchemaSource.BOOTSTRAP_ATTRIBUTE
        assert entry.column.startswith("ATT")
        assert entry.syntax == attrtyp & 0xFF


def test_unresolvable_reference_is_wrapped_without_losing_raw(monkeypatch: pytest.MonkeyPatch) -> None:
    """A reference syntax pointing at an ATTRTYP absent from the schema is wrapped, never raised."""
    import dissect.database.ese.ntds.util as util

    schema = extended_schema()

    # corp-Score uses syntax 9 (integer); force its decoder to fail the way an unresolved OID/DN reference does.
    def broken_decoder(db: object, value: object) -> object:
        raise ValueError(f"Attribute not found for ATTRTYP value: {value!r}")

    monkeypatch.setitem(util.SYNTAX_ENCODE_DECODE_MAP, 9, (None, broken_decoder))

    column = schema.lookup_attribute(name="corp-Score").column
    obj = make_object(schema, {column: 777})

    result = obj.get("corp-Score")
    assert isinstance(result, UndecodedValue)
    assert result.reason == DeficiencyReason.UNRESOLVED_REFERENCE
    assert result.raw == 777
    assert "corp-Score" in result.detail


def test_malformed_structured_value_is_retained(monkeypatch: pytest.MonkeyPatch) -> None:
    """A truncated structured blob (e.g. security descriptor) degrades to an explicit undecoded value."""
    import dissect.database.ese.ntds.util as util

    schema = extended_schema()

    def broken_decoder(db: object, value: object) -> object:
        raise EOFError("unexpected end of stream")

    monkeypatch.setitem(util.SYNTAX_ENCODE_DECODE_MAP, 9, (None, broken_decoder))

    column = schema.lookup_attribute(name="corp-Score").column
    raw = b"\x01\x02\x03"
    obj = make_object(schema, {column: raw})

    result = obj.get("corp-Score")
    assert isinstance(result, UndecodedValue)
    assert result.reason == DeficiencyReason.MALFORMED_VALUE
    assert result.raw == raw
    assert "EOFError" in result.detail


def test_syntax_two_oid_fallback_for_unregistered_attrtyp() -> None:
    """Syntax-2 values resolve to an OID string via the prefix table when no schema entry indexes the ATTRTYP."""
    import dissect.database.ese.ntds.util as util

    schema = extended_schema()
    db = FakeDatabase(schema)

    # 524304 has no schema entry but encodes the OID 2.5.5.16 through the bootstrap prefix table.
    assert schema.lookup(attrtyp=524304) is None
    assert util._attrtyp_to_oid(db, 524304) == "2.5.5.16"
