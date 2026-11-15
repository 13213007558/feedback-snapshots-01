"""Tests for explainable reading of an extended NTDS schema.

These tests use minimal in-memory schema/record fixtures instead of a full NTDS.dit file. They model the
two situations an offline investigation of a schema-extended enterprise AD runs into:

- an attribute reusing an existing ``lDAPDisplayName`` but with a different ATTRTYP (a same-name collision),
  and
- objects of a custom subclass whose ``objectClass`` contains an unregistered class ATTRTYP.

The goal is to prove that known fields still decode normally while unknown fields remain inspectable
losslessly, with the precise insufficient definition reported instead of a generic string.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from dissect.database.ese.ntds import util
from dissect.database.ese.ntds.objects import Top
from dissect.database.ese.ntds.objects.object import Object, _get_attribute
from dissect.database.ese.ntds.schema import Schema, SchemaSource
from dissect.database.ese.ntds.util import DecodeReason, UndecodedValue, explain_decode

# A made-up ATTRTYP range for the extended-schema entries. Prefix index 99 is deliberately *not* part of
# BOOTSTRAP_OID_PREFIXES, so attrtyp_to_oid() cannot resolve it either.
CUSTOM_PREFIX = 99
CUSTOM_ATTR_ID = (CUSTOM_PREFIX << 16) + 1
CUSTOM_CLASS_ID = (CUSTOM_PREFIX << 16) + 2
UNKNOWN_ATTR_ID = (CUSTOM_PREFIX << 16) + 3
BOOTSTRAP_CN_ID = 3  # The ATTRTYP of the bootstrapped "cn" attribute (ATTm3)

# Physical column names follow ATT<syntax-letter><ATTRTYP>; derive them instead of hardcoding the letters.
CUSTOM_CN_COLUMN = f"ATTi{CUSTOM_ATTR_ID}"  # syntax 8 -> letter "i"
CUSTOM_NOTES_COLUMN = f"ATTm{CUSTOM_ATTR_ID + 10}"  # syntax 12 -> letter "m"
UNKNOWN_BLOB_COLUMN = f"ATT{chr(ord('a') + (0x00080063 & 0xFFFF))}{UNKNOWN_ATTR_ID}"


class FakeRecord:
    """Minimal stand-in for :class:`dissect.database.ese.record.Record`.

    Only implements the surface used by the NTDS object layer: column ``get`` and ``as_dict``.
    """

    def __init__(self, values: dict[str, Any]):
        self._values = values

    def get(self, column: str, raw: bool = False) -> Any:
        return self._values.get(column)

    def as_dict(self, raw: bool = False) -> dict[str, Any]:
        return dict(self._values)


class FakeDB:
    """Minimal stand-in for :class:`dissect.database.ese.ntds.database.Database`."""

    def __init__(self, schema: Schema):
        self.data = SimpleNamespace(schema=schema)
        # No PEK and no SD table: decoders must still work for the non-protected syntaxes under test.
        self.pek = None
        self.sd = SimpleNamespace(sd=lambda identifier: None)


def _extended_schema() -> Schema:
    """Build a schema that exercises every extended-schema edge case."""
    schema = Schema()

    # A custom attribute that *reuses the lDAPDisplayName "cn" but has a different ATTRTYP and a different
    # syntax (boolean instead of unicode). It is added first so it temporarily wins the name index.
    schema._add_attribute(
        dnt=101,
        id=CUSTOM_ATTR_ID,
        name="cn",
        syntax=0x00080008,
        om_syntax=None,
        om_object_class=None,
        is_single_valued=True,
        link_id=None,
        search_flags=None,
        source=SchemaSource.DATABASE,
    )

    # Database definition for the standard "cn": added second so it wins the name index back. Its ATTRTYP
    # also matches the bootstrap placeholder, which is the expected (unambiguous) bootstrap replacement.
    schema._add_attribute(
        dnt=100,
        id=BOOTSTRAP_CN_ID,
        name="cn",
        syntax=0x0008000C,
        om_syntax=None,
        om_object_class=None,
        is_single_valued=True,
        link_id=None,
        search_flags=None,
        source=SchemaSource.DATABASE,
    )

    # A multi-valued unicode attribute with a unique name.
    schema._add_attribute(
        dnt=102,
        id=CUSTOM_ATTR_ID + 10,
        name="customNotes",
        syntax=0x0008000C,
        om_syntax=None,
        om_object_class=None,
        is_single_valued=False,
        link_id=None,
        search_flags=None,
        source=SchemaSource.DATABASE,
    )

    # A single-valued attribute using a syntax number no decoder knows about.
    schema._add_attribute(
        dnt=103,
        id=UNKNOWN_ATTR_ID,
        name="customBlob",
        syntax=0x00080063,  # low byte 0x63 (99) is outside SYNTAX_ENCODE_DECODE_MAP
        om_syntax=None,
        om_object_class=None,
        is_single_valued=True,
        link_id=None,
        search_flags=None,
        source=SchemaSource.DATABASE,
    )

    # A custom subclass registered in the database schema, plus an unregistered class used by an object.
    schema._add_class(dnt=200, id=CUSTOM_CLASS_ID, name="customUser", source=SchemaSource.DATABASE)
    return schema


@pytest.fixture
def db() -> FakeDB:
    return FakeDB(_extended_schema())


def _record() -> FakeRecord:
    """A record carrying values for both same-name attributes, a multivalue and an unknown-syntax value."""
    return FakeRecord(
        {
            "ATTm3": "canonical name",  # Standard cn (unicode syntax 12)
            CUSTOM_CN_COLUMN: True,  # Custom same-name cn (boolean syntax 8)
            CUSTOM_NOTES_COLUMN: ["note one", "note two"],  # Multi-valued customNotes
            UNKNOWN_BLOB_COLUMN: b"\xde\xad\xbe\xef",  # Unknown syntax customBlob
            "ATTc0": [0x00010000, CUSTOM_CLASS_ID, 0x7FFFFFFF],  # objectClass: top, customUser, unknown
            "ATTq999999": b"orphan column",  # Column without any schema entry at all
        }
    )


def test_bootstrap_definition_is_replaced_by_database_definition(db: FakeDB) -> None:
    """The database cn entry supersedes the bootstrap placeholder while recording the override."""
    cn = db.data.schema.lookup_attribute(name="cn")
    assert cn.source is SchemaSource.DATABASE
    assert cn.dnt == 100

    overrides = [conflict for conflict in db.data.schema.conflicts() if not conflict.ambiguous]
    assert any(
        conflict.index == "attribute_id"
        and conflict.key == BOOTSTRAP_CN_ID
        and conflict.winner.source is SchemaSource.DATABASE
        and conflict.shadowed.source is SchemaSource.BOOTSTRAP
        for conflict in overrides
    ), overrides


def test_same_name_attributes_have_distinct_columns_and_are_both_reachable(db: FakeDB) -> None:
    """A name collision must not collapse two attributes into one decoding rule."""
    assert db.data.schema.is_ambiguous_name("cn")

    # The name index resolves to one winner, but the shadowed definition stays reachable by ATTRTYP/column.
    winner = db.data.schema.lookup_attribute(name="cn")
    shadowed = db.data.schema.lookup_attribute(id=CUSTOM_ATTR_ID)
    assert winner.id == BOOTSTRAP_CN_ID
    assert shadowed is not None
    assert shadowed.id == CUSTOM_ATTR_ID
    assert winner.column != shadowed.column
    assert db.data.schema.lookup_attribute(column=shadowed.column) is shadowed

    explained = list(db.data.schema.explain_attribute("cn"))
    assert {entry.id for entry, _oid, ambiguous in explained} == {BOOTSTRAP_CN_ID, CUSTOM_ATTR_ID}
    assert all(ambiguous for _entry, _oid, ambiguous in explained)

    # The final name-index binding is the standard cn winning back the slot from the custom attribute.
    name_collisions = [
        item
        for item in db.data.schema.conflicts(ambiguous_only=True)
        if item.index == "attribute_name" and item.winner is winner
    ]
    assert len(name_collisions) == 1
    collision = name_collisions[0]
    assert collision.key == "cn"
    assert collision.shadowed is shadowed


def test_known_field_still_decodes_through_syntax_rule(db: FakeDB) -> None:
    """The standard cn value decodes as unicode despite the collision on its display name."""
    obj = Object(db, _record())
    assert obj.get("cn") == "canonical name"

    schema = db.data.schema.lookup_attribute(id=BOOTSTRAP_CN_ID)
    decoded, decision = explain_decode(db, schema, "canonical name")
    assert decoded == "canonical name"
    assert decision.rule == "syntax"
    # The collision is still surfaced as rationale, but it did not block syntax-based decoding
    assert decision.reason is DecodeReason.NAME_COLLISION
    assert decision.ambiguous_name is True


def test_collision_does_not_borrow_the_other_attributes_decoder(db: FakeDB) -> None:
    """The custom same-name boolean attribute must not use the unicode decoder of the standard cn."""
    custom = db.data.schema.lookup_attribute(id=CUSTOM_ATTR_ID)
    decoded, decision = explain_decode(db, custom, True)

    assert decoded is True
    assert decision.rule == "syntax"
    assert decision.ambiguous_name is True
    assert decision.reason is DecodeReason.NAME_COLLISION
    assert "cn" in decision.detail


def test_multivalued_attribute_decodes_every_member(db: FakeDB) -> None:
    """Multi-valued attributes decode element by element and default to an empty list when unset."""
    schema = db.data.schema.lookup_attribute(name="customNotes")
    decoded, decision = explain_decode(db, schema, ["a", "b"])
    assert decoded == ["a", "b"]
    assert decision.rule == "syntax"

    obj = Object(db, _record())
    assert obj.get("customNotes") == ["note one", "note two"]
    assert _get_attribute(db, FakeRecord({}), "customNotes") == []


def test_unknown_syntax_is_lossless_and_names_the_deficiency(db: FakeDB) -> None:
    """An unknown syntax returns an UndecodedValue with the exact reason and the untouched bytes."""
    schema = db.data.schema.lookup_attribute(name="customBlob")
    raw = b"\xde\xad\xbe\xef"

    decoded, decision = explain_decode(db, schema, raw)
    assert isinstance(decoded, UndecodedValue)
    assert decoded.raw == raw
    assert bytes(decoded) == raw
    assert decoded.reason is DecodeReason.UNKNOWN_SYNTAX
    assert "99" in decoded.detail
    assert decision.decoder is None
    assert decision.reason is DecodeReason.UNKNOWN_SYNTAX

    obj = Object(db, _record())
    value = obj.get("customBlob")
    assert isinstance(value, UndecodedValue)
    assert value.raw == raw


def test_unregistered_object_class_is_retained_but_known_ancestor_still_upcasts(db: FakeDB) -> None:
    """Objects of a custom subclass keep the unknown class ATTRTYP while still decoding known fields."""
    obj = Object.from_record(db, _record())

    # "top" is a registered known class, so the object upcasts instead of falling back to a bare Object,
    # even though the most specific class (customUser) and one ATTRTYP are not registered as Python types.
    assert isinstance(obj, Top)

    object_class = obj.object_class
    assert "top" in object_class
    assert "customUser" in object_class
    # The unregistered class survives as its raw ATTRTYP rather than raising or being stringified vaguely
    assert 0x7FFFFFFF in object_class
    assert obj.unregistered_object_classes == [0x7FFFFFFF]

    # repr() must not blow up on the unknown class either
    repr(obj)


def test_unknown_column_is_kept_losslessly_in_as_dict(db: FakeDB) -> None:
    """Columns without any schema entry are retained under their raw column name, never dropped."""
    obj = Object(db, _record())
    result = obj.as_dict()

    orphan = result["ATTq999999"]
    assert isinstance(orphan, UndecodedValue)
    assert orphan.raw == b"orphan column"
    assert orphan.reason is DecodeReason.MISSING_SCHEMA
    assert orphan.schema is None

    # The registered attributes in the same record still decode normally
    assert result["cn"] == "canonical name"
    assert result["customNotes"] == ["note one", "note two"]


def test_missing_schema_entry_reports_missing_schema_reason(db: FakeDB) -> None:
    """Decoding with no schema entry at all produces a specific reason, not a generic string."""
    decoded, decision = explain_decode(db, None, b"whatever")
    assert isinstance(decoded, UndecodedValue)
    assert decoded.reason is DecodeReason.MISSING_SCHEMA
    assert decision.rule is None
    assert decision.schema is None


def test_none_value_is_passed_through_with_a_decision(db: FakeDB) -> None:
    """An unset (``None``) value stays ``None`` but still yields an explainable decision."""
    schema = db.data.schema.lookup_attribute(name="customBlob")
    decoded, decision = explain_decode(db, schema, None)
    assert decoded is None
    assert decision.reason is DecodeReason.UNKNOWN_SYNTAX


def test_failing_decoder_is_wrapped_losslessly(db: FakeDB, monkeypatch: pytest.MonkeyPatch) -> None:
    """A decoder that raises on malformed data must not crash the object; the raw value is retained."""

    def boom(_db: object, _value: object) -> object:
        raise EOFError("simulated truncated security descriptor")

    # customBlob uses an unknown syntax by default; repoint syntax 99 to a failing decoder for this test
    monkeypatch.setitem(util.SYNTAX_ENCODE_DECODE_MAP, 99, (None, boom))

    schema = db.data.schema.lookup_attribute(name="customBlob")
    raw = b"\xde\xad\xbe\xef"
    decoded, decision = explain_decode(db, schema, raw)

    assert isinstance(decoded, UndecodedValue)
    assert decoded.raw == raw
    assert bytes(decoded) == raw
    assert decoded.reason is DecodeReason.NO_DECODER
    assert "simulated truncated security descriptor" in decoded.detail
    assert decision.rule == "syntax"


def test_oid_association_is_available_for_registered_and_unknown_prefixes(db: FakeDB) -> None:
    """ATTRTYP/OID association works where a prefix exists and clearly fails where none is registered."""
    cn = db.data.schema.lookup_attribute(id=BOOTSTRAP_CN_ID)
    # Prefix index 0 maps to the X.500 attribute arc (2.5.4), so cn -> 2.5.4.3
    assert db.data.schema.oid(cn) == "2.5.4.3"

    custom = db.data.schema.lookup_attribute(id=CUSTOM_ATTR_ID)
    # Prefix index 99 was intentionally not registered, so the OID cannot be fabricated
    assert db.data.schema.oid(custom) is None

    # The entry still exposes its ATTRTYP, column, syntax and display name for manual interpretation
    assert custom.column == CUSTOM_CN_COLUMN
    assert custom.syntax == 8
    assert custom.name == "cn"
