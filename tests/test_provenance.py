"""Tests for field-level load provenance."""

import pytest

from marshmallow import (
    INCLUDE,
    FieldSource,
    LoadProvenance,
    Schema,
    ValidationError,
    fields,
    post_load,
    pre_load,
)


class AddressSchema(Schema):
    zip_code = fields.Str(data_key="zipCode", load_default="00000")
    city = fields.Str(required=True)


class UserSchema(Schema):
    name = fields.Str(data_key="Name")
    email = fields.Email(data_key="UserName", attribute="contact")
    address = fields.Nested(AddressSchema, data_key="homeAddress")
    role = fields.Str(load_default="member")
    tenant = fields.Str()

    @pre_load
    def add_tenant(self, data, **kwargs):
        data = dict(data)
        data.setdefault("tenant", "internal")
        return data

    @post_load
    def stamp(self, data, **kwargs):
        data["stamped"] = True
        return data


def test_opt_in_returns_pair_and_leaves_data_unchanged():
    schema = UserSchema()
    payload = {
        "Name": "Mick",
        "UserName": "mick@example.com",
        "homeAddress": {"city": "Springfield"},
    }
    data, provenance = schema.load(payload, provenance=True)

    assert data == {
        "name": "Mick",
        "contact": "mick@example.com",
        "address": {"zip_code": "00000", "city": "Springfield"},
        "role": "member",
        "tenant": "internal",
        "stamped": True,
    }
    assert isinstance(provenance, LoadProvenance)


def test_opt_out_is_unchanged():
    schema = UserSchema()
    payload = {"Name": "Mick", "UserName": "mick@example.com"}
    assert schema.load(payload) == {
        "name": "Mick",
        "contact": "mick@example.com",
        "role": "member",
        "tenant": "internal",
        "stamped": True,
    }


def test_sources_by_output_path():
    provenance = LoadProvenance()
    UserSchema().load(
        {
            "Name": "Mick",
            "UserName": "mick@example.com",
            "homeAddress": {"city": "Springfield"},
        },
        provenance=provenance,
    )

    assert provenance.by_path("name") is FieldSource.INPUT
    assert provenance.by_path("contact") is FieldSource.INPUT
    assert provenance.by_path("address.city") is FieldSource.INPUT
    assert provenance.by_path(("address", "zip_code")) is FieldSource.DEFAULT
    assert provenance.by_path("role") is FieldSource.DEFAULT
    assert provenance.by_path("tenant") is FieldSource.PROCESSOR
    assert provenance.by_path("stamped") is FieldSource.PROCESSOR


def test_sources_by_alias_and_nested_alias():
    provenance = LoadProvenance()
    UserSchema().load(
        {
            "Name": "Mick",
            "UserName": "mick@example.com",
            "homeAddress": {"city": "Springfield"},
        },
        provenance=provenance,
    )

    assert provenance.by_alias("Name") is FieldSource.INPUT
    assert provenance.by_alias("UserName") is FieldSource.INPUT
    assert provenance.by_alias("homeAddress.city") is FieldSource.INPUT
    assert provenance.by_alias("homeAddress.zipCode") is FieldSource.DEFAULT
    # `get` accepts either namespace.
    assert provenance.get("homeAddress.zipCode") is FieldSource.DEFAULT
    assert provenance["role"] is FieldSource.DEFAULT


def test_input_wins_over_pre_load_modification():
    class ModifiedSchema(Schema):
        name = fields.Str()

        @pre_load
        def upper(self, data, **kwargs):
            return {"name": data["name"].upper()}

    provenance = LoadProvenance()
    data = ModifiedSchema().load({"name": "mick"}, provenance=provenance)

    assert data == {"name": "MICK"}
    assert provenance["name"] is FieldSource.INPUT


def test_pre_load_added_field_is_processor_even_if_nested():
    class InnerSchema(Schema):
        a = fields.Str()
        b = fields.Str(load_default="b")

    class OuterSchema(Schema):
        inner = fields.Nested(InnerSchema, data_key="Inner")

        @pre_load
        def build(self, data, **kwargs):
            return {"Inner": {"a": "made"}}

    provenance = LoadProvenance()
    data = OuterSchema().load({}, provenance=provenance)

    assert data == {"inner": {"a": "made", "b": "b"}}
    assert provenance.by_path("inner") is FieldSource.PROCESSOR
    assert provenance.by_path("inner.a") is FieldSource.PROCESSOR
    assert provenance.by_path("inner.b") is FieldSource.DEFAULT


def test_pre_load_modified_nested_field_stays_input():
    class InnerSchema(Schema):
        a = fields.Str()

    class OuterSchema(Schema):
        inner = fields.Nested(InnerSchema, data_key="Inner")

        @pre_load
        def modify(self, data, **kwargs):
            data = dict(data)
            data["Inner"] = {"a": "changed"}
            return data

    provenance = LoadProvenance()
    assert OuterSchema().load({"Inner": {"a": "real"}}, provenance=provenance) == {
        "inner": {"a": "changed"}
    }
    assert provenance.by_path("inner.a") is FieldSource.INPUT


def test_list_many_and_mapping_paths():
    class ItemSchema(Schema):
        id = fields.Int(data_key="ID")
        note = fields.Str(load_default="n/a")

    class CartSchema(Schema):
        items = fields.List(fields.Nested(ItemSchema), data_key="lineItems")
        index = fields.Dict(
            keys=fields.Str(), values=fields.Nested(ItemSchema), load_default=dict
        )

    data, provenance = CartSchema().load(
        {
            "lineItems": [{"ID": 1}, {"ID": 2, "note": "x"}],
            "index": {"first": {"ID": 7}},
        },
        provenance=True,
    )

    assert data == {
        "items": [{"id": 1, "note": "n/a"}, {"id": 2, "note": "x"}],
        "index": {"first": {"id": 7, "note": "n/a"}},
    }
    assert provenance.by_alias("lineItems.0.note") is FieldSource.DEFAULT
    assert provenance.by_alias("lineItems.1.note") is FieldSource.INPUT
    assert provenance.by_path(("items", 1, "id")) is FieldSource.INPUT
    assert provenance.by_alias("index.first.ID") is FieldSource.INPUT
    assert provenance.by_path("index.first.note") is FieldSource.DEFAULT


def test_many_schema():
    class ItemSchema(Schema):
        id = fields.Int(data_key="ID")
        note = fields.Str(load_default="n/a")

    data, provenance = ItemSchema(many=True).load(
        [{"ID": 1}, {"ID": 2, "note": "y"}], provenance=True
    )

    assert data == [{"id": 1, "note": "n/a"}, {"id": 2, "note": "y"}]
    assert provenance.by_path((0, "id")) is FieldSource.INPUT
    assert provenance.by_path((0, "note")) is FieldSource.DEFAULT
    assert provenance.by_path((1, "note")) is FieldSource.INPUT


def test_unknown_include_is_input():
    class MySchema(Schema):
        known = fields.Str()

    data, provenance = MySchema(unknown=INCLUDE).load(
        {"known": "x", "extra": "y"}, provenance=True
    )
    assert data == {"known": "x", "extra": "y"}
    assert provenance.by_path("extra") is FieldSource.INPUT


def test_defaults_are_still_mapped():
    class MySchema(Schema):
        a = fields.Str(load_default="A")
        b = fields.Str()

    data, provenance = MySchema().load({}, provenance=True)
    assert data == {"a": "A"}
    assert provenance["a"] is FieldSource.DEFAULT
    assert "b" not in provenance


def test_provenance_empty_on_validation_error():
    class MySchema(Schema):
        a = fields.Int(required=True)

    provenance = LoadProvenance()
    with pytest.raises(ValidationError):
        MySchema().load({}, provenance=provenance)
    assert len(provenance) == 0


def test_deeply_nested_paths_are_not_duplicated():
    class InnerSchema(Schema):
        a = fields.Str()
        b = fields.Str(load_default="b")

    class MidSchema(Schema):
        inner = fields.Nested(InnerSchema, data_key="Inner")

    class OuterSchema(Schema):
        mid = fields.Nested(MidSchema, data_key="Mid")

    data, provenance = OuterSchema().load(
        {"Mid": {"Inner": {"a": "x"}}}, provenance=True
    )

    assert data == {"mid": {"inner": {"a": "x", "b": "b"}}}
    assert provenance.by_path("mid.inner.a") is FieldSource.INPUT
    assert provenance.by_path("mid.inner.b") is FieldSource.DEFAULT
    assert "outer.outer" not in provenance.as_dict()


def test_deeply_nested_alias_paths():
    class InnerSchema(Schema):
        a = fields.Str()

    class MidSchema(Schema):
        inner = fields.Nested(InnerSchema, data_key="Inner")

    class OuterSchema(Schema):
        mid = fields.Nested(MidSchema, data_key="Mid")

    _data, provenance = OuterSchema().load(
        {"Mid": {"Inner": {"a": "x"}}}, provenance=True
    )

    assert provenance.by_alias("Mid.Inner.a") is FieldSource.INPUT
    assert provenance.by_alias("mid.Inner.a") is None
    assert provenance.by_path("mid.inner.a") is FieldSource.INPUT


def test_nested_many_paths():
    class InnerSchema(Schema):
        a = fields.Str()

    class OuterSchema(Schema):
        children = fields.Nested(InnerSchema, many=True)

    data, provenance = OuterSchema().load(
        {"children": [{"a": "one"}, {"a": "two"}]}, provenance=True
    )

    assert data == {"children": [{"a": "one"}, {"a": "two"}]}
    assert provenance.by_alias("children.0.a") is FieldSource.INPUT
    assert provenance.by_alias("children.1.a") is FieldSource.INPUT
    assert provenance.by_path(("children", 1, "a")) is FieldSource.INPUT


def test_as_dict_is_json_serializable():
    provenance = LoadProvenance()
    UserSchema().load(
        {"Name": "Mick", "homeAddress": {"city": "SP"}}, provenance=provenance
    )

    assert provenance.as_dict()["role"] == "default"
    assert provenance.as_dict(by="alias")["homeAddress.city"] == "input"
