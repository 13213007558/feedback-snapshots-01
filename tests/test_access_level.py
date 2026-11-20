"""Acceptance tests for output access levels (marshmallow.experimental.access_level)."""

import json

import pytest
from marshmallow import Schema, fields, post_dump
from marshmallow.experimental.access_level import (
    AccessLevel,
    AccessLevelSchema,
    UnregisteredOutputError,
    UnregisteredOutputPolicy,
)


class ProfileSchema(AccessLevelSchema, Schema):
    # Public by default: no explicit access metadata.
    display_name = fields.String(attribute="name")
    # Alias must be preserved; internal field hidden from third parties.
    email = fields.String(data_key="contactEmail", metadata={"access": AccessLevel.INTERNAL})


class AccountSchema(AccessLevelSchema, Schema):
    id = fields.Integer()
    handle = fields.String()
    ssn = fields.String(metadata={"access": AccessLevel.INTERNAL})
    profile = fields.Nested(ProfileSchema)
    roles = fields.List(fields.String(), metadata={"access": AccessLevel.INTERNAL})

    @post_dump
    def add_computed_field(self, data, **kwargs):
        # Business field added after field serialization.
        data["computed_internal_flag"] = True
        return data

    output_access = {"computed_internal_flag": AccessLevel.INTERNAL}


@pytest.fixture
def account():
    return {
        "id": 7,
        "handle": "alice",
        "ssn": "123-45-6789",
        "profile": {"name": "Alice", "email": "alice@example.com"},
        "roles": ["admin"],
    }


@pytest.fixture
def schema():
    return AccountSchema()


def test_internal_dump_keeps_everything(schema, account):
    data = schema.dump(account, access=AccessLevel.INTERNAL)
    assert data == {
        "id": 7,
        "handle": "alice",
        "ssn": "123-45-6789",
        "profile": {
            "display_name": "Alice",
            "contactEmail": "alice@example.com",
        },
        "roles": ["admin"],
        "computed_internal_flag": True,
    }


def test_public_dump_strips_internal_keys_everywhere(schema, account):
    data = schema.dump(account, access=AccessLevel.PUBLIC)
    assert data == {
        "id": 7,
        "handle": "alice",
        "profile": {"display_name": "Alice"},
    }
    # Explicit assertions that over-level keys never reach the final dict.
    assert "ssn" not in data
    assert "roles" not in data
    assert "computed_internal_flag" not in data
    assert "contactEmail" not in data["profile"]
    assert "email" not in data["profile"]


def test_allowed_values_are_unchanged(schema, account):
    public = schema.dump(account, access=AccessLevel.PUBLIC)
    internal = schema.dump(account, access=AccessLevel.INTERNAL)
    assert public["id"] == internal["id"] == account["id"]
    assert public["handle"] == internal["handle"] == account["handle"]
    assert public["profile"]["display_name"] == "Alice"


def test_dumps_json_is_filtered_too(schema, account):
    payload = schema.dumps(account, access=AccessLevel.PUBLIC)
    data = json.loads(payload)
    assert set(data) == {"id", "handle", "profile"}
    assert set(data["profile"]) == {"display_name"}


def test_nested_level_propagates_without_explicit_access(schema, account):
    # No access argument on the nested schema: it inherits the root level.
    public = schema.dump(account, access=AccessLevel.PUBLIC)
    assert "contactEmail" not in public["profile"]
    internal = schema.dump(account, access=AccessLevel.INTERNAL)
    assert internal["profile"]["contactEmail"] == "alice@example.com"


def test_many_dump_filters_each_item(schema, account):
    accounts = [account, account]
    data = schema.dump(accounts, many=True, access=AccessLevel.PUBLIC)
    assert len(data) == len(accounts)
    for item in data:
        assert set(item) == {"id", "handle", "profile"}
        assert set(item["profile"]) == {"display_name"}


def test_only_projection_combined_with_level(schema, account):
    projected = AccountSchema(only=("id", "ssn", "profile.email"))
    public = projected.dump(account, access=AccessLevel.PUBLIC)
    # only narrows the fields; the level then removes the internal ones.
    assert public == {"id": 7, "profile": {}}
    internal = projected.dump(account, access=AccessLevel.INTERNAL)
    # post_dump keys are independent of `only`; the registered computed field stays.
    assert internal == {
        "id": 7,
        "ssn": "123-45-6789",
        "profile": {"contactEmail": "alice@example.com"},
        "computed_internal_flag": True,
    }


def test_exclude_combined_with_level(account):
    projected = AccountSchema(exclude=("id",))
    public = projected.dump(account, access=AccessLevel.PUBLIC)
    assert "id" not in public
    assert "ssn" not in public
    assert public["handle"] == "alice"


def test_registered_public_post_dump_field_survives(account):
    class PublicEnvelopeSchema(AccessLevelSchema, Schema):
        name = fields.String()

        @post_dump
        def add_public_flag(self, data, **kwargs):
            data["public_flag"] = "ok"
            return data

        output_access = {"public_flag": AccessLevel.PUBLIC}

    data = PublicEnvelopeSchema().dump({"name": "bob"}, access=AccessLevel.PUBLIC)
    assert data == {"name": "bob", "public_flag": "ok"}


def test_unregistered_post_dump_key_defaults_to_internal(account):
    class LooseSchema(AccessLevelSchema, Schema):
        name = fields.String()

        @post_dump
        def add_secret(self, data, **kwargs):
            data["runtime_secret"] = "x"
            return data

    public = LooseSchema().dump({"name": "bob"}, access=AccessLevel.PUBLIC)
    assert public == {"name": "bob"}
    internal = LooseSchema().dump({"name": "bob"}, access=AccessLevel.INTERNAL)
    assert internal["runtime_secret"] == "x"


def test_unregistered_post_dump_key_can_raise(account):
    class StrictSchema(AccessLevelSchema):
        unregistered_output_policy = UnregisteredOutputPolicy.RAISE

        name = fields.String()

        @post_dump
        def add_secret(self, data, **kwargs):
            data["runtime_secret"] = "x"
            return data

    with pytest.raises(UnregisteredOutputError, match="runtime_secret"):
        StrictSchema().dump({"name": "bob"}, access=AccessLevel.PUBLIC)
    # At the internal level the default level allows the key through.
    assert (
        StrictSchema().dump({"name": "bob"}, access=AccessLevel.INTERNAL)["runtime_secret"] == "x"
    )


def test_default_top_level_access_is_internal(schema, account):
    # Backwards-compatible default: no access argument means full payload.
    assert schema.dump(account)["ssn"] == "123-45-6789"


def test_nested_schema_cannot_widen_access(account):
    class NarrowNested(AccessLevelSchema, Schema):
        name = fields.String()
        token = fields.String(metadata={"access": AccessLevel.INTERNAL})

    class RootSchema(AccessLevelSchema, Schema):
        child = fields.Nested(NarrowNested)

    data = RootSchema().dump(
        {"child": {"name": "kid", "token": "t"}},
        access=AccessLevel.INTERNAL,
    )
    assert data["child"] == {"name": "kid", "token": "t"}
    public = RootSchema().dump(
        {"child": {"name": "kid", "token": "t"}},
        access=AccessLevel.PUBLIC,
    )
    assert public["child"] == {"name": "kid"}


class AddressSchema(AccessLevelSchema, Schema):
    city = fields.String()
    geo = fields.String(metadata={"access": AccessLevel.INTERNAL})


class CustomerSchema(AccessLevelSchema, Schema):
    name = fields.String()
    addresses = fields.List(fields.Nested(AddressSchema))
    manager = fields.Nested(lambda: CustomerSchema(only=("name",)))


def test_list_of_nested_propagates_level():
    customer = {
        "name": "c1",
        "addresses": [
            {"city": "Berlin", "geo": "52.5,13.4"},
            {"city": "Paris", "geo": "48.8,2.3"},
        ],
    }
    public = CustomerSchema().dump(customer, access=AccessLevel.PUBLIC)
    assert public == {
        "name": "c1",
        "addresses": [{"city": "Berlin"}, {"city": "Paris"}],
    }
    internal = CustomerSchema().dump(customer, access=AccessLevel.INTERNAL)
    assert internal["addresses"][0]["geo"] == "52.5,13.4"


def test_self_referential_nested_is_filtered():
    customer = {
        "name": "boss",
        "manager": {"name": "cto", "addresses": []},
        "addresses": [],
    }
    public = CustomerSchema().dump(customer, access=AccessLevel.PUBLIC)
    assert public["manager"] == {"name": "cto"}


def test_output_access_inherits_and_extends():
    class BaseSchema(AccessLevelSchema, Schema):
        name = fields.String()
        output_access = {"base_flag": AccessLevel.PUBLIC}

    class ChildSchema(BaseSchema):
        title = fields.String()
        output_access = {**BaseSchema.output_access, "child_flag": AccessLevel.INTERNAL}

        @post_dump
        def add_flags(self, data, **kwargs):
            data["base_flag"] = 1
            data["child_flag"] = 2
            return data

    payload = {"name": "n", "title": "t"}
    child_flag_value = 2
    public = ChildSchema().dump(payload, access=AccessLevel.PUBLIC)
    assert public == {"name": "n", "title": "t", "base_flag": 1}
    internal = ChildSchema().dump(payload, access=AccessLevel.INTERNAL)
    assert internal["child_flag"] == child_flag_value
