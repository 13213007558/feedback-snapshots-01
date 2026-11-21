import pytest

from graphql import (
    AllowListFieldAuthorizer,
    ExecutionResult,
    FieldAuthorizer,
    RuleBasedFieldAuthorizer,
    build_schema,
    graphql_sync,
    parse,
)
from graphql.execution import execute, subscribe
from graphql.pyutils import is_awaitable
from graphql.type import assert_object_type

pytestmark = pytest.mark.anyio


async def await_value(value):
    """Await a maybe-awaitable value, matching the execution entry-point return."""
    if is_awaitable(value):
        return await value
    return value


def build_test_schema():
    schema = build_schema(
        """
        type User {
          id: ID!
          ssn: String
          nickname: String
        }

        type Query {
          viewer: User
          denied: String
        }
        """
    )
    calls = []

    def tracked(name):
        def resolver(source, _info, **_args):
            calls.append(name)
            return source[name]

        return resolver

    for type_name in ("Query", "User"):
        object_type = assert_object_type(schema.get_type(type_name))
        for field_name, field in object_type.fields.items():
            field.resolve = tracked(field_name)
    root_value = {
        "viewer": {"id": "1", "ssn": "123-45-6789", "nickname": "Ada"},
        "denied": "secret",
    }
    return schema, root_value, calls


def describe_field_authorizer_interface():
    def is_a_protocol_implemented_by_the_concrete_authorizers():
        allow_list = AllowListFieldAuthorizer([("Query", "viewer")])
        rule_based = RuleBasedFieldAuthorizer({"Query": True})
        assert isinstance(allow_list, FieldAuthorizer)
        assert isinstance(rule_based, FieldAuthorizer)

    def custom_authorizer_only_needs_authorize_field():
        class DenyAll:
            def authorize_field(self, _info):
                return False

        assert isinstance(DenyAll(), FieldAuthorizer)


def describe_allow_list_field_authorizer():
    def allows_listed_fields_and_omits_the_rest():
        schema, root_value, calls = build_test_schema()
        authorizer = AllowListFieldAuthorizer(
            [("Query", "viewer"), ("User", "id"), ("User", "nickname")]
        )
        result = graphql_sync(
            schema,
            "{ viewer { id nickname ssn __typename } denied }",
            root_value=root_value,
            field_authorizer=authorizer,
        )
        assert result == (
            {"viewer": {"id": "1", "nickname": "Ada", "__typename": "User"}},
            None,
        )
        # The resolvers of denied fields never run.
        assert sorted(calls) == ["id", "nickname", "viewer"]

    def accepts_dot_separated_strings():
        authorizer = AllowListFieldAuthorizer(["Query.viewer", "User.id"])
        assert authorizer.allowed_fields == {("Query", "viewer"), ("User", "id")}

    def rejects_malformed_entries():
        with pytest.raises(ValueError, match="dot-separated strings"):
            AllowListFieldAuthorizer(["User"])
        with pytest.raises(ValueError, match="dot-separated strings"):
            malformed_tuple: tuple[object, ...] = ("User", "id", "extra")
            AllowListFieldAuthorizer([malformed_tuple])  # type: ignore[list-item]

    def denies_everything_not_listed_by_default():
        schema, root_value, calls = build_test_schema()
        result = graphql_sync(
            schema,
            "{ viewer { id } denied }",
            root_value=root_value,
            field_authorizer=AllowListFieldAuthorizer([]),
        )
        assert result == ({}, None)
        assert calls == []

    def can_default_to_allowing_unlisted_fields():
        schema, root_value, _calls = build_test_schema()
        authorizer = AllowListFieldAuthorizer([("User", "id")], default_decision=True)
        result = graphql_sync(
            schema,
            "{ viewer { id ssn } denied }",
            root_value=root_value,
            field_authorizer=authorizer,
        )
        assert result == (
            {"viewer": {"id": "1", "ssn": "123-45-6789"}, "denied": "secret"},
            None,
        )


def describe_rule_based_field_authorizer():
    def evaluates_callable_rules_per_field():
        schema, root_value, calls = build_test_schema()
        authorizer = RuleBasedFieldAuthorizer(
            {"Query": True, "User": lambda field_name, _type: field_name != "ssn"}
        )
        result = graphql_sync(
            schema,
            "{ viewer { id ssn nickname } denied }",
            root_value=root_value,
            field_authorizer=authorizer,
        )
        assert result == (
            {"viewer": {"id": "1", "nickname": "Ada"}, "denied": "secret"},
            None,
        )
        assert "ssn" not in calls

    def supports_boolean_type_rules():
        schema, root_value, calls = build_test_schema()
        authorizer = RuleBasedFieldAuthorizer({"Query": True, "User": False})
        result = graphql_sync(
            schema,
            "{ viewer { id ssn } denied }",
            root_value=root_value,
            field_authorizer=authorizer,
        )
        # The whole User object is still resolved, but none of its fields run.
        assert result == ({"viewer": {}, "denied": "secret"}, None)
        assert calls == ["viewer", "denied"]

    def falls_back_to_the_default_decision_for_unmapped_types():
        schema, root_value, calls = build_test_schema()
        authorizer = RuleBasedFieldAuthorizer(
            {"User": lambda field_name, _type: field_name == "id"},
            default_decision=True,
        )
        result = graphql_sync(
            schema,
            "{ viewer { id ssn } denied }",
            root_value=root_value,
            field_authorizer=authorizer,
        )
        assert result == (
            {"viewer": {"id": "1"}, "denied": "secret"},
            None,
        )
        assert "ssn" not in calls

    def callable_rule_can_abstain_with_undefined():
        from graphql.pyutils import Undefined
        from graphql.pyutils.undefined import UndefinedType

        schema, root_value, _calls = build_test_schema()

        def abstain(_field_name: str, _type: object) -> UndefinedType:
            return Undefined

        authorizer = RuleBasedFieldAuthorizer(
            {"User": abstain},
            default_decision=True,
        )
        result = graphql_sync(
            schema,
            "{ viewer { id } }",
            root_value=root_value,
            field_authorizer=authorizer,
        )
        assert result == ({"viewer": {"id": "1"}}, None)


def describe_runtime_context_and_aliases():
    def decides_from_the_authenticated_context():
        schema, root_value, _calls = build_test_schema()

        class ContextAuthorizer(RuleBasedFieldAuthorizer):
            def authorize_field(self, info):
                if info.field_name == "ssn":
                    return info.context["role"] == "admin"
                return True

        query = "{ viewer { id ssn } }"
        user_result = graphql_sync(
            schema,
            query,
            root_value=root_value,
            context_value={"role": "user"},
            field_authorizer=ContextAuthorizer({}),
        )
        assert user_result == ({"viewer": {"id": "1"}}, None)

        admin_result = graphql_sync(
            schema,
            query,
            root_value=root_value,
            context_value={"role": "admin"},
            field_authorizer=ContextAuthorizer({}),
        )
        assert admin_result == (
            {"viewer": {"id": "1", "ssn": "123-45-6789"}},
            None,
        )

    def uses_the_schema_field_name_not_the_response_alias():
        schema, root_value, calls = build_test_schema()
        authorizer = AllowListFieldAuthorizer([("Query", "viewer"), ("User", "id")])
        result = graphql_sync(
            schema,
            "{ viewer { key: id hidden: ssn } }",
            root_value=root_value,
            field_authorizer=authorizer,
        )
        assert result == ({"viewer": {"key": "1"}}, None)
        assert calls == ["viewer", "id"]

    def keeps_the_standard_null_rules_for_allowed_fields():
        schema = build_schema(
            """
            type Query {
              nullable: String
              nonNull: String!
            }
            """
        )

        def resolver(_source, _info, **_args):
            return None

        query_type = assert_object_type(schema.get_type("Query"))
        query_type.fields["nullable"].resolve = resolver
        query_type.fields["nonNull"].resolve = resolver
        authorizer = AllowListFieldAuthorizer(
            [("Query", "nullable"), ("Query", "nonNull")]
        )
        result = graphql_sync(
            schema,
            "{ nullable nonNull }",
            field_authorizer=authorizer,
        )
        # Allowed fields behave exactly as without an authorizer: the nullable
        # field becomes null while the non-null error nulls the whole response.
        assert result.data is None
        assert result.errors and len(result.errors) == 1


def describe_async_field_authorizer():
    async def test_async_decision_omits_denied_fields_without_resolvers():
        schema, root_value, calls = build_test_schema()

        class AsyncAuthorizer:
            async def authorize_field(self, info):
                return info.field_name in ("viewer", "id", "nickname")

        result = await await_value(
            execute(
                schema,
                parse("{ viewer { id nickname ssn } denied }"),
                root_value=root_value,
                field_authorizer=AsyncAuthorizer(),
            )
        )
        assert result == (
            {"viewer": {"id": "1", "nickname": "Ada"}},
            None,
        )
        assert sorted(calls) == ["id", "nickname", "viewer"]

    async def test_async_decision_works_inside_lists():
        schema = build_schema(
            """
            type Item {
              name: String
              hidden: String
            }

            type Query {
              items: [Item]
            }
            """
        )
        calls = []

        def tracked(name):
            def resolver(source, _info, **_args):
                calls.append((name, source["id"]))
                return source[name]

            return resolver

        for field_name, field in assert_object_type(
            schema.get_type("Item")
        ).fields.items():
            field.resolve = tracked(field_name)
        assert_object_type(schema.get_type("Query")).fields["items"].resolve = (
            lambda source, _info: source["items"]
        )

        class ListAuthorizer:
            async def authorize_field(self, info):
                return info.field_name in ("items", "name")

        result = await await_value(
            execute(
                schema,
                parse("{ items { name hidden } }"),
                root_value={
                    "items": [
                        {"id": 1, "name": "a", "hidden": "x"},
                        {"id": 2, "name": "b", "hidden": "y"},
                    ]
                },
                field_authorizer=ListAuthorizer(),
            )
        )
        assert result == (
            {"items": [{"name": "a"}, {"name": "b"}]},
            None,
        )
        assert calls == [("name", 1), ("name", 2)]

    async def test_authorizer_error_follows_null_rules():
        schema, root_value, _calls = build_test_schema()

        class FailingAuthorizer:
            async def authorize_field(self, info):
                if info.field_name == "ssn":
                    raise RuntimeError("authorization backend down")
                return True

        result = await await_value(
            execute(
                schema,
                parse("{ viewer { id ssn } }"),
                root_value=root_value,
                field_authorizer=FailingAuthorizer(),
            )
        )
        assert result.data == {"viewer": {"id": "1", "ssn": None}}
        assert result.errors and "authorization backend down" in (
            result.errors[0].message
        )


def describe_subscription_authorization():
    def _subscription_schema():
        schema = build_schema(
            """
            type Query {
              dummy: String
            }

            type Subscription {
              allowed: String
              denied: String
            }
            """
        )
        calls = []

        def make_subscribe(name):
            async def subscribe(_root, _info):
                calls.append(name)
                yield {name: "value"}

            return subscribe

        for field_name, field in assert_object_type(
            schema.subscription_type
        ).fields.items():
            field.subscribe = make_subscribe(field_name)
        return schema, calls

    async def rejects_a_subscription_to_a_denied_field():
        schema, calls = _subscription_schema()
        authorizer = AllowListFieldAuthorizer([("Subscription", "allowed")])
        result = subscribe(
            schema,
            parse("subscription { denied }"),
            field_authorizer=authorizer,
        )
        if is_awaitable(result):
            result = await result
        assert isinstance(result, ExecutionResult)
        assert result.errors and "Not authorized" in result.errors[0].message
        assert calls == []

    async def allows_a_subscription_to_an_allowed_field():
        from inspect import isasyncgen

        schema, calls = _subscription_schema()
        authorizer = AllowListFieldAuthorizer([("Subscription", "allowed")])
        stream = subscribe(
            schema,
            parse("subscription { allowed }"),
            field_authorizer=authorizer,
        )
        if is_awaitable(stream):
            stream = await stream
        assert isasyncgen(stream)
        event = await anext(stream)
        assert event == ({"allowed": "value"}, None)
        assert calls == ["allowed"]
        await stream.aclose()

    async def rejects_when_an_async_authorizer_denies_the_field():
        from inspect import isasyncgen

        schema, calls = _subscription_schema()

        class AsyncSubscriptionAuthorizer:
            async def authorize_field(self, info):
                return info.field_name == "allowed"

        denied = subscribe(
            schema,
            parse("subscription { denied }"),
            field_authorizer=AsyncSubscriptionAuthorizer(),
        )
        if is_awaitable(denied):
            denied = await denied
        assert isinstance(denied, ExecutionResult)
        assert denied.errors and "Not authorized" in denied.errors[0].message
        assert calls == []

        allowed = subscribe(
            schema,
            parse("subscription { allowed }"),
            field_authorizer=AsyncSubscriptionAuthorizer(),
        )
        if is_awaitable(allowed):
            allowed = await allowed
        assert isasyncgen(allowed)
        event = await anext(allowed)
        assert event == ({"allowed": "value"}, None)
        assert calls == ["allowed"]
        await allowed.aclose()
