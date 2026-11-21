"""Tests for gateway document parse and validation caching."""

from __future__ import annotations

import asyncio

import pytest

from graphql import build_schema, graphql_sync, parse
from graphql.gateway import (
    AllowListPermissionPolicy,
    GatewayDocumentCache,
    PermissionPolicy,
    authorization_middleware,
    get_authorization_fingerprint,
    get_document_fingerprint,
    get_schema_fingerprint,
)

from .harness import (
    DOCUMENT,
    POLICY_V1,
    POLICY_V2,
    SCHEMA_V1,
    build_calls,
    make_schema_v1,
    make_schema_v2,
    root_value,
)


def describe_schema_fingerprint():
    def is_stable_for_equivalent_schemas():
        first = build_schema("type Query { greeting: String }")
        second = build_schema("type Query { greeting: String }")
        assert get_schema_fingerprint(first) == get_schema_fingerprint(second)
        assert len(get_schema_fingerprint(first)) == 64

    def changes_when_a_field_type_changes():
        first = build_schema("type Query { greeting: String }")
        second = build_schema("type Query { greeting: Int }")
        assert get_schema_fingerprint(first) != get_schema_fingerprint(second)

    def changes_when_an_applied_directive_changes():
        first = build_schema(
            """
            directive @requiresScope(scope: String!) on FIELD_DEFINITION
            type Query { email: String }
            """
        )
        second = build_schema(
            """
            directive @requiresScope(scope: String!) on FIELD_DEFINITION
            type Query { email: String @requiresScope(scope: "user:email") }
            """
        )
        assert get_schema_fingerprint(first) != get_schema_fingerprint(second)

    def changes_when_policy_metadata_is_attached():
        first = build_schema("type Query { email: String }")
        second = build_schema("type Query { email: String }")
        second.query_type.fields["email"].extensions = {"scope": "user:email"}
        assert get_authorization_fingerprint(first) != (
            get_authorization_fingerprint(second)
        )

    def ignores_plain_additions_without_policy_metadata():
        first = build_schema("type Query { greeting: String }")
        second = build_schema("type Query { greeting: String health: String }")
        assert get_authorization_fingerprint(first) == (
            get_authorization_fingerprint(second)
        )

    def ignores_resolver_functions():
        first = build_schema("type Query { greeting: String }")
        second = build_schema("type Query { greeting: String }")
        first.query_type.fields["greeting"].resolve = lambda *_args: "hello"
        assert get_schema_fingerprint(first) == get_schema_fingerprint(second)


def describe_document_fingerprint():
    def ignores_comments_and_whitespace():
        assert get_document_fingerprint(parse("{ greeting }")) == (
            get_document_fingerprint(parse("# comment\n{ greeting }"))
        )

    def distinguishes_different_aliases():
        assert get_document_fingerprint(parse("{ greeting }")) != (
            get_document_fingerprint(parse("{ hello: greeting }"))
        )


def describe_gateway_document_cache():
    def reuses_the_parsed_document_across_schemas():
        cache = GatewayDocumentCache()
        schema_v1 = make_schema_v1(build_calls())
        schema_v2 = make_schema_v2(build_calls())

        first = cache.prepare(schema_v1, DOCUMENT)
        second = cache.prepare(schema_v2, DOCUMENT)

        assert first.parse_cache_hit is False
        assert second.parse_cache_hit is True
        assert first.document is second.document
        assert first.document_fingerprint == second.document_fingerprint

    def keeps_parse_entries_apart_when_parse_options_differ():
        cache = GatewayDocumentCache()
        first = cache.parse(DOCUMENT)
        second = cache.parse(DOCUMENT, no_location=True)
        third = cache.parse(DOCUMENT)

        assert first.cache_hit is False
        assert second.cache_hit is False
        assert second.document.definitions[0].loc is None
        assert third.cache_hit is True
        assert third.document is first.document

    def revalidates_when_the_schema_fingerprint_changes():
        cache = GatewayDocumentCache()
        schema_v1 = make_schema_v1(build_calls())
        schema_v2 = make_schema_v2(build_calls())

        first = cache.prepare(schema_v1, DOCUMENT)
        second = cache.prepare(schema_v2, DOCUMENT)

        assert first.validation_cache_hit is False
        assert second.validation_cache_hit is False
        assert first.schema_fingerprint != second.schema_fingerprint
        assert first.is_valid and second.is_valid

    def revalidates_when_the_policy_fingerprint_changes():
        cache = GatewayDocumentCache()
        schema = make_schema_v1(build_calls())

        first = cache.prepare(schema, DOCUMENT, policy=POLICY_V1)
        second = cache.prepare(schema, DOCUMENT, policy=POLICY_V2)

        assert first.validation_cache_hit is False
        assert second.validation_cache_hit is False
        assert first.policy_fingerprint == POLICY_V1.fingerprint
        assert second.policy_fingerprint == POLICY_V2.fingerprint

    def reuses_validation_for_the_same_schema_and_policy():
        cache = GatewayDocumentCache()
        schema = make_schema_v1(build_calls())

        first = cache.prepare(schema, DOCUMENT, policy=POLICY_V1)
        second = cache.prepare(schema, DOCUMENT, policy=POLICY_V1)

        assert first.validation_cache_hit is False
        assert second.validation_cache_hit is True
        assert second.schema_fingerprint == first.schema_fingerprint
        assert second.policy_fingerprint == first.policy_fingerprint

    def only_reuses_accepted_results_after_a_safe_schema_change():
        cache = GatewayDocumentCache()
        schema_v1 = make_schema_v1(build_calls())
        schema_v1_extra = build_schema(
            """
            directive @requiresScope(scope: String!) on FIELD_DEFINITION
            type User {
              id: ID!
              name: String
              email: String
            }
            type Query {
              viewer: User
              health: String
            }
            """
        )

        first = cache.prepare(schema_v1, DOCUMENT, policy=POLICY_V1)
        second = cache.prepare(schema_v1_extra, DOCUMENT, policy=POLICY_V1)

        assert first.is_valid
        assert second.validation_cache_hit is True
        assert second.validation_reused is True

    def does_not_reuse_a_result_for_a_narrowing_change():
        cache = GatewayDocumentCache()
        wide = build_schema("type Query { greeting: String }")
        narrow = build_schema("type Query { greeting: Int }")

        first = cache.prepare(wide, "{ greeting }", policy=POLICY_V1)
        second = cache.prepare(narrow, "{ greeting }", policy=POLICY_V1)

        assert first.is_valid
        assert second.validation_cache_hit is False
        assert second.validation_reused is False

    def does_not_treat_a_weakened_field_as_a_safe_reuse():
        cache = GatewayDocumentCache()
        strict = build_schema("type Query { greeting: String! }")
        loose = build_schema("type Query { greeting: String }")

        first = cache.prepare(strict, "{ greeting }", policy=POLICY_V1)
        second = cache.prepare(loose, "{ greeting }", policy=POLICY_V1)

        assert first.is_valid
        assert second.validation_cache_hit is False

    def does_not_reuse_an_invalid_result_for_a_fixed_schema():
        cache = GatewayDocumentCache()
        broken = build_schema("type Query { viewer: String }")
        fixed = build_schema("type Query { viewer: String, email: String }")

        first = cache.prepare(broken, "{ viewer email }", policy=POLICY_V1)
        second = cache.prepare(fixed, "{ viewer email }", policy=POLICY_V1)

        assert first.is_valid is False
        assert second.validation_reused is False

    def requires_a_policy_fingerprint():
        class AnonymousPolicy:
            def authorize_field(self, _info):
                return True

        cache = GatewayDocumentCache()
        schema = make_schema_v1(build_calls())
        with pytest.raises(TypeError, match="non-empty string fingerprint"):
            cache.prepare(schema, DOCUMENT, policy=AnonymousPolicy())

    def rejects_mismatched_explicit_policy_fingerprint():
        cache = GatewayDocumentCache()
        schema = make_schema_v1(build_calls())
        with pytest.raises(ValueError, match="does not match"):
            cache.prepare(
                schema,
                DOCUMENT,
                policy=POLICY_V1,
                policy_fingerprint=POLICY_V2.fingerprint,
            )

    def tracks_cache_statistics():
        cache = GatewayDocumentCache()
        schema = make_schema_v1(build_calls())
        cache.prepare(schema, DOCUMENT, policy=POLICY_V1)
        cache.prepare(schema, DOCUMENT, policy=POLICY_V1)

        stats = cache.stats
        assert stats.parse_misses == 1
        assert stats.parse_hits == 1
        assert stats.validation_misses == 1
        assert stats.validation_hits == 1

    def evicts_old_entries_at_the_capacity_limit():
        cache = GatewayDocumentCache(max_entries=1)
        schema = make_schema_v1(build_calls())
        cache.prepare(schema, "{ viewer { id } }", policy=POLICY_V1)
        cache.prepare(schema, "{ viewer { name } }", policy=POLICY_V1)
        third = cache.prepare(schema, "{ viewer { id } }", policy=POLICY_V1)
        assert third.parse_cache_hit is False


def describe_authorization_middleware():
    def omits_denied_fields_and_never_runs_their_resolvers():
        calls = build_calls()
        schema = make_schema_v1(calls)
        result = graphql_sync(
            schema,
            DOCUMENT,
            root_value=root_value(),
            middleware=[authorization_middleware(POLICY_V2)],
        )

        assert result.data == {
            "viewer": {"id": "user-1", "name": "Ada", "email": None},
        }
        assert result.errors is not None
        assert result.errors[0].extensions == {
            "code": "FORBIDDEN",
            "field": "User.email",
        }
        assert "email" not in calls

    def returns_false_only_for_the_denied_field():
        class DenyEmail:
            fingerprint = "deny-email-v1"

            def authorize_field(self, info):
                return info.field_name != "email"

        calls = build_calls()
        schema = make_schema_v1(calls)
        result = graphql_sync(
            schema,
            DOCUMENT,
            root_value=root_value(),
            middleware=[authorization_middleware(DenyEmail())],
        )
        assert result.data == {
            "viewer": {"id": "user-1", "name": "Ada", "email": None},
        }
        assert calls == ["viewer", "id", "name"]

    def supports_async_policy_decisions():
        class AsyncDenyEmail:
            fingerprint = "async-deny-email-v1"

            async def authorize_field(self, info):
                return info.field_name != "email"

        calls = build_calls()
        schema = make_schema_v1(calls)
        from graphql import execute

        result = execute(
            schema,
            parse(DOCUMENT),
            root_value=root_value(),
            middleware=[authorization_middleware(AsyncDenyEmail())],
        )
        result = asyncio.run(_await_result(result))
        assert result.data == {
            "viewer": {"id": "user-1", "name": "Ada", "email": None},
        }
        assert calls == ["viewer", "id", "name"]

    def uses_the_schema_field_name_not_the_response_alias():
        schema = build_schema(
            "type User { name: String email: String } type Query { viewer: User }"
        )
        policy = AllowListPermissionPolicy([("Query", "viewer"), ("User", "name")])
        result = graphql_sync(
            schema,
            "{ viewer { contact: email name } }",
            root_value={"viewer": {"name": "Ada", "email": "ada@example.com"}},
            middleware=[authorization_middleware(policy)],
        )
        assert result.data == {"viewer": {"contact": None, "name": "Ada"}}
        assert result.errors[0].extensions == {
            "code": "FORBIDDEN",
            "field": "User.email",
        }

    def always_allows_meta_fields():
        class DenyAll:
            fingerprint = "deny-all-v1"

            def authorize_field(self, _info):
                return False

        schema = build_schema("type Query { viewer: String }")
        result = graphql_sync(
            schema,
            "{ __typename }",
            middleware=[authorization_middleware(DenyAll())],
        )
        assert result.data == {"__typename": "Query"}


async def _await_result(result):
    if hasattr(result, "__await__"):
        return await result
    return result


def describe_gateway_cache_execution():
    def executes_the_document_with_the_current_schema_before_the_upgrade():
        calls = build_calls()
        schema = make_schema_v1(calls)
        cache = GatewayDocumentCache()

        result = cache.execute_sync(
            schema,
            DOCUMENT,
            policy=POLICY_V1,
            root_value=root_value(),
        )

        assert result.data == {
            "viewer": {
                "id": "user-1",
                "name": "Ada",
                "email": "ada@example.com",
            },
        }
        assert not result.errors
        assert calls == ["viewer", "id", "name", "email"]
        assert result.extensions == {
            "gateway": {
                "schema_fingerprint": get_schema_fingerprint(schema),
                "policy_fingerprint": POLICY_V1.fingerprint,
                "document_fingerprint": get_document_fingerprint(parse(DOCUMENT)),
                "parse_cache_hit": False,
                "validation_cache_hit": False,
                "validation_reused": False,
            },
        }

    def revalidates_after_a_policy_sensitive_schema_upgrade():
        calls_v1 = build_calls()
        calls_v2 = build_calls()
        schema_v1 = make_schema_v1(calls_v1)
        schema_v2 = make_schema_v2(calls_v2)
        cache = GatewayDocumentCache()

        first = cache.execute_sync(
            schema_v1,
            DOCUMENT,
            policy=POLICY_V1,
            root_value=root_value(),
        )
        second = cache.execute_sync(
            schema_v2,
            DOCUMENT,
            policy=POLICY_V1,
            root_value=root_value(),
        )

        assert first.data == second.data
        assert first.extensions["gateway"]["validation_cache_hit"] is False
        assert second.extensions["gateway"]["parse_cache_hit"] is True
        assert second.extensions["gateway"]["validation_cache_hit"] is False
        assert (
            second.extensions["gateway"]["schema_fingerprint"]
            != (first.extensions["gateway"]["schema_fingerprint"])
        )

    def reuses_validation_after_a_plain_additive_schema_upgrade():
        calls_v1 = build_calls()
        calls_v2 = build_calls()
        schema_v1 = make_schema_v1(calls_v1)
        schema_v2 = build_schema(
            SCHEMA_V1 + "extend type Query { health: String }",
            assume_valid=True,
        )

        cache = GatewayDocumentCache()
        first = cache.execute_sync(
            schema_v1,
            DOCUMENT,
            policy=POLICY_V1,
            root_value=root_value(),
        )
        second = cache.execute_sync(
            schema_v2,
            DOCUMENT,
            policy=POLICY_V1,
            root_value=root_value(),
        )

        assert first.data == second.data
        assert second.extensions["gateway"]["validation_cache_hit"] is True
        assert second.extensions["gateway"]["validation_reused"] is True
        assert calls_v2 == []

    def denies_a_tightened_field_even_when_validation_was_cached():
        calls = build_calls()
        schema = make_schema_v1(calls)
        cache = GatewayDocumentCache()

        allowed = cache.execute_sync(
            schema,
            DOCUMENT,
            policy=POLICY_V1,
            root_value=root_value(),
        )
        assert allowed.data["viewer"]["email"] == "ada@example.com"
        assert allowed.extensions["gateway"]["validation_cache_hit"] is False
        calls.clear()
        denied = cache.execute_sync(
            schema,
            DOCUMENT,
            policy=POLICY_V2,
            root_value=root_value(),
        )
        assert denied.data["viewer"]["email"] is None
        assert [error.message for error in denied.errors] == [
            "Not authorized to access field 'User.email'.",
        ]
        assert denied.extensions["gateway"]["validation_cache_hit"] is False
        assert "email" not in calls

    def denies_a_tightened_field_after_the_schema_upgrade():
        calls_v2 = build_calls()
        schema_v2 = make_schema_v2(calls_v2)
        cache = GatewayDocumentCache()

        result = cache.execute_sync(
            schema_v2,
            DOCUMENT,
            policy=POLICY_V2,
            root_value=root_value(),
        )

        assert result.data == {
            "viewer": {"id": "user-1", "name": "Ada", "email": None},
        }
        assert [error.message for error in result.errors] == [
            "Not authorized to access field 'User.email'.",
        ]
        assert "email" not in calls_v2

    def denies_a_tightened_field_for_an_async_execution():
        async def run() -> None:
            calls = build_calls()
            schema = make_schema_v2(calls)
            cache = GatewayDocumentCache()
            await cache.execute(
                schema,
                DOCUMENT,
                policy=POLICY_V1,
                root_value=root_value(),
            )
            calls.clear()
            result = await cache.execute(
                schema,
                DOCUMENT,
                policy=POLICY_V2,
                root_value=root_value(),
            )
            assert result.data == {
                "viewer": {"id": "user-1", "name": "Ada", "email": None},
            }
            assert "email" not in calls

        asyncio.run(run())

    def does_not_cache_an_execution_result():
        calls = build_calls()
        schema = make_schema_v1(calls)
        cache = GatewayDocumentCache()

        cache.execute_sync(schema, DOCUMENT, policy=POLICY_V1, root_value=root_value())
        cache.execute_sync(schema, DOCUMENT, policy=POLICY_V1, root_value=root_value())

        assert calls == [
            "viewer",
            "id",
            "name",
            "email",
            "viewer",
            "id",
            "name",
            "email",
        ]

    def returns_validation_errors_without_executing():
        calls = build_calls()
        schema = build_schema("type Query { viewer: String }")
        cache = GatewayDocumentCache()

        result = cache.execute_sync(
            schema,
            DOCUMENT,
            policy=POLICY_V1,
            root_value={"viewer": "not-an-object"},
        )

        assert result.data is None
        assert result.errors
        assert calls == []


def describe_permission_policy_protocol():
    def accepts_a_policy_with_only_the_required_members():
        class DenyAll:
            fingerprint = "deny-all-v1"

            def authorize_field(self, _info):
                return False

        assert isinstance(DenyAll(), PermissionPolicy)

    def allow_list_policy_keeps_meta_fields_visible():
        policy = AllowListPermissionPolicy([])
        info = type(
            "Info",
            (),
            {
                "field_name": "__typename",
                "parent_type": type("Type", (), {"name": "User"})(),
            },
        )()
        assert policy.authorize_field(info) is True


def describe_prepared_operation_metadata():
    def exposes_the_bindings_of_a_validated_document():
        cache = GatewayDocumentCache()
        schema = make_schema_v1(build_calls())
        prepared = cache.prepare(schema, DOCUMENT, policy=POLICY_V1)

        assert prepared.is_valid
        assert prepared.schema_fingerprint == get_schema_fingerprint(schema)
        assert prepared.policy_fingerprint == POLICY_V1.fingerprint
        assert prepared.cache_info == {
            "schema_fingerprint": prepared.schema_fingerprint,
            "policy_fingerprint": POLICY_V1.fingerprint,
            "document_fingerprint": prepared.document_fingerprint,
            "parse_cache_hit": False,
            "validation_cache_hit": False,
            "validation_reused": False,
        }

    def accepted_validation_is_not_an_execution_permit():
        cache = GatewayDocumentCache()
        schema = make_schema_v1(build_calls())
        prepared = cache.prepare(schema, DOCUMENT, policy=POLICY_V1)

        # Even though ``prepared`` was validated under the old permissions, the
        # gateway execution still applies the current policy to each field.
        result = cache.execute_sync(
            schema,
            DOCUMENT,
            policy=POLICY_V2,
            root_value=root_value(),
        )
        assert prepared.is_valid
        assert result.data["viewer"]["email"] is None
        assert result.errors[0].path == ["viewer", "email"]
