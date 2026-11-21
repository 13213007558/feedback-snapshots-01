from __future__ import annotations

import pytest

from graphql import (
    PUBLIC_EXTENSION,
    DefaultErrorCodes,
    DisclosureMode,
    ErrorDisclosurePolicy,
    ExecutionResult,
    GraphQLError,
    PublicGraphQLError,
    disclose_execution_result,
)

pytestmark = pytest.mark.anyio


def describe_public_error():
    def marks_itself_with_the_public_extension():
        error = PublicGraphQLError("Bad input", extensions={"code": "BAD_EMAIL"})
        assert error.extensions[PUBLIC_EXTENSION] is True

    def keeps_explicit_public_marker_value():
        error = PublicGraphQLError(
            "Bad input", extensions={PUBLIC_EXTENSION: "yes", "code": "X"}
        )
        assert error.extensions[PUBLIC_EXTENSION] == "yes"


def describe_strict_policy():
    def keeps_message_and_path_for_public_errors():
        policy = ErrorDisclosurePolicy()
        error = PublicGraphQLError(
            "Email is invalid.",
            path=["createUser", "email"],
            extensions={"code": "BAD_EMAIL", "field": "email"},
        )
        formatted = policy.disclose_error(error)
        assert formatted["message"] == "Email is invalid."
        assert formatted["path"] == ["createUser", "email"]
        # Only allowlisted extensions survive; the public marker is stripped.
        assert formatted["extensions"] == {
            "code": "BAD_EMAIL",
            "field": "email",
        }
        assert PUBLIC_EXTENSION not in formatted["extensions"]

    def masks_internal_errors_but_keeps_path():
        seen: list[GraphQLError] = []
        policy = ErrorDisclosurePolicy(on_internal_error=seen.append)
        original = RuntimeError("postgres://user:pw@db/internal timeout")
        error = GraphQLError(str(original), path=["sensor", "reading"], cause=original)

        formatted = policy.disclose_error(error)

        assert formatted == {
            "message": "Internal server error.",
            "path": ["sensor", "reading"],
            "extensions": {"code": DefaultErrorCodes.INTERNAL},
        }
        # No sensitive detail leaks into the public payload.
        assert "postgres" not in str(formatted)
        # The original exception stays available for internal handling.
        assert seen == [error]
        assert policy.original_error(error) is original

    def treats_plain_graphql_errors_as_internal():
        policy = ErrorDisclosurePolicy()
        error = GraphQLError("Some resolver detail", path=["field"])
        assert policy.is_public(error) is False
        formatted = policy.disclose_error(error)
        assert formatted["message"] == "Internal server error."

    def path_is_always_preserved_even_without_locations():
        policy = ErrorDisclosurePolicy(include_locations=False)
        error = GraphQLError("boom", path=["a", 0, "b"])
        formatted = policy.disclose_error(error)
        assert "locations" not in formatted
        assert formatted["path"] == ["a", 0, "b"]

    def strips_non_allowlisted_extensions_from_public_errors():
        policy = ErrorDisclosurePolicy(public_extension_keys=["code"])
        error = PublicGraphQLError(
            "nope",
            path=["f"],
            extensions={"code": "X", "secret": "leak", PUBLIC_EXTENSION: True},
        )
        formatted = policy.disclose_error(error)
        assert formatted["extensions"] == {"code": "X"}


def describe_modes():
    def trusted_mode_forwards_original_messages():
        policy = ErrorDisclosurePolicy(mode=DisclosureMode.TRUSTED)
        error = GraphQLError("internal detail", path=["f"])
        formatted = policy.disclose_error(error)
        assert formatted["message"] == "internal detail"

    def debug_mode_adds_a_correlation_id():
        ids = iter(["id-1", "id-2"])
        policy = ErrorDisclosurePolicy(
            mode=DisclosureMode.DEBUG, error_id_factory=lambda: next(ids)
        )
        error = GraphQLError("boom", path=["f"])
        formatted = policy.disclose_error(error)
        assert formatted["message"] == "Internal server error."
        assert formatted["extensions"] == {
            "code": DefaultErrorCodes.INTERNAL,
            "errorId": "id-1",
        }

    def debug_mode_requires_an_id_factory():
        policy = ErrorDisclosurePolicy(mode=DisclosureMode.DEBUG)
        with pytest.raises(ValueError):
            policy.disclose_error(GraphQLError("boom", path=["f"]))

    def debug_mode_still_masks_the_underlying_message():
        policy = ErrorDisclosurePolicy(
            mode=DisclosureMode.DEBUG, error_id_factory=lambda: "id"
        )
        error = GraphQLError("secret dsn", path=["f"])
        formatted = policy.disclose_error(error)
        assert "secret" not in formatted["message"]


def describe_result_formatting():
    def passes_data_through_and_sanitizes_errors():
        policy = ErrorDisclosurePolicy()
        result = ExecutionResult(
            data={"sensor": None},
            errors=[
                PublicGraphQLError("bad", path=["sensor", "label"]),
                GraphQLError("secret", path=["sensor", "reading"]),
            ],
        )
        formatted = policy.disclose_result(result)
        assert formatted["data"] == {"sensor": None}
        messages = [error["message"] for error in formatted["errors"]]
        assert messages == ["bad", "Internal server error."]

    def keeps_result_extensions_and_drops_empty_error_list():
        policy = ErrorDisclosurePolicy()
        result = ExecutionResult(data={"ok": True}, extensions={"cost": 1})
        formatted = policy.disclose_result(result)
        assert formatted == {"data": {"ok": True}, "extensions": {"cost": 1}}
        assert "errors" not in formatted

    def convenience_wrapper_uses_given_mode():
        result = ExecutionResult(errors=[GraphQLError("detail", path=["f"])])
        formatted = disclose_execution_result(result, mode=DisclosureMode.TRUSTED)
        assert formatted["errors"][0]["message"] == "detail"


def describe_subscription():
    async def sanitizes_each_event_independently():
        async def raw_events():
            yield ExecutionResult(
                data={"sensorEvent": None},
                errors=[GraphQLError("secret dsn", path=["sensorEvent", "reading"])],
            )
            yield ExecutionResult(data={"sensorEvent": {"id": "s2"}}, errors=None)

        policy = ErrorDisclosurePolicy()
        events = [
            event
            async for event in policy.disclose_subscription(raw_events())
        ]

        assert events[0]["errors"][0]["message"] == "Internal server error."
        assert events[0]["errors"][0]["path"] == ["sensorEvent", "reading"]
        assert events[1] == {"data": {"sensorEvent": {"id": "s2"}}}
