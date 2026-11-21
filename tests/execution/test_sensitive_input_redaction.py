"""Public validation errors for sensitive (e.g. one-time credential) input.

These tests pin the security contract for input fields and arguments marked
``sensitive``:

* validation errors still identify *which* field is wrong, via the message and
  the error path/location;
* the supplied input value never appears in the public ``message`` or
  ``extensions``, neither for the failing field nor for sibling fields;
* this holds for nested variables, inline literals, operation defaults and
  errors raised by custom scalars.
"""

from __future__ import annotations

import json

from graphql import (
    GraphQLError,
    GraphQLArgument,
    GraphQLField,
    GraphQLInputField,
    GraphQLInputObjectType,
    GraphQLInt,
    GraphQLList,
    GraphQLNonNull,
    GraphQLObjectType,
    GraphQLScalarType,
    GraphQLSchema,
    GraphQLString,
    graphql_sync,
    parse,
    validate,
)

# A stand-in for a one-time credential. It must never show up in an error.
SECRET = "one-time-token-123456"


def _token_coerce(value):
    if not isinstance(value, str) or not value.startswith("tok_"):
        # A scalar whose exception message embeds the offending value.
        raise ValueError(f"malformed token {value!r}")
    return value


def _token_coerce_graphql_error(value):
    if not isinstance(value, str) or not value.startswith("tok_"):
        # Scalars may raise GraphQLError with extensions carrying input data.
        raise GraphQLError(
            f"malformed token {value!r}", extensions={"received": value}
        )
    return value


TokenScalar = GraphQLScalarType("Token", parse_value=_token_coerce)
TokenScalarWithExtensions = GraphQLScalarType(
    "TokenExt", parse_value=_token_coerce_graphql_error
)


def _build_schema(scalar=TokenScalar, argument_sensitive=True, field_sensitive=True):
    auth_input = GraphQLInputObjectType(
        "AuthInput",
        {
            "token": GraphQLInputField(
                GraphQLNonNull(scalar), sensitive=field_sensitive
            ),
            "label": GraphQLInputField(GraphQLString),
        },
    )
    schema = GraphQLSchema(
        query=GraphQLObjectType("Query", {"ok": GraphQLField(GraphQLString)}),
        mutation=GraphQLObjectType(
            "Mutation",
            {
                "redeem": GraphQLField(
                    GraphQLString,
                    args={
                        "auth": GraphQLArgument(
                            GraphQLNonNull(auth_input),
                            sensitive=argument_sensitive,
                        )
                    },
                    resolve=lambda *_args: "redeemed",
                )
            },
        ),
    )
    return schema, auth_input


def _serialized_errors(result):
    return [error.formatted for error in (result.errors or [])]


def _assert_no_secret(payload):
    blob = json.dumps(payload)
    assert SECRET not in blob
    assert "malformed token" not in blob


def describe_sensitive_input_redaction():
    def describe_nested_variables():
        def custom_scalar_error_keeps_path_but_redacts_value():
            schema, _ = _build_schema()
            result = graphql_sync(
                schema,
                "mutation ($a: AuthInput!) { redeem(auth: $a) }",
                variable_values={"a": {"token": SECRET, "label": "phone"}},
            )
            errors = _serialized_errors(result)
            _assert_no_secret(errors)
            assert errors == [
                {
                    "message": "Variable '$a' has invalid value at .token:"
                    " Expected value of type 'Token' to be valid.",
                    "locations": [{"line": 1, "column": 11}],
                }
            ]

        def graphql_error_extensions_are_not_copied_out():
            schema, _ = _build_schema(scalar=TokenScalarWithExtensions)
            result = graphql_sync(
                schema,
                "mutation ($a: AuthInput!) { redeem(auth: $a) }",
                variable_values={"a": {"token": SECRET}},
            )
            errors = _serialized_errors(result)
            _assert_no_secret(errors)
            assert "extensions" not in errors[0]
            assert errors[0]["message"].endswith(
                "Expected value of type 'TokenExt' to be valid."
            )

        def missing_required_field_redacts_sibling_credential():
            schema, _ = _build_schema()
            # The secret rides in a sibling field while the required token is
            # absent; the whole object must be redacted.
            result = graphql_sync(
                schema,
                "mutation ($a: AuthInput!) { redeem(auth: $a) }",
                variable_values={"a": {"label": SECRET}},
            )
            errors = _serialized_errors(result)
            _assert_no_secret(errors)
            assert errors[0]["message"] == (
                "Variable '$a' has invalid value: Expected value of type"
                " 'AuthInput' to include required field 'token',"
                " found: [redacted]."
            )

        def unknown_field_redacts_the_whole_sensitive_object():
            schema, _ = _build_schema()
            result = graphql_sync(
                schema,
                "mutation ($a: AuthInput!) { redeem(auth: $a) }",
                variable_values={
                    "a": {"token": "tok_valid", "label": SECRET, "bogus": 1}
                },
            )
            errors = _serialized_errors(result)
            _assert_no_secret(errors)
            assert errors[0]["message"].endswith(
                "not to include unknown field 'bogus', found: [redacted]."
            )

    def describe_inline_literals():
        def custom_scalar_error_keeps_location_but_redacts_value():
            schema, _ = _build_schema()
            result = graphql_sync(
                schema,
                f'mutation {{ redeem(auth: {{ token: "{SECRET}",'
                ' label: "phone" }) }',
            )
            errors = _serialized_errors(result)
            _assert_no_secret(errors)
            assert errors == [
                {
                    "message": "Expected value of type 'Token' to be valid.",
                    "locations": [{"line": 1, "column": 34}],
                }
            ]

        def static_validation_redacts_literal_value():
            schema, _ = _build_schema()
            errors = [
                error.formatted
                for error in validate(
                    schema,
                    parse(
                        f'mutation {{ redeem(auth: {{ token: "{SECRET}"'
                        " }) }"
                    ),
                )
            ]
            _assert_no_secret(errors)
            assert errors[0]["message"] == (
                "Expected value of type 'Token' to be valid."
            )

    def describe_default_values():
        def invalid_operation_default_is_redacted():
            schema, _ = _build_schema()
            result = graphql_sync(
                schema,
                "mutation ($a: AuthInput! = { token: "
                f'"{SECRET}"' " }) { redeem(auth: $a) }",
                variable_values={},
            )
            errors = _serialized_errors(result)
            _assert_no_secret(errors)
            assert errors[0]["message"] == (
                "Expected value of type 'Token' to be valid."
            )

    def describe_field_level_redaction():
        def non_sensitive_siblings_stay_visible_without_argument_marker():
            # Only the nested field is marked sensitive; the argument itself is
            # not. A leaf error on the sensitive field redacts just that field's
            # value and keeps the precise path, without touching other data.
            schema, _ = _build_schema(argument_sensitive=False)
            result = graphql_sync(
                schema,
                "mutation ($a: AuthInput!) { redeem(auth: $a) }",
                variable_values={"a": {"token": SECRET, "label": "keep-me"}},
            )
            errors = _serialized_errors(result)
            blob = json.dumps(errors)
            _assert_no_secret(errors)
            assert "keep-me" not in blob  # leaf error only renders the bad value
            assert errors[0]["message"] == (
                "Variable '$a' has invalid value at .token:"
                " Expected value of type 'Token' to be valid."
            )

        def object_level_error_redacts_only_sensitive_sibling():
            # Unknown field on a nested object whose sibling is sensitive: the
            # sensitive sibling is redacted while non-sensitive data and the
            # unknown field stay visible.
            nested_input = GraphQLInputObjectType(
                "NestedAuth",
                {
                    "token": GraphQLInputField(
                        GraphQLNonNull(TokenScalar), sensitive=True
                    ),
                    "label": GraphQLInputField(GraphQLString),
                },
            )
            wrapper_input = GraphQLInputObjectType(
                "WrapperInput", {"nested": GraphQLInputField(nested_input)}
            )
            schema = GraphQLSchema(
                query=GraphQLObjectType(
                    "Query", {"ok": GraphQLField(GraphQLString)}
                ),
                mutation=GraphQLObjectType(
                    "Mutation",
                    {
                        "redeem": GraphQLField(
                            GraphQLString,
                            args={
                                "input": GraphQLArgument(
                                    GraphQLNonNull(wrapper_input)
                                )
                            },
                            resolve=lambda *_args: "ok",
                        )
                    },
                ),
            )
            result = graphql_sync(
                schema,
                "mutation ($i: WrapperInput!) { redeem(input: $i) }",
                variable_values={
                    "i": {
                        "nested": {
                            "token": "tok_valid",
                            "label": "keep-me",
                            "bogus": 1,
                        }
                    }
                },
            )
            errors = _serialized_errors(result)
            blob = json.dumps(errors)
            assert "keep-me" in blob
            assert "bogus" in blob
            assert "tok_valid" not in blob
            assert "[redacted]" in blob

        def redaction_descends_through_nested_lists():
            nested_input = GraphQLInputObjectType(
                "NestedAuth",
                {
                    "token": GraphQLInputField(
                        GraphQLNonNull(TokenScalar), sensitive=True
                    ),
                    "label": GraphQLInputField(GraphQLString),
                },
            )
            batch_input = GraphQLInputObjectType(
                "BatchInput",
                {"items": GraphQLInputField(GraphQLList(nested_input))},
            )
            schema = GraphQLSchema(
                query=GraphQLObjectType(
                    "Query", {"ok": GraphQLField(GraphQLString)}
                ),
                mutation=GraphQLObjectType(
                    "Mutation",
                    {
                        "redeemBatch": GraphQLField(
                            GraphQLString,
                            args={
                                "batch": GraphQLArgument(
                                    GraphQLNonNull(batch_input)
                                )
                            },
                            resolve=lambda *_args: "ok",
                        )
                    },
                ),
            )
            result = graphql_sync(
                schema,
                "mutation ($b: BatchInput!) { redeemBatch(batch: $b) }",
                variable_values={
                    "b": {"items": [{"token": SECRET, "label": "visible"}]}
                },
            )
            errors = _serialized_errors(result)
            _assert_no_secret(errors)
            # The path still points at the exact failing nested field.
            assert errors[0]["message"] == (
                "Variable '$b' has invalid value at .items[0].token:"
                " Expected value of type 'Token' to be valid."
            )

    def describe_non_sensitive_inputs():
        def ordinary_errors_keep_their_verbose_messages():
            plain_input = GraphQLInputObjectType(
                "PlainInput",
                {"stars": GraphQLInputField(GraphQLNonNull(GraphQLInt))},
            )
            schema = GraphQLSchema(
                query=GraphQLObjectType(
                    "Query", {"ok": GraphQLField(GraphQLString)}
                ),
                mutation=GraphQLObjectType(
                    "Mutation",
                    {
                        "set": GraphQLField(
                            GraphQLString,
                            args={"p": GraphQLArgument(GraphQLNonNull(plain_input))},
                            resolve=lambda *_args: "ok",
                        )
                    },
                ),
            )
            result = graphql_sync(
                schema,
                "mutation ($p: PlainInput!) { set(p: $p) }",
                variable_values={"p": {"stars": "bad"}},
            )
            assert result.errors[0].message == (
                "Variable '$p' has invalid value at .stars: Int cannot"
                " represent non-integer value: 'bad'"
            )

