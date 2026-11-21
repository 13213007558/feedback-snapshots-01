from graphql import (
    GraphQLArgument,
    GraphQLDefaultInput,
    GraphQLField,
    GraphQLObjectType,
    GraphQLScalarType,
    GraphQLSchema,
    GraphQLString,
    graphql_sync,
    parse_const_value,
)


def make_schema_with_counter(calls):
    """Schema with a custom scalar that counts its coercion invocations."""

    def coerce_input_value(value):
        calls.append(value)
        return f"coerced:{value}"

    def coerce_input_literal(node):
        calls.append(node.value)
        return f"coerced:{node.value}"

    counter = GraphQLScalarType(
        "Counter",
        coerce_input_value=coerce_input_value,
        coerce_input_literal=coerce_input_literal,
    )

    def resolve_echo(_obj, _info, **args):
        return ", ".join(f"{name}={value}" for name, value in sorted(args.items()))

    return GraphQLSchema(
        query=GraphQLObjectType(
            "Query",
            {
                "echo": GraphQLField(
                    GraphQLString,
                    args={
                        "var": GraphQLArgument(counter),
                        "lit": GraphQLArgument(counter),
                        "dflt": GraphQLArgument(
                            counter, default=GraphQLDefaultInput("default")
                        ),
                    },
                    resolve=resolve_echo,
                )
            },
        )
    )


def preview_permission_rule(leaf_type):
    """Preview entries may coerce registered built-in types, but not Counter."""
    return leaf_type.name != "Counter"


def describe_coercion_permission_rule():
    def preview_does_not_invoke_denied_scalar_in_variables():
        calls = []
        schema = make_schema_with_counter(calls)
        result = graphql_sync(
            schema,
            "query ($var: Counter) { echo(var: $var) }",
            variable_values={"var": "variable"},
            permission_rule=preview_permission_rule,
        )
        assert calls == []
        assert result.data is None
        assert [error.message for error in result.errors] == [
            "Variable '$var' has invalid value:"
            " Coercion of type 'Counter' is not permitted."
        ]

    def preview_does_not_invoke_denied_scalar_in_literals():
        calls = []
        schema = make_schema_with_counter(calls)
        result = graphql_sync(
            schema,
            '{ echo(lit: "literal") }',
            permission_rule=preview_permission_rule,
        )
        assert calls == []
        assert result.data is None
        assert [error.message for error in result.errors] == [
            "Coercion of type 'Counter' is not permitted."
        ]

    def preview_does_not_invoke_denied_scalar_in_default_values():
        calls = []
        schema = make_schema_with_counter(calls)
        result = graphql_sync(
            schema,
            "{ echo }",
            permission_rule=preview_permission_rule,
        )
        assert calls == []
        assert result.data == {"echo": None}
        assert [error.message for error in result.errors] == [
            "Argument 'dflt' has invalid default value:"
            " Coercion of type 'Counter' is not permitted."
        ]

    def preview_does_not_invoke_denied_scalar_in_variable_default_values():
        calls = []
        schema = make_schema_with_counter(calls)
        result = graphql_sync(
            schema,
            'query ($var: Counter = "var default") { echo(var: $var) }',
            permission_rule=preview_permission_rule,
        )
        assert calls == []
        assert result.data is None
        assert [error.message for error in result.errors] == [
            "Coercion of type 'Counter' is not permitted."
        ]

    def formal_calls_process_variables_literals_and_default_values():
        calls = []
        schema = make_schema_with_counter(calls)
        result = graphql_sync(
            schema,
            'query ($var: Counter) { echo(var: $var, lit: "literal") }',
            variable_values={"var": "variable"},
        )
        assert result.errors is None
        assert result.data == {
            "echo": "dflt=coerced:default, lit=coerced:literal, var=coerced:variable"
        }
        # All three values have been processed (schema and request validation
        # may coerce them additional times).
        assert set(calls) == {"variable", "literal", "default"}

    def same_schema_serves_preview_and_formal_calls():
        calls = []
        schema = make_schema_with_counter(calls)
        query = 'query ($var: Counter) { echo(var: $var, lit: "literal") }'

        preview = graphql_sync(
            schema,
            query,
            variable_values={"var": "variable"},
            permission_rule=preview_permission_rule,
        )
        assert calls == []
        assert preview.errors

        formal = graphql_sync(schema, query, variable_values={"var": "variable"})
        assert formal.errors is None
        assert formal.data == {
            "echo": "dflt=coerced:default, lit=coerced:literal, var=coerced:variable"
        }
        assert set(calls) == {"variable", "literal", "default"}

        # Memoized coerced defaults are not reused for preview calls.
        call_count = len(calls)
        preview = graphql_sync(
            schema,
            query,
            variable_values={"var": "variable"},
            permission_rule=preview_permission_rule,
        )
        assert len(calls) == call_count
        assert preview.errors

    def permitting_rule_invokes_the_scalar():
        calls = []
        schema = make_schema_with_counter(calls)
        result = graphql_sync(
            schema,
            'query ($var: Counter) { echo(var: $var, lit: "literal") }',
            variable_values={"var": "variable"},
            permission_rule=lambda _leaf_type: True,
        )
        assert result.errors is None
        assert result.data == {
            "echo": "dflt=coerced:default, lit=coerced:literal, var=coerced:variable"
        }
        assert set(calls) == {"variable", "literal", "default"}
