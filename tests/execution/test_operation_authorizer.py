from __future__ import annotations

import pytest

from graphql import (
    GraphQLError,
    execute,
    execute_sync,
    graphql,
    graphql_sync,
    parse,
    subscribe,
)
from graphql.execution import Executor
from graphql.language import OperationDefinitionNode, OperationType
from graphql.type import (
    GraphQLArgument,
    GraphQLField,
    GraphQLObjectType,
    GraphQLScalarType,
    GraphQLSchema,
    GraphQLString,
)

pytestmark = pytest.mark.anyio

resolved_fields: list[str] = []
coerced_values: list[object] = []


@pytest.fixture(autouse=True)
def _reset_side_effects():
    resolved_fields.clear()
    coerced_values.clear()


def _recorded_scalar() -> GraphQLScalarType:
    def coerce_input_value(value: object) -> object:
        coerced_values.append(value)
        return value

    return GraphQLScalarType("Recorded", coerce_input_value=coerce_input_value)


def _make_schema() -> GraphQLSchema:
    recorded = _recorded_scalar()

    def resolve_greeting(_root: object, _info: object, name: object = None) -> str:
        resolved_fields.append("greeting")
        return f"Hello, {name}!"

    def resolve_set_greeting(
        _root: object, _info: object, name: object = None
    ) -> str:
        resolved_fields.append("setGreeting")
        return f"Set to {name}!"

    def resolve_event(_root: object, _info: object) -> str:
        resolved_fields.append("event")
        return "event payload"

    return GraphQLSchema(
        query=GraphQLObjectType(
            "Query",
            {
                "greeting": GraphQLField(
                    GraphQLString,
                    args={"name": GraphQLArgument(recorded)},
                    resolve=resolve_greeting,
                ),
            },
        ),
        mutation=GraphQLObjectType(
            "Mutation",
            {
                "setGreeting": GraphQLField(
                    GraphQLString,
                    args={"name": GraphQLArgument(recorded)},
                    resolve=resolve_set_greeting,
                ),
            },
        ),
        subscription=GraphQLObjectType(
            "Subscription",
            {"event": GraphQLField(GraphQLString, resolve=resolve_event)},
        ),
    )


schema = _make_schema()

document = parse(
    """
    query GetGreeting($name: Recorded) { greeting(name: $name) }
    mutation SetGreeting($name: Recorded) { setGreeting(name: $name) }
    """
)


def _deny_mutations(operation: OperationDefinitionNode) -> bool:
    return operation.operation is not OperationType.MUTATION


def describe_operation_authorizer():
    def allows_execution_when_no_authorizer_is_provided():
        result = execute_sync(
            schema,
            document,
            variable_values={"name": "Ada"},
            operation_name="SetGreeting",
        )
        assert result.errors is None
        assert result.data == {"setGreeting": "Set to Ada!"}
        assert resolved_fields == ["setGreeting"]
        assert coerced_values == ["Ada"]

    def authorizer_receives_the_operation_selected_by_the_client():
        seen: list[tuple[str | None, OperationType]] = []

        def authorizer(operation: OperationDefinitionNode) -> bool:
            seen.append(
                (operation.name and operation.name.value, operation.operation)
            )
            return True

        result = execute_sync(
            schema,
            document,
            variable_values={"name": "Ada"},
            operation_name="SetGreeting",
            operation_authorizer=authorizer,
        )
        assert result.errors is None
        assert seen == [("SetGreeting", OperationType.MUTATION)]
        assert resolved_fields == ["setGreeting"]

        seen.clear()
        resolved_fields.clear()

        result = execute_sync(
            schema,
            document,
            variable_values={"name": "Ada"},
            operation_name="GetGreeting",
            operation_authorizer=authorizer,
        )
        assert result.errors is None
        assert seen == [("GetGreeting", OperationType.QUERY)]
        assert resolved_fields == ["greeting"]

    def denies_operation_based_on_its_operation_type():
        result = execute_sync(
            schema,
            document,
            variable_values={"name": "Ada"},
            operation_name="SetGreeting",
            operation_authorizer=_deny_mutations,
        )
        assert result.data is None
        assert result.errors == [
            GraphQLError("Operation 'SetGreeting' is not authorized.")
        ]
        # no resolver ran and no variable was coerced
        assert resolved_fields == []
        assert coerced_values == []

        result = execute_sync(
            schema,
            document,
            variable_values={"name": "Ada"},
            operation_name="GetGreeting",
            operation_authorizer=_deny_mutations,
        )
        assert result.errors is None
        assert result.data == {"greeting": "Hello, Ada!"}
        assert resolved_fields == ["greeting"]
        assert coerced_values == ["Ada"]

    def denies_anonymous_operation_with_a_standard_message():
        result = execute_sync(
            schema,
            parse("{ greeting }"),
            operation_authorizer=lambda _operation: False,
        )
        assert result.data is None
        assert result.errors == [
            GraphQLError("Anonymous operation is not authorized.")
        ]
        assert resolved_fields == []

    def denies_operation_with_a_custom_message():
        result = execute_sync(
            schema,
            document,
            operation_name="SetGreeting",
            operation_authorizer=lambda _operation: "Mutations are closed.",
        )
        assert result.data is None
        assert result.errors == [GraphQLError("Mutations are closed.")]
        assert resolved_fields == []
        assert coerced_values == []

    def denies_operation_with_a_custom_error():
        error = GraphQLError("Not allowed.", extensions={"code": "FORBIDDEN"})
        result = execute_sync(
            schema,
            document,
            operation_name="SetGreeting",
            operation_authorizer=lambda _operation: error,
        )
        assert result.data is None
        assert result.errors == [error]
        assert result.errors[0].extensions == {"code": "FORBIDDEN"}
        assert resolved_fields == []
        assert coerced_values == []

    def check_runs_before_variable_coercion_reports_errors():
        # invalid variables would normally produce coercion errors, but the
        # authorization denial must take precedence
        result = execute_sync(
            schema,
            document,
            variable_values={"name": {}},
            operation_name="SetGreeting",
            operation_authorizer=_deny_mutations,
        )
        assert result.errors == [
            GraphQLError("Operation 'SetGreeting' is not authorized.")
        ]
        assert coerced_values == []

    def works_via_graphql_sync():
        result = graphql_sync(
            schema,
            "query GetGreeting { greeting }"
            " mutation SetGreeting { setGreeting }",
            operation_name="SetGreeting",
            operation_authorizer=_deny_mutations,
        )
        assert result.data is None
        assert result.errors == [
            GraphQLError("Operation 'SetGreeting' is not authorized.")
        ]
        assert resolved_fields == []

    async def works_via_graphql():
        result = await graphql(
            schema,
            "query GetGreeting { greeting }"
            " mutation SetGreeting { setGreeting }",
            operation_name="SetGreeting",
            operation_authorizer=_deny_mutations,
        )
        assert result.data is None
        assert result.errors == [
            GraphQLError("Operation 'SetGreeting' is not authorized.")
        ]
        assert resolved_fields == []

    def works_via_execute():
        result = execute(
            schema,
            document,
            operation_name="SetGreeting",
            operation_authorizer=_deny_mutations,
        )
        assert result.data is None
        assert result.errors == [
            GraphQLError("Operation 'SetGreeting' is not authorized.")
        ]
        assert resolved_fields == []

    def works_via_subscribe():
        subscription_document = parse(
            "subscription Watch { event } mutation SetGreeting { setGreeting }"
        )
        result = subscribe(
            schema,
            subscription_document,
            operation_name="SetGreeting",
            operation_authorizer=_deny_mutations,
        )
        assert result.data is None
        assert result.errors == [
            GraphQLError("Operation 'SetGreeting' is not authorized.")
        ]
        assert resolved_fields == []

    def works_via_executor_build():
        executor_or_errors = Executor.build(
            schema,
            document,
            operation_name="SetGreeting",
            operation_authorizer=_deny_mutations,
        )
        assert executor_or_errors == [
            GraphQLError("Operation 'SetGreeting' is not authorized.")
        ]
        assert coerced_values == []
