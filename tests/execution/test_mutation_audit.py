"""Tests for mutation root field auditing and authorization."""

from __future__ import annotations

from asyncio import sleep

import pytest
from graphql import (
    ExecutionResult,
    GraphQLArgument,
    GraphQLField,
    GraphQLInt,
    GraphQLNonNull,
    GraphQLObjectType,
    GraphQLSchema,
    MutationAuditEntry,
    MutationAuditStatus,
    MutationAuthorizationError,
    execute,
    execute_sync,
    graphql,
    parse,
    validate,
)
from graphql.pyutils import is_awaitable

pytestmark = pytest.mark.anyio


class RecordingAuditor:
    """Auditor collecting mutation audit entries in order."""

    def __init__(self) -> None:
        self.entries: list[MutationAuditEntry] = []

    def __call__(self, entry: MutationAuditEntry) -> None:
        self.entries.append(entry)


class Ledger:
    """In-memory backend mutated by the schema's mutation fields."""

    def __init__(self, asynchronous: bool = False) -> None:
        self.asynchronous = asynchronous
        self.balance = 0
        self.calls: list[str] = []

    def _record(self, operation: str) -> None:
        self.calls.append(operation)

    def deposit(self, amount: int) -> int:
        self._record("deposit")
        self.balance += amount
        return self.balance

    def withdraw(self, amount: int) -> int:
        self._record("withdraw")
        self.balance -= amount
        return self.balance

    async def deposit_async(self, amount: int) -> int:
        await sleep(0)
        return self.deposit(amount)

    async def withdraw_async(self, amount: int) -> int:
        await sleep(0)
        return self.withdraw(amount)


def build_schema(ledger: Ledger) -> GraphQLSchema:
    deposit_resolver = (
        (lambda _r, _i, amount: ledger.deposit_async(amount))
        if ledger.asynchronous
        else (lambda _r, _i, amount: ledger.deposit(amount))
    )
    withdraw_resolver = (
        (lambda _r, _i, amount: ledger.withdraw_async(amount))
        if ledger.asynchronous
        else (lambda _r, _i, amount: ledger.withdraw(amount))
    )
    return GraphQLSchema(
        query=GraphQLObjectType(
            "Query",
            {"balance": GraphQLField(GraphQLInt, resolve=lambda *_: ledger.balance)},
        ),
        mutation=GraphQLObjectType(
            "Mutation",
            {
                "deposit": GraphQLField(
                    GraphQLInt,
                    args={"amount": GraphQLArgument(GraphQLNonNull(GraphQLInt))},
                    resolve=deposit_resolver,
                ),
                "withdraw": GraphQLField(
                    GraphQLInt,
                    args={"amount": GraphQLArgument(GraphQLNonNull(GraphQLInt))},
                    resolve=withdraw_resolver,
                ),
            },
        ),
    )


async def await_if_needed(result):
    return await result if is_awaitable(result) else result


def describe_mutation_audit():
    async def records_authorized_start_and_success_for_serial_root_fields():
        ledger = Ledger(asynchronous=True)
        schema = build_schema(ledger)
        auditor = RecordingAuditor()

        result = await await_if_needed(
            execute(
                schema,
                parse(
                    """
                    mutation WhateverNameTheClientPicked {
                      first: deposit(amount: 10)
                      second: withdraw(amount: 4)
                    }
                    """
                ),
                mutation_auditor=auditor,
            )
        )

        assert isinstance(result, ExecutionResult)
        assert result.errors is None
        assert result.data == {"first": 10, "second": 6}

        # The real schema field names are audited, not the response aliases or
        # the customized client operation name.
        assert auditor.entries == [
            MutationAuditEntry("deposit", MutationAuditStatus.AUTHORIZED),
            MutationAuditEntry("deposit", MutationAuditStatus.SUCCESS),
            MutationAuditEntry("withdraw", MutationAuditStatus.AUTHORIZED),
            MutationAuditEntry("withdraw", MutationAuditStatus.SUCCESS),
        ]
        # The root fields were actually executed serially in document order.
        assert ledger.calls == ["deposit", "withdraw"]
        # Audit entries only carry the field name and the status, never
        # mutation arguments or variable values.
        assert all(
            entry._fields == ("field_name", "status") for entry in auditor.entries
        )

    async def records_denial_and_skips_the_rejected_resolver():
        ledger = Ledger(asynchronous=True)
        schema = build_schema(ledger)
        auditor = RecordingAuditor()

        def authorizer(info) -> bool:
            return info.field_name != "withdraw"

        result = await await_if_needed(
            execute(
                schema,
                parse(
                    """
                    mutation Banking($sum: Int!) {
                      deposit(amount: 5)
                      withdraw(amount: $sum)
                    }
                    """
                ),
                variable_values={"sum": 3},
                mutation_authorizer=authorizer,
                mutation_auditor=auditor,
            )
        )

        assert isinstance(result, ExecutionResult)
        assert result.data == {"deposit": 5, "withdraw": None}
        assert result.errors is not None
        assert len(result.errors) == 1
        error = result.errors[0]
        assert error.message == MutationAuthorizationError("withdraw").message
        assert error.path == ["withdraw"]
        assert error.extensions == {
            "code": "FORBIDDEN",
            "field": "withdraw",
        }

        assert auditor.entries == [
            MutationAuditEntry("deposit", MutationAuditStatus.AUTHORIZED),
            MutationAuditEntry("deposit", MutationAuditStatus.SUCCESS),
            MutationAuditEntry("withdraw", MutationAuditStatus.DENIED),
        ]
        # The rejected resolver never ran; the authorized one did.
        assert ledger.calls == ["deposit"]

    async def does_not_audit_operations_that_are_only_parsed_or_validated():
        ledger = Ledger()
        schema = build_schema(ledger)
        auditor = RecordingAuditor()

        source = """
            mutation Banking {
              deposit(amount: 10)
              withdraw(amount: 4)
            }
        """
        document = parse(source)

        # Parsing and validating the document must not create audit entries.
        assert validate(schema, document) == []
        assert auditor.entries == []

        # An execution that fails before any resolver runs (here: the named
        # operation does not exist) must not audit a mutation either.
        failed = await await_if_needed(
            execute(
                schema,
                document,
                operation_name="MissingOperation",
                mutation_auditor=auditor,
            )
        )
        assert failed.errors is not None
        assert auditor.entries == []

        # Query operations are never audited, even when they are executed.
        query_result = await await_if_needed(
            execute(
                schema,
                parse("{ balance }"),
                mutation_auditor=auditor,
            )
        )
        assert query_result.errors is None
        assert auditor.entries == []

    async def audits_through_the_full_graphql_request_pipeline():
        ledger = Ledger(asynchronous=True)
        schema = build_schema(ledger)
        auditor = RecordingAuditor()

        result = await graphql(
            schema,
            """
            mutation Banking($amount: Int!) {
              deposit(amount: $amount)
            }
            """,
            variable_values={"amount": 7},
            mutation_auditor=auditor,
        )

        assert result.errors is None
        assert result.data == {"deposit": 7}
        assert auditor.entries == [
            MutationAuditEntry("deposit", MutationAuditStatus.AUTHORIZED),
            MutationAuditEntry("deposit", MutationAuditStatus.SUCCESS),
        ]

        # A document rejected during validation never reaches the executor and
        # therefore produces no audit records.
        rejected = await graphql(
            schema,
            "mutation Banking { deposit(amount: 10) { balance } }",
            mutation_auditor=auditor,
        )
        assert rejected.errors is not None
        assert len(auditor.entries) == 2

    def supports_synchronous_mutation_execution():
        ledger = Ledger()
        schema = build_schema(ledger)
        auditor = RecordingAuditor()

        result = execute_sync(
            schema,
            parse("mutation Banking { deposit(amount: 2) }"),
            mutation_auditor=auditor,
        )

        assert result == ({"deposit": 2}, None)
        assert ledger.calls == ["deposit"]
        assert auditor.entries == [
            MutationAuditEntry("deposit", MutationAuditStatus.AUTHORIZED),
            MutationAuditEntry("deposit", MutationAuditStatus.SUCCESS),
        ]

    async def keeps_working_without_an_auditor_when_only_authorizing():
        ledger = Ledger(asynchronous=True)
        schema = build_schema(ledger)

        def authorizer(info) -> bool:
            return info.field_name == "deposit"

        result = await await_if_needed(
            execute(
                schema,
                parse("mutation Banking { withdraw(amount: 1) deposit(amount: 1) }"),
                mutation_authorizer=authorizer,
            )
        )

        assert result.data == {"withdraw": None, "deposit": 1}
        assert result.errors is not None
        assert result.errors[0].path == ["withdraw"]
        assert ledger.calls == ["deposit"]

    def does_not_audit_subscription_operations():
        # The audit hook only applies to mutation operations; a per-event
        # executor created for a subscription must therefore stay silent even
        # when the auditor is configured.
        from graphql import Executor, build_schema

        subscription_schema = build_schema(
            """
            type Query { ping: String }
            type Subscription { counter: Int }
            """
        )
        executor = Executor.build(
            subscription_schema,
            parse("subscription { counter }"),
            mutation_auditor=RecordingAuditor(),
            mutation_authorizer=lambda _info: False,
        )
        assert isinstance(executor, Executor)
        assert executor.operation.operation.value == "subscription"
        subscription_type = subscription_schema.subscription_type
        assert subscription_type is not None

        result = executor.execute_root_grouped_field_set(
            subscription_type,
            None,
            {},
            False,
            None,
        )
        assert result == {}
