"""Tests for pymongo.write_proxy using an in-memory test service."""

from __future__ import annotations

import unittest
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

from pymongo.errors import ConnectionFailure, PyMongoError
from pymongo.write_proxy import (
    TRANSIENT_TRANSACTION_ERROR,
    NamespaceReapprovalRequired,
    WriteProxy,
)


class FakeService:
    """In-memory test service standing in for a MongoDB deployment."""

    def __init__(self) -> None:
        self.documents: dict[tuple[str, str], list[dict[str, Any]]] = {}
        # Errors raised by upcoming commits, one per commit, to simulate
        # transient transport failures.
        self.commit_errors: list[Exception] = []


class FakeClient:
    def __init__(self, service: FakeService) -> None:
        self._service = service

    def start_session(self) -> FakeSession:
        return FakeSession(self._service)

    def get_database(self, name: str) -> FakeDatabase:
        return FakeDatabase(self._service, name)

    def __getitem__(self, name: str) -> FakeDatabase:
        return self.get_database(name)


class FakeDatabase:
    def __init__(self, service: FakeService, name: str) -> None:
        self._service = service
        self._name = name

    def get_collection(self, name: str) -> FakeCollection:
        return FakeCollection(self._service, self._name, name)

    def __getitem__(self, name: str) -> FakeCollection:
        return self.get_collection(name)


class FakeCollection:
    def __init__(self, service: FakeService, database: str, name: str) -> None:
        self._service = service
        self._key = (database, name)

    def insert_one(self, document: dict[str, Any], session: Any = None) -> Any:
        self._write(session, lambda docs: docs.append(dict(document)))
        return SimpleNamespace(acknowledged=True)

    def update_one(
        self, filter: dict[str, Any], update: dict[str, Any], session: Any = None
    ) -> Any:
        def apply(docs: list[dict[str, Any]]) -> None:
            for doc in docs:
                if all(doc.get(key) == value for key, value in filter.items()):
                    doc.update(update.get("$set", {}))
                    return

        self._write(session, apply)
        return SimpleNamespace(acknowledged=True)

    def delete_one(self, filter: dict[str, Any], session: Any = None) -> Any:
        def apply(docs: list[dict[str, Any]]) -> None:
            for index, doc in enumerate(docs):
                if all(doc.get(key) == value for key, value in filter.items()):
                    del docs[index]
                    return

        self._write(session, apply)
        return SimpleNamespace(acknowledged=True)

    def _write(self, session: Any, operation: Callable[[list[dict[str, Any]]], None]) -> None:
        if session is not None and session.in_transaction:
            session._stage(self._key, operation)
        else:
            operation(self._service.documents.setdefault(self._key, []))


class FakeSession:
    """Session with ``with_transaction`` retry semantics like PyMongo's."""

    def __init__(self, service: FakeService) -> None:
        self._service = service
        self.in_transaction = False
        self._staged: list[tuple[tuple[str, str], Callable[[list[dict[str, Any]]], None]]] = []
        self.ended = False

    def __enter__(self) -> FakeSession:
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.end_session()

    def end_session(self) -> None:
        self.ended = True

    def _stage(
        self, key: tuple[str, str], operation: Callable[[list[dict[str, Any]]], None]
    ) -> None:
        self._staged.append((key, operation))

    def start_transaction(self) -> None:
        self.in_transaction = True
        self._staged = []

    def commit_transaction(self) -> None:
        try:
            if self._service.commit_errors:
                raise self._service.commit_errors.pop(0)
            for key, operation in self._staged:
                operation(self._service.documents.setdefault(key, []))
        finally:
            self.in_transaction = False
            self._staged = []

    def abort_transaction(self) -> None:
        self.in_transaction = False
        self._staged = []

    def with_transaction(self, callback: Callable[..., Any], **kwargs: Any) -> Any:
        while True:
            self.start_transaction()
            try:
                result = callback(self)
            except Exception as exc:
                self.abort_transaction()
                if isinstance(exc, PyMongoError) and exc.has_error_label(
                    TRANSIENT_TRANSACTION_ERROR
                ):
                    continue
                raise
            try:
                self.commit_transaction()
            except Exception as exc:
                if isinstance(exc, PyMongoError) and exc.has_error_label(
                    TRANSIENT_TRANSACTION_ERROR
                ):
                    continue
                raise
            return result


class TestWriteProxy(unittest.TestCase):
    def setUp(self) -> None:
        self.service = FakeService()
        self.proxy = WriteProxy(FakeClient(self.service))

    def test_retry_after_transient_error_cannot_leave_approved_scope(self):
        # The first attempt is approved for sales.orders and fails with a
        # transient transport error. Routing rules change before the retry,
        # so the next callback invocation picks another database.
        routed_databases = iter(["sales", "archive"])
        approval = self.proxy.approve_transaction(("sales", "orders"))

        def callback(txn):
            database = next(routed_databases)
            txn.client[database]["orders"].insert_one({"attempt": txn.attempt})

        self.service.commit_errors.append(
            ConnectionFailure(
                "transient transport failure", error_labels={TRANSIENT_TRANSACTION_ERROR}
            )
        )

        with self.assertRaises(NamespaceReapprovalRequired) as ctx:
            self.proxy.run_transaction(approval, callback)

        # The caller sees a re-approval decision, not a transport failure.
        exc = ctx.exception
        self.assertEqual((exc.database, exc.collection), ("archive", "orders"))
        self.assertEqual(exc.attempt, 2)
        self.assertEqual(exc.approved, frozenset({("sales", "orders")}))
        self.assertFalse(exc.has_error_label(TRANSIENT_TRANSACTION_ERROR))

        # Transaction and normal namespaces are recorded separately.
        self.assertEqual(
            [(use.namespace, use.attempt, use.accepted) for use in self.proxy.transaction_log],
            [(("sales", "orders"), 1, True), (("archive", "orders"), 2, False)],
        )
        self.assertEqual(
            [use.namespace for use in self.proxy.reapproval_requests],
            [("archive", "orders")],
        )
        self.assertEqual(self.proxy.transaction_namespaces, {("sales", "orders")})
        self.assertEqual(self.proxy.normal_log, [])
        # Both attempts were aborted; nothing reached the test service.
        self.assertEqual(self.service.documents, {})

    def test_transient_error_retries_within_approved_scope(self):
        approval = self.proxy.approve_transaction(("sales", "orders"))

        def callback(txn):
            txn.client["sales"]["orders"].insert_one({"attempt": txn.attempt})
            return "committed"

        self.service.commit_errors.append(
            ConnectionFailure(
                "transient transport failure", error_labels={TRANSIENT_TRANSACTION_ERROR}
            )
        )

        self.assertEqual(self.proxy.run_transaction(approval, callback), "committed")

        # A pure transport failure retries within the approved scope: the
        # log shows repeated attempts on the same approved namespace and no
        # re-approval request.
        self.assertEqual(
            [(use.namespace, use.attempt, use.accepted) for use in self.proxy.transaction_log],
            [(("sales", "orders"), 1, True), (("sales", "orders"), 2, True)],
        )
        self.assertEqual(self.proxy.reapproval_requests, [])
        self.assertEqual(self.proxy.transaction_namespaces, {("sales", "orders")})
        self.assertEqual(self.service.documents, {("sales", "orders"): [{"attempt": 2}]})

    def test_normal_session_commands_are_recorded_separately(self):
        session = self.proxy.start_session()
        self.proxy["sales"]["orders"].insert_one({"sku": "abc123"}, session=session)
        self.proxy["analytics"]["events"].insert_one({"kind": "pageview"})
        session.end_session()

        # Normal sessions remain usable and unrestricted; their namespaces
        # are recorded apart from transaction namespaces.
        self.assertEqual(
            self.proxy.normal_namespaces, {("sales", "orders"), ("analytics", "events")}
        )
        self.assertEqual(self.proxy.transaction_log, [])
        self.assertEqual(self.proxy.reapproval_requests, [])
        self.assertEqual(
            self.service.documents,
            {
                ("sales", "orders"): [{"sku": "abc123"}],
                ("analytics", "events"): [{"kind": "pageview"}],
            },
        )

    def test_out_of_scope_rejected_on_first_attempt(self):
        approval = self.proxy.approve_transaction(("sales", "orders"))

        def callback(txn):
            txn.client["archive"]["orders"].delete_one({})

        with self.assertRaises(NamespaceReapprovalRequired) as ctx:
            self.proxy.run_transaction(approval, callback)
        self.assertEqual(ctx.exception.attempt, 1)
        self.assertEqual(
            [use.namespace for use in self.proxy.reapproval_requests],
            [("archive", "orders")],
        )

    def test_approval_requires_explicit_namespaces(self):
        with self.assertRaises(ValueError):
            self.proxy.approve_transaction()
        with self.assertRaises(ValueError):
            self.proxy.approve_transaction(("", "orders"))


if __name__ == "__main__":
    unittest.main()
