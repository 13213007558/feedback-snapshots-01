"""Tools for write proxies that pin restricted transactions to approved namespaces.

A write proxy approves a transaction for an explicit set of ``(database,
collection)`` namespaces *before* running it. When a transient error makes
PyMongo re-invoke the transaction callback (see
:meth:`~pymongo.synchronous.client_session.ClientSession.with_transaction`),
application routing rules may already have changed, so a naive retry can
silently target a different database or collection. This module pins the
approved scope at approval time: every attempt of a restricted transaction,
including retries, may only touch the originally approved namespaces, while
commands sent through normal sessions remain unrestricted.

Namespaces used by transaction commands and by normal commands are recorded
in separate logs, so callers can tell a *re-approval* (a retry tried to
leave the approved scope and was rejected) apart from a mere *transport
failure* (a transient error that re-ran the callback within the scope).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, TypeVar

from pymongo.errors import PyMongoError

__all__ = [
    "NamespaceReapprovalRequired",
    "NamespaceUse",
    "RestrictedTransaction",
    "TransactionApproval",
    "WriteProxy",
]

_T = TypeVar("_T")

#: Error label PyMongo attaches to transient transaction errors. Errors
#: carrying this label are transport-level failures that
#: ``with_transaction`` retries by re-invoking the callback.
TRANSIENT_TRANSACTION_ERROR = "TransientTransactionError"

#: Write commands intercepted by the proxy, mapped to the command name
#: recorded in the namespace logs.
_WRITE_COMMANDS = {
    "insert_one": "insert",
    "insert_many": "insert",
    "update_one": "update",
    "update_many": "update",
    "replace_one": "update",
    "delete_one": "delete",
    "delete_many": "delete",
    "find_one_and_delete": "findAndModify",
    "find_one_and_replace": "findAndModify",
    "find_one_and_update": "findAndModify",
    "bulk_write": "bulkWrite",
}


class NamespaceReapprovalRequired(PyMongoError):
    """A restricted transaction tried to leave its approved scope.

    Raised instead of executing the offending command. This error
    deliberately carries no ``TransientTransactionError`` label, so
    ``with_transaction`` aborts the transaction instead of retrying it,
    and callers can distinguish a required re-approval from a transient
    transport failure.

    .. versionadded:: 4.21
    """

    def __init__(
        self,
        database: str,
        collection: str,
        approved: Iterable[tuple[str, str]],
        attempt: int,
    ) -> None:
        self.database = database
        self.collection = collection
        self.approved = frozenset(approved)
        self.attempt = attempt
        super().__init__(
            "transaction attempt %d routed to namespace %s.%s outside the "
            "approved scope %s; re-approve the transaction for the new "
            "namespace before retrying" % (attempt, database, collection, sorted(self.approved))
        )


@dataclass(frozen=True)
class NamespaceUse:
    """One command namespace recorded by a :class:`WriteProxy`.

    .. versionadded:: 4.21
    """

    database: str
    collection: str
    command: str
    in_transaction: bool
    attempt: int
    accepted: bool

    @property
    def namespace(self) -> tuple[str, str]:
        """The ``(database, collection)`` pair this entry refers to."""
        return (self.database, self.collection)


class TransactionApproval:
    """An immutable approval for an explicit set of namespaces.

    The scope is frozen when the approval is created, so later changes to
    application routing rules cannot widen it.

    .. versionadded:: 4.21
    """

    def __init__(self, namespaces: Iterable[tuple[str, str]]) -> None:
        scope = frozenset(namespaces)
        if not scope:
            raise ValueError("a transaction approval requires at least one namespace")
        for database, collection in scope:
            if not database or not collection:
                raise ValueError(
                    "approved namespaces must be non-empty (database, collection) pairs"
                )
        self._namespaces = scope

    @property
    def namespaces(self) -> frozenset[tuple[str, str]]:
        """The approved ``(database, collection)`` pairs."""
        return self._namespaces

    def allows(self, database: str, collection: str) -> bool:
        """Return True if the namespace is within the approved scope."""
        return (database, collection) in self._namespaces

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({sorted(self._namespaces)!r})"


class WriteProxy:
    """Proxy that records command namespaces and pins restricted transactions.

    :param client: A client-like object, such as
        :class:`~pymongo.mongo_client.MongoClient` or a test double, that
        provides ``start_session()`` and database/collection access.

    .. versionadded:: 4.21
    """

    def __init__(self, client: Any) -> None:
        self._client = client
        self._transaction_log: list[NamespaceUse] = []
        self._normal_log: list[NamespaceUse] = []

    @property
    def client(self) -> Any:
        """The underlying client."""
        return self._client

    @property
    def transaction_log(self) -> list[NamespaceUse]:
        """Namespaces used by transaction commands, in execution order.

        Repeated entries with the same approved namespace and increasing
        :attr:`NamespaceUse.attempt` numbers indicate transient transport
        failures that were retried within the approved scope. Entries with
        ``accepted=False`` indicate a rejected re-approval attempt.
        """
        return list(self._transaction_log)

    @property
    def normal_log(self) -> list[NamespaceUse]:
        """Namespaces used by normal (non-transaction) commands, in order."""
        return list(self._normal_log)

    @property
    def transaction_namespaces(self) -> set[tuple[str, str]]:
        """Namespaces actually used by accepted transaction commands."""
        return {use.namespace for use in self._transaction_log if use.accepted}

    @property
    def normal_namespaces(self) -> set[tuple[str, str]]:
        """Namespaces used by normal (non-transaction) commands."""
        return {use.namespace for use in self._normal_log}

    @property
    def reapproval_requests(self) -> list[NamespaceUse]:
        """Transaction commands rejected for leaving the approved scope."""
        return [use for use in self._transaction_log if not use.accepted]

    def approve_transaction(self, *namespaces: tuple[str, str]) -> TransactionApproval:
        """Approve a transaction for explicit ``(database, collection)`` namespaces."""
        return TransactionApproval(namespaces)

    def start_session(self) -> Any:
        """Start a normal, unrestricted session on the underlying client."""
        return self._client.start_session()

    def get_database(self, name: str) -> _ProxyDatabase:
        """Get a database handle for normal (unrestricted) commands."""
        return _ProxyDatabase(self, name)

    def __getitem__(self, name: str) -> _ProxyDatabase:
        return self.get_database(name)

    def run_transaction(
        self,
        approval: TransactionApproval,
        callback: Callable[[RestrictedTransaction], _T],
        session: Any | None = None,
        **txn_options: Any,
    ) -> _T:
        """Run ``callback`` in a transaction restricted to ``approval``.

        The approved scope is pinned when the transaction is approved, not
        when each attempt runs. If a transient transport error makes
        PyMongo re-invoke the callback, later attempts are checked against
        the same approval even when the application's routing rules have
        changed in the meantime.

        :param approval: The :class:`TransactionApproval` pinning the scope.
        :param callback: A callable taking a :class:`RestrictedTransaction`.
            It may be invoked multiple times after transient errors.
        :param session: An optional existing session to run the
            transaction on. If omitted, a new session is started and ended
            automatically.
        :param txn_options: Additional keyword arguments forwarded to
            ``with_transaction``, such as ``read_concern`` or
            ``write_concern``.

        :raises NamespaceReapprovalRequired: if any attempt routes to a
            namespace outside ``approval``. This signals a re-approval
            decision, not a transport failure: it carries no
            ``TransientTransactionError`` label, so the transaction is
            aborted rather than retried.

        :return: The return value of ``callback``.
        """
        attempt = 0

        def _scoped_callback(real_session: Any) -> _T:
            nonlocal attempt
            attempt += 1
            return callback(RestrictedTransaction(self, approval, real_session, attempt))

        if session is not None:
            return session.with_transaction(_scoped_callback, **txn_options)
        with self._client.start_session() as new_session:
            return new_session.with_transaction(_scoped_callback, **txn_options)

    def _record(self, use: NamespaceUse) -> None:
        if use.in_transaction:
            self._transaction_log.append(use)
        else:
            self._normal_log.append(use)


class RestrictedTransaction:
    """A transaction handle restricted to a :class:`TransactionApproval`.

    Instances are handed to the callback passed to
    :meth:`WriteProxy.run_transaction`, once per attempt. Collection
    access through :attr:`client` only permits the approved namespaces and
    binds the underlying session automatically.

    .. versionadded:: 4.21
    """

    def __init__(
        self, proxy: WriteProxy, approval: TransactionApproval, session: Any, attempt: int
    ) -> None:
        self._proxy = proxy
        self._approval = approval
        self._session = session
        self._attempt = attempt

    @property
    def approval(self) -> TransactionApproval:
        """The approval this transaction is restricted to."""
        return self._approval

    @property
    def attempt(self) -> int:
        """The 1-based transaction attempt number."""
        return self._attempt

    @property
    def client(self) -> _RestrictedClient:
        """A client view limited to the approved namespaces."""
        return _RestrictedClient(self)


class _RestrictedClient:
    def __init__(self, transaction: RestrictedTransaction) -> None:
        self._transaction = transaction

    def get_database(self, name: str) -> _RestrictedDatabase:
        return _RestrictedDatabase(self._transaction, name)

    def __getitem__(self, name: str) -> _RestrictedDatabase:
        return self.get_database(name)


class _RestrictedDatabase:
    def __init__(self, transaction: RestrictedTransaction, name: str) -> None:
        self._transaction = transaction
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def get_collection(self, name: str) -> _RestrictedCollection:
        return _RestrictedCollection(self._transaction, self._name, name)

    def __getitem__(self, name: str) -> _RestrictedCollection:
        return self.get_collection(name)


class _RestrictedCollection:
    def __init__(self, transaction: RestrictedTransaction, database: str, collection: str) -> None:
        self._transaction = transaction
        self._database = database
        self._collection = collection

    @property
    def database_name(self) -> str:
        return self._database

    @property
    def name(self) -> str:
        return self._collection

    @property
    def full_name(self) -> str:
        return f"{self._database}.{self._collection}"

    @property
    def namespace(self) -> tuple[str, str]:
        return (self._database, self._collection)

    def _execute(self, method: str, *args: Any, **kwargs: Any) -> Any:
        txn = self._transaction
        proxy = txn._proxy
        command = _WRITE_COMMANDS[method]
        if not txn.approval.allows(self._database, self._collection):
            proxy._record(
                NamespaceUse(self._database, self._collection, command, True, txn.attempt, False)
            )
            raise NamespaceReapprovalRequired(
                self._database, self._collection, txn.approval.namespaces, txn.attempt
            )
        proxy._record(
            NamespaceUse(self._database, self._collection, command, True, txn.attempt, True)
        )
        real_collection = proxy.client[self._database][self._collection]
        # The restricted session is bound here; callers cannot override it.
        kwargs["session"] = txn._session
        return getattr(real_collection, method)(*args, **kwargs)


def _make_restricted_write_method(method: str) -> Callable[..., Any]:
    def write_method(self: _RestrictedCollection, *args: Any, **kwargs: Any) -> Any:
        return self._execute(method, *args, **kwargs)

    write_method.__name__ = method
    write_method.__qualname__ = f"_RestrictedCollection.{method}"
    write_method.__doc__ = f"Run ``{method}`` if the namespace is approved."
    return write_method


for _method in _WRITE_COMMANDS:
    setattr(_RestrictedCollection, _method, _make_restricted_write_method(_method))


class _ProxyDatabase:
    def __init__(self, proxy: WriteProxy, name: str) -> None:
        self._proxy = proxy
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def get_collection(self, name: str) -> _ProxyCollection:
        return _ProxyCollection(self._proxy, self._name, name)

    def __getitem__(self, name: str) -> _ProxyCollection:
        return self.get_collection(name)


class _ProxyCollection:
    """Normal (unrestricted) collection handle that records namespaces."""

    def __init__(self, proxy: WriteProxy, database: str, collection: str) -> None:
        self._proxy = proxy
        self._database = database
        self._collection = collection

    @property
    def database_name(self) -> str:
        return self._database

    @property
    def name(self) -> str:
        return self._collection

    @property
    def full_name(self) -> str:
        return f"{self._database}.{self._collection}"

    @property
    def namespace(self) -> tuple[str, str]:
        return (self._database, self._collection)

    def _execute(self, method: str, *args: Any, **kwargs: Any) -> Any:
        self._proxy._record(
            NamespaceUse(self._database, self._collection, _WRITE_COMMANDS[method], False, 0, True)
        )
        real_collection = self._proxy.client[self._database][self._collection]
        # Normal commands are unrestricted; any caller-provided session
        # (or none) is passed through unchanged.
        return getattr(real_collection, method)(*args, **kwargs)


def _make_proxy_write_method(method: str) -> Callable[..., Any]:
    def write_method(self: _ProxyCollection, *args: Any, **kwargs: Any) -> Any:
        return self._execute(method, *args, **kwargs)

    write_method.__name__ = method
    write_method.__qualname__ = f"_ProxyCollection.{method}"
    write_method.__doc__ = f"Run ``{method}`` and record the namespace."
    return write_method


for _method in _WRITE_COMMANDS:
    setattr(_ProxyCollection, _method, _make_proxy_write_method(_method))
