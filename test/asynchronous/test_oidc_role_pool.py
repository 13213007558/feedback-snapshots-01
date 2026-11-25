"""Offline tests for OIDC account-material changes and pool reuse."""

from __future__ import annotations

import time
from typing import Any

from pymongo.asynchronous.auth_oidc import _OIDCAuthenticator
from pymongo.asynchronous.helpers import _handle_reauth
from pymongo.asynchronous.pool import AsyncConnection, Pool
from pymongo.auth_oidc_shared import _OIDCProperties
from pymongo.auth_shared import MongoCredential, _Cache
from pymongo.errors import OperationFailure
from pymongo.pool_options import PoolOptions
from test.asynchronous import AsyncUnitTest

_IS_SYNC = False


class _FakeSocket:
    def __init__(self) -> None:
        self.closed = False

    async def close(self) -> None:
        self.closed = True


class _RecordingPoolDouble:
    """Minimal pool double used to record the public borrow/reauth sequence."""

    def __init__(self, connection: AsyncConnection, events: list[str]) -> None:
        self.connection = connection
        self.borrow_count = 0
        self.checkin_count = 0
        self.reauthentication_count = 0
        self.events = events

    async def borrow(self) -> AsyncConnection:
        self.borrow_count += 1
        self.events.append("borrow")
        return self.connection

    def record_reauthentication(self) -> None:
        self.reauthentication_count += 1
        self.events.append("reauthenticate:B")

    async def checkin(self, connection: AsyncConnection) -> None:
        self.checkin_count += 1
        self.events.append("checkin")


class _OfflineRolePool(Pool):
    def __init__(self, credentials: MongoCredential, authenticator: _OIDCAuthenticator) -> None:
        options = PoolOptions(pause_enabled=False, credentials=credentials)
        super().__init__(("localhost", 27017), options)
        self.authenticator = authenticator
        self.borrow_count = 0
        self.created_connections: list[_RoleConnection] = []

    async def borrow(self) -> AsyncConnection:
        self.borrow_count += 1
        return await self._get_conn(time.monotonic())

    async def connect(self, handler: Any = None) -> AsyncConnection:
        connection = _RoleConnection(self, "B", 2)
        self.authenticator.bind_connection(connection)
        self.created_connections.append(connection)
        return connection


class _RoleConnection(AsyncConnection):
    def __init__(self, pool: Pool, role: str, token_generation: int) -> None:
        connection_id = getattr(pool, "_test_connection_id", 0) + 1
        pool._test_connection_id = connection_id  # type: ignore[attr-defined]
        super().__init__(_FakeSocket(), pool, ("localhost", 27017), connection_id, False)
        self.role = role
        self.token_generation = token_generation


def _credentials(authenticator: _OIDCAuthenticator) -> MongoCredential:
    credentials = MongoCredential(
        "MONGODB-OIDC", "$external", None, None, _OIDCProperties(), _Cache()
    )
    credentials.cache.data = authenticator
    return credentials


def _authenticator(role: str = "A") -> _OIDCAuthenticator:
    return _OIDCAuthenticator(
        username="",
        properties=_OIDCProperties(),
        access_token="role-a-token",
        token_gen_id=1,
        approved_role=role,
    )


class TestOIDCRolePool(AsyncUnitTest):
    async def test_expired_reauthentication_uses_current_role_once(self) -> None:
        authenticator = _authenticator()
        credentials = _credentials(authenticator)
        pool = Pool(("localhost", 27017), PoolOptions(credentials=credentials))
        connection = _RoleConnection(pool, "A", 1)
        authenticator.bind_connection(connection)
        connection.performed_handshake = True

        # Approval changes to B before the old connection's token expires.
        authenticator.approve_role("B")
        authenticator.access_token = "role-b-token"
        authenticator.token_gen_id = 2

        sasl_commands: list[dict[str, Any]] = []

        async def record_command(
            dbname: str, spec: dict[str, Any], no_reauth: bool = False
        ) -> dict[str, Any]:
            sasl_commands.append(spec)
            return {"ok": 1}

        connection.command = record_command  # type: ignore[method-assign]

        events: list[str] = []
        recording_pool = _RecordingPoolDouble(connection, events)
        original_authenticate = connection.authenticate

        async def authenticate(reauthenticate: bool = False) -> None:
            await original_authenticate(reauthenticate=reauthenticate)
            if reauthenticate:
                recording_pool.record_reauthentication()

        connection.authenticate = authenticate  # type: ignore[method-assign]

        attempts = 0

        @_handle_reauth
        async def run_query(conn: AsyncConnection) -> str:
            nonlocal attempts
            attempts += 1
            events.append(f"command:{conn.oidc_account_role}")
            if attempts == 1:
                raise OperationFailure("reauthentication required", code=391)
            return "finished"

        borrowed = await recording_pool.borrow()
        result = await run_query(borrowed)
        await recording_pool.checkin(borrowed)

        self.assertEqual(result, "finished")
        self.assertEqual(recording_pool.borrow_count, 1)
        self.assertEqual(recording_pool.checkin_count, 1)
        self.assertEqual(recording_pool.reauthentication_count, 1)
        self.assertEqual(attempts, 2)
        self.assertEqual(connection.oidc_account_role, "B")
        self.assertEqual(len(sasl_commands), 1)
        self.assertIn(b"role-b-token", bytes(sasl_commands[0]["payload"]))
        self.assertEqual(
            events,
            ["borrow", "command:A", "reauthenticate:B", "command:B", "checkin"],
        )

    async def test_completed_old_role_task_connection_is_not_reborrowed(self) -> None:
        authenticator = _authenticator()
        credentials = _credentials(authenticator)
        pool = _OfflineRolePool(credentials, authenticator)

        old_connection = _RoleConnection(pool, "A", 1)
        authenticator.bind_connection(old_connection)
        self.assertEqual(old_connection.oidc_token_gen_id, 1)
        self.assertEqual(old_connection.oidc_account_role, "A")

        # Approval moves from role A to role B, retiring A's account material.
        authenticator.approve_role("B")
        authenticator.access_token = "role-b-token"
        authenticator.token_gen_id = 2

        # The query that owned the A connection is allowed to finish and then
        # returns its connection. Check-in must withdraw it from future borrows.
        await pool.checkin(old_connection)

        self.assertTrue(old_connection.closed)
        self.assertEqual(len(pool.conns), 0)

        new_connection = await pool.borrow()
        try:
            self.assertEqual(pool.borrow_count, 1)
            self.assertEqual(len(pool.created_connections), 1)
            self.assertIs(new_connection, pool.created_connections[0])
            self.assertEqual(new_connection.role, "B")
            self.assertEqual(new_connection.oidc_account_role, "B")
            self.assertEqual(new_connection.oidc_token_gen_id, 2)
            self.assertIsNot(new_connection, old_connection)
            self.assertEqual(list(pool.conns), [])
        finally:
            await pool.checkin(new_connection)

        self.assertEqual(list(pool.conns), [new_connection])
        self.assertNotIn(old_connection, pool.conns)

    async def test_idle_withdrawn_role_connection_is_retired_on_borrow(self) -> None:
        authenticator = _authenticator()
        credentials = _credentials(authenticator)
        pool = _OfflineRolePool(credentials, authenticator)

        idle_connection = _RoleConnection(pool, "A", 1)
        authenticator.bind_connection(idle_connection)
        pool.conns.appendleft(idle_connection)

        authenticator.approve_role("B")
        authenticator.access_token = "role-b-token"
        authenticator.token_gen_id = 2

        borrowed = await pool.borrow()
        try:
            self.assertEqual(pool.borrow_count, 1)
            self.assertTrue(idle_connection.closed)
            self.assertEqual(len(pool.created_connections), 1)
            self.assertIs(borrowed, pool.created_connections[0])
            self.assertEqual(borrowed.oidc_account_role, "B")
            self.assertIsNot(borrowed, idle_connection)
        finally:
            await pool.checkin(borrowed)

        self.assertEqual(list(pool.conns), [borrowed])
        self.assertNotIn(idle_connection, pool.conns)


if __name__ == "__main__":
    from test.asynchronous import unittest

    unittest.main()
