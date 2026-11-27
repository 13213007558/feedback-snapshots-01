"""Revocable write permission over an established WebSocket edit connection.

These tests model a collaborative document editor. A client opens a single
WebSocket connection and streams ``read``/``write`` messages, while an
operator may revoke that client's write permission for one document at any
moment. The connection itself stays authenticated and usable for reads; only
the authorization decision attached to each *commit* changes.

A pausable in-memory store lets the tests pin an edit in flight:

* ``PausableDocumentStore`` blocks every commit while paused, and exposes an
  event that fires once a commit is actually waiting at that gate. This is
  what makes "the first edit was admitted but has not been stored yet"
  deterministic.
* ``WritePermissionRegistry`` is the mutable authorization table. Revoking a
  document here does not tear down any socket; the store consults it again
  while committing, so an edit that was accepted earlier is settled against
  the permissions in force when it reaches the store.
* ``EditResource`` distinguishes committed writes, rejected (not yet
  committed) writes, always-allowed read-only messages, and two different
  connection close reasons.
"""

import asyncio

import pytest

import falcon
import falcon.testing

# Application-private policy code (RFC 6455 reserves 4000-4999 for apps).
CLOSE_WRITE_REVOKED = 4403
CLOSE_NORMAL = 1000

_DOC_A = 'playbook'
_DOC_B = 'ledger'


class WriteDeniedError(PermissionError):
    """Raised when a commit fails the store's permission check."""


class WritePermissionRegistry:
    """Mutable mapping of ``(identity, document)`` to a write grant.

    The registry is intentionally shared between the store and whatever
    operator process revokes access. Looking the grant up at commit time
    (rather than once when the message arrives) is what makes revocation take
    effect for edits that were already admitted onto the connection.
    """

    def __init__(self):
        self._grants = set()

    def grant(self, identity, document):
        """Allow *identity* to commit writes to *document*."""
        self._grants.add((identity, document))

    def revoke(self, identity, document):
        """Revoke *identity*'s write grant for *document* without closing sockets."""
        self._grants.discard((identity, document))

    def can_write(self, identity, document):
        """Return ``True`` if *identity* may currently commit to *document*."""
        return (identity, document) in self._grants


class PausableDocumentStore:
    """In-memory document store whose commit step can be held open.

    The pause gate models a slow backend so that a test can arrange a revoke
    while a write is in flight. Every commit re-evaluates the permission
    registry, so a grant removed while a commit is parked causes that very
    commit to be rejected instead of stored.
    """

    def __init__(self, permissions, seed):
        self._permissions = permissions
        self._documents = dict(seed)
        self._paused = False
        self._gate = asyncio.Event()
        self._in_flight = 0
        self._parked = asyncio.Event()
        self.writes_committed = []

    @property
    def committed_writes(self):
        """The ordered ``(document, content)`` tuples that actually landed."""
        return list(self.writes_committed)

    @property
    def in_flight(self):
        """The number of commits currently inside the store (parked or running)."""
        return self._in_flight

    def snapshot(self):
        """Return a deep-enough copy of the current document contents."""
        return dict(self._documents)

    def pause(self):
        """Block subsequent commits until :meth:`resume` is called."""
        self._paused = True
        self._gate.clear()

    def resume(self):
        """Release all commits that accumulated while the store was paused."""
        self._paused = False
        self._gate.set()

    async def wait_in_flight(self):
        """Wait until at least one commit is parked at the pause gate."""
        while not self._parked.is_set():
            await asyncio.sleep(0)

    async def commit_write(self, identity, document, content):
        """Commit an edit, re-checking permission at the moment of the write."""
        self._in_flight += 1
        try:
            if self._paused:
                self._parked.set()
                await self._gate.wait()

            # NOTE: The grant is evaluated here, at commit time, not when the
            #   message was received on the WebSocket.
            if not self._permissions.can_write(identity, document):
                raise WriteDeniedError(document)

            self._documents[document] = content
            self.writes_committed.append((document, content))
        finally:
            self._in_flight -= 1

    def read(self, document):
        """Return the document content, or ``None`` if it does not exist."""
        return self._documents.get(document)


class EditResource:
    """WebSocket responder that settles each message against current grants."""

    def __init__(self, store):
        self._store = store

    async def on_websocket(self, req, ws, identity):
        await ws.accept()
        session_revoked = False

        try:
            while True:
                message = await ws.receive_media()
                op = message['op']
                document = message['doc']
                message_id = message['id']

                if op == 'done':
                    # The client is finished; the close code advertises whether
                    # a revocation was observed during this session.
                    code = CLOSE_WRITE_REVOKED if session_revoked else CLOSE_NORMAL
                    await ws.close(code)
                    return

                if op == 'read':
                    # Read-only access is independent of the write grant.
                    await ws.send_media(
                        {
                            'id': message_id,
                            'status': 'ok',
                            'doc': document,
                            'content': self._store.read(document),
                        }
                    )
                    continue

                assert op == 'write'
                try:
                    await self._store.commit_write(
                        identity, document, message['content']
                    )
                except WriteDeniedError:
                    session_revoked = True
                    await ws.send_media(
                        {
                            'id': message_id,
                            'status': 'denied',
                            'doc': document,
                        }
                    )
                else:
                    await ws.send_media(
                        {
                            'id': message_id,
                            'status': 'committed',
                            'doc': document,
                        }
                    )
        except falcon.WebSocketDisconnected:
            # The client went away (e.g. test context exit) before sending
            # 'done'; nothing more to settle.
            return


@pytest.fixture
def harness():
    """Build a fresh app, permission registry, and paused-capable store."""
    permissions = WritePermissionRegistry()
    permissions.grant('alice', _DOC_A)
    permissions.grant('alice', _DOC_B)

    store = PausableDocumentStore(
        permissions, {_DOC_A: 'v0', _DOC_B: 'opening-balance'}
    )
    app = falcon.asgi.App()
    app.add_route('/edit/{identity}', EditResource(store))

    return app, store, permissions


async def _drain(ws, count):
    """Read exactly *count* JSON responses, preserving arrival order."""
    responses = []
    for _ in range(count):
        responses.append(await ws.receive_json())
    return responses


async def test_revoke_before_first_commit_settles_each_message(harness):
    # Revocation while the first admitted edit is still waiting to be stored.
    app, store, permissions = harness

    async with falcon.testing.ASGIConductor(app) as conductor:
        async with conductor.simulate_ws('/edit/alice') as ws:
            store.pause()

            # m1 is admitted and parks inside the store before it can write.
            await ws.send_json(
                {'id': 'm1', 'op': 'write', 'doc': _DOC_A, 'content': 'v1'}
            )
            await store.wait_in_flight()

            # Revoke while m1 is in flight; the connection itself stays open.
            permissions.revoke('alice', _DOC_A)

            # m2 has only reached the receive buffer and never started a commit,
            # and m3 is a read-only message that must remain executable.
            await ws.send_json(
                {'id': 'm2', 'op': 'write', 'doc': _DOC_A, 'content': 'v2'}
            )
            await ws.send_json({'id': 'm3', 'op': 'read', 'doc': _DOC_A})

            store.resume()
            responses = await _drain(ws, 3)

            # Responses are correlated with their request by id and order.
            assert [response['id'] for response in responses] == ['m1', 'm2', 'm3']
            assert responses[0] == {'id': 'm1', 'status': 'denied', 'doc': _DOC_A}
            assert responses[1] == {'id': 'm2', 'status': 'denied', 'doc': _DOC_A}
            assert responses[2] == {
                'id': 'm3',
                'status': 'ok',
                'doc': _DOC_A,
                'content': 'v0',
            }

            # Nothing was ever written to the revoked document, and every
            # parked or queued commit has fully settled (none left hanging).
            assert store.committed_writes == []
            assert store.in_flight == 0
            assert store.read(_DOC_A) == 'v0'
            assert not ws.closed

            # A fresh write after revocation is rejected, then 'done' surfaces
            # the distinct policy close code.
            await ws.send_json(
                {'id': 'm4', 'op': 'write', 'doc': _DOC_A, 'content': 'v4'}
            )
            response = await ws.receive_json()
            assert response == {'id': 'm4', 'status': 'denied', 'doc': _DOC_A}

            await ws.send_json({'id': 'done', 'op': 'done', 'doc': _DOC_A})
            with pytest.raises(falcon.WebSocketDisconnected) as exc_info:
                await ws.receive_json()

            assert exc_info.value.code == CLOSE_WRITE_REVOKED
            assert ws.closed
            assert ws.close_code == CLOSE_WRITE_REVOKED


async def test_revoke_after_first_commit_keeps_prior_write(harness):
    # Revocation after the first edit has fully committed.
    app, store, permissions = harness

    async with falcon.testing.ASGIConductor(app) as conductor:
        async with conductor.simulate_ws('/edit/alice') as ws:
            await ws.send_json(
                {'id': 'm1', 'op': 'write', 'doc': _DOC_A, 'content': 'v1'}
            )
            response = await ws.receive_json()
            assert response == {'id': 'm1', 'status': 'committed', 'doc': _DOC_A}

            # The first edit really landed before the revoke.
            assert store.committed_writes == [(_DOC_A, 'v1')]
            assert store.read(_DOC_A) == 'v1'

            permissions.revoke('alice', _DOC_A)

            # A different document's grant is untouched and still writable.
            await ws.send_json(
                {'id': 'm2', 'op': 'write', 'doc': _DOC_B, 'content': 'audit-1'}
            )
            await ws.send_json(
                {'id': 'm3', 'op': 'write', 'doc': _DOC_A, 'content': 'v2'}
            )
            await ws.send_json({'id': 'm4', 'op': 'read', 'doc': _DOC_A})
            responses = await _drain(ws, 3)

            assert [response['id'] for response in responses] == ['m2', 'm3', 'm4']
            assert responses[0] == {
                'id': 'm2',
                'status': 'committed',
                'doc': _DOC_B,
            }
            assert responses[1] == {'id': 'm3', 'status': 'denied', 'doc': _DOC_A}
            assert responses[2] == {
                'id': 'm4',
                'status': 'ok',
                'doc': _DOC_A,
                'content': 'v1',
            }

            # Only the authorized writes landed; the revoked document kept the
            # value from its one committed edit.
            assert store.committed_writes == [(_DOC_A, 'v1'), (_DOC_B, 'audit-1')]
            assert store.snapshot() == {_DOC_A: 'v1', _DOC_B: 'audit-1'}

            await ws.send_json({'id': 'done', 'op': 'done', 'doc': _DOC_A})
            with pytest.raises(falcon.WebSocketDisconnected) as exc_info:
                await ws.receive_json()

            assert exc_info.value.code == CLOSE_WRITE_REVOKED
            assert ws.close_code == CLOSE_WRITE_REVOKED


async def test_clean_session_closes_with_normal_code(harness):
    # Without a revocation, reads and writes succeed and the socket closes
    # with the standard normal-closure code, distinct from 4403.
    app, store, _permissions = harness

    async with falcon.testing.ASGIConductor(app) as conductor:
        async with conductor.simulate_ws('/edit/alice') as ws:
            await ws.send_json(
                {'id': 'm1', 'op': 'write', 'doc': _DOC_A, 'content': 'v1'}
            )
            await ws.send_json({'id': 'm2', 'op': 'read', 'doc': _DOC_A})
            responses = await _drain(ws, 2)

            assert [response['id'] for response in responses] == ['m1', 'm2']
            assert responses[0]['status'] == 'committed'
            assert responses[1] == {
                'id': 'm2',
                'status': 'ok',
                'doc': _DOC_A,
                'content': 'v1',
            }

            await ws.send_json({'id': 'done', 'op': 'done', 'doc': _DOC_A})
            with pytest.raises(falcon.WebSocketDisconnected) as exc_info:
                await ws.receive_json()

            assert exc_info.value.code == CLOSE_NORMAL
            assert ws.close_code == CLOSE_NORMAL

        assert store.committed_writes == [(_DOC_A, 'v1')]


async def test_client_disconnect_before_done_does_not_break_store(harness):
    # If the client drops the connection instead of sending 'done', the
    # responder exits cleanly and committed data is preserved.
    app, store, _permissions = harness

    async with falcon.testing.ASGIConductor(app) as conductor:
        async with conductor.simulate_ws('/edit/alice') as ws:
            await ws.send_json(
                {'id': 'm1', 'op': 'write', 'doc': _DOC_B, 'content': 'audit-2'}
            )
            response = await ws.receive_json()
            assert response['status'] == 'committed'

    assert store.committed_writes == [(_DOC_B, 'audit-2')]
    assert store.read(_DOC_B) == 'audit-2'
