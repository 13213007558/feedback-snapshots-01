"""Wiring for the bounded migration job.

A job is defined once, with fixed source/destination connection details and a
fixed list of *approved* source UIDs. Nothing here discovers or enumerates new
mail: UIDs outside the approved list are unreachable to the engine.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Sequence

from .evidence import MailboxAnchor, parse_uidvalidity
from .gateway import AioimaplibGateway
from .progress import ProgressStore
from .engine import MigrationEngine

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ImapConnection:
    host: str
    port: int
    username: str
    password: str
    mailbox: str
    ssl: bool = True


def _aioimaplib_client_factory(connection: ImapConnection):
    """Return an async factory producing connected, logged-in aioimaplib clients."""

    async def factory():
        import aioimaplib

        if connection.ssl:
            client = aioimaplib.IMAP4_SSL(host=connection.host, port=connection.port)
        else:
            client = aioimaplib.IMAP4(host=connection.host, port=connection.port)
        await client.wait_hello_from_server()
        response = await client.login(connection.username, connection.password)
        if response.result != "OK":
            raise RuntimeError(f"login refused for {connection.username}: {response}")
        return client

    return factory


async def discover_anchor(connection: ImapConnection) -> MailboxAnchor:
    """Open one connection to pin UIDVALIDITY for a fixed mailbox."""
    gateway = AioimaplibGateway(_aioimaplib_client_factory(connection))
    try:
        await gateway.open()
        response = await gateway.select(connection.mailbox)
        uidvalidity = parse_uidvalidity(response.lines)
        if uidvalidity is None:
            raise RuntimeError(f"server did not return UIDVALIDITY for {connection.mailbox}")
        return MailboxAnchor(connection.host, connection.mailbox, uidvalidity)
    finally:
        await gateway.close()


async def run_job(
    source: ImapConnection,
    destination: ImapConnection,
    approved_uids: Sequence[int],
    progress_path: str,
    gateway_factory=None,
) -> ProgressStore:
    """Migrate exactly the approved UIDs, resuming from saved progress.

    ``gateway_factory`` is injectable for tests/transcripts; production leaves
    it ``None`` and gets real aioimaplib connections pinned to ``source``.
    """
    store = ProgressStore(progress_path)
    if store.state is None:
        source_anchor = (
            await discover_anchor(source)
            if gateway_factory is None
            else MailboxAnchor(source.host, source.mailbox, 9001)
        )
        dest_anchor = (
            await discover_anchor(destination)
            if gateway_factory is None
            else MailboxAnchor(destination.host, destination.mailbox, 9002)
        )
        store.init_job(source_anchor, dest_anchor)
        for uid in approved_uids:
            store.add_approved_uid(uid)

    if gateway_factory is None:
        gateway_factory = lambda: AioimaplibGateway(  # noqa: E731
            _aioimaplib_client_factory(source)
        )

    engine = MigrationEngine(store, gateway_factory)
    try:
        for record in store.all_records():
            if not record.is_terminal:
                await engine.migrate_uid(record.source_uid)
    finally:
        await engine.close()
    return store
