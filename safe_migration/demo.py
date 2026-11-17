"""Synthetic command transcripts for the safe migration state machine.

Runs entirely against :class:`~safe_migration.gateway.ScriptedGateway` (no
sockets). It demonstrates the two failure shapes requested:

1. MOVE executed by the server but the tagged response is lost (disconnect).
2. COPY succeeds (COPYUID) but the source-deletion acknowledgement is lost.

Plus two reference cases: an explicit MOVE refusal (definite failure) and a
no-UIDPLUS server where a mailbox-wide EXPUNGE is forbidden.
"""
from __future__ import annotations

import asyncio
import os
import tempfile

from .engine import MigrationEngine
from .evidence import MailboxAnchor
from .gateway import ScriptedGateway, ScriptedStep
from .progress import ProgressStore

SOURCE = MailboxAnchor("src.example", "INBOX", 9001)
DESTINATION = MailboxAnchor("dst.example", "Archive/Migrated", 9002)

RFC822 = (
    b"From: approved@src.example\r\n"
    b"To: archive@dst.example\r\n"
    b"Message-ID: <approved-uid-7@src.example>\r\n"
    b"Subject: approved migration message\r\n\r\n"
    b"pre-approved body content\r\n"
)
DEST_LINES = [
    b"OK [UIDVALIDITY 9002] UIDs valid",
    b"OK [UIDNEXT 500] Predicted next UID",
]


def fetch_lines(uid: int, literal: bytes = RFC822):
    return [
        f"* {uid} FETCH (UID {uid} INTERNALDATE \"18-Nov-2026 10:00:00 +0000\" "
        f"RFC822.SIZE {len(literal)} BODY[] {{{len(literal)}}}".encode(),
        literal,
        b")",
    ]


def make_store(path: str) -> ProgressStore:
    store = ProgressStore(path)
    store.init_job(SOURCE, DESTINATION)
    store.add_approved_uid(7)
    return store


def print_transcript(title: str, gateways):
    print("=" * 78)
    print(title)
    print("=" * 78)
    for index, gateway in enumerate(gateways, 1):
        print(f"--- connection #{index} ---")
        for line in gateway.transcript:
            print(line)
    print()


def print_outcome(store: ProgressStore):
    for record in store.all_records():
        print(f"uid={record.source_uid} status={record.status} "
              f"target_uid={record.target_uid} review_reason={record.review_reason}")
        for entry in record.log:
            print(f"    | {entry}")
    print()


async def scenario_move_answer_lost(workdir: str):
    """MOVE is sent, server executes it, but the connection drops first."""
    first = ScriptedGateway(
        ["MOVE", "UIDPLUS"],
        select_lines_by_mailbox={DESTINATION.mailbox: DEST_LINES},
        script=[
            ScriptedStep("UID FETCH", lines=fetch_lines(7)),
            ScriptedStep("UID MOVE", result="DISCONNECT"),
        ],
    )
    second = ScriptedGateway(
        ["MOVE", "UIDPLUS"],
        select_lines_by_mailbox={DESTINATION.mailbox: DEST_LINES},
        script=[
            # Recheck source: the UID no longer resolves.
            ScriptedStep("UID FETCH", result="NO", lines=[b"7 OK UID not found"]),
            # Bounded exact-header search on the destination yields one UID ...
            ScriptedStep("UID SEARCH", lines=[b"* SEARCH 437"]),
            # ... whose full fingerprint matches the source message.
            ScriptedStep("UID FETCH", lines=fetch_lines(437)),
            ScriptedStep("UID FETCH", lines=fetch_lines(7)),
        ],
    )

    store = make_store(os.path.join(workdir, "move_lost.json"))
    engine = MigrationEngine(store, lambda: first)
    await engine.migrate_uid(7)
    print_transcript(
        "SCENARIO 1 (run A): UID MOVE sent, server drops connection before tagged OK",
        [first],
    )

    engine = MigrationEngine(store, lambda: second)
    await engine.migrate_uid(7)
    print_transcript("SCENARIO 1 (run B, recheck on a fresh connection)", [second])
    print_outcome(store)


async def scenario_copy_ok_delete_lost(workdir: str):
    """COPY returns COPYUID, then the UID EXPUNGE answer is lost."""
    first = ScriptedGateway(
        ["UIDPLUS"],  # note: no MOVE capability
        select_lines_by_mailbox={DESTINATION.mailbox: DEST_LINES},
        script=[
            ScriptedStep("UID FETCH", lines=fetch_lines(7)),
            ScriptedStep("UID COPY", lines=[b"OK [COPYUID 9002 7 437]"]),
            ScriptedStep("UID FETCH", lines=fetch_lines(437)),
            ScriptedStep("UID STORE", lines=[b"* 7 FETCH (UID 7 FLAGS (\\Deleted))"]),
            ScriptedStep("UID EXPUNGE", result="DISCONNECT"),
        ],
    )
    second = ScriptedGateway(
        ["UIDPLUS"],
        select_lines_by_mailbox={DESTINATION.mailbox: DEST_LINES},
        script=[
            # Source still present (EXPUNGE answer lost, deletion unconfirmed) ...
            ScriptedStep("UID FETCH", lines=[b"* 7 FETCH (UID 7)"]),
            # ... and the COPYUID-named target still verifies by fingerprint.
            ScriptedStep("UID FETCH", lines=fetch_lines(437)),
            # Back on source: only the UID-scoped removal is retried.
            ScriptedStep("UID STORE", lines=[b"* 7 FETCH (UID 7 FLAGS (\\Deleted))"]),
            ScriptedStep("UID EXPUNGE", lines=[b"7 EXPUNGE"]),
        ],
    )

    store = make_store(os.path.join(workdir, "copy_delete_lost.json"))
    engine = MigrationEngine(store, lambda: first)
    await engine.migrate_uid(7)
    print_transcript(
        "SCENARIO 2 (run A): UID COPY ok (COPYUID), UID EXPUNGE answer lost",
        [first],
    )

    engine = MigrationEngine(store, lambda: second)
    await engine.migrate_uid(7)
    print_transcript("SCENARIO 2 (run B, recheck then UID-scoped delete)", [second])
    print_outcome(store)


async def scenario_move_refused(workdir: str):
    """Explicit tagged NO: a definite, evidence-backed failure."""
    gateway = ScriptedGateway(
        ["MOVE", "UIDPLUS"],
        select_lines_by_mailbox={DESTINATION.mailbox: DEST_LINES},
        script=[
            ScriptedStep("UID FETCH", lines=fetch_lines(7)),
            ScriptedStep("UID MOVE", result="NO",
                         lines=[b"NO [TRYCREATE] target mailbox does not exist"]),
        ],
    )
    store = make_store(os.path.join(workdir, "move_refused.json"))
    engine = MigrationEngine(store, lambda: gateway)
    await engine.migrate_uid(7)
    print_transcript("SCENARIO 3: MOVE refused with tagged NO (deterministic failure)",
                     [gateway])
    print_outcome(store)


async def scenario_no_uidplus(workdir: str):
    """No MOVE and no UIDPLUS: copy works, source removal goes to review."""
    gateway = ScriptedGateway(
        [],  # neither MOVE nor UIDPLUS advertised
        select_lines_by_mailbox={DESTINATION.mailbox: DEST_LINES},
        script=[
            ScriptedStep("UID FETCH", lines=fetch_lines(7)),
            ScriptedStep("UID COPY", lines=[b"OK [COPYUID 9002 7 437]"]),
            ScriptedStep("UID FETCH", lines=fetch_lines(437)),
            ScriptedStep("UID STORE", lines=[b"* 7 FETCH (UID 7 FLAGS (\\Deleted))"]),
            # No UID EXPUNGE is attempted: a mailbox-wide EXPUNGE is forbidden.
        ],
    )
    store = make_store(os.path.join(workdir, "no_uidplus.json"))
    engine = MigrationEngine(store, lambda: gateway)
    await engine.migrate_uid(7)
    print_transcript("SCENARIO 4: no MOVE/UIDPLUS -> review, no full-mailbox EXPUNGE",
                     [gateway])
    print_outcome(store)


async def main():
    with tempfile.TemporaryDirectory(prefix="safe-migration-") as workdir:
        await scenario_move_answer_lost(workdir)
        await scenario_copy_ok_delete_lost(workdir)
        await scenario_move_refused(workdir)
        await scenario_no_uidplus(workdir)
        print(f"progress documents were written under {workdir}")


if __name__ == "__main__":
    asyncio.run(main())
