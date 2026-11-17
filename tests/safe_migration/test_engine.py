import pytest

from safe_migration.engine import MigrationEngine, UnknownUid
from safe_migration.evidence import MigrationStatus
from safe_migration.gateway import ScriptedGateway, ScriptedStep
from tests.safe_migration.conftest import DEST_LINES, RFC822, fetch_lines


def engine(store, gateways):
    gateways = list(gateways)
    return MigrationEngine(store, lambda: gateways.pop(0))


def gateway(capabilities, script):
    return ScriptedGateway(capabilities,
                           select_lines_by_mailbox={"Archive/Migrated": DEST_LINES},
                           script=script)


@pytest.mark.asyncio()
async def test_move_happy_path_confirmed_on_copyuid(store):
    gw = gateway(["MOVE", "UIDPLUS"], [
        ScriptedStep("UID FETCH", lines=fetch_lines(7)),
        ScriptedStep("UID MOVE", lines=[b"OK [COPYUID 9002 7 437]", b"7 EXPUNGE"]),
        ScriptedStep("UID FETCH", lines=fetch_lines(437)),
    ])
    status = await MigrationEngine(store, lambda: gw).migrate_uid(7)
    assert status == MigrationStatus.CONFIRMED
    record = store.get(7)
    assert record.target_uid == 437
    assert record.copyuid["target_uids"] == (437,)


@pytest.mark.asyncio()
async def test_move_refused_is_definite_failure(store):
    gw = gateway(["MOVE", "UIDPLUS"], [
        ScriptedStep("UID FETCH", lines=fetch_lines(7)),
        ScriptedStep("UID MOVE", result="NO", lines=[b"NO [TRYCREATE] no mailbox"]),
    ])
    status = await MigrationEngine(store, lambda: gw).migrate_uid(7)
    assert status == MigrationStatus.FAILED
    assert store.get(7).is_terminal


@pytest.mark.asyncio()
async def test_move_answer_lost_then_confirmed_by_evidence(store):
    first = gateway(["MOVE", "UIDPLUS"], [
        ScriptedStep("UID FETCH", lines=fetch_lines(7)),
        ScriptedStep("UID MOVE", result="DISCONNECT"),
    ])
    status = await MigrationEngine(store, lambda: first).migrate_uid(7)
    assert status == MigrationStatus.MOVE_SENT_UNKNOWN

    second = gateway(["MOVE", "UIDPLUS"], [
        ScriptedStep("UID FETCH", result="NO", lines=[b"7 OK gone"]),
        ScriptedStep("UID SEARCH", lines=[b"* SEARCH 437"]),
        ScriptedStep("UID FETCH", lines=fetch_lines(437)),
        ScriptedStep("UID FETCH", lines=fetch_lines(7)),
    ])
    status = await MigrationEngine(store, lambda: second).migrate_uid(7)
    assert status == MigrationStatus.CONFIRMED
    # No COPY/EXPUNGE fallback was ever emitted after the lost MOVE.
    wire = "\n".join(second.transcript)
    assert "UID COPY" not in wire
    assert "UID EXPUNGE" not in wire


@pytest.mark.asyncio()
async def test_move_answer_lost_but_still_at_source_retries_fresh(store):
    first = gateway(["MOVE", "UIDPLUS"], [
        ScriptedStep("UID FETCH", lines=fetch_lines(7)),
        ScriptedStep("UID MOVE", result="DISCONNECT"),
    ])
    await MigrationEngine(store, lambda: first).migrate_uid(7)

    second = gateway(["MOVE", "UIDPLUS"], [
        ScriptedStep("UID FETCH", lines=[b"* 7 FETCH (UID 7)"]),
        ScriptedStep("UID SEARCH", lines=[b"* SEARCH"]),
        # Evidence says MOVE did not happen -> a brand new attempt runs.
        ScriptedStep("UID FETCH", lines=fetch_lines(7)),
        ScriptedStep("UID MOVE", lines=[b"OK [COPYUID 9002 7 437]"]),
        ScriptedStep("UID FETCH", lines=fetch_lines(437)),
    ])
    status = await MigrationEngine(store, lambda: second).migrate_uid(7)
    assert status == MigrationStatus.CONFIRMED


@pytest.mark.asyncio()
async def test_copy_ok_expunge_lost_then_uid_scoped_retry(store):
    first = gateway(["UIDPLUS"], [
        ScriptedStep("UID FETCH", lines=fetch_lines(7)),
        ScriptedStep("UID COPY", lines=[b"OK [COPYUID 9002 7 437]"]),
        ScriptedStep("UID FETCH", lines=fetch_lines(437)),
        ScriptedStep("UID STORE", lines=[b"* 7 FETCH (UID 7 FLAGS (\\Deleted))"]),
        ScriptedStep("UID EXPUNGE", result="DISCONNECT"),
    ])
    status = await MigrationEngine(store, lambda: first).migrate_uid(7)
    assert status == MigrationStatus.COPY_OK_DELETE_UNKNOWN

    second = gateway(["UIDPLUS"], [
        ScriptedStep("UID FETCH", lines=[b"* 7 FETCH (UID 7)"]),
        ScriptedStep("UID FETCH", lines=fetch_lines(437)),
        ScriptedStep("UID STORE", lines=[b"* 7 FETCH (UID 7 FLAGS (\\Deleted))"]),
        ScriptedStep("UID EXPUNGE", lines=[b"7 EXPUNGE"]),
    ])
    status = await MigrationEngine(store, lambda: second).migrate_uid(7)
    assert status == MigrationStatus.CONFIRMED
    # Only a UID-scoped expunge is ever sent; a bare EXPUNGE never is.
    assert not any("C: EXPUNGE" in line for line in second.transcript)


@pytest.mark.asyncio()
async def test_no_uidplus_parks_review_without_mailbox_expunge(store):
    gw = gateway([], [
        ScriptedStep("UID FETCH", lines=fetch_lines(7)),
        ScriptedStep("UID COPY", lines=[b"OK [COPYUID 9002 7 437]"]),
        ScriptedStep("UID FETCH", lines=fetch_lines(437)),
        ScriptedStep("UID STORE", lines=[b"* 7 FETCH (UID 7 FLAGS (\\Deleted))"]),
    ])
    status = await MigrationEngine(store, lambda: gw).migrate_uid(7)
    assert status == MigrationStatus.REVIEW
    record = store.get(7)
    assert record.review_reason == "no-uidplus-expunge"
    assert not any("EXPUNGE" in line for line in gw.transcript)


@pytest.mark.asyncio()
async def test_lookalike_message_is_not_accepted_as_success(store):
    """A body look-alike at a different UID must never confirm the move."""
    lookalike = RFC822.replace(b"<approved-uid-7@src.example>",
                               b"<different-message-id@other>")
    first = gateway(["MOVE", "UIDPLUS"], [
        ScriptedStep("UID FETCH", lines=fetch_lines(7)),
        ScriptedStep("UID MOVE", result="DISCONNECT"),
    ])
    await MigrationEngine(store, lambda: first).migrate_uid(7)

    second = gateway(["MOVE", "UIDPLUS"], [
        ScriptedStep("UID FETCH", result="NO", lines=[b"7 OK gone"]),
        ScriptedStep("UID SEARCH", lines=[b"* SEARCH 999"]),
        ScriptedStep("UID FETCH", lines=fetch_lines(999, lookalike)),
        ScriptedStep("UID FETCH", lines=fetch_lines(7)),
    ])
    status = await MigrationEngine(store, lambda: second).migrate_uid(7)
    assert status == MigrationStatus.REVIEW
    assert store.get(7).review_reason == "move-result-ambiguous"
    assert store.get(7).target_uid is None


@pytest.mark.asyncio()
async def test_non_unique_search_result_is_ambiguous(store):
    first = gateway(["MOVE", "UIDPLUS"], [
        ScriptedStep("UID FETCH", lines=fetch_lines(7)),
        ScriptedStep("UID MOVE", result="DISCONNECT"),
    ])
    await MigrationEngine(store, lambda: first).migrate_uid(7)

    second = gateway(["MOVE", "UIDPLUS"], [
        ScriptedStep("UID FETCH", result="NO", lines=[b"7 OK gone"]),
        ScriptedStep("UID SEARCH", lines=[b"* SEARCH 437 438"]),
        ScriptedStep("UID FETCH", lines=fetch_lines(7)),
    ])
    status = await MigrationEngine(store, lambda: second).migrate_uid(7)
    assert status == MigrationStatus.REVIEW


@pytest.mark.asyncio()
async def test_unapproved_uid_is_rejected(store):
    with pytest.raises(UnknownUid):
        await MigrationEngine(store, lambda: gateway([], [])).migrate_uid(999)


@pytest.mark.asyncio()
async def test_uidvalidity_mismatch_parks_review(store):
    gw = ScriptedGateway(
        ["MOVE"],
        select_lines=[b"OK [UIDVALIDITY 1111] UIDs valid"],
        script=[ScriptedStep("UID FETCH", lines=fetch_lines(7))],
    )
    status = await MigrationEngine(store, lambda: gw).migrate_uid(7)
    assert status == MigrationStatus.REVIEW
    assert store.get(7).review_reason == "uidvalidity-mismatch"


@pytest.mark.asyncio()
async def test_terminal_record_is_immutable(store):
    gw = gateway(["MOVE", "UIDPLUS"], [
        ScriptedStep("UID FETCH", lines=fetch_lines(7)),
        ScriptedStep("UID MOVE", result="NO", lines=[b"NO refused"]),
    ])
    engine = MigrationEngine(store, lambda: gw)
    first = await engine.migrate_uid(7)
    second = await engine.migrate_uid(7)
    assert first == second == MigrationStatus.FAILED
