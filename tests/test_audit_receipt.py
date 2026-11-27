import asyncio

import pytest

from loguru import logger
from loguru._audit import FAILED, PENDING, SUCCESS

from .conftest import new_event_loop_context


async def foreign_coroutine():
    logger.bind(tag="foreign").info("Held by another event loop")


def test_receipt_reports_success_failure_and_pending():
    async def sink(message):
        if message.record["extra"]["tag"] == "fail":
            raise RuntimeError("Sink write failed")

    async def main():
        other_loop = asyncio.new_event_loop()
        try:
            handler_id = logger.add(sink, audit=True, catch=True, format="{message}")

            await asyncio.to_thread(other_loop.run_until_complete, foreign_coroutine())

            logger.bind(tag="ok").info("A success")
            logger.bind(tag="fail").error("A failure")

            receipt = logger.receipt(handler_id)
            await receipt

            statuses = {
                entry.record["extra"]["tag"]: entry for entry in receipt.entries
            }

            assert statuses["ok"].status == SUCCESS
            assert statuses["fail"].status == FAILED
            assert statuses["foreign"].status == PENDING

            correlation_ids = {entry.id for entry in receipt}
            assert correlation_ids == {
                statuses["foreign"].id,
                statuses["ok"].id,
                statuses["fail"].id,
            }
            assert len(correlation_ids) == 3
            assert receipt.cutoff == max(correlation_ids)

            second_receipt = logger.receipt(handler_id)
            second_statuses = {
                entry.record["extra"]["tag"]: entry.status
                for entry in second_receipt.entries
            }
            first_statuses = {
                entry.record["extra"]["tag"]: entry.status for entry in receipt
            }
            assert second_statuses == first_statuses
            assert second_receipt.cutoff == receipt.cutoff
        finally:
            other_loop.close()

    asyncio.run(main())


def test_receipt_read_twice_returns_same_snapshot():
    async def sink(message):
        pass

    async def main():
        handler_id = logger.add(sink, audit=True, format="{message}")
        logger.bind(tag="a").info("First")
        logger.bind(tag="b").info("Second")

        receipt = logger.receipt(handler_id)
        await receipt

        first = [(entry.id, entry.status) for entry in receipt.entries]
        second = [(entry.id, entry.status) for entry in receipt.entries]

        assert first == second
        assert [entry.status for entry in receipt] == [SUCCESS, SUCCESS]

    asyncio.run(main())


def test_receipt_is_not_affected_by_later_writes():
    async def sink(message):
        pass

    async def main():
        handler_id = logger.add(sink, audit=True, format="{message}")
        logger.bind(tag="before").info("Before cutoff")

        receipt = logger.receipt(handler_id)
        await receipt

        assert len(receipt) == 1

        logger.bind(tag="after").info("After cutoff")
        await logger.complete()

        assert len(receipt) == 1
        assert [entry.record["extra"]["tag"] for entry in receipt] == ["before"]

    asyncio.run(main())


def test_enqueued_receipt_reports_success_and_failure():
    def sink(message):
        if message.record["extra"]["tag"] == "fail":
            raise RuntimeError("Sink write failed")

    handler_id = logger.add(
        sink, enqueue=True, audit=True, catch=True, format="{message}"
    )

    logger.bind(tag="ok").info("A success")
    logger.bind(tag="fail").error("A failure")
    logger.bind(tag="ok2").info("Another success")

    receipt = logger.receipt(handler_id)

    assert [entry.status for entry in receipt] == [SUCCESS, FAILED, SUCCESS]
    assert [entry.id for entry in receipt] == [1, 2, 3]

    again = logger.receipt(handler_id)
    assert [(entry.id, entry.status) for entry in again] == [
        (entry.id, entry.status) for entry in receipt
    ]

    logger.remove()


def test_enqueued_receipt_marks_unconfirmed_record_pending(capsys):
    started = asyncio.Event()
    release = asyncio.Event()

    async def slow_sink(message):
        started.set()
        await release.wait()

    with new_event_loop_context() as loop:
        handler_id = logger.add(
            slow_sink, enqueue=True, audit=True, loop=loop, format="{message}"
        )

        async def emit():
            logger.info("In flight")

        loop.run_until_complete(emit())

        async def wait_started():
            await started.wait()

        loop.run_until_complete(wait_started())

        receipt = logger.receipt(handler_id)
        entries = receipt.entries

        assert len(entries) == 1
        assert entries[0].status == PENDING

        async def finish():
            release.set()
            await logger.receipt(handler_id)

        loop.run_until_complete(finish())

        confirmed = logger.receipt(handler_id)
        assert [entry.status for entry in confirmed] == [SUCCESS]
        assert receipt.entries[0].status == PENDING

    logger.remove()
    capsys.readouterr()


def test_synchronous_read_freezes_in_flight_record_as_pending():
    async def sink(message):
        await asyncio.sleep(0)

    async def main():
        handler_id = logger.add(sink, audit=True, format="{message}")
        logger.info("In flight")

        receipt = logger.receipt(handler_id)
        assert [entry.status for entry in receipt.entries] == [PENDING]

        await logger.complete()

        assert [entry.status for entry in receipt.entries] == [PENDING]

    asyncio.run(main())


def test_receipt_for_non_audited_handler_raises():
    handler_id = logger.add(lambda message: None, format="{message}")

    with pytest.raises(ValueError, match="was not added with 'audit=True'"):
        logger.receipt(handler_id)


def test_receipt_for_unknown_handler_raises():
    with pytest.raises(ValueError, match="There is no existing handler with id 42"):
        logger.receipt(42)


def test_receipt_with_invalid_handler_id_type():
    with pytest.raises(TypeError, match="Invalid handler id"):
        logger.receipt("not-an-int")


def test_receipt_without_handler_id_groups_audited_handlers():
    async def sink(message):
        pass

    async def main():
        audited = logger.add(sink, audit=True, format="{message}")
        logger.add(sink, format="{message}")

        logger.info("Hello")

        book = logger.receipt()

        assert list(book) == [audited]
        await book
        assert len(book[audited]) == 1
        assert [entry.status for entry in book[audited]] == [SUCCESS]

    asyncio.run(main())


def test_receipt_entries_keep_correlation_identifier_and_message():
    def sink(message):
        pass

    handler_id = logger.add(
        sink, enqueue=True, audit=True, format="{message}"
    )

    logger.bind(correlation="abc-123").info("Correlated")

    receipt = logger.receipt(handler_id)
    entry = receipt[1]

    assert entry.id == 1
    assert entry.status == SUCCESS
    assert entry.record["extra"]["correlation"] == "abc-123"
    assert entry.record["message"] == "Correlated"

    with pytest.raises(KeyError):
        receipt[999]

    logger.remove()


def test_plain_complete_still_works_with_audited_handler(capsys):
    async def sink(message):
        print(message, end="")

    async def main():
        logger.add(sink, audit=True, format="{message}")
        logger.info("One")
        logger.info("Two")
        await logger.complete()

    asyncio.run(main())

    out, err = capsys.readouterr()
    assert out == "One\nTwo\n"
    assert err == ""


def test_direct_sink_failure_is_recorded_without_enqueue():
    def sink(message):
        if message.record["extra"]["tag"] == "fail":
            raise RuntimeError("Sink write failed")

    handler_id = logger.add(sink, audit=True, catch=True, format="{message}")

    logger.bind(tag="ok").info("A success")
    logger.bind(tag="fail").error("A failure")

    receipt = logger.receipt(handler_id)

    assert [entry.status for entry in receipt] == [SUCCESS, FAILED]
    assert receipt[1].record["extra"]["tag"] == "ok"
    assert receipt[2].record["extra"]["tag"] == "fail"

    logger.remove()


def test_audit_disabled_by_default_tracks_nothing():
    handler_id = logger.add(lambda message: None, format="{message}")
    logger.info("Not audited")

    handler = logger._core.handlers[handler_id]
    assert handler.audit_tracker is None

    with pytest.raises(ValueError):
        logger.receipt(handler_id)
