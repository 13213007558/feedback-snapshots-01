import threading

import pytest

from loguru import logger


class FailingSink:
    """A sink whose preparation fails while the second handler is being built."""

    def __init__(self, failure):
        if failure:
            raise RuntimeError("The second new handler failed to initialize")

    def write(self, message):
        raise AssertionError("A cleaned-up handler must never receive a message")


class PreparingSink:
    """A sink that emits a record while it is being prepared, then aborts."""

    def __init__(self, log):
        log.info("during-preparation")
        raise RuntimeError("Preparation aborted")

    def write(self, message):
        raise AssertionError("A cleaned-up handler must never receive a message")


class GatedSink:
    """An enqueue sink whose worker thread blocks until the gate is opened."""

    def __init__(self, name, gate, delivered):
        self.name = name
        self.gate = gate
        self.delivered = delivered

    def write(self, message):
        self.gate.wait(timeout=5)
        self.delivered.append((self.name, str(message).strip()))


def test_reconfigure_failure_keeps_old_configuration(writer):
    logger.add(writer, format="{message}")
    logger.info("before")

    with pytest.raises(RuntimeError, match="The second new handler failed to initialize"):
        logger.reconfigure(
            handlers=[
                {"sink": writer, "format": "new: {message}"},
                {"sink": FailingSink(True)},
            ]
        )

    # The old handler is still in place and still applies its own formatting rules.
    logger.info("after-failure")

    assert writer.read() == "before\nafter-failure\n"
    assert list(logger._core.handlers) == [0]
    # The identifiers reserved during the aborted preparation can be reused.
    assert logger._core.handlers_count == 1


def test_records_dispatched_during_preparation_go_to_old_handlers(writer):
    logger.add(writer, format="old: {message}")

    with pytest.raises(RuntimeError, match="Preparation aborted"):
        logger.reconfigure(handlers=[{"sink": PreparingSink(logger)}])

    # The record emitted while the new handlers were being built is handled by the old ones.
    assert writer.read() == "old: during-preparation\n"
    assert list(logger._core.handlers) == [0]
    assert logger._core.handlers_count == 1


def test_enqueued_records_are_drained_by_old_handlers_after_failure():
    gate = threading.Event()
    old_delivered = []
    new_delivered = []

    old_id = logger.add(
        GatedSink("old", gate, old_delivered), enqueue=True, catch=False, format="{message}"
    )

    logger.info("queued-before-switch")

    with pytest.raises(RuntimeError, match="The second new handler failed to initialize"):
        logger.reconfigure(
            handlers=[
                {"sink": GatedSink("new", gate, new_delivered), "enqueue": True},
                {"sink": FailingSink(True)},
            ]
        )

    # The record already sitting in the old queue is still owned by the old configuration.
    gate.set()
    logger.complete()

    assert old_delivered == [("old", "queued-before-switch")]
    assert new_delivered == []
    assert list(logger._core.handlers) == [old_id]


def test_failed_enqueued_handler_thread_is_terminated():
    writer_threads_before = {
        thread.name for thread in threading.enumerate() if thread.name.startswith("loguru-writer-")
    }

    logger.add(lambda _: None, format="{message}")

    with pytest.raises(RuntimeError, match="The second new handler failed to initialize"):
        logger.reconfigure(
            handlers=[{"sink": lambda _: None, "enqueue": True}, {"sink": FailingSink(True)}]
        )

    writer_threads_after = {
        thread.name for thread in threading.enumerate() if thread.name.startswith("loguru-writer-")
    }

    # The worker thread spawned during the aborted preparation has been joined on cleanup.
    assert writer_threads_after == writer_threads_before
    assert list(logger._core.handlers) == [0]
    assert logger._core.handlers_count == 1


def test_successful_switch_uses_new_handlers_labels_and_filters(writer):
    logger.add(writer, format="old: {message}")
    logger.info("old-message")

    ids = logger.reconfigure(
        handlers=[
            {
                "sink": writer,
                "format": "new: {message}",
                "filter": lambda record: record["extra"].get("accepted"),
            }
        ]
    )

    logger.bind(accepted=False).info("filtered-out")
    logger.bind(accepted=True).info("accepted-message")

    assert writer.read() == "old: old-message\nnew: accepted-message\n"
    assert ids == [1]
    assert list(logger._core.handlers) == [1]


def test_reconfigure_can_succeed_after_a_failure(writer):
    logger.add(writer, format="old: {message}")

    with pytest.raises(RuntimeError, match="The second new handler failed to initialize"):
        logger.reconfigure(
            handlers=[
                {"sink": writer, "format": "new: {message}"},
                {"sink": FailingSink(True)},
            ]
        )

    ids = logger.reconfigure(handlers=[{"sink": writer, "format": "new: {message}"}])

    logger.info("after-success")

    assert writer.read() == "new: after-success\n"
    assert ids == [1]
    assert list(logger._core.handlers) == [1]


def test_reconfigure_with_empty_handlers(writer):
    logger.add(writer, format="{message}")

    ids = logger.reconfigure(handlers=[])

    logger.info("dropped")

    assert ids == []
    assert logger._core.handlers == {}
    assert logger._core.min_level == float("inf")
    assert writer.read() == ""


def test_reconfigure_requires_a_sink_in_each_config(writer):
    logger.add(writer, format="{message}")

    with pytest.raises(TypeError, match="handler at index 1"):
        logger.reconfigure(
            handlers=[{"sink": writer}, {"format": "{message}"}]
        )

    assert list(logger._core.handlers) == [0]
    assert logger._core.handlers_count == 1
