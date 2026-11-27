import asyncio
import re
import sys
import time

import pytest

import loguru
from loguru import logger

from .conftest import default_threading_excepthook


def broken_sink(m):
    raise ValueError("Error!")


def test_catch_is_true(capsys):
    logger.add(broken_sink, catch=True)
    logger.debug("Fail")
    out, err = capsys.readouterr()
    assert out == ""
    assert err != ""


def test_catch_is_false(capsys):
    logger.add(broken_sink, catch=False)
    with pytest.raises(ValueError, match="Error!"):
        logger.debug("Fail")
    out, err = capsys.readouterr()
    assert out == err == ""


def test_no_sys_stderr(capsys, monkeypatch):
    with monkeypatch.context() as context:
        context.setattr(sys, "stderr", None)
        logger.add(broken_sink, catch=True)
        logger.debug("a")

        out, err = capsys.readouterr()
        assert out == err == ""


def test_broken_sys_stderr(capsys, monkeypatch):
    def broken_write(*args, **kwargs):
        raise OSError

    with monkeypatch.context() as context:
        context.setattr(sys.stderr, "write", broken_write)
        logger.add(broken_sink, catch=True)
        logger.debug("a")

        out, err = capsys.readouterr()
        assert out == err == ""


def test_encoding_error(capsys):
    def sink(m):
        raise UnicodeEncodeError("utf8", "", 10, 11, "too bad")

    logger.add(sink, catch=True)
    logger.debug("test")

    out, err = capsys.readouterr()
    lines = err.strip().splitlines()

    assert out == ""
    assert lines[0] == "--- Logging error in Loguru Handler #0 ---"
    assert lines[1].startswith("Record was: {")
    assert lines[1].endswith("}")
    assert lines[-2].startswith("UnicodeEncodeError:")
    assert lines[-1] == "--- End of logging error ---"


def test_unprintable_record(writer, capsys):
    class Unprintable:
        def __repr__(self):
            raise ValueError("Failed")

    logger.add(writer, format="{message} {extra[unprintable]}", catch=True)
    logger.bind(unprintable=1).debug("a")
    logger.bind(unprintable=Unprintable()).debug("b")
    logger.bind(unprintable=2).debug("c")

    out, err = capsys.readouterr()
    lines = err.strip().splitlines()

    assert writer.read() == "a 1\nc 2\n"
    assert out == ""
    assert lines[0] == "--- Logging error in Loguru Handler #0 ---"
    assert lines[1] == "Record was: /!\\ Unprintable record /!\\"
    assert lines[-2] == "ValueError: Failed"
    assert lines[-1] == "--- End of logging error ---"


@pytest.mark.parametrize("enqueue", [False, True])
def test_broken_sink_message(capsys, enqueue):
    logger.add(broken_sink, catch=True, enqueue=enqueue)
    logger.debug("Oops")
    time.sleep(0.1)

    out, err = capsys.readouterr()
    lines = err.strip().splitlines()

    assert out == ""
    assert lines[0] == "--- Logging error in Loguru Handler #0 ---"
    assert re.match(r"Record was: \{.*Oops.*\}", lines[1])
    assert lines[-2].startswith("ValueError: Error!")
    assert lines[-1] == "--- End of logging error ---"


@pytest.mark.parametrize("enqueue", [False, True])
def test_broken_sink_caught_keep_working(enqueue):
    output = ""

    def half_broken_sink(m):
        nonlocal output
        if m.startswith("NOK"):
            raise ValueError("Broken!")
        output += m

    logger.add(half_broken_sink, format="{message}", enqueue=enqueue, catch=True)
    logger.info("A")
    logger.info("NOK")
    logger.info("B")

    time.sleep(0.1)
    assert output == "A\nB\n"


def test_broken_sink_not_caught_enqueue():
    called = 0

    def broken_sink(m):
        nonlocal called
        called += 1
        raise ValueError("Nop")

    logger.add(broken_sink, format="{message}", enqueue=True, catch=False)

    with default_threading_excepthook():
        logger.info("A")
        logger.info("B")
        time.sleep(0.1)

    assert called == 2


# Secrets used below are intentionally distinctive so that their absence from "sys.stderr" can be
# asserted unambiguously in the restricted disclosure tests.
SECRET_VALUE = "INVITATION-CODE-1234"


def restricted_error_report(capsys):
    out, err = capsys.readouterr()
    assert out == ""
    lines = err.strip().splitlines()
    assert lines[0].startswith("--- Logging error in Loguru Handler #")
    assert lines[-1] == "--- End of logging error ---"
    return err, lines


def test_error_report_full_by_default(capsys):
    logger.add(broken_sink, catch=True)
    logger.bind(secret=SECRET_VALUE).debug("Hello")

    err, lines = restricted_error_report(capsys)

    assert "Record was: {" in lines[1]
    assert SECRET_VALUE in err
    assert "ValueError: Error!" in err
    assert "Stage:" not in err


def test_error_report_restricted_sync(capsys):
    logger.add(broken_sink, catch=True, error_report="restricted")
    logger.bind(secret=SECRET_VALUE).debug("Hello")

    err, lines = restricted_error_report(capsys)

    assert lines[1].startswith("Handler: ")
    assert lines[2] == "Stage: write (synchronous sink write)"
    assert lines[3].startswith("Record: {")
    assert SECRET_VALUE not in err
    assert "Hello" not in err
    assert "ValueError: Error!" not in err
    assert "Exception: ValueError" in lines
    assert "Broken" not in err or "broken_sink" in err


def test_error_report_restricted_keeps_allowed_fields(capsys):
    logger.add(broken_sink, catch=True, error_report={"fields": ["level", "name", "function"]})
    logger.bind(secret=SECRET_VALUE).debug("Hello")

    err, lines = restricted_error_report(capsys)

    record_line = next(line for line in lines if line.startswith("Record: "))
    assert "'level': 'DEBUG'" in record_line
    assert "'function': 'test_error_report_restricted_keeps_allowed_fields'" in record_line
    assert "secret" not in record_line
    assert "'line':" not in record_line
    assert SECRET_VALUE not in err


def test_error_report_restricted_hides_source_lines(capsys):
    logger.add(broken_sink, catch=True, error_report="restricted")

    def failing_callback():
        unreachable = "SECRET-SOURCE-LINE"  # noqa: F841
        logger.bind(secret=SECRET_VALUE).debug("Hello")

    failing_callback()

    err, _ = restricted_error_report(capsys)

    assert "test_add_option_catch.py" in err
    assert "in broken_sink" in err
    assert "SECRET-SOURCE-LINE" not in err


def test_error_report_restricted_exception_none(capsys):
    logger.add(broken_sink, catch=True, error_report={"exception": "none", "traceback": False})
    logger.bind(secret=SECRET_VALUE).debug("Hello")

    err, lines = restricted_error_report(capsys)

    assert "Exception:" not in err
    assert "Traceback (most recent call last):" not in err
    assert SECRET_VALUE not in err


def test_error_report_restricted_stage_filter(capsys):
    def broken_filter(record):
        raise RuntimeError("FILTER-%s" % SECRET_VALUE)

    logger.add(broken_sink, catch=True, error_report="restricted", filter=broken_filter)
    logger.debug("Hello")

    err, lines = restricted_error_report(capsys)

    assert lines[2] == "Stage: filter (record filtering)"
    assert SECRET_VALUE not in err


def test_error_report_restricted_stage_format(capsys):
    logger.add(broken_sink, catch=True, error_report="restricted", format="{missing[key]}")
    logger.debug("Hello")

    err, lines = restricted_error_report(capsys)

    assert lines[2] == "Stage: format (record formatting)"
    assert "Exception: ValueError" in lines


@pytest.mark.parametrize("enqueue", [False, True])
def test_error_report_restricted_enqueue(capsys, enqueue):
    logger.add(broken_sink, catch=True, enqueue=enqueue, error_report="restricted")
    logger.bind(secret=SECRET_VALUE).debug("Hello")
    logger.complete()

    err, lines = restricted_error_report(capsys)

    expected_stage = "queued-write (background thread sink write)" if enqueue else "write"
    assert any(line.startswith("Stage: " + expected_stage) for line in lines)
    assert SECRET_VALUE not in err
    assert "ValueError: Error!" not in err


def test_error_report_restricted_stop_stage(capsys):
    class StopError:
        def write(self, message):
            pass

        def stop(self):
            raise OSError("STOP-%s" % SECRET_VALUE)

    handler_id = logger.add(StopError(), catch=True, error_report="restricted")
    logger.info("A")
    logger.remove(handler_id)

    err, lines = restricted_error_report(capsys)

    assert lines[2] == "Stage: stop (sink termination)"
    assert "Exception: OSError" in lines
    assert SECRET_VALUE not in err


def test_error_report_restricted_coroutine(capsys):
    async def broken_coroutine_sink(message):
        raise ValueError("ASYNC-%s" % SECRET_VALUE)

    async def main():
        logger.add(broken_coroutine_sink, catch=True, error_report="restricted")
        logger.bind(secret=SECRET_VALUE).info("Hello")
        await asyncio.sleep(0.1)
        await logger.complete()

    asyncio.run(main())

    err, lines = restricted_error_report(capsys)

    assert lines[2] == "Stage: coroutine (asynchronous sink coroutine)"
    assert "Exception: ValueError" in lines
    assert SECRET_VALUE not in err
    assert "Hello" not in err


@pytest.mark.parametrize(
    "value",
    [
        "invalid",
        42,
        {"unknown": True},
        {"fields": "level"},
        {"fields": [1]},
        {"traceback": "yes"},
        {"exception": "full"},
    ],
)
def test_error_report_invalid(value):
    expected = (TypeError, ValueError)
    with pytest.raises(expected):
        logger.add(broken_sink, error_report=value)
    assert logger._core.handlers == {}


def test_error_report_restricted_two_sinks_acceptance(capsys):
    projections = []
    coroutine_failure = []

    class LocalFailure:
        def write(self, message):
            if "fail" not in message.record["extra"]:
                projections.append(message.record)
                return
            raise RuntimeError("LOCAL-%s" % SECRET_VALUE)

    async def remote_sink(message):
        projections.append(message.record)
        if "async-fail" in message.record["extra"]:
            coroutine_failure.append(True)
            raise ValueError("REMOTE-%s" % SECRET_VALUE)

    async def main():
        logger.add(LocalFailure(), format="{message}", catch=True, error_report="restricted")
        logger.add(remote_sink, format="{message}", catch=True, error_report="restricted")
        logger.bind(secret=SECRET_VALUE).info("audit-event")
        logger.bind(secret=SECRET_VALUE, fail=True).info("audit-event")
        logger.bind(secret=SECRET_VALUE, **{"async-fail": True}).info("audit-event")
        await asyncio.sleep(0.1)
        await logger.complete()

    asyncio.run(main())

    out, err = capsys.readouterr()

    assert out == ""
    assert len(projections) == 5
    assert all(record["message"] == "audit-event" for record in projections)
    assert all(record["extra"]["secret"] == SECRET_VALUE for record in projections)
    assert coroutine_failure == [True]

    assert err.count("Stage: write (synchronous sink write)") == 1
    assert err.count("Stage: coroutine (asynchronous sink coroutine)") == 1
    assert "Handler: " in err
    assert "Exception: RuntimeError" in err
    assert "Exception: ValueError" in err
    assert SECRET_VALUE not in err
    assert "audit-event" not in err


def test_error_report_restricted_never_projects_exception_value(capsys):
    logger.add(broken_sink, catch=True, error_report={"fields": ["exception", "message"]})

    try:
        raise KeyError(SECRET_VALUE)
    except KeyError:
        logger.exception("Hello")

    err, lines = restricted_error_report(capsys)

    assert lines[3] == "Record: {'exception': '<redacted>', 'message': '<redacted>'}"
    assert SECRET_VALUE not in err
    assert "Hello" not in err


def test_error_report_restricted_control_characters_are_escaped(capsys):
    def inject_line_break(record):
        record["name"] = "evil\n--- End of logging error ---"
        return True

    logger.add(
        broken_sink,
        catch=True,
        error_report={"fields": ["name"]},
        filter=inject_line_break,
    )
    logger.debug("Hello")

    err, lines = restricted_error_report(capsys)

    assert lines[3] == "Record: {'name': 'evil\\\\n--- End of logging error ---'}"
    # The injected line break is neutralized, so it can't forge a whole report section.
    assert lines[-1] == "--- End of logging error ---"
    assert err.count("\n--- End of logging error ---\n") == 1
    assert err.count("--- Logging error in Loguru Handler") == 1


def test_error_report_restricted_missing_field(capsys):
    logger.add(broken_sink, catch=True, error_report={"fields": ["name", "unknown"]})
    logger.debug("Hello")

    err, lines = restricted_error_report(capsys)

    assert "'unknown': '<missing>'" in lines[3]


def test_error_report_restricted_does_not_crash_on_unexpected_failure(capsys, monkeypatch):
    logger.add(broken_sink, catch=True, error_report="restricted")

    def broken_write(*args, **kwargs):
        raise RuntimeError("Cannot write")

    monkeypatch.setattr(
        loguru._error_interceptor.ErrorInterceptor, "_print_restricted", broken_write
    )

    logger.debug("Hello")  # Should neither propagate nor raise.

    out, err = capsys.readouterr()
    assert out == err == ""
