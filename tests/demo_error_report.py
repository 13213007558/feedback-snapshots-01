"""Demonstrate the restricted disclosure policy of handlers' error reports.

Run it from the repository root with:

    .venv/bin/python tests/demo_error_report.py

The standard error stream below stands for a platform with broader access than the log sinks.
The same records are handed to three receivers: the platform itself, an audit sink that fails
synchronously, and a coroutine receiver that first succeeds and then fails asynchronously. The
audit and remote receivers show that they still receive their own full projection of the records
even when their sibling handlers fail.

The script exits with a non-zero status if a disallowed record field or an exception value leaks
into the diagnostics written to the platform stream.
"""

import asyncio
import contextlib
import io
import sys

from loguru import logger

SECRET = "INVITATION-CODE-1234"
MESSAGE = "audit-event"


def main():
    accepted = []
    sink_ids = []

    logger.remove()

    def audit_receiver(message):
        if "local-failure" in message.record["extra"]:
            raise RuntimeError(
                "Could not persist audit event: %s" % message.record["extra"]["secret"]
            )

    async def remote_receiver(message):
        accepted.append(message.record)
        if "async-failure" in message.record["extra"]:
            raise ValueError(
                "Could not publish audit event: %s" % message.record["extra"]["secret"]
            )

    async def run():
        sink_ids.append(
            logger.add(sys.stderr, format="{message}", catch=True, error_report="restricted")
        )
        sink_ids.append(
            logger.add(audit_receiver, format="{message}", catch=True, error_report="restricted")
        )
        sink_ids.append(
            logger.add(remote_receiver, format="{message}", catch=True, error_report="restricted")
        )

        logger.bind(secret=SECRET).info(MESSAGE)
        logger.bind(secret=SECRET, **{"local-failure": True}).info(MESSAGE)
        logger.bind(secret=SECRET, **{"async-failure": True}).info(MESSAGE)

        await asyncio.sleep(0.1)
        await logger.complete()

    platform = io.StringIO()

    with contextlib.redirect_stderr(platform):
        asyncio.run(run())

    report = platform.getvalue()

    print("Audit receiver received %d projections:" % len(accepted))
    for record in accepted:
        print(
            "  - %r (secret kept for its own processing: %r)"
            % (record["message"], record["extra"]["secret"])
        )

    print()
    print("Everything written to the platform stream:")
    print(report)

    assert len(accepted) == 3
    assert "Stage: write (synchronous sink write)" in report
    assert "Stage: coroutine (asynchronous sink coroutine)" in report
    assert "Exception: RuntimeError" in report
    assert "Exception: ValueError" in report
    assert "Handler: audit_receiver" in report
    assert "Handler: remote_receiver" in report
    assert SECRET not in report
    assert "Could not persist" not in report
    assert "Could not publish" not in report

    for sink_id in sink_ids:
        logger.remove(sink_id)


if __name__ == "__main__":
    main()
