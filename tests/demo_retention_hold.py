"""Runnable demo: retention holds, ordinary logs and a failed compression.

Run from the repository root:

    .venv/bin/python tests/demo_retention_hold.py

Everything happens inside a fresh temporary directory, which is printed and
left on disk for inspection.
"""

import contextlib
import datetime
import gzip
import io
import os
import tempfile

from loguru import logger
from loguru._file_sink import PARTIAL_SUFFIX, write_hold


def rotate_on_signal(message, _):
    return message.record["extra"].get("rotate", False)


def snapshot(directory):
    return sorted(
        name
        for name in os.listdir(directory)
        if os.path.isfile(os.path.join(directory, name))
    )


def main():
    directory = tempfile.mkdtemp(prefix="loguru-hold-demo-")
    print("Working directory:", directory)

    held = os.path.join(directory, "service.2026-11-20_00-00-00_000000.log")
    ordinary = os.path.join(directory, "service.2026-11-21_00-00-00_000000.log")
    expired = os.path.join(directory, "service.2026-11-22_00-00-00_000000.log")

    for path, body in [
        (held, "incident evidence\n"),
        (ordinary, "ordinary old log\n"),
        (expired, "expired hold log\n"),
    ]:
        with open(path, "w") as file:
            file.write(body)

    write_hold(held, datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
    write_hold(expired, datetime.datetime(2026, 11, 23, tzinfo=datetime.timezone.utc))

    candidates_seen = []

    def retention(logs):
        names = sorted(os.path.basename(path) for path in logs)
        candidates_seen.append(names)
        print("  retention candidates:", names)
        for path in sorted(logs, key=os.path.getmtime)[:-2]:
            os.remove(path)

    real_open = gzip.open
    state = {"parts": 0, "failed": False}

    def flaky_open(path, *args, **kwargs):
        if isinstance(path, str) and path.endswith(PARTIAL_SUFFIX):
            state["parts"] += 1
            if state["parts"] == 3 and not state["failed"]:
                state["failed"] = True
                handle = real_open(path, *args, **kwargs)
                handle.write(b"partial output")
                handle.close()
                raise OSError("Compression interrupted")
        return real_open(path, *args, **kwargs)

    gzip.open = flaky_open

    logger.add(
        os.path.join(directory, "service.log"),
        format="{message}",
        rotation=rotate_on_signal,
        retention=retention,
        compression="gz",
        catch=True,
    )

    print("\n-- before rotation --")
    print("  files:", snapshot(directory))

    logger.info("first active chunk")
    print("\n-- first rotation (one compression fails) --")
    with contextlib.redirect_stderr(io.StringIO()):
        logger.bind(rotate=True).info("first rotation")
    print("  (the OSError raised by the failing callback was caught by loguru)")
    print("  files:", snapshot(directory))
    print("  retention ran:", bool(candidates_seen))

    print("\n-- second rotation (recovery succeeds) --")
    logger.bind(rotate=True).info("second rotation")
    print("  files:", snapshot(directory))
    leftovers = [name for name in snapshot(directory) if name.endswith(PARTIAL_SUFFIX)]
    print("  half-finished files left:", leftovers)

    logger.remove()
    print("\nFinal directory:", directory)


if __name__ == "__main__":
    main()
