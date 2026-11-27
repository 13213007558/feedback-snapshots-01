import datetime
import gzip
import os

from loguru import logger
from loguru._file_sink import PARTIAL_SUFFIX, hold_is_active, hold_path, write_hold

from .conftest import check_dir


def rotate_on_signal(message, _):
    return message.record["extra"].get("rotate", False)


def test_hold_excludes_evidence_and_failed_compression_is_recovered(
    tmp_path, monkeypatch, capsys
):
    held_raw = tmp_path / "service.2026-11-20_00-00-00_000000.log"
    normal_raw = tmp_path / "service.2026-11-21_00-00-00_000000.log"
    stale_raw = tmp_path / "service.2026-11-22_00-00-00_000000.log"

    held_raw.write_text("incident evidence\n")
    normal_raw.write_text("ordinary old log\n")
    stale_raw.write_text("expired hold log\n")

    write_hold(
        str(held_raw),
        datetime.datetime(2026, 12, 1, tzinfo=datetime.timezone.utc),
    )
    write_hold(
        str(stale_raw),
        datetime.datetime(2026, 11, 23, tzinfo=datetime.timezone.utc),
    )

    seen_candidates = []

    def retention(logs):
        seen_candidates.append(sorted(os.path.basename(log) for log in logs))
        # Keep only the newest two files handed off to retention.
        for log in sorted(logs, key=os.path.getmtime)[:-2]:
            os.remove(log)

    real_gzip_open = gzip.open
    state = {"parts": 0, "failed": False, "failing": False}

    def flaky_gzip_open(path, *args, **kwargs):
        if isinstance(path, str) and path.endswith(PARTIAL_SUFFIX):
            state["parts"] += 1
            # Recovery finalizes two old archives first; the third .part write
            # is the archive of the file handed off by this rotation.
            state["failing"] = state["parts"] == 3 and not state["failed"]
            if state["failing"]:
                state["failed"] = True
                handle = real_gzip_open(path, *args, **kwargs)
                handle.write(b"partial output")
                handle.close()
                raise OSError("Compression interrupted")
        return real_gzip_open(path, *args, **kwargs)

    monkeypatch.setattr(gzip, "open", flaky_gzip_open)

    logger.add(
        tmp_path / "service.log",
        format="{message}",
        rotation=rotate_on_signal,
        retention=retention,
        compression="gz",
        catch=True,
    )

    logger.info("first active chunk")
    logger.bind(rotate=True).info("first rotation")

    # First rotation: the archive of the file just rotated fails midway. The
    # raw file stays recoverable and no half-finished archive survives.
    assert state["failed"]
    assert not list(tmp_path.glob("*" + PARTIAL_SUFFIX))
    pending_rotated = next(
        path for path in tmp_path.glob("service.2026-11-27_*.log")
    )
    check_dir(
        tmp_path,
        files=[
            ("service.2026-11-20_00-00-00_000000.log", "incident evidence\n"),
            ("service.2026-11-20_00-00-00_000000.log.hold", None),
            ("service.2026-11-21_00-00-00_000000.log.gz", None),
            ("service.2026-11-22_00-00-00_000000.log.gz", None),
            (pending_rotated.name, "first active chunk\n"),
        ],
    )
    # The interrupted rotation aborts before retention runs and before a new
    # active file is created.
    assert not (tmp_path / "service.log").exists()
    assert seen_candidates == []
    out, err = capsys.readouterr()
    assert out == ""
    assert err.count("OSError: Compression interrupted") == 1
    assert hold_is_active(str(held_raw))

    logger.bind(rotate=True).info("second rotation")

    # Second rotation succeeds: the pending raw log is compressed, the evidence
    # stays protected, and retention finally runs over finalized archives only.
    assert not pending_rotated.exists()
    assert pending_rotated.with_name(pending_rotated.name + ".gz").exists()
    assert held_raw.exists()
    assert os.path.exists(hold_path(str(held_raw)))
    assert not list(tmp_path.glob("*" + PARTIAL_SUFFIX))

    candidates = seen_candidates[-1]
    assert "service.2026-11-20_00-00-00_000000.log" not in candidates
    assert all(not name.endswith(".hold") for name in candidates)

    # Cleanup scope is limited to non-held finalized archives: the held
    # evidence survives, while ordinary archives follow the retention rule.
    remaining = {path.name for path in tmp_path.iterdir()}
    assert "service.2026-11-20_00-00-00_000000.log" in remaining
    assert "service.2026-11-20_00-00-00_000000.log.hold" in remaining
    assert not any(name.endswith(PARTIAL_SUFFIX) for name in remaining)


def test_hold_marker_follows_archive_after_compression(tmp_path):
    from functools import partial

    from loguru._file_sink import Compression

    raw = tmp_path / "service.2026-11-20_00-00-00_000000.log"
    raw.write_text("evidence\n")
    write_hold(
        str(raw), datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
    )

    compress = partial(Compression.copy_compress, opener=gzip.open, mode="wb")
    Compression.compression(str(raw), ".gz", compress)

    archive = tmp_path / "service.2026-11-20_00-00-00_000000.log.gz"
    assert archive.exists()
    assert not raw.exists()
    assert not os.path.exists(hold_path(str(raw)))
    assert os.path.exists(hold_path(str(archive)))
    assert hold_is_active(str(archive))

    with gzip.open(str(archive)) as file:
        assert file.read() == b"evidence\n"


def test_expired_hold_is_deleted_and_file_becomes_deletable(tmp_path):
    raw = tmp_path / "service.2026-11-20_00-00-00_000000.log"
    raw.write_text("old\n")
    write_hold(
        str(raw),
        datetime.datetime(2026, 11, 1, tzinfo=datetime.timezone.utc),
    )

    removed = []

    def retention(logs):
        removed.extend(logs)
        for log in logs:
            os.remove(log)

    logger.add(tmp_path / "service.log", retention=retention)
    logger.remove()

    assert not raw.exists()
    assert not os.path.exists(hold_path(str(raw)))
    assert str(raw) in removed
