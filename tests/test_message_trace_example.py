"""The investigation example must show timed and untimed records differently."""

from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

import dissect.etl.etl as etl_module
from dissect.etl.c_etl import c_etl
from dissect.etl.etl import ETL
from examples.message_trace_investigation import GUID, START_TIME, build_demo_etl, summarise

if TYPE_CHECKING:
    import pytest


def test_demo_etl_timed_and_untimed(monkeypatch: pytest.MonkeyPatch) -> None:
    # ``tests/test_etl_buffer.py`` replaces ``dissect.etl.etl.c_etl`` with a mock
    # at module level. Restore the real definition so this test exercises the
    # public ETL path regardless of collection order.
    monkeypatch.setattr(etl_module, "c_etl", c_etl)

    etl = ETL(BytesIO(build_demo_etl()))
    results = summarise(etl)

    assert len(results) == 2

    timed, untimed = results
    assert timed["status"] == untimed["status"] == "ok"

    # Same message bytes in both records.
    assert timed["message"] == untimed["message"] == b"\x00\x10\x00\xc0demo\xff\xff\xff\xff"

    # Only the timed record has a timestamp, derived from its own FILETIME.
    assert timed["timestamp"] is not None
    assert timed["timestamp_filetime"] == START_TIME
    assert untimed["timestamp"] is None
    assert untimed["timestamp_filetime"] is None

    # The untimed record is not anchored to the logfile start.
    assert etl.start.isoformat() != untimed["timestamp"]

    # Each record keeps its own properties and process/thread evidence.
    assert timed["process_id"] == 0x1234
    assert timed["thread_id"] == 0x5678
    assert untimed["process_id"] is None
    assert untimed["thread_id"] is None
    assert untimed["guid"] == str(GUID)
    assert timed["guid"] is None
    assert timed["sequence_number"] == 1
    assert untimed["sequence_number"] == 2

    # Adjacent records still have distinct positions.
    assert timed["record_offset"] != untimed["record_offset"]
