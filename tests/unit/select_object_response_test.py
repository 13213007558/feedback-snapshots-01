# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# [2014] - [2025] MinIO, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for caller-scoped Select result visibility."""

from binascii import crc32
from io import BytesIO

import pytest

from minio import Minio, SelectCaller, SelectVisibility, SelectVisibilityError
from minio.error import MinioException
from minio.models import SelectObjectContentRequest, SelectObjectResponse

SCANNED = "91000111"
PROCESSED = "92000222"
RETURNED = "93000333"
RECORD_ONE = b'{"id": 1}\n'
RECORD_TWO = b'{"id": 2}\n'


def _header(name, value):
    name_bytes = name.encode()
    value_bytes = value.encode()
    return (
        bytes([len(name_bytes)]) + name_bytes + b"\x07"
        + len(value_bytes).to_bytes(2, "big") + value_bytes
    )


def _frame(event_type="", payload=b"", error_message=None):
    headers = _header(
        ":message-type", "event" if error_message is None else "error",
    )
    if event_type:
        headers += _header(":event-type", event_type)
    if error_message is not None:
        headers += _header(":error-code", "TestFailure")
        headers += _header(":error-message", error_message)

    total_length = 16 + len(headers) + len(payload)
    prelude = (
        total_length.to_bytes(4, "big")
        + len(headers).to_bytes(4, "big")
    )
    prelude_crc = crc32(prelude) & 0xFFFFFFFF
    message = prelude + prelude_crc.to_bytes(4, "big") + headers + payload
    message_crc = crc32(message) & 0xFFFFFFFF
    return (
        prelude + prelude_crc.to_bytes(4, "big") + headers + payload
        + message_crc.to_bytes(4, "big")
    )


def _stats_payload():
    return (
        "<Stats>"
        f"<BytesScanned>{SCANNED}</BytesScanned>"
        f"<BytesProcessed>{PROCESSED}</BytesProcessed>"
        f"<BytesReturned>{RETURNED}</BytesReturned>"
        "</Stats>"
    ).encode()


def _success_frames():
    return b"".join((
        _frame("Records", RECORD_ONE),
        _frame("Progress", _stats_payload()),
        _frame("Records", RECORD_TWO),
        _frame("End"),
    ))


def _failure_frames():
    message = (
        f"processing failed after processed={PROCESSED} "
        f"scanned={SCANNED} returned={RETURNED}"
    )
    return b"".join((
        _frame("Records", RECORD_ONE),
        _frame("Progress", _stats_payload()),
        _frame("Records", RECORD_TWO),
        _frame(error_message=message),
    ))


class FakeSelectHTTPResponse:
    """Minimal raw HTTP response used by SelectObjectResponse."""

    headers = {}

    def __init__(self, payload):
        self._stream = BytesIO(payload)
        self.closed = False
        self.close_count = 0
        self.release_count = 0

    def read(self, size):
        return self._stream.read(size)

    def isclosed(self):
        return self.closed

    def close(self):
        self.close_count += 1
        self.closed = True

    def release_conn(self):
        self.release_count += 1


def _response(payload, **kwargs):
    http_response = FakeSelectHTTPResponse(payload)
    response = SelectObjectResponse(
        http_response,
        bucket_name="bucket",
        region="us-east-1",
        object_name="object.json",
        **kwargs,
    )
    return response, http_response


def test_default_and_admin_callers_receive_complete_output_and_stats():
    callers = (
        {},
        {"visibility": "admin"},
        {"caller": SelectCaller("platform", "admin")},
    )
    for kwargs in callers:
        response, raw = _response(_success_frames(), **kwargs)

        chunks = list(response.stream())

        assert chunks == [RECORD_ONE, RECORD_TWO]
        assert response.stats().bytes_scanned == SCANNED
        assert response.stats().bytes_processed == PROCESSED
        assert response.stats().bytes_returned == RETURNED

        response.close()
        assert raw.close_count == 1
        assert raw.release_count == 1


def test_restricted_caller_receives_records_without_statistics():
    failure_log = []
    response, raw = _response(
        _success_frames(),
        visibility=SelectVisibility.restricted(),
        failure_log=failure_log,
    )

    chunks = list(response.stream())

    assert chunks == [RECORD_ONE, RECORD_TWO]
    assert response.stats() is None
    assert response.progress() is None
    assert failure_log == []

    response.close()
    assert raw.close_count == 1
    assert raw.release_count == 1

    structured, _ = _response(
        _success_frames(),
        caller=SelectCaller("department", "normal"),
    )
    events = list(structured.events())
    event_kinds = [event["level"] for event in events]
    assert event_kinds == ["record", "record", "end"]
    assert all("stats" not in event for event in events)


def test_restricted_early_termination_does_not_reveal_progress():
    frames = b"".join((
        _frame("Progress", _stats_payload()),
        _frame("Records", RECORD_ONE),
        _frame("Records", RECORD_TWO),
        _frame("End"),
    ))
    response, raw = _response(frames, restricted=True)

    stream = response.stream()
    assert next(stream) == RECORD_ONE
    stream.close()
    response.close()

    assert response.stats() is None
    audit_text = repr(response.audit_log)
    assert SCANNED not in audit_text
    assert PROCESSED not in audit_text
    assert RETURNED not in audit_text
    assert raw.close_count == 1
    assert raw.release_count == 1


def test_admin_succeeds_while_strict_normal_caller_fails():
    frames = _success_frames()
    admin, admin_raw = _response(frames, visibility="admin")
    assert list(admin.stream()) == [RECORD_ONE, RECORD_TWO]
    assert admin.stats() is not None
    admin.close()
    assert admin_raw.close_count == 1

    failures = []
    normal, normal_raw = _response(
        frames,
        visibility=SelectVisibility.strict(),
        failure_log=failures,
    )
    chunks = []
    with normal:
        with pytest.raises(SelectVisibilityError) as exc_info:
            for chunk in normal.stream():
                chunks.append(chunk)

    assert chunks == [RECORD_ONE]
    assert isinstance(exc_info.value, PermissionError)
    with pytest.raises(SelectVisibilityError):
        normal.stats()
    assert failures and failures[0]["level"] == "error"
    assert PROCESSED not in repr(failures)
    assert normal_raw.close_count == 1
    assert normal_raw.release_count == 1


def test_restricted_failure_keeps_records_and_redacts_stat_values(caplog):
    failure_log = []
    response, raw = _response(
        _failure_frames(),
        visibility="normal",
        failure_log=failure_log,
    )
    chunks = []

    with response:
        with pytest.raises(MinioException) as exc_info:
            for chunk in response.stream():
                chunks.append(chunk)

    assert chunks == [RECORD_ONE, RECORD_TWO]
    message = str(exc_info.value)
    assert "TestFailure" in message
    assert SCANNED not in message
    assert PROCESSED not in message
    assert RETURNED not in message
    assert failure_log
    assert all(record["level"] == "error" for record in failure_log)
    assert all(record["redacted"] for record in failure_log)
    assert not any(
        secret in repr(failure_log)
        for secret in (SCANNED, PROCESSED, RETURNED)
    )
    assert not any(
        secret in caplog.text
        for secret in (SCANNED, PROCESSED, RETURNED)
    )
    assert raw.close_count == 1
    assert raw.release_count == 1


def test_select_client_passes_visibility_to_response(monkeypatch):
    client = Minio(
        endpoint="localhost:9000",
        access_key="x",
        secret_key="y",
    )
    raw = FakeSelectHTTPResponse(_success_frames())

    def fake_execute(**kwargs):
        return raw

    monkeypatch.setattr(client, "_execute", fake_execute)
    request = SelectObjectContentRequest(
        expression="select * from S3Object",
        input_serialization=(
            SelectObjectContentRequest.CSVInputSerialization()
        ),
        output_serialization=(
            SelectObjectContentRequest.CSVOutputSerialization()
        ),
    )

    result = client.select_object_content(
        bucket_name="bucket",
        object_name="object.csv",
        request=request,
        restricted=True,
    )

    assert isinstance(result, SelectObjectResponse)
    assert result.visibility_policy.name == "restricted"
    assert list(result.stream()) == [RECORD_ONE, RECORD_TWO]
    assert result.stats() is None
    result.close()
