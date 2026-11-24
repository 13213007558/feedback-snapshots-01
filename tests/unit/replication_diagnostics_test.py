# -*- coding: utf-8 -*-
"""End-to-end diagnostics tests for ordinary and multipart replication."""

# pylint: disable=invalid-name,missing-function-docstring,no-self-use
# pylint: disable=redefined-outer-name,unused-argument

from __future__ import annotations

import base64
import io
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlsplit

import pytest

from minio import Minio
from minio.args import SourceObject
from minio.diagnostics import (SOURCE_SSE_MATERIAL,
                               SYNTHETIC_RESPONSE_MATERIAL,
                               TARGET_SSE_MATERIAL, DiagnosticRecorder,
                               RecordingTransport, ReplicationDiagnostics,
                               shareable_error)
from minio.sse import SseCustomerKey

SOURCE_MARKER = b"source-placeholder-material-0001".ljust(32, b"x")[:32]
TARGET_MARKER = b"target-placeholder-material-0002".ljust(32, b"x")[:32]
MP_SOURCE_MARKER = b"mp-source-placeholder-0003".ljust(32, b"x")[:32]
MP_TARGET_MARKER = b"mp-target-placeholder-0004".ljust(32, b"x")[:32]
RESPONSE_MARKER = "synthetic-response-internal-marker-7558-061"

assert len(SOURCE_MARKER) == 32
assert len(TARGET_MARKER) == 32


class FakeResponse:
    """Small urllib3-like response."""

    def __init__(self, status, data=b"", headers=None):
        self.status = status
        self.data = data if isinstance(data, bytes) else data.encode()
        header_items = (headers or {}).items()
        self.headers = {
            "content-type": "application/xml",
            **{key.lower(): value for key, value in header_items},
        }

    def read(self, cache_content=False):
        return self.data

    def release_conn(self):
        return None


def xml_error():
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<Error><Code>InternalError</Code>"
        f"<Message>part copy failed: {RESPONSE_MARKER}</Message>"
        "<RequestId>request-id-failure</RequestId></Error>"
    ).encode()


def copy_part_xml():
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<CopyPartResult>"
        "<ETag>&quot;part-etag&quot;</ETag>"
        "<LastModified>2026-11-24T10:00:00.000Z</LastModified>"
        "</CopyPartResult>"
    ).encode()


def copy_object_xml():
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<CopyObjectResult><ETag>&quot;object-etag&quot;</ETag>"
        "<LastModified>2026-11-24T10:00:00.000Z</LastModified>"
        "</CopyObjectResult>"
    ).encode()


class ReplicationBackend:
    """Stateful local S3 transport with one injected part-copy failure."""

    def __init__(self):
        self.lock = threading.RLock()
        self.upload_count = 0
        self.part_failures_left = 1
        self.initial_head_seen = set()
        self.both_jobs_seen = threading.Event()

    def __call__(self, request):
        parsed = urlsplit(request["url"])
        query = parse_qs(parsed.query, keep_blank_values=True)
        method = request["method"].upper()
        object_name = parsed.path.rsplit("/", 1)[-1]

        if method == "HEAD":
            with self.lock:
                self.initial_head_seen.add(object_name)
                if len(self.initial_head_seen) == 2:
                    self.both_jobs_seen.set()
            self.both_jobs_seen.wait(5)
            size = 1024 if object_name == "ordinary-source" else (
                5 * 1024 ** 3 + 64
            )
            return FakeResponse(
                200,
                b"",
                {"ETag": '"source-etag"', "Content-Length": str(size)},
            )

        if method == "PUT" and "partNumber" in query:
            with self.lock:
                fail = self.part_failures_left > 0
                if fail:
                    self.part_failures_left -= 1
            if fail:
                return FakeResponse(
                    500,
                    xml_error(),
                    {"x-internal-debug-marker": RESPONSE_MARKER},
                )
            return FakeResponse(200, copy_part_xml())

        if method == "POST" and "uploads" in query:
            with self.lock:
                self.upload_count += 1
                upload_id = f"upload-{self.upload_count}"
            body = (
                "<InitiateMultipartUploadResult>"
                "<Bucket>target-bucket</Bucket>"
                "<Key>multipart-target</Key>"
                f"<UploadId>{upload_id}</UploadId>"
                "</InitiateMultipartUploadResult>"
            ).encode()
            return FakeResponse(200, body)

        if method == "POST" and "uploadId" in query:
            body = (
                "<CompleteMultipartUploadResult>"
                "<ETag>&quot;complete-etag&quot;</ETag>"
                "</CompleteMultipartUploadResult>"
            ).encode()
            return FakeResponse(200, body)

        if method == "DELETE" and "uploadId" in query:
            return FakeResponse(204, b"")

        if method == "PUT":
            return FakeResponse(200, copy_object_xml())

        raise AssertionError(f"unexpected request {method} {request['url']}")


def header_value(request, suffix):
    for key, value in request["headers"].items():
        if key.lower().endswith(suffix):
            return value
    raise AssertionError(f"missing header ending {suffix}")


@pytest.fixture
def scenario():
    backend = ReplicationBackend()
    transport = RecordingTransport(handler=backend)
    client = Minio(
        endpoint="localhost:9000",
        secure=False,
        region="us-east-1",
        access_key="AKIA-TEST",
        secret_key="secret-key-for-signature",
        http_client=transport,
    )
    trace = io.StringIO()
    client.trace_on(trace)
    recorder = DiagnosticRecorder()
    recorder.protect(RESPONSE_MARKER, SYNTHETIC_RESPONSE_MATERIAL)
    diagnostics = ReplicationDiagnostics(
        client, recorder=recorder, max_attempts=2,
    )

    def run_ordinary():
        return diagnostics.copy(
            job_id="ordinary-copy-job",
            bucket_name="target-bucket",
            object_name="ordinary-target",
            source=SourceObject(
                bucket_name="source-bucket",
                object_name="ordinary-source",
                ssec=SseCustomerKey(SOURCE_MARKER),
            ),
            sse=SseCustomerKey(TARGET_MARKER),
        )

    def run_multipart():
        return diagnostics.copy(
            job_id="multipart-recovery-job",
            bucket_name="target-bucket",
            object_name="multipart-target",
            source=SourceObject(
                bucket_name="source-bucket",
                object_name="multipart-source",
                ssec=SseCustomerKey(MP_SOURCE_MARKER),
            ),
            sse=SseCustomerKey(MP_TARGET_MARKER),
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        ordinary_future = pool.submit(run_ordinary)
        multipart_future = pool.submit(run_multipart)
        ordinary = ordinary_future.result(timeout=10)
        multipart = multipart_future.result(timeout=10)

    return {
        "client": client,
        "transport": transport,
        "trace": trace.getvalue(),
        "recorder": recorder,
        "diagnostics": diagnostics,
        "ordinary": ordinary,
        "multipart": multipart,
    }


def test_actual_requests_keep_signed_and_sse_material(scenario):
    requests = scenario["transport"].requests
    assert requests

    source_name = (
        "x-amz-copy-source-server-side-encryption-customer-key"
    )
    target_name = "x-amz-server-side-encryption-customer-key"
    source_values = [
        value
        for request in requests
        for key, value in request["headers"].items()
        if key.lower() == source_name
    ]
    target_values = [
        value
        for request in requests
        if request["method"].upper() != "HEAD"
        for key, value in request["headers"].items()
        if key.lower() == target_name
    ]

    assert source_values and target_values
    assert len(set(source_values)) == 2
    assert len(set(target_values)) == 2
    decoded_sources = {base64.b64decode(value) for value in source_values}
    decoded_targets = {base64.b64decode(value) for value in target_values}
    assert SOURCE_MARKER in decoded_sources
    assert TARGET_MARKER in decoded_targets
    assert MP_SOURCE_MARKER in decoded_sources
    assert MP_TARGET_MARKER in decoded_targets
    assert source_values[0] not in target_values

    for request in requests:
        authorization = header_value(request, "authorization")
        assert authorization.startswith("AWS4-HMAC-SHA256")
        assert "Signature=" in authorization


def test_trace_is_correlated_and_redacts_materials(scenario):
    trace = scenario["trace"]
    recorder = scenario["recorder"]
    raw_values = []
    for request in scenario["transport"].requests:
        for key, value in request["headers"].items():
            lowered = key.lower()
            if "sse-customer-key" in lowered or lowered == "authorization":
                raw_values.append(str(value))

    assert "ordinary-copy-job" in trace
    assert "multipart-recovery-job" in trace
    assert "attempt=1" in trace and "attempt=2" in trace
    assert "upload_part_copy" in trace
    assert "create_multipart_upload" in trace
    assert "[REDACTED]:source_sse_material" in trace
    assert "[REDACTED]:target_sse_material" in trace
    assert RESPONSE_MARKER not in trace
    for marker in (
            SOURCE_MARKER, TARGET_MARKER, MP_SOURCE_MARKER, MP_TARGET_MARKER,
    ):
        assert marker.decode() not in trace
    for value in raw_values:
        assert value not in trace

    shareable = recorder.to_json()
    assert "ordinary-copy-job" in shareable
    assert "multipart-recovery-job" in shareable
    assert RESPONSE_MARKER not in shareable
    for marker in (
            SOURCE_MARKER, TARGET_MARKER, MP_SOURCE_MARKER, MP_TARGET_MARKER,
    ):
        assert marker.decode() not in shareable
    for value in raw_values:
        assert value not in shareable


def test_failure_and_recovery_share_one_attempt_chain(scenario):
    recorder = scenario["recorder"]
    chain = recorder.chain("multipart-recovery-job")

    assert chain.attempts == [1, 2]
    assert chain.recovered is True
    assert len(chain.failures) == 1
    assert chain.failures
    failure = chain.failures[0]
    assert failure["job_id"] == "multipart-recovery-job"
    assert failure["chain_id"] == "multipart-recovery-job"
    assert failure["attempt"] == 1
    assert failure["error"]["code"] == "InternalError"
    assert RESPONSE_MARKER not in str(failure)

    first_error = scenario["diagnostics"].attempt_errors[
        "multipart-recovery-job"
    ][0]
    safe_error = shareable_error(first_error)
    assert first_error.shareable.code == "InternalError"
    assert safe_error.chain_id == "multipart-recovery-job"
    assert safe_error.attempt == 1
    assert safe_error.code == "InternalError"
    assert RESPONSE_MARKER not in str(safe_error)
    assert "synthetic-response-internal-marker" not in str(safe_error)


def test_material_categories_are_recorded_separately(scenario):
    records = scenario["recorder"].for_job("multipart-recovery-job")
    categories = {
        material["category"]
        for record in records
        for material in record.get("materials", [])
    }
    assert SOURCE_SSE_MATERIAL in categories
    assert TARGET_SSE_MATERIAL in categories

    source_stages = {
        record["stage"]
        for record in records
        if any(
            material["category"] == SOURCE_SSE_MATERIAL
            for material in record.get("materials", [])
        )
    }
    target_stages = {
        record["stage"]
        for record in records
        if any(
            material["category"] == TARGET_SSE_MATERIAL
            for material in record.get("materials", [])
        )
    }
    assert "head_source" in source_stages or "upload_part_copy" in source_stages
    assert "create_multipart_upload" in target_stages
