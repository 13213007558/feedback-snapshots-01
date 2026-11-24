# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# [2024] - [2026] MinIO, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the RDMA dispatch path. The libminiocpp.so loader is
mocked so these tests run on any host without RDMA hardware or libraries."""

from __future__ import annotations

import ctypes
import unittest
from unittest import mock

from minio.minio import Minio
from minio.rdma import (_RDMA_MAX_MEMORY_REG_SIZE, RDMAClient,
                        RDMACommitUnknown, RDMAFallbackUnavailable,
                        RDMANotStarted, RDMAOutcomeUnknown,
                        RDMAPartialTransfer, RDMAStatus)


class _FakeLib:
    """Recording local stand-in for libminiocpp.so.

    Records every native call and can be told to fail the next put/get with a
    chosen :class:`RDMAStatus` and byte count, so the dispatch boundary can be
    observed without RDMA hardware. The trailing argument of each put/get is
    the ``_TransferResult`` out-parameter the real library fills in.
    """

    def __init__(self):
        self.put_calls = []
        self.get_calls = []
        self.client_new_calls = []
        # (status, bytes_transferred) applied to the next put/get; None means
        # "succeed".
        self.put_failure = None
        self.get_failure = None
        # Acknowledgement the failing put still observed from the server.
        self.put_etag = b""
        self.put_checksum = b""
        # Leading bytes the failing get wrote into the caller's buffer.
        self.get_prefix = b""

    def _fail(self, kind, args):
        status, moved = (
            self.put_failure if kind == "put" else self.get_failure
        )
        result = args[-1]
        result.status = int(status)
        result.bytes_transferred = moved
        if kind == "put":
            ctypes.memmove(args[7], self.put_etag, len(self.put_etag))
            ctypes.memmove(args[8], self.put_checksum, len(self.put_checksum))
        elif moved and self.get_prefix:
            target = args[3]
            ptr = (
                target.value if isinstance(target, ctypes.c_void_p) else target
            )
            ctypes.memmove(ptr, self.get_prefix[:moved], moved)
        return -1

    def _stub(self, kind):
        def call(*args):
            if kind == "client_new":
                self.client_new_calls.append(args)
                return 0x1234
            if kind == "put":
                self.put_calls.append(args)
                if self.put_failure is not None:
                    return self._fail("put", args)
                etag = args[7]
                checksum = args[8]
                ctypes.memmove(etag, b'"deadbeef"\0', 11)
                ctypes.memmove(checksum, b'crc64-stub\0', 11)
                args[-1].status = int(RDMAStatus.NOT_STARTED)
                return ctypes.c_ssize_t(args[4]).value  # size arg
            if kind == "get":
                self.get_calls.append(args)
                if self.get_failure is not None:
                    return self._fail("get", args)
                return ctypes.c_ssize_t(args[4]).value
            if kind == "alloc":
                return 0
            if kind == "available":
                return 1
            return 0
        return call

    def __getattr__(self, name):
        if name == "miniocpp_client_new":
            return self._stub("client_new")
        if name == "miniocpp_put_object":
            return self._stub("put")
        if name == "miniocpp_get_object":
            return self._stub("get")
        if name == "miniocpp_rdma_available":
            return self._stub("available")
        if name == "miniocpp_alloc_aligned":
            return self._stub("alloc")
        if name == "miniocpp_free_aligned":
            return lambda *a: None
        if name == "miniocpp_client_free":
            return lambda *a: None
        if name == "miniocpp_last_error":
            return lambda: b"injected failure"
        raise AttributeError(name)


class RDMADispatchTest(unittest.TestCase):
    def setUp(self):
        import minio.rdma as rdma_mod
        self._fake = _FakeLib()
        # Stash the original loader and swap in our fake.
        self._orig = rdma_mod._LIB
        rdma_mod._LIB = self._fake
        # Patch ctypes argtype binding (loader sets these on a real CDLL only).
        # Our fake just exposes attributes by name.

    def tearDown(self):
        import minio.rdma as rdma_mod
        rdma_mod._LIB = self._orig

    def test_put_object_dispatches_to_rdma(self):
        client = Minio(
            endpoint="example.com",
            access_key="k",
            secret_key="s",
            secure=False,
            enable_rdma=True,
        )
        buf = bytearray(b"x" * 1024)
        resp = client.put_object(
            bucket_name="bucket",
            object_name="object",
            data=buf,
            length=len(buf),
        )
        self.assertEqual(resp.etag, "deadbeef")
        self.assertEqual(len(self._fake.put_calls), 1)

    def test_get_object_dispatches_to_rdma(self):
        client = Minio(
            endpoint="example.com",
            access_key="k",
            secret_key="s",
            secure=False,
            enable_rdma=True,
        )
        dst = bytearray(2048)
        n = client.get_object(
            bucket_name="bucket",
            object_name="object",
            into=dst,
            length=len(dst),
        )
        self.assertEqual(n, 2048)
        self.assertEqual(len(self._fake.get_calls), 1)

    def test_rdma_off_skips_dispatch(self):
        client = Minio(
            endpoint="example.com",
            access_key="k",
            secret_key="s",
            secure=False,
            enable_rdma=False,
        )
        # With enable_rdma=False, passing a buffer should fall through to the
        # HTTP path; calling it without a real server raises a network error,
        # not an RDMA error. We only verify the dispatch never ran.
        with self.assertRaises(Exception):
            client.put_object(
                bucket_name="bucket",
                object_name="object",
                data=bytearray(b"x"),
                length=1,
            )
        self.assertEqual(len(self._fake.put_calls), 0)


class RDMAOversizeGuardTest(unittest.TestCase):
    """The RDMA descriptor size limit is enforced (inclusive) before the
    native call. A raw pointer is used so the buffer-vs-length guard cannot
    fire first, isolating the size-limit guard."""

    def setUp(self):
        import minio.rdma as rdma_mod
        self._fake = _FakeLib()
        self._orig = rdma_mod._LIB
        rdma_mod._LIB = self._fake

    def tearDown(self):
        import minio.rdma as rdma_mod
        rdma_mod._LIB = self._orig

    def _client(self):
        return RDMAClient("example.com", "", "k", "s", "", False)

    def test_put_rejects_over_limit_without_native_call(self):
        client = self._client()
        with self.assertRaises(ValueError):
            client.put("bucket", "object", 1,
                       length=_RDMA_MAX_MEMORY_REG_SIZE + 1)
        self.assertEqual(len(self._fake.put_calls), 0)

    def test_get_rejects_over_limit_without_native_call(self):
        client = self._client()
        with self.assertRaises(ValueError):
            client.get("bucket", "object", 1,
                       length=_RDMA_MAX_MEMORY_REG_SIZE + 1)
        self.assertEqual(len(self._fake.get_calls), 0)

    def test_put_allows_exact_limit(self):
        client = self._client()
        client.put("bucket", "object", 1,
                   length=_RDMA_MAX_MEMORY_REG_SIZE)
        self.assertEqual(len(self._fake.put_calls), 1)

    def test_get_allows_exact_limit(self):
        client = self._client()
        client.get("bucket", "object", 1,
                   length=_RDMA_MAX_MEMORY_REG_SIZE)
        self.assertEqual(len(self._fake.get_calls), 1)


class _HttpResponse:
    """Minimal urllib3-style response the HTTP fallback consumes."""

    def __init__(self, data=b"", headers=None):
        self.status = 200
        self.data = data
        self.headers = headers or {}

    def read(self, size=-1):
        if size is None or size < 0:
            return self.data
        return self.data[:size]

    def release_conn(self):
        pass


class _RDMAFakeHarness(unittest.TestCase):
    """Installs a recording local RDMA stand-in for one test."""

    def setUp(self):
        import minio.rdma as rdma_mod
        self._fake = _FakeLib()
        self._orig = rdma_mod._LIB
        rdma_mod._LIB = self._fake

    def tearDown(self):
        import minio.rdma as rdma_mod
        rdma_mod._LIB = self._orig

    def _client(self):
        return Minio(
            endpoint="example.com",
            access_key="k",
            secret_key="s",
            secure=False,
            enable_rdma=True,
        )


class RDMAFailureBoundaryTest(_RDMAFakeHarness):
    """Drive the dispatcher against a recording local RDMA stand-in.

    The three native failure statuses must lead to distinct outcomes:
    NOT_STARTED falls back to HTTPS, PARTIAL surfaces the valid buffer prefix,
    and COMMIT_UNKNOWN is never re-issued as a fresh upload. No RDMA hardware
    or real server is involved.
    """

    # -- put ------------------------------------------------------------

    def test_put_not_started_falls_back_to_http(self):
        client = self._client()
        self._fake.put_failure = (RDMAStatus.NOT_STARTED, 0)
        body = bytearray(b"payload")
        http_response = _HttpResponse(
            headers={"etag": "http-etag", "x-amz-version-id": "v1"})
        with mock.patch.object(
                client, "_execute", return_value=http_response) as execute:
            resp = client.put_object(
                bucket_name="bucket",
                object_name="object",
                data=body,
                length=len(body),
            )
        # RDMA was tried first, then the same bytes went over HTTP.
        self.assertEqual(len(self._fake.put_calls), 1)
        execute.assert_called_once()
        sent = execute.call_args.kwargs
        self.assertEqual(sent["method"], "PUT")
        self.assertEqual(sent["body"], bytes(body))
        self.assertEqual(resp.etag, "http-etag")
        self.assertEqual(resp.version_id, "v1")

    def test_put_partial_does_not_attempt_http(self):
        client = self._client()
        self._fake.put_failure = (RDMAStatus.PARTIAL, 3)
        with mock.patch.object(client, "_execute") as execute:
            with self.assertRaises(RDMAPartialTransfer) as raised:
                client.put_object(
                    bucket_name="bucket",
                    object_name="object",
                    data=bytearray(b"payload"),
                    length=7,
                )
        self.assertEqual(raised.exception.bytes_transferred, 3)
        execute.assert_not_called()

    def test_put_commit_unknown_keeps_acknowledgement(self):
        client = self._client()
        self._fake.put_failure = (RDMAStatus.COMMIT_UNKNOWN, 7)
        # A server acknowledgement the native call saw before failing.
        self._fake.put_etag = b'"committed-etag"\0'
        self._fake.put_checksum = b"crc64-seen\0"
        with mock.patch.object(client, "_execute") as execute:
            with self.assertRaises(RDMACommitUnknown) as raised:
                client.put_object(
                    bucket_name="bucket",
                    object_name="object",
                    data=bytearray(b"payload"),
                    length=7,
                )
        # Not replayed over HTTP as if it were a brand-new overwrite.
        execute.assert_not_called()
        self.assertEqual(raised.exception.bytes_transferred, 7)
        self.assertEqual(raised.exception.etag, "committed-etag")
        self.assertEqual(raised.exception.checksum, "crc64-seen")

    def test_put_raw_pointer_not_started_cannot_fall_back(self):
        client = self._client()
        self._fake.put_failure = (RDMAStatus.NOT_STARTED, 0)
        with mock.patch.object(client, "_execute") as execute:
            with self.assertRaises(RDMAFallbackUnavailable):
                client.put_object(
                    bucket_name="bucket",
                    object_name="object",
                    data=0x1000,
                    length=7,
                )
        execute.assert_not_called()

    # -- get ------------------------------------------------------------

    def test_get_not_started_falls_back_and_fills_caller_buffer(self):
        client = self._client()
        self._fake.get_failure = (RDMAStatus.NOT_STARTED, 0)
        dst = bytearray(b"\0" * 8)
        http_response = _HttpResponse(data=b"abcdefgh")

        def execute(**kwargs):
            self.assertFalse(kwargs["preload_content"])
            return http_response

        with mock.patch.object(
                client, "_execute", side_effect=execute) as execute_mock:
            n = client.get_object(
                bucket_name="bucket",
                object_name="object",
                into=dst,
                length=len(dst),
            )
        self.assertEqual(len(self._fake.get_calls), 1)
        execute_mock.assert_called_once()
        self.assertEqual(n, 8)
        self.assertEqual(bytes(dst), b"abcdefgh")

    def test_get_raw_pointer_not_started_cannot_fall_back(self):
        client = self._client()
        self._fake.get_failure = (RDMAStatus.NOT_STARTED, 0)
        with mock.patch.object(client, "_execute") as execute:
            with self.assertRaises(RDMAFallbackUnavailable):
                client.get_object(
                    bucket_name="bucket",
                    object_name="object",
                    into=0x1000,
                    length=8,
                )
        execute.assert_not_called()

    def test_get_read_only_bytes_target_rejected(self):
        client = self._client()
        with self.assertRaises((TypeError, ValueError)):
            client.get_object(
                bucket_name="bucket",
                object_name="object",
                into=b"12345678",  # type: ignore[arg-type]
                length=8,
            )
        self.assertEqual(len(self._fake.get_calls), 0)

    def test_get_partial_reports_prefix_and_skips_http(self):
        client = self._client()
        self._fake.get_failure = (RDMAStatus.PARTIAL, 4)
        self._fake.get_prefix = b"WXYZ"
        dst = bytearray(b"\0" * 8)
        with mock.patch.object(client, "_execute") as execute:
            with self.assertRaises(RDMAPartialTransfer) as raised:
                client.get_object(
                    bucket_name="bucket",
                    object_name="object",
                    into=dst,
                    length=len(dst),
                )
        execute.assert_not_called()
        # The prefix the transport wrote is visible; the rest is untouched.
        self.assertEqual(raised.exception.bytes_transferred, 4)
        self.assertEqual(bytes(dst[:4]), b"WXYZ")
        self.assertEqual(bytes(dst[4:]), b"\0" * 4)

    def test_get_commit_unknown_skips_http(self):
        client = self._client()
        self._fake.get_failure = (RDMAStatus.COMMIT_UNKNOWN, 8)
        with mock.patch.object(client, "_execute") as execute:
            with self.assertRaises(RDMAOutcomeUnknown) as raised:
                client.get_object(
                    bucket_name="bucket",
                    object_name="object",
                    into=bytearray(8),
                    length=8,
                )
        self.assertNotIsInstance(raised.exception, RDMANotStarted)
        self.assertEqual(raised.exception.bytes_transferred, 8)
        execute.assert_not_called()


# A library that never fills the out-parameter must not be mistaken for
# "nothing happened"; the sentinel is reported as an unknown outcome.
_UNKNOWN_OUTCOME = -1  # sentinel for "library reported no outcome"


class RDMAUnknownOutcomeTest(_RDMAFakeHarness):
    def test_put_unreported_status_is_unknown_and_not_retried(self):
        client = self._client()
        self._fake.put_failure = (_UNKNOWN_OUTCOME, 5)
        with mock.patch.object(client, "_execute") as execute:
            with self.assertRaises(RDMAOutcomeUnknown) as raised:
                client.put_object(
                    bucket_name="bucket",
                    object_name="object",
                    data=bytearray(b"payload"),
                    length=7,
                )
        self.assertNotIsInstance(
            raised.exception, (RDMANotStarted, RDMAPartialTransfer))
        self.assertEqual(raised.exception.bytes_transferred, 5)
        execute.assert_not_called()

    def test_get_unreported_status_is_unknown_and_not_retried(self):
        client = self._client()
        self._fake.get_failure = (_UNKNOWN_OUTCOME, 5)
        with mock.patch.object(client, "_execute") as execute:
            with self.assertRaises(RDMAOutcomeUnknown) as raised:
                client.get_object(
                    bucket_name="bucket",
                    object_name="object",
                    into=bytearray(8),
                    length=8,
                )
        self.assertNotIsInstance(raised.exception, RDMANotStarted)
        self.assertEqual(raised.exception.bytes_transferred, 5)
        execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
