# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage,
# (C) [2024] - [2026] MinIO, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""RDMA dispatch via libminiocpp.so.

Loaded lazily on first use when ``Minio(enable_rdma=True)`` was set.
``libminiocpp.so`` must be findable via the platform loader
(``LD_LIBRARY_PATH`` on Linux, or the path in the ``MINIOCPP_LIB`` env var).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import enum
import os
from typing import Optional, Union


class RDMAError(RuntimeError):
    """libminiocpp.so returned an error from a put/get call."""


class RDMANotAvailable(RDMAError):
    """RDMA cannot be used on this host (library or device unavailable)."""


class RDMAStatus(enum.IntEnum):
    """Outcome of a failed ``miniocpp_put_object``/``get_object`` call.

    The native call reports a negative byte count on failure and fills the
    trailing ``miniocpp_xfer_result`` out-parameter. The status is what makes
    the failure boundary explicit:

    ``NOT_STARTED``
        No byte was handed to the transport. Nothing reached the server, so
        the caller may retry the same operation over HTTPS with the same
        credentials and signing configuration.

    ``PARTIAL``
        The transfer began and some bytes moved. For a get, the leading
        ``bytes_transferred`` bytes of the caller's buffer are valid and the
        rest must be treated as untouched. The operation must not be
        transparently retried.

    ``COMMIT_UNKNOWN``
        All (or an unknown part of) the data may have reached the server and
        an acknowledgement may already exist. The outcome of a put is
        unknown: the caller must reconcile instead of issuing the upload
        again as if it were a fresh overwrite.
    """

    NOT_STARTED = 0
    PARTIAL = 1
    COMMIT_UNKNOWN = 2


class RDMATransferError(RDMAError):
    """Base class for a failed transfer with an explicit outcome boundary."""

    def __init__(self, message: str, *, bytes_transferred: int = 0):
        self.bytes_transferred = bytes_transferred
        super().__init__(message)


class RDMANotStarted(RDMATransferError):
    """The transfer did not start; retrying over HTTPS is safe."""


class RDMAFallbackUnavailable(RDMATransferError):
    """The transfer did not start, but HTTPS cannot stand in for it.

    Raised when the caller passed a raw int pointer, which may name device
    memory: nothing was sent, yet the CPU cannot read or write that memory to
    carry the same operation over HTTP. Pass a host buffer to enable the
    fallback.
    """


class RDMAPartialTransfer(RDMATransferError):
    """The transfer started and stopped partway through.

    For a get, ``bytes_transferred`` is the length of the valid prefix of the
    caller-supplied buffer. For a put, it is the number of bytes the transport
    accepted before the failure. Never retry this as a fresh operation.
    """


class RDMAOutcomeUnknown(RDMATransferError):
    """The native call failed without a trustworthy transfer outcome."""


class RDMACommitUnknown(RDMAOutcomeUnknown):
    """A started put may already have been committed by the server.

    ``etag``/``checksum`` preserve any server acknowledgement the native call
    observed before it failed. Use them to reconcile (for example with
    ``stat_object``) instead of uploading the object again.
    """

    def __init__(
            self,
            message: str,
            *,
            bytes_transferred: int = 0,
            etag: Optional[str] = None,
            checksum: Optional[str] = None,
    ):
        self.etag = etag
        self.checksum = checksum
        super().__init__(message, bytes_transferred=bytes_transferred)


class _TransferResult(ctypes.Structure):
    """Trailing out-parameter of the native put/get calls.

    ``status`` is one of :class:`RDMAStatus` and ``bytes_transferred`` is the
    number of bytes that moved before the failure. On success the return value
    is authoritative and this struct is ignored.
    """

    _fields_ = [
        ("status", ctypes.c_int),
        ("bytes_transferred", ctypes.c_size_t),
    ]


# Largest transfer a single RDMA descriptor can describe: the
# x-amz-rdma-token carries the window size in a 32-bit field, so a buffer past
# this cannot be named to the server at all. Reject it with a clear error
# instead of an opaque C failure; split the transfer into parts no larger than
# this (multipart upload / ranged read). Keep in step with
# kRDMAMaxMemoryRegSize in minio-cpp -- a value even one byte larger lets a
# buffer through here that libminiocpp then declines, silently falling back to
# a much slower HTTP transfer.
_RDMA_MAX_MEMORY_REG_SIZE = 2**32 - 1  # 4 GiB - 1


_LIB: Optional[ctypes.CDLL] = None


def _load() -> ctypes.CDLL:
    """Load libminiocpp.so once and register all ctypes signatures."""
    global _LIB  # pylint: disable=global-statement
    if _LIB is not None:
        return _LIB

    path = os.environ.get("MINIOCPP_LIB")
    if not path:
        path = ctypes.util.find_library("miniocpp") or "libminiocpp.so"
    try:
        lib = ctypes.CDLL(path)
    except OSError as exc:
        raise RDMANotAvailable(
            f"failed to load libminiocpp.so ({path}): {exc}. "
            "Install minio-cpp with -DMINIO_CPP_ENABLE_RDMA=ON "
            "or set MINIOCPP_LIB."
        ) from exc

    void_p = ctypes.c_void_p
    c_char_p = ctypes.c_char_p
    c_size_t = ctypes.c_size_t
    c_ssize_t = ctypes.c_ssize_t
    c_int = ctypes.c_int
    char_buf64 = ctypes.c_char * 64

    lib.miniocpp_client_new.argtypes = [
        c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_int,
    ]
    lib.miniocpp_client_new.restype = void_p

    lib.miniocpp_client_free.argtypes = [void_p]
    lib.miniocpp_client_free.restype = None

    # The trailing _TransferResult out-parameter carries the failure boundary
    # (NOT_STARTED / PARTIAL / COMMIT_UNKNOWN). Libraries predating it simply
    # leave the sentinel we pre-fill in place, which is reported as an unknown
    # outcome -- never as "safe to retry".
    lib.miniocpp_put_object.argtypes = [
        void_p, c_char_p, c_char_p, void_p, c_size_t,
        void_p, void_p, char_buf64, char_buf64,
        ctypes.POINTER(_TransferResult),
    ]
    lib.miniocpp_put_object.restype = c_ssize_t

    lib.miniocpp_get_object.argtypes = [
        void_p, c_char_p, c_char_p, void_p, c_size_t, void_p, void_p,
        ctypes.POINTER(_TransferResult),
    ]
    lib.miniocpp_get_object.restype = c_ssize_t

    lib.miniocpp_alloc_aligned.argtypes = [c_size_t]
    lib.miniocpp_alloc_aligned.restype = void_p

    lib.miniocpp_free_aligned.argtypes = [void_p]
    lib.miniocpp_free_aligned.restype = None

    lib.miniocpp_rdma_available.argtypes = []
    lib.miniocpp_rdma_available.restype = c_int

    lib.miniocpp_last_error.argtypes = []
    lib.miniocpp_last_error.restype = c_char_p

    _LIB = lib
    return lib


def is_available() -> bool:
    """True if libminiocpp.so loaded and this host has a usable RDMA device.

    Reports a usable local device, not a reachable server: DC is
    connectionless, so there is no session to probe. A server that will not
    serve RDMA declines per request with ``x-amz-rdma-reply: 501``, and the
    caller falls back to HTTP there.
    """
    try:
        return _load().miniocpp_rdma_available() != 0
    except RDMANotAvailable:
        return False


def alloc_aligned(size: int) -> int:
    """Allocate a page-aligned buffer.

    Returns a raw pointer as int, or 0 on failure.
    """
    return _load().miniocpp_alloc_aligned(size) or 0


def free_aligned(ptr: int) -> None:
    """Release a buffer previously returned by :func:`alloc_aligned`."""
    if ptr:
        _load().miniocpp_free_aligned(ptr)


def _last_error(lib: ctypes.CDLL) -> str:
    """Return the thread-local last error string from libminiocpp."""
    msg = lib.miniocpp_last_error()
    return msg.decode() if msg else "unknown error"


def _new_transfer_result() -> _TransferResult:
    """Return an out-parameter pre-filled with the "no outcome" sentinel.

    A library that fills the struct overwrites the sentinel; one that does not
    (older libminiocpp) leaves it in place, so a failure without a reported
    boundary is treated as an unknown outcome rather than "safe to retry".
    """
    # ctypes Structure fields are initialized through its constructor.
    return _TransferResult(status=-1, bytes_transferred=0)


def _transfer_failure(
    operation: str,
    detail: str,
    result: _TransferResult,
    *,
    etag: str = "",
    checksum: str = "",
) -> RDMATransferError:
    """Map a native failure onto the typed transfer-outcome boundary."""
    try:
        status = RDMAStatus(result.status)
    except ValueError:
        return RDMAOutcomeUnknown(
            f"RDMA {operation} failed without a reported outcome: {detail}",
            bytes_transferred=int(result.bytes_transferred),
        )

    moved = int(result.bytes_transferred)
    if status is RDMAStatus.NOT_STARTED:
        if moved:
            return RDMAOutcomeUnknown(
                f"RDMA {operation} reported no start but "
                f"{moved} bytes moved: {detail}",
                bytes_transferred=moved,
            )
        return RDMANotStarted(
            f"RDMA {operation} did not start: {detail}"
        )
    if status is RDMAStatus.PARTIAL:
        return RDMAPartialTransfer(
            f"RDMA {operation} transferred {moved} bytes before failing; "
            f"do not retry as a fresh operation: {detail}",
            bytes_transferred=moved,
        )
    if operation == "put":
        return RDMACommitUnknown(
            f"RDMA put outcome is unknown; the server may already have "
            f"committed the object, reconcile before retrying: {detail}",
            bytes_transferred=moved,
            etag=etag or None,
            checksum=checksum or None,
        )
    return RDMAOutcomeUnknown(
        f"RDMA {operation} failed after {moved} bytes with an unknown "
        f"outcome; treat the already-written prefix as valid and the rest "
        f"as untouched: {detail}",
        bytes_transferred=moved,
    )


def _buffer_pointer(
    buf: Union[int, memoryview, bytes, bytearray],
    *,
    writable: bool,
) -> tuple[int, int, object]:
    """Return ``(ptr, length, owner)`` for a buffer-protocol object or int.

    ``owner`` is the object that backs the returned pointer. The caller MUST
    keep it referenced until the C call that uses ``ptr`` has returned;
    otherwise the backing memory may be freed and ``ptr`` left dangling.

    For raw int pointers the caller-supplied length is unknown; returns 0 for
    length (the caller must pass it separately) and ``None`` as the owner.

    When ``writable`` is True the C side writes results back through ``ptr``,
    so a read-only source (``bytes`` or a read-only ``memoryview``) is
    rejected rather than silently writing into a throwaway copy the caller
    would never see.
    """
    if isinstance(buf, int):
        # bool is a subclass of int: True would be taken as address 1.
        if isinstance(buf, bool):
            raise TypeError("raw RDMA pointer must be an int, not bool")
        # A non-positive value is either null (0) or, when negative, coerced
        # by ctypes.c_void_p into a huge unsigned address — both invalid.
        if buf <= 0:
            raise ValueError("raw RDMA pointer must be a positive address")
        return buf, 0, None
    if isinstance(buf, bytes):
        if writable:
            raise ValueError(
                "read-only bytes cannot be used as an RDMA get target; "
                "pass a bytearray or writable memoryview"
            )
        owner = (ctypes.c_char * len(buf)).from_buffer_copy(buf)
        return ctypes.addressof(owner), len(buf), owner
    if isinstance(buf, bytearray):
        owner = (ctypes.c_char * len(buf)).from_buffer(buf)
        return ctypes.addressof(owner), len(buf), owner
    if isinstance(buf, memoryview):
        if not buf.contiguous:
            raise ValueError("memoryview must be contiguous for RDMA")
        if buf.readonly:
            if writable:
                raise ValueError(
                    "read-only memoryview cannot be used as an RDMA get "
                    "target; pass a writable buffer"
                )
            owner = (ctypes.c_char * buf.nbytes).from_buffer_copy(buf)
            return ctypes.addressof(owner), buf.nbytes, owner
        owner = (ctypes.c_char * buf.nbytes).from_buffer(buf)
        return ctypes.addressof(owner), buf.nbytes, owner
    raise TypeError(
        f"unsupported buffer type for RDMA: {type(buf).__name__}; "
        "pass memoryview, bytearray, bytes, or raw int pointer"
    )


class RDMAClient:
    """Wraps a single miniocpp_client* handle."""

    # pylint: disable=too-many-positional-arguments,too-many-arguments
    def __init__(self, endpoint: str, region: str, access_key: str,
                 secret_key: str, session_token: str, secure: bool):
        lib = _load()
        self._lib = lib
        self._handle = lib.miniocpp_client_new(
            endpoint.encode(),
            region.encode() if region else b"",
            access_key.encode() if access_key else b"",
            secret_key.encode() if secret_key else b"",
            session_token.encode() if session_token else b"",
            1 if secure else 0,
        )
        if not self._handle:
            raise RDMAError(f"miniocpp_client_new: {_last_error(lib)}")

    def close(self) -> None:
        """Release the underlying miniocpp_client* handle."""
        handle = getattr(self, "_handle", None)
        if handle:
            self._lib.miniocpp_client_free(handle)
            self._handle = None

    def __del__(self):
        self.close()

    def put(self, bucket: str, obj: str,
            buf: Union[int, memoryview, bytes, bytearray],
            length: Optional[int] = None) -> tuple[int, str, str]:
        """Put ``buf`` to ``bucket/obj`` via RDMA.

        Returns (bytes, etag, checksum).
        """
        # ``owner`` backs ``ptr``; it must stay referenced until the C call
        # below returns, else the buffer is freed and ``ptr`` dangles.
        ptr, inferred, owner = _buffer_pointer(buf, writable=False)
        size = length if length is not None else inferred
        if size <= 0:
            raise ValueError("length must be > 0 for RDMA put")
        if owner is not None and size > inferred:
            raise ValueError(
                f"length {size} exceeds buffer size {inferred}"
            )
        if size > _RDMA_MAX_MEMORY_REG_SIZE:
            raise ValueError(
                f"RDMA put size {size} exceeds the "
                f"{_RDMA_MAX_MEMORY_REG_SIZE} bytes an RDMA descriptor can "
                f"describe; split into parts of at most that many "
                f"bytes (multipart upload / ranged read)"
            )
        etag = (ctypes.c_char * 64)()
        checksum = (ctypes.c_char * 64)()
        result = _new_transfer_result()
        nbytes = self._lib.miniocpp_put_object(
            self._handle, bucket.encode(), obj.encode(),
            ctypes.c_void_p(ptr), size, None, None, etag, checksum, result,
        )
        del owner
        if nbytes < 0:
            raise _transfer_failure(
                "put",
                _last_error(self._lib),
                result,
                etag=etag.value.decode(errors="replace").replace('"', ""),
                checksum=checksum.value.decode(errors="replace"),
            )
        return (
            int(nbytes),
            etag.value.decode(errors="replace").replace('"', ""),
            checksum.value.decode(errors="replace"),
        )

    def get(self, bucket: str, obj: str,
            buf: Union[int, memoryview, bytearray],
            length: Optional[int] = None) -> int:
        """RDMA-get ``bucket/obj`` into ``buf``; returns the byte count."""
        # ``owner`` backs ``ptr``; it must stay referenced until the C call
        # below returns, else the buffer is freed and ``ptr`` dangles.
        ptr, inferred, owner = _buffer_pointer(buf, writable=True)
        size = length if length is not None else inferred
        if size <= 0:
            raise ValueError("length must be > 0 for RDMA get")
        if owner is not None and size > inferred:
            raise ValueError(
                f"length {size} exceeds buffer size {inferred}"
            )
        if size > _RDMA_MAX_MEMORY_REG_SIZE:
            raise ValueError(
                f"RDMA get size {size} exceeds the "
                f"{_RDMA_MAX_MEMORY_REG_SIZE} bytes an RDMA descriptor can "
                f"describe; split into parts of at most that many "
                f"bytes (multipart upload / ranged read)"
            )
        result = _new_transfer_result()
        nbytes = self._lib.miniocpp_get_object(
            self._handle, bucket.encode(), obj.encode(),
            ctypes.c_void_p(ptr), size, None, None, result,
        )
        del owner
        if nbytes < 0:
            raise _transfer_failure("get", _last_error(self._lib), result)
        return int(nbytes)
