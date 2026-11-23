# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Verified, atomic file delivery for streaming decryption.

:class:`aws_encryption_sdk.streaming_client.StreamDecryptor` releases plaintext a
frame at a time, as soon as each frame's authenticated-encryption tag has been
verified.  For a message that uses a signing algorithm suite this means regular
frame plaintext is observable before the message-level signature in the footer
has been checked.  Callers that hand decrypted files to another service (for
example a search index) need a stricter boundary: nothing may be published until
the whole message has been read and authenticated.

:class:`VerifiedFileDelivery` provides that boundary.  It reads the message from
a non-rewindable source exactly once into a private staging area with bounded
memory use, and publishes to the destination path only after the entire message
has been read successfully, including verification of the footer signature when
the algorithm suite is signed.  Publication is a single
:func:`os.replace`, so the destination path is either absent/unchanged or holds
the complete plaintext; a partial file is never exposed.

Only a verified delivery creates any file in the destination directory.  While
the message is being read, decrypted plaintext lives in a private staging
directory (created with mode ``0700`` under ``staging_dir``, by default the
operating system's temporary directory), either in memory or in an anonymous
temporary file.  A failed or aborted delivery leaves no file behind, in the
destination directory or in staging.  The temporary file used to publish a
successful delivery is created in the same staging directory and renamed into
place, so even a success does not leave a transient name in the destination
directory.  If the staging directory is on a different file system from the
destination, publication falls back to a hidden temporary file next to the
destination; that file is removed on any failure and is never the destination
name.

The delivery distinguishes three outcomes:

* :attr:`DeliveryStatus.COMMITTED` -- the message was fully read and
  authenticated and the complete plaintext was published exactly once.
* :attr:`DeliveryStatus.ABORTED` -- the delivery was closed before it completed;
  staged plaintext was discarded and the destination was not changed.
* :attr:`DeliveryStatus.FAILED` -- reading, verification, or destination writing
  failed; staged data and any temporary file were removed and the destination
  was not changed.

The existing :class:`aws_encryption_sdk.streaming_client.StreamDecryptor` and
``EncryptionSDKClient`` read entry points are unchanged and keep serving callers
that authenticate a message incrementally, signed or unsigned.
"""
import abc
import errno
import logging
import os
import shutil
import tempfile
from enum import Enum

import attr
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher

from aws_encryption_sdk.exceptions import AWSEncryptionSDKClientError, SerializationError
from aws_encryption_sdk.internal.formatting.deserialize import deserialize_footer, deserialize_tag
from aws_encryption_sdk.internal.formatting.encryption_context import assemble_content_aad
from aws_encryption_sdk.internal.utils import get_aad_content_string

_LOGGER = logging.getLogger(__name__)

#: Default upper bound, in plaintext bytes, for in-memory staging.
DEFAULT_STAGING_MEMORY_LIMIT = 1024 * 1024

#: Upper bound, in bytes, for each copy/read step while draining or publishing.
DEFAULT_COPY_CHUNK_SIZE = 256 * 1024

#: Default permissions for the published file.
DEFAULT_DESTINATION_MODE = 0o600

_STAGING_DIR_PREFIX = "esdk-delivery-"

#: Upper bound, in ciphertext bytes, for each streaming read of a non-framed body.
DEFAULT_NON_FRAMED_CHUNK_SIZE = 1024 * 1024


class DeliveryStatus(Enum):
    """Outcome of a verified file delivery."""

    #: Complete plaintext was verified and published.
    COMMITTED = "committed"
    #: Delivery was closed before completion; nothing was published.
    ABORTED = "aborted"
    #: Reading, verification, or destination writing failed; nothing was published.
    FAILED = "failed"


class DeliveryError(AWSEncryptionSDKClientError):
    """Base class for verified file delivery errors."""


class DeliveryVerificationError(DeliveryError):
    """Raised when a message cannot be fully read and authenticated."""


class DeliveryWriteError(DeliveryError):
    """Raised when verified plaintext cannot be published to the destination."""


class DeliveryAbortedError(DeliveryError):
    """Raised when a closed, uncommitted delivery is asked to commit."""


@attr.s
class DeliveryResult(object):
    """Describes the outcome of a :class:`VerifiedFileDelivery` attempt.

    :param DeliveryStatus status: Final status of the delivery
    :param str destination: Absolute destination path
    :param int bytes_written: Number of plaintext bytes published on success
    :param bool signed: Whether the message used a signing algorithm suite
    :param bool signature_verified: Whether the footer signature was verified
    :param header: Parsed message header, if it was read
    :param Exception error: Failure that prevented delivery, if any
    """

    status = attr.ib()
    destination = attr.ib()
    bytes_written = attr.ib()
    signed = attr.ib()
    signature_verified = attr.ib()
    header = attr.ib(default=None)
    error = attr.ib(default=None)

    @property
    def committed(self):
        """Whether the complete plaintext was published.

        :rtype: bool
        """
        return self.status is DeliveryStatus.COMMITTED

    @property
    def aborted(self):
        """Whether the delivery was closed before completion.

        :rtype: bool
        """
        return self.status is DeliveryStatus.ABORTED

    @property
    def failed(self):
        """Whether delivery failed and left the destination unchanged.

        :rtype: bool
        """
        return self.status is DeliveryStatus.FAILED


class _BoundedNonFramedDecryptor(object, metaclass=abc.ABCMeta):
    """Mixin that decrypts a non-framed body in bounded chunks.

    :class:`aws_encryption_sdk.streaming_client.StreamDecryptor` reads an entire
    non-framed body into memory before decrypting it.  Delivery must handle
    arbitrarily large files with a finite working set, so this override decrypts
    and stages the body incrementally.  Authentication is unchanged: the same
    GCM tag and footer signature are verified before delivery publishes
    anything, and the existing public decryptor keeps its own behaviour.
    """

    def _read_bytes_from_non_framed_body(self, b):
        if not getattr(self, "_bounded_non_framed_started", False):
            self._bounded_non_framed_remaining = self.body_length
            algorithm = self._header.algorithm
            aad_content_string = get_aad_content_string(
                content_type=self._header.content_type, is_final_frame=True
            )
            associated_data = assemble_content_aad(
                message_id=self._header.message_id,
                aad_content_string=aad_content_string,
                seq_num=1,
                length=self.body_length,
            )
            self._bounded_non_framed_decryptor = Cipher(
                algorithm.encryption_algorithm(self._derived_data_key),
                algorithm.encryption_mode(self._unframed_body_iv),
                backend=default_backend(),
            ).decryptor()
            self._bounded_non_framed_decryptor.authenticate_additional_data(associated_data)
            self._bounded_non_framed_started = True

        if b is None or b < 0:
            b = DEFAULT_NON_FRAMED_CHUNK_SIZE
        read_size = min(b, self._bounded_non_framed_remaining, DEFAULT_NON_FRAMED_CHUNK_SIZE)

        plaintext = b""
        if read_size > 0:
            ciphertext = self.source_stream.read(read_size)
            if not ciphertext:
                raise SerializationError(
                    "Total message body contents less than specified in body description"
                )
            if self.verifier is not None:
                self.verifier.update(ciphertext)
            plaintext = self._bounded_non_framed_decryptor.update(ciphertext)
            self._bounded_non_framed_remaining -= len(ciphertext)

        if self._bounded_non_framed_remaining == 0:
            tag = deserialize_tag(stream=self.source_stream, header=self._header, verifier=self.verifier)
            plaintext += self._bounded_non_framed_decryptor.finalize_with_tag(tag)
            self.footer = deserialize_footer(stream=self.source_stream, verifier=self.verifier)

        return plaintext


def _delivery_decryptor_class():
    """Return a ``StreamDecryptor`` subclass with bounded non-framed reads.

    Resolved lazily because :mod:`aws_encryption_sdk` imports this module from
    its package ``__init__`` before importing the streaming client.
    """
    from aws_encryption_sdk.streaming_client import StreamDecryptor

    return type("_BoundedDeliveryDecryptor", (_BoundedNonFramedDecryptor, StreamDecryptor), {})


def _build_decryptor(source, options):
    """Construct the decryptor used to read the message."""
    return _delivery_decryptor_class()(source=source, **options)


def _copy_stream(source, destination, chunk_size=DEFAULT_COPY_CHUNK_SIZE):
    """Copy all bytes from ``source`` to ``destination`` using bounded chunks.

    :returns: Number of bytes copied
    :rtype: int
    """
    copied = 0
    while True:
        chunk = source.read(chunk_size)
        if not chunk:
            return copied
        destination.write(chunk)
        copied += len(chunk)


def _fsync_directory(path):
    """Best-effort durability for a directory entry after an atomic rename."""
    try:
        directory_fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(directory_fd)
    except OSError:
        _LOGGER.debug("Could not fsync directory %s", path, exc_info=True)
    finally:
        os.close(directory_fd)


def _write_pending_file(pending_path, staging, destination_mode, chunk_size):
    """Write staged plaintext to ``pending_path`` and make its contents durable.

    :returns: Number of bytes written
    :rtype: int
    """
    staging.seek(0)
    file_descriptor = os.open(pending_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(file_descriptor, "wb") as output:
        bytes_written = _copy_stream(staging, output, chunk_size=chunk_size)
        output.flush()
        os.fsync(output.fileno())
    if destination_mode is not None:
        os.chmod(pending_path, destination_mode)
    return bytes_written


def _publish_in_place(staging_directory, staging, destination, destination_mode, chunk_size):
    """Publish by renaming a fully written file from the private staging directory.

    This keeps every temporary name out of the destination directory.  It only
    works when both paths are on the same file system.
    """
    pending_path = os.path.join(staging_directory, "pending")
    try:
        bytes_written = _write_pending_file(pending_path, staging, destination_mode, chunk_size)
        os.replace(pending_path, destination)
        _fsync_directory(os.path.dirname(destination))
        return bytes_written
    finally:
        try:
            os.unlink(pending_path)
        except OSError:
            pass


def _publish_alongside(staging, destination, destination_mode, chunk_size):
    """Publish through a hidden temporary file beside the destination.

    Used only when the staging directory is on a different file system.  The
    temporary file is removed on every failure path, so a failed write leaves
    the destination unchanged and adds no durable file.
    """
    destination_directory = os.path.dirname(destination)
    basename = os.path.basename(destination) or "delivery"
    prefix = ".{name}.esdk-".format(name=basename[:64])
    file_descriptor, temporary_path = tempfile.mkstemp(prefix=prefix, suffix=".part", dir=destination_directory)
    try:
        staging.seek(0)
        with os.fdopen(file_descriptor, "wb") as output:
            file_descriptor = None
            bytes_written = _copy_stream(staging, output, chunk_size=chunk_size)
            output.flush()
            os.fsync(output.fileno())
        if destination_mode is not None:
            os.chmod(temporary_path, destination_mode)
        os.replace(temporary_path, destination)
        temporary_path = None
        _fsync_directory(destination_directory)
        return bytes_written
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except OSError:
                _LOGGER.debug("Could not remove temporary delivery file %s", temporary_path, exc_info=True)


def _publish(staging_directory, staging, destination, destination_mode, chunk_size):
    """Atomically publish staged plaintext to ``destination``."""
    try:
        return _publish_in_place(
            staging_directory, staging, destination, destination_mode, chunk_size=chunk_size
        )
    except OSError as error:
        if error.errno != errno.EXDEV:
            raise
        _LOGGER.debug(
            "Staging directory is on a different file system; publishing beside destination", exc_info=True
        )
        return _publish_alongside(
            staging, destination, destination_mode, chunk_size=chunk_size
        )


class VerifiedFileDelivery(object):
    """Stage a decrypted message and publish it only after full verification.

    The source is read exactly once and is never sought, so it may be a pipe or
    any other non-rewindable stream.  Decrypted plaintext is staged with a
    :class:`tempfile.SpooledTemporaryFile`: up to ``staging_memory_limit`` bytes
    are held in memory and larger messages roll over to an anonymous temporary
    file.  Both live in a private directory, so no plaintext and no partial
    delivery is ever visible in the destination directory.

    Call :meth:`commit` to drain the message, verify it, and atomically publish
    the complete plaintext.  Calling :meth:`close` before :meth:`commit` aborts
    the delivery: no destination file is created or changed and the returned
    result reports ``ABORTED``.  Using the delivery as a context manager and
    leaving the block without committing likewise aborts it.

    :param source: Ciphertext source; read once and never sought
    :type source: io.IOBase or file-like
    :param destination: Path of the file to publish
    :type destination: str or os.PathLike
    :param staging_dir: Directory used for private on-disk staging (optional;
        defaults to the operating system temporary directory)
    :type staging_dir: str or None
    :param int staging_memory_limit: Maximum plaintext bytes kept in memory
    :param int destination_mode: Permission bits for the published file, or
        ``None`` to keep the temporary file's mode
    :param kwargs: All other parameters are passed to
        :class:`aws_encryption_sdk.streaming_client.StreamDecryptor`
    """

    def __init__(
        self,
        source,
        destination,
        staging_dir=None,
        staging_memory_limit=DEFAULT_STAGING_MEMORY_LIMIT,
        destination_mode=DEFAULT_DESTINATION_MODE,
        **kwargs
    ):
        self._destination = os.path.abspath(os.fspath(destination))
        destination_directory = os.path.dirname(self._destination)
        if not os.path.isdir(destination_directory):
            raise ValueError("destination directory does not exist: {}".format(destination_directory))
        if os.path.isdir(self._destination):
            raise ValueError("destination is a directory: {}".format(self._destination))
        if not isinstance(staging_memory_limit, int) or staging_memory_limit < 0:
            raise ValueError("staging_memory_limit must be a non-negative integer")
        if staging_dir is not None and not os.path.isdir(staging_dir):
            raise ValueError("staging_dir must be an existing directory")
        if destination_mode is not None and not isinstance(destination_mode, int):
            raise ValueError("destination_mode must be an integer or None")

        self._destination_mode = destination_mode
        self._staging_memory_limit = staging_memory_limit
        self._staged_bytes = 0
        self._header = None
        self._result = None
        self._closed = False
        self._decryptor = _build_decryptor(source, kwargs)

        # A private directory (mode 0700) keeps staging and publish temporaries
        # out of the destination directory name space.
        self._staging_directory = tempfile.mkdtemp(prefix=_STAGING_DIR_PREFIX, dir=staging_dir)
        try:
            if staging_memory_limit == 0:
                self._staging = tempfile.TemporaryFile(
                    mode="w+b", dir=self._staging_directory, prefix="plaintext-"
                )
            else:
                self._staging = tempfile.SpooledTemporaryFile(
                    max_size=staging_memory_limit,
                    mode="w+b",
                    dir=self._staging_directory,
                    prefix="plaintext-",
                )
        except Exception:
            shutil.rmtree(self._staging_directory, ignore_errors=True)
            raise

    @property
    def destination(self):
        """Absolute path of the destination file.

        :rtype: str
        """
        return self._destination

    @property
    def header(self):
        """Parsed message header, reading it from the source if needed.

        :rtype: aws_encryption_sdk.structures.MessageHeader
        """
        return self._decryptor.header

    @property
    def staging_memory_limit(self):
        """Maximum plaintext bytes retained in memory before rolling to disk.

        :rtype: int
        """
        return self._staging_memory_limit

    @property
    def staged_bytes(self):
        """Number of plaintext bytes read into staging so far.

        :rtype: int
        """
        return self._staged_bytes

    @property
    def staging_on_disk(self):
        """Whether staged plaintext has rolled over to an on-disk file.

        :rtype: bool
        """
        if self._staging is None:
            return False
        return bool(getattr(self._staging, "_rolled", True))

    @property
    def staging_discarded(self):
        """Whether the staging area has been destroyed.

        :rtype: bool
        """
        return self._staging is None

    @property
    def result(self):
        """Latest :class:`DeliveryResult`, or ``None`` before completion.

        :rtype: DeliveryResult or None
        """
        return self._result

    @property
    def status(self):
        """Latest :class:`DeliveryStatus`, or ``None`` before completion.

        :rtype: DeliveryStatus or None
        """
        if self._result is None:
            return None
        return self._result.status

    def _cleanup(self):
        """Destroy staged plaintext and the private staging directory."""
        if self._staging is not None:
            try:
                self._staging.close()
            except Exception:  # noqa: broad-except; cleanup must not mask the outcome
                _LOGGER.debug("Could not close staging area", exc_info=True)
            self._staging = None
        staging_directory = getattr(self, "_staging_directory", None)
        if staging_directory is not None:
            shutil.rmtree(staging_directory, ignore_errors=True)
        try:
            self._decryptor.close()
        except Exception:  # noqa: broad-except; the wrapped close may refuse an incomplete read
            _LOGGER.debug("Wrapped decryptor close raised an error", exc_info=True)

    def _stage_plaintext(self):
        """Read and authenticate the whole message, staging all plaintext."""
        self._header = self._decryptor.header
        while True:
            chunk = self._decryptor.read(DEFAULT_COPY_CHUNK_SIZE)
            if not chunk:
                break
            self._staging.write(chunk)
            self._staged_bytes += len(chunk)
        # StreamDecryptor sets ``footer`` only after it consumed a final frame and
        # deserialized the footer, which for signed suites verifies the signature.
        if not hasattr(self._decryptor, "footer"):
            raise DeliveryVerificationError(
                "Message ended before final authentication completed; nothing was published"
            )

    def _signature_state(self):
        """Return ``(signed, signature_verified)`` for the parsed header."""
        header = self._header
        if header is None:
            return False, False
        signed = bool(header.algorithm.is_signing())
        return signed, signed

    def _record_failure(self, error):
        """Record a failed delivery, discard staging, and leave the target alone."""
        signed, _ = self._signature_state()
        self._result = DeliveryResult(
            status=DeliveryStatus.FAILED,
            destination=self._destination,
            bytes_written=0,
            signed=signed,
            signature_verified=False,
            header=self._header,
            error=error,
        )
        self._closed = True
        self._cleanup()

    def commit(self):
        """Verify the whole message and publish the plaintext exactly once.

        :returns: Result describing the committed delivery
        :rtype: DeliveryResult
        :raises DeliveryVerificationError: if the message cannot be fully read or
            authenticated
        :raises DeliveryWriteError: if the verified plaintext cannot be published
        :raises DeliveryAbortedError: if the delivery was already closed
        """
        if self._result is not None and self._result.committed:
            return self._result
        if self._closed:
            if self._result is not None and self._result.status is DeliveryStatus.FAILED:
                raise DeliveryError(
                    "Delivery already failed and cannot be committed; nothing was published"
                ) from self._result.error
            raise DeliveryAbortedError(
                "Delivery was closed before completion and cannot be committed; nothing was published"
            )

        try:
            self._stage_plaintext()
        except DeliveryVerificationError as error:
            self._record_failure(error)
            raise
        except BaseException as error:
            # Includes interruption (KeyboardInterrupt and friends): staged
            # plaintext must still be destroyed and the target left untouched.
            wrapped = DeliveryVerificationError(
                "Message could not be fully read and authenticated: {}".format(error)
            )
            self._record_failure(wrapped)
            if isinstance(error, Exception):
                raise wrapped from error
            raise

        try:
            bytes_written = _publish(
                self._staging_directory,
                self._staging,
                self._destination,
                self._destination_mode,
                chunk_size=DEFAULT_COPY_CHUNK_SIZE,
            )
        except BaseException as error:
            wrapped = DeliveryWriteError(
                "Verified plaintext could not be published to {}: {}".format(self._destination, error)
            )
            self._record_failure(wrapped)
            if isinstance(error, Exception):
                raise wrapped from error
            raise

        signed, signature_verified = self._signature_state()
        self._result = DeliveryResult(
            status=DeliveryStatus.COMMITTED,
            destination=self._destination,
            bytes_written=bytes_written,
            signed=signed,
            signature_verified=signature_verified,
            header=self._header,
        )
        self._closed = True
        self._cleanup()
        return self._result

    def close(self):
        """Close the delivery, aborting it if it has not been committed.

        Closing before :meth:`commit` discards staged plaintext and reports
        ``ABORTED``; it never creates or changes the destination file.  This is
        how a caller distinguishes an intentional early stop from a complete,
        committed delivery.

        :returns: Final delivery result
        :rtype: DeliveryResult
        """
        if self._closed:
            return self._result
        signed, _ = self._signature_state()
        self._result = DeliveryResult(
            status=DeliveryStatus.ABORTED,
            destination=self._destination,
            bytes_written=0,
            signed=signed,
            signature_verified=False,
            header=self._header,
        )
        self._closed = True
        self._cleanup()
        return self._result

    def abort(self):
        """Abort the delivery, discarding staged plaintext.

        :returns: Final delivery result
        :rtype: DeliveryResult
        """
        return self.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def __del__(self):
        staging_directory = getattr(self, "_staging_directory", None)
        if staging_directory is not None:
            try:
                shutil.rmtree(staging_directory, ignore_errors=True)
            except Exception:  # noqa: broad-except; interpreter shutdown cleanup
                pass


__all__ = (
    "DEFAULT_COPY_CHUNK_SIZE",
    "DEFAULT_DESTINATION_MODE",
    "DEFAULT_STAGING_MEMORY_LIMIT",
    "DeliveryAbortedError",
    "DeliveryError",
    "DeliveryResult",
    "DeliveryStatus",
    "DeliveryVerificationError",
    "DeliveryWriteError",
    "VerifiedFileDelivery",
)
