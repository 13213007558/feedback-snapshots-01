# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Authenticity-gated streaming decryptor.

The standard :class:`aws_encryption_sdk.streaming_client.StreamDecryptor` hands each
frame's plaintext to its caller as soon as that frame's per-frame authenticated
encryption tag is verified, before the message-level signature (if any) in the
footer has been checked.  Some archive formats cannot be safely published until
the entire message has been authenticated.

:class:`StagedStreamDecryptor` provides an *optional* alternative reading path:
it keeps decrypted plaintext in a controlled staging area and exposes nothing to
the caller until the underlying message is fully read and its final
authentication (footer signature, when present) has succeeded.  To keep handling
files larger than available memory, the staging area is a
:class:`tempfile.SpooledTemporaryFile`: it stays in memory up to a configurable
threshold and is transparently rolled over to a private temporary file on disk
beyond that threshold.  The staging data is destroyed when the stream is closed,
including on interruption or final verification failure.
"""
import io
import logging
import os
import tempfile

from aws_encryption_sdk.streaming_client import StreamDecryptor

_LOGGER = logging.getLogger(__name__)

# Keep small, fully-in-memory messages in RAM by default; anything larger spills
# to a private temporary file instead of being buffered entirely in memory.
DEFAULT_STAGING_SPOOL_SIZE = 10 * 1024 * 1024


class _NamedSpooledTemporaryFile(tempfile.SpooledTemporaryFile):
    """Spooled temporary file that rolls over to a named file on disk.

    The default rollover uses an unnamed OS temporary handle whose ``name`` is
    only a file descriptor, which gives callers no inspectable on-disk path.
    This variant rolls over to a :class:`tempfile.NamedTemporaryFile` created
    with ``delete=False`` so the staging location is observable on disk. The
    file is tracked by its path and explicitly unlinked on :meth:`close`, which
    keeps cleanup deterministic across platforms (including when the process is
    interrupted) rather than relying on interpreter finalization.
    """

    def rollover(self):
        if self._rolled:
            return
        previous_file = self._file
        args = self._TemporaryFileArgs
        args.update(prefix="esdk-staged-", suffix=".tmp", delete=False)
        new_file = tempfile.NamedTemporaryFile(**args)
        del self._TemporaryFileArgs

        position = previous_file.tell()
        if hasattr(new_file, "buffer"):
            new_file.buffer.write(previous_file.detach().getvalue())
        else:
            new_file.write(previous_file.getvalue())
        new_file.seek(position, 0)

        self._file = new_file
        self._rolled = True

    def close(self):
        path = self._file.name if self._rolled else None
        super(_NamedSpooledTemporaryFile, self).close()
        if path is not None:
            try:
                os.unlink(path)
            except OSError:
                # The file may already be gone; nothing else can be done here.
                _LOGGER.debug("Could not remove staging file %s", path, exc_info=True)


class StagedStreamDecryptor(io.IOBase):
    """Streaming decryptor that releases plaintext only after full authentication.

    Behaves as a standard file-like object wrapping a
    :class:`aws_encryption_sdk.streaming_client.StreamDecryptor`.  All plaintext
    produced by the wrapped decryptor is written to a controlled staging area.
    Reads from this object return no data until the entire source message has
    been processed and its final authentication has completed successfully.

    The staging area is a :class:`tempfile.SpooledTemporaryFile`.  While the
    accumulated plaintext is at or below ``staging_spool_size`` it is held in
    memory; beyond that threshold it is transparently rolled over to a private
    temporary file inside ``staging_dir``, so messages larger than the memory
    threshold can still be processed.  The staging area is removed automatically
    when this stream is closed, whether the close follows a successful read, an
    interruption, or a final verification failure.

    :param staging_spool_size: Maximum plaintext bytes to retain in memory before
        rolling the staging area over to a temporary file on disk (optional)
    :type staging_spool_size: int
    :param staging_dir: Directory in which on-disk staging files are created;
        defaults to the operating system's temporary directory (optional)
    :type staging_dir: str
    :param config: Client configuration object (config or individual parameters
        required, passed through to the wrapped :class:`StreamDecryptor`)
    :type config: aws_encryption_sdk.streaming_client.DecryptorConfig
    :param kwargs: All other parameters accepted by :class:`StreamDecryptor`
    """

    def __init__(self, staging_spool_size=DEFAULT_STAGING_SPOOL_SIZE, staging_dir=None, **kwargs):
        if not isinstance(staging_spool_size, int) or staging_spool_size < 0:
            raise ValueError("staging_spool_size must be a non-negative integer")
        if staging_dir is not None and not os.path.isdir(staging_dir):
            raise ValueError("staging_dir must be an existing directory")

        self._staging_spool_size = staging_spool_size
        self._staging_dir = staging_dir
        self._decryptor = StreamDecryptor(**kwargs)

        # Holds unauthenticated plaintext until the whole message authenticates.
        self._staging = _NamedSpooledTemporaryFile(
            max_size=staging_spool_size, dir=staging_dir
        )
        self._authenticated = False
        self._staged_bytes = 0

    @property
    def header(self):
        """Returns the parsed message header, reading it from the source if needed.

        The header is authenticated by the header authentication block before any
        body plaintext is produced, so exposing it never releases staged plaintext.

        :rtype: aws_encryption_sdk.structures.MessageHeader
        """
        return self._decryptor.header

    @property
    def authenticated(self):
        """Returns ``True`` once the full message has been authenticated.

        :rtype: bool
        """
        return self._authenticated

    @property
    def staged_bytes(self):
        """Returns the number of plaintext bytes currently held in the staging area.

        :rtype: int
        """
        return self._staged_bytes

    @property
    def staging_on_disk(self):
        """Returns ``True`` once the staging area has spilled to a temporary file.

        :rtype: bool
        """
        rolled = getattr(self._staging, "_rolled", False)
        return bool(rolled)

    @property
    def staging_path(self):
        """Returns the path of the on-disk staging file, or ``None`` while in memory.

        :rtype: str or None
        """
        if not self.staging_on_disk:
            return None
        file_handle = getattr(self._staging, "_file", None)
        return getattr(file_handle, "name", None)

    def readable(self):
        """Return ``True`` if the stream can be read from.

        :rtype: bool
        """
        return not self.closed

    def _drain_to_staging(self):
        """Read and stage every remaining plaintext chunk from the wrapped decryptor.

        :raises Exception: any error raised by the wrapped stream, including final
            verification failures, propagates to the caller; staged data remains
            held until :meth:`close` destroys it.
        """
        while True:
            chunk = self._decryptor.read(self._decryptor.line_length)
            if not chunk:
                break
            self._staging.write(chunk)
            self._staged_bytes += len(chunk)

    def _authenticate(self):
        """Drain the full message and mark the staging area as publishable."""
        if self._authenticated:
            return
        self._drain_to_staging()
        # Reaching this point means the wrapped StreamDecryptor reached end of
        # message, including footer deserialization and signature verification.
        self._authenticated = True
        self._staging.seek(0)

    def read(self, b=-1):
        """Read authenticated plaintext, blocking until full authentication.

        No data is returned until the entire source message has been read and
        authenticated.  Once authenticated, subsequent calls behave like a normal
        file read and may return fewer bytes than requested.

        :param int b: Maximum number of bytes to return; a negative value requests
            the entire authenticated plaintext
        :returns: Authenticated plaintext bytes
        :rtype: bytes
        :raises Exception: if final authentication fails or the message is truncated
        """
        if self.closed:
            raise ValueError("I/O operation on closed file")
        if b is None or b < 0:
            b = -1

        if not self._authenticated:
            self._authenticate()

        if b < 0:
            return self._staging.read()
        return self._staging.read(b)

    def tell(self):
        """Returns the number of authenticated plaintext bytes returned so far.

        :rtype: int
        """
        if not self._authenticated:
            return 0
        return self._staging.tell()

    def readline(self):
        """Read one line-sized chunk of authenticated plaintext."""
        if self.closed:
            raise ValueError("I/O operation on closed file")
        if not self._authenticated:
            self._authenticate()
        return self._staging.readline()

    def readlines(self):
        """Read all chunks of authenticated plaintext as a list."""
        return list(self)

    def __iter__(self):
        return self

    def next(self):
        if self.closed:
            raise StopIteration()
        line = self.readline()
        if not line:
            raise StopIteration()
        return line

    __next__ = next

    def writable(self):
        """This stream is read-only."""
        return False

    def writelines(self, lines):
        raise NotImplementedError("writelines is not available for this object")

    def write(self, b):
        raise NotImplementedError("write is not available for this object")

    def seek(self, offset, whence=0):
        raise NotImplementedError("seek is not available for this object")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def close(self):
        """Close the stream and destroy all staged plaintext.

        The wrapped decryptor is closed first so its own checks run, then the
        staging area is removed regardless of the outcome.  Any error from the
        wrapped stream (for example a missing footer on interruption) does not
        prevent the staged data from being cleaned up.
        """
        if self.closed:
            return
        close_error = None
        try:
            self._decryptor.close()
        except Exception as error:  # noqa: broad-except; staging cleanup must still run
            close_error = error
            _LOGGER.debug("Wrapped decryptor close raised an error: %s", error)
        finally:
            self._staging.close()
            self._staged_bytes = 0
            super(StagedStreamDecryptor, self).close()
        if close_error is not None:
            raise close_error


__all__ = ("DEFAULT_STAGING_SPOOL_SIZE", "StagedStreamDecryptor")
