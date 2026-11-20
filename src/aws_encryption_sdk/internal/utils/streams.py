# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Helper stream utility objects for AWS Encryption SDK."""
import io

from wrapt import ObjectProxy

from aws_encryption_sdk.exceptions import ActionNotAllowedError, MaxHeaderLengthExceeded
from aws_encryption_sdk.internal.str_ops import to_bytes


class ROStream(ObjectProxy):
    """Provides a read-only interface on top of a file-like object.

    Used to provide MasterKeyProviders with read-only access to plaintext.

    :param wrapped: File-like object
    """

    def write(self, b):  # pylint: disable=unused-argument
        """Blocks calls to write.

        :raises ActionNotAllowedError: when called
        """
        raise ActionNotAllowedError("Write not allowed on ROStream objects")


class LimitedReadStream(ObjectProxy):
    """Provides a read-only view of a stream that may read at most a fixed
    number of bytes.

    A read larger than the remaining budget is rejected before any of the
    wrapped stream is consumed.  Reads within the budget are forwarded as
    normal, including short reads at the end of the wrapped stream.

    :param wrapped: File-like object
    :param int max_bytes: Maximum number of bytes that may be read
    """

    def __init__(self, wrapped, max_bytes):
        """Creates the limited view."""
        super(LimitedReadStream, self).__init__(wrapped)
        self.__max_bytes = max_bytes
        self.__bytes_read = 0
        self.__exceeded = False
        self.__eof = False

    @property
    def bytes_read(self):
        """Number of bytes handed out through this view."""
        return self.__bytes_read

    def read(self, b=-1):
        """Read up to ``b`` bytes without reading past the configured limit.

        A request larger than the remaining budget is rejected before any
        underlying bytes are consumed, so a header field that would cross the
        limit is never read.  Reads that reach the end of the wrapped stream
        first return a short read (or ``b""``) as usual, allowing a truncated
        header to surface as a normal parse error.

        :param int b: Number of bytes to read
        :raises MaxHeaderLengthExceeded: if the request would pass the limit
        """
        if self.__exceeded:
            raise MaxHeaderLengthExceeded(self.__bytes_read + 1, self.__max_bytes)
        if self.__eof:
            return b""
        remaining = self.__max_bytes - self.__bytes_read
        if b is None or b < 0:
            b = remaining
        if b == 0:
            return b""
        if b > remaining:
            self.__exceeded = True
            raise MaxHeaderLengthExceeded(self.__bytes_read + b, self.__max_bytes)
        data = self.__wrapped__.read(b)
        if not data:
            self.__eof = True
        self.__bytes_read += len(data)
        return data


class TeeStream(ObjectProxy):
    """Provides a ``tee``-like interface on top of a file-like object, which collects read bytes
    into a local :class:`io.BytesIO`.

    :param wrapped: File-like object
    :param tee: Stream to copy read bytes into.
    :type tee: io.BaseIO
    """

    # Prime ObjectProxy's attributes to allow setting in init.
    __tee = None  # pylint: disable=unused-private-member

    def __init__(self, wrapped, tee):
        """Creates the local tee stream."""
        super(TeeStream, self).__init__(wrapped)
        self.__tee = tee

    def read(self, b=None):
        """Reads data from source, copying it into ``tee`` before returning.

        :param int b: number of bytes to read
        """
        data = self.__wrapped__.read(b)
        self.__tee.write(data)
        return data


class InsistentReaderBytesIO(ObjectProxy):
    """Wrapper around a readable stream that insists on reading exactly the requested
    number of bytes. It will keep trying to read bytes from the wrapped stream until
    either the requested number of bytes are available or the wrapped stream has
    nothing more to return.

    :param wrapped: File-like object
    """

    def read(self, b=-1):
        """Keep reading from source stream until either the source stream is done
        or the requested number of bytes have been obtained.

        :param int b: number of bytes to read
        :return: All bytes read from wrapped stream
        :rtype: bytes
        """
        remaining_bytes = b
        data = io.BytesIO()
        while True:
            try:
                chunk = to_bytes(self.__wrapped__.read(remaining_bytes))
            except ValueError:
                if self.__wrapped__.closed:
                    break
                raise

            if not chunk:
                break

            data.write(chunk)
            remaining_bytes -= len(chunk)

            if remaining_bytes <= 0:
                break
        return data.getvalue()
