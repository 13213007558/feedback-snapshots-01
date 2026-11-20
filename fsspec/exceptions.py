"""
fsspec user-defined exception classes
"""

import asyncio


class BlocksizeMismatchError(ValueError):
    """
    Raised when a cached file is opened with a different blocksize than it was
    written with
    """


class FSTimeoutError(asyncio.TimeoutError):
    """
    Raised when a fsspec function timed out occurs
    """


class ConnectionNotConfigured(LookupError):
    """
    Raised when a named connection is not registered in this process

    This can happen when a deferred-open object (e.g. ``fsspec.core.OpenFile``)
    is restored by a worker which has not been configured with the connection
    alias recorded in the serialized payload.
    """
