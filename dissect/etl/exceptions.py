from __future__ import annotations


class Error(Exception):
    pass


class InvalidBufferError(Error):
    pass


class InvalidHeaderError(Error):
    pass


class InvalidMarkerError(Error):
    pass


class InvalidRecordError(Error):
    pass


class ManifestNotFoundError(Error):
    pass


class InvalidTemplateError(Error):
    """Raised when a manifest template declares an invalid count or length relationship."""


class InvalidPayloadError(Error):
    """Raised when an event payload does not satisfy the count or length declarations of its template."""


class ExtendedDataItemException(Error):
    pass


class InvalidHookIdException(Error):
    pass


class NoMoreEventsError(Error):
    pass
