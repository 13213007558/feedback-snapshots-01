from __future__ import annotations


class Error(Exception):
    pass


class ReferenceNotFoundError(Error):
    pass


class ClassNotFoundError(ReferenceNotFoundError):
    """Raised when a class definition does not exist in a namespace or its system fallback."""


class InvalidClassDefinitionError(Error):
    """Raised when a class definition exists but can not be interpreted."""


class InvalidDatabaseError(Error):
    pass


class UnmappedPageError(Error):
    pass
