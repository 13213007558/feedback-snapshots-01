from __future__ import annotations


class Error(Exception):
    pass


class RegistryKeyNotFoundError(Error):
    pass


class RegistryValueNotFoundError(Error):
    pass


class MountNotFoundError(Error):
    """A registry path does not identify an explicitly mounted hive."""


class MissingContextError(Error):
    """Required offline context is missing, so a logical path cannot be resolved."""


class ControlSetNotFoundError(Error):
    """Select evidence or explicit context refers to a control set absent from the SYSTEM hive."""


class UserContextError(Error):
    """A user-relative path is ambiguous or names a user hive that is not mounted."""
