from __future__ import annotations


class Error(Exception):
    pass


class InvalidHeaderError(Error):
    pass


class FileNotFoundError(Error, FileNotFoundError):
    pass


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotAReparsePointError(Error):
    pass


class InvalidSecurityDataError(Error, ValueError):
    pass


class InvalidDirectoryEntryError(Error, ValueError):
    pass


class SecurityIdOutOfRangeError(InvalidSecurityDataError, IndexError):
    def __init__(self, security_id: int, num_entries: int):
        self.security_id = security_id
        self.num_entries = num_entries
        super().__init__(
            f"SecurityId {security_id:#x} is out of range for a security table with {num_entries} entries"
        )


class EmptySecurityDescriptorError(InvalidSecurityDataError):
    def __init__(self, security_id: int, offset: int):
        self.security_id = security_id
        self.offset = offset
        super().__init__(
            f"SecurityId {security_id:#x} refers to an empty security descriptor slot at offset {offset:#x}; "
            "there are no descriptor bytes to associate"
        )
