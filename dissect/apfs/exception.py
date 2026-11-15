from __future__ import annotations


class Error(Exception):
    pass


class EncryptionError(Error):
    """Base class for errors related to volume encryption."""


class VolumeLockedError(EncryptionError):
    """The volume or a snapshot of it can not be read because it is not unlocked."""


class VolumeMismatchError(EncryptionError):
    """An encryption context does not belong to the volume it is used with."""


class UnsupportedEncryptionError(EncryptionError):
    """The volume uses an encryption mode that is not supported."""


class UnsupportedKeyGenerationError(UnsupportedEncryptionError):
    """The volume or snapshot requires a key generation that is not supported."""


class FileNotFoundError(Error, FileNotFoundError):
    pass


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotASymlinkError(Error):
    pass
