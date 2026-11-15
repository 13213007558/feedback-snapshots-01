from __future__ import annotations


class Error(Exception):
    pass


class InvalidHeaderError(Error):
    pass


class InvalidIntegrityError(InvalidHeaderError):
    """Raised when a metadata block fails its cryptographic integrity validation.

    This is distinct from a wrong key or passphrase: the outer structure may parse and its
    checksum may be valid while the authenticated integrity digest does not match, or the
    authenticated decryption of an integrity datum fails.
    """
