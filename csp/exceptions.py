class CSPNonceError(Exception):
    pass


class CSPNonceConflictError(CSPNonceError):
    """Raised when the nonce rendered into a response body cannot be reconciled
    with the nonce carried by the enforced Content-Security-Policy header."""
