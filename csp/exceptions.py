from django.core.exceptions import ImproperlyConfigured


class CSPNonceError(Exception):
    pass


class CSPStrictError(ImproperlyConfigured):
    """Raised when strict CSP validation rejects an ambiguous directive config."""

    pass
