"""
django-simple-history exceptions and warnings classes.
"""


class MultipleRegistrationsError(Exception):
    """The model has been registered to have history tracking more than once"""

    pass


class NotHistoricalModelError(TypeError):
    """No related history model found."""

    pass


class RelatedNameConflictError(Exception):
    """Related name conflicting with history manager"""

    pass


class AlternativeManagerError(Exception):
    """Manager does not belong to model"""

    pass


class PseudonymizationError(Exception):
    """Base class for errors raised while severing historical user links."""

    pass


class InvalidPseudonymizationIdentity(PseudonymizationError, ValueError):
    """The identity to pseudonymize is missing or cannot be normalized."""

    pass


class PseudonymizationConflict(PseudonymizationError):
    """
    A historical row already contains a different pseudonym than the one derived
    for the requested identity.

    This normally means that the row was pseudonymized with another secret or
    namespace. It is reported instead of silently mixing two anonymous subjects.
    """

    pass
