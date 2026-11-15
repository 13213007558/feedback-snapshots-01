from __future__ import annotations

from dissect.database.exception import Error


class InvalidDatabase(Error, ValueError):
    """Raised when the file does not contain a usable bbolt transaction view.

    This also derives from :class:`ValueError` for backwards compatibility with
    the previous behaviour of rejecting an unusable bbolt file with a value error.
    """
