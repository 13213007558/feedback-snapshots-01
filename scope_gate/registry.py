"""Live scope registry for the scoped archive gateway.

Scopes are strings of the form ``"<operation>:<route>"``, e.g.
``"read:ARCHIVE_A"`` or ``"write:ARCHIVE_B"``. The registry is the single
source of truth for what a calling AE title is *currently* allowed to do;
grants can be revoked at any time, including while an association that was
approved earlier is still open.
"""

import threading


class ScopeRegistry:
    """Thread-safe mapping of calling AE title -> currently granted scopes."""

    def __init__(self):
        self._lock = threading.Lock()
        self._grants: dict[str, set[str]] = {}

    def register(self, ae_title: str, scopes) -> None:
        """Register *ae_title* with the given iterable of scopes."""
        with self._lock:
            self._grants[ae_title.strip().upper()] = set(scopes)

    def grant(self, ae_title: str, scope: str) -> None:
        """Add a single *scope* to an already registered AE title."""
        with self._lock:
            self._grants[ae_title.strip().upper()].add(scope)

    def revoke(self, ae_title: str, scope: str) -> None:
        """Withdraw a single *scope*; takes effect immediately."""
        with self._lock:
            self._grants[ae_title.strip().upper()].discard(scope)

    def revoke_all(self, ae_title: str) -> None:
        """Withdraw every scope from *ae_title*."""
        with self._lock:
            self._grants[ae_title.strip().upper()] = set()

    def scopes_for(self, ae_title: str):
        """Return the live scopes for *ae_title*.

        Returns ``None`` if the AE title was never registered, otherwise a
        ``frozenset`` snapshot of the scopes allowed *right now*.
        """
        with self._lock:
            scopes = self._grants.get(ae_title.strip().upper())
            return None if scopes is None else frozenset(scopes)
