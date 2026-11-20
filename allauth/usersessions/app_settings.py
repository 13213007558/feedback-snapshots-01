from __future__ import annotations

from enum import Enum
from typing import TypeVar


_T = TypeVar("_T")


class AppSettings:
    class ClientIPPolicy(str, Enum):
        # Store the IP address as reported by the client.
        FULL = "full"
        # Store a coarse, network level address only (IPv4 /24, IPv6 /48).
        MASKED = "masked"
        # Do not store the IP address at all.
        NONE = "none"

    class UserAgentPolicy(str, Enum):
        # Store the full user agent string.
        FULL = "full"
        # Store a coarse device category only, e.g. "Mobile", "Desktop".
        DEVICE = "device"
        # Do not store the user agent at all.
        NONE = "none"

    def __init__(self, prefix: str) -> None:
        self.prefix = prefix

    def _setting(self, name: str, dflt: _T) -> _T:
        from allauth.utils import get_setting

        return get_setting(self.prefix + name, dflt)

    @property
    def ADAPTER(self) -> str:
        return self._setting(
            "ADAPTER", "allauth.usersessions.adapter.DefaultUserSessionsAdapter"
        )

    @property
    def TRACK_ACTIVITY(self) -> bool:
        """Whether or not sessions are to be actively tracked. When tracking is
        enabled, the last seen IP address and last seen timestamp will be kept
        track of.
        """
        return self._setting("TRACK_ACTIVITY", False)

    @property
    def CLIENT_IP_POLICY(self) -> ClientIPPolicy:
        """Determines how much of the client IP address is persisted on the
        user session record.
        """
        return self.ClientIPPolicy(
            self._setting("CLIENT_IP_POLICY", self.ClientIPPolicy.FULL.value)
        )

    @property
    def USER_AGENT_POLICY(self) -> UserAgentPolicy:
        """Determines how much of the client user agent is persisted on the
        user session record.
        """
        return self.UserAgentPolicy(
            self._setting("USER_AGENT_POLICY", self.UserAgentPolicy.FULL.value)
        )


_app_settings = AppSettings("USERSESSIONS_")


def __getattr__(name):
    # See https://peps.python.org/pep-0562/
    return getattr(_app_settings, name)
