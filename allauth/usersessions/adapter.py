from __future__ import annotations

from django.utils.module_loading import import_string

from allauth.core.internal.adapter import BaseAdapter
from allauth.usersessions import app_settings
from allauth.usersessions.internal import clientkit


class DefaultUserSessionsAdapter(BaseAdapter):
    """The adapter class allows you to override various functionality of the
    ``allauth.usersessions`` app.  To do so, point
    ``settings.USERSESSIONS_ADAPTER`` to your own class that derives from
    ``DefaultUserSessionsAdapter`` and override the behavior by altering the
    implementation of the methods according to your own needs.
    """

    def end_sessions(self, sessions) -> None:
        for session in sessions:
            session.end()

    def redact_client_ip(self, ip: str | None) -> str | None:
        """Turns the raw client IP address into the value that is persisted on
        the user session record, honoring ``USERSESSIONS_CLIENT_IP_POLICY``.
        """
        policy = app_settings.CLIENT_IP_POLICY
        if policy == app_settings.ClientIPPolicy.NONE:
            return None
        if policy == app_settings.ClientIPPolicy.MASKED:
            return clientkit.mask_client_ip(ip)
        return ip

    def redact_user_agent(self, user_agent: str | None) -> str:
        """Turns the raw client user agent into the value that is persisted on
        the user session record, honoring ``USERSESSIONS_USER_AGENT_POLICY``.
        """
        policy = app_settings.USER_AGENT_POLICY
        if policy == app_settings.UserAgentPolicy.NONE:
            return ""
        if policy == app_settings.UserAgentPolicy.DEVICE:
            category = clientkit.device_category(user_agent)
            return str(clientkit.DEVICE_CATEGORY_LABELS[category])
        return user_agent or ""


def get_adapter() -> DefaultUserSessionsAdapter:
    return import_string(app_settings.ADAPTER)()
