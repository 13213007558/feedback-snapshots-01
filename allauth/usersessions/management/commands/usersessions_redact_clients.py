from __future__ import annotations

from django.core.management.base import BaseCommand

from allauth.usersessions.adapter import get_adapter
from allauth.usersessions.models import UserSession


class Command(BaseCommand):
    help = (
        "Re-apply the configured USERSESSIONS_CLIENT_IP_POLICY and "
        "USERSESSIONS_USER_AGENT_POLICY to all stored user sessions."
    )

    def handle(self, *args, **options) -> None:
        adapter = get_adapter()
        updated = 0
        for session in UserSession.objects.all().iterator():
            ip = adapter.redact_client_ip(session.ip)
            user_agent = adapter.redact_user_agent(session.user_agent)
            if ip != session.ip or user_agent != session.user_agent:
                session.ip = ip
                session.user_agent = user_agent
                session.save(update_fields=["ip", "user_agent"])
                updated += 1
        self.stdout.write(f"Redacted client information on {updated} user session(s).")
