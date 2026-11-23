from django.core.management.base import BaseCommand

from axes.conf import settings
from axes.deidentification import REDACTED
from axes.models import AccessAttempt


class Command(BaseCommand):
    help = "List access attempts"

    def handle(self, *args, **options):
        for obj in AccessAttempt.objects.all():
            if settings.AXES_DEIDENTIFY_ENABLED:
                ip_address = obj.ip_address_hash or REDACTED
                username = obj.username_hash or REDACTED
            else:
                ip_address = obj.ip_address
                username = obj.username
            self.stdout.write(
                f"{ip_address}\t{username}\t{obj.failures_since_start}"
            )
