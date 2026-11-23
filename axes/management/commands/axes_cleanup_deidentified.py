from django.core.management.base import BaseCommand

from axes.conf import settings
from axes.handlers.proxy import AxesProxyHandler


class Command(BaseCommand):
    help = (
        "Hard-delete de-identified audit records that are older than the "
        "AXES_DEIDENTIFY_RETENTION_DAYS retention period. Idempotent."
    )

    def handle(self, *args, **options):
        if settings.AXES_DEIDENTIFY_RETENTION_DAYS is None:
            self.stdout.write(
                "AXES_DEIDENTIFY_RETENTION_DAYS is not set; nothing to clean up."
            )
            return

        count = AxesProxyHandler.clean_expired_deidentified_records()
        if count:
            self.stdout.write(f"{count} expired records removed.")
        else:
            self.stdout.write("No expired records found.")
