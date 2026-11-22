import datetime as dt

from auditcase.models import CaseFile
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

UTC = dt.timezone.utc


def at(year, month, day, hour=0, minute=0):
    return dt.datetime(year, month, day, hour, minute, tzinfo=UTC)


class Command(BaseCommand):
    help = "Create the deterministic SQLite dataset used by the audit demo."

    def handle(self, *args, **options):
        history = CaseFile.history.model
        CaseFile.objects.all().delete()
        history.objects.all().delete()
        user_model = get_user_model()
        user_model.objects.all().delete()

        retained = user_model.objects.create(username="retained-officer")
        former = user_model.objects.create(username="former-officer")

        created = at(2026, 1, 15, 8)
        legal = CaseFile(
            case_secret="LEGAL-RAW-RECORD", department="LEGAL", approved=True
        )
        legal._history_date = created
        legal.save()

        restricted = CaseFile(
            case_secret="EXEC-RAW-RECORD", department="EXEC", approved=True
        )
        restricted._history_date = created
        restricted.save()

        pending = CaseFile(
            case_secret="PENDING-RAW-RECORD", department="LEGAL", approved=False
        )
        pending._history_date = created
        pending.save()

        tie = at(2026, 3, 1, 9)
        legal.case_secret = "LEGAL-RAW-RECORD-v2"
        legal._history_date = tie
        legal._history_user = retained
        legal.save()

        pending.approved = True
        pending._history_date = tie
        pending._history_user = retained
        pending.save()

        legal.case_secret = "LEGAL-RAW-RECORD-v3"
        legal._history_date = at(2026, 3, 2, 10, 30)
        legal._history_user = former
        legal.save()

        restricted.case_secret = "EXEC-RAW-RECORD-v2"
        restricted._history_date = at(2026, 3, 3, 8)
        restricted._history_user = retained
        restricted.save()

        pending.approved = False
        pending.case_secret = "PENDING-RAW-RECORD-v2"
        pending._history_date = at(2026, 3, 4, 8)
        pending._history_user = retained
        pending.save()

        # A later re-approval produces a sixth exportable LEGAL event.
        pending.approved = True
        pending.case_secret = "PENDING-RAW-RECORD-v3"
        pending._history_date = at(2026, 3, 6, 8)
        pending._history_user = retained
        pending.save()

        # The history author is removed: history_user_id becomes NULL.
        former.delete()

        if hasattr(legal, "_history_user"):
            del legal._history_user
        legal._history_date = at(2026, 3, 5, 12)
        legal.delete()

        total = history.objects.count()
        self.stdout.write(
            self.style.SUCCESS(
                f"Seeded {total} historical rows across "
                f"{CaseFile.objects.count()} live case files."
            )
        )
        self.stdout.write(
            "Scenarios present: same-timestamp changes, a deleted history "
            "author, EXEC rows outside the access rule and unapproved rows."
        )
