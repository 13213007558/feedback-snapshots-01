from django.core.management.base import BaseCommand

from axes.subjects import backfill_subject_attempts


class Command(BaseCommand):
    help = (
        "Seed subject lockout windows from pre-migration username/network-group "
        "records. Safe to run repeatedly."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "subject",
            nargs="*",
            type=str,
            help="Registered subjects to backfill. Defaults to every subject.",
        )

    def handle(self, *args, **options):
        subjects = options["subject"] or [None]
        count = 0
        for subject in subjects:
            count += backfill_subject_attempts(subject)

        if count:
            self.stdout.write(f"{count} subject attempt windows migrated.")
        else:
            self.stdout.write("No attempts found.")
