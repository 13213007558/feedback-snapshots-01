from django.core.management.base import BaseCommand

from axes.utils import reset


class Command(BaseCommand):
    help = "Reset all access attempts and lockouts for given registered subjects"

    def add_arguments(self, parser):
        parser.add_argument("subject", nargs="+", type=str)

    def handle(self, *args, **options):
        count = 0

        for subject in options["subject"]:
            count += reset(subject=subject)

        if count:
            self.stdout.write(f"{count} attempts removed.")
        else:
            self.stdout.write("No attempts found.")
