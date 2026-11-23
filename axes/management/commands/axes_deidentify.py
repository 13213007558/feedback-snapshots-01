from django.core.management.base import BaseCommand

from axes.handlers.proxy import AxesProxyHandler


class Command(BaseCommand):
    help = (
        "Convert cleartext login audit records to de-identified markers in "
        "batches. Safe to re-run and to run while new failures are recorded."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--batch-size",
            type=int,
            default=500,
            help="Number of records processed in each batch",
        )

    def handle(self, *args, **options):
        count = AxesProxyHandler.convert_legacy_records(
            batch_size=options["batch_size"]
        )
        if count:
            self.stdout.write(f"{count} records de-identified.")
        else:
            self.stdout.write("No cleartext records left to convert.")
