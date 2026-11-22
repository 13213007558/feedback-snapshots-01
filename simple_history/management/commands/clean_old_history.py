from django.core.management.base import CommandError
from django.db import router, transaction
from django.utils import timezone
from django.utils.module_loading import import_string

from . import populate_history


class Command(populate_history.Command):
    args = "<app.model app.model ...>"
    help = "Scans HistoricalRecords for old entries " "and deletes them."

    DONE_CLEANING_FOR_MODEL = "Removed {count} historical records for {model}\n"
    PROTECTED_RECORD_FOR_MODEL = (
        "Protecting historical record {history_id} for {model}: {reason}\n"
    )
    PROTECTED_SUMMARY_FOR_MODEL = (
        "Kept {count} protected historical records for {model}\n"
    )
    INVALID_POLICY = "Invalid cleanup policy"

    def add_arguments(self, parser):
        parser.add_argument("models", nargs="*", type=str)
        parser.add_argument(
            "--auto",
            action="store_true",
            dest="auto",
            default=False,
            help="Automatically search for models with the HistoricalRecords field "
            "type",
        )
        parser.add_argument(
            "--days",
            help="Only Keep the last X Days of history, default is 30",
            dest="days",
            type=int,
            default=30,
        )

        parser.add_argument(
            "-d", "--dry", action="store_true", help="Dry (test) run only, no changes"
        )
        parser.add_argument(
            "--policy",
            dest="policy",
            default=None,
            help="Dotted path to a HistoryCleanupPolicy subclass (or callable) "
            "that decides which expired historical records must be kept and why.",
        )
        parser.add_argument(
            "--database",
            dest="database",
            default=None,
            help="Database alias to clean. Defaults to the database selected by "
            "the project's database routers.",
        )

    def handle(self, *args, **options):
        self.verbosity = options["verbosity"]

        to_process = set()
        model_strings = options.get("models", []) or args

        if model_strings:
            for model_pair in self._handle_model_list(*model_strings):
                to_process.add(model_pair)

        elif options["auto"]:
            to_process = self._auto_models()

        else:
            self.log(self.COMMAND_HINT)

        policy = self._load_policy(options["policy"])

        self._process(
            to_process,
            days_back=options["days"],
            dry_run=options["dry"],
            policy=policy,
            using=options["database"],
        )

    def _load_policy(self, policy_path):
        if not policy_path:
            return None
        try:
            policy = import_string(policy_path)
        except ImportError as error:
            raise CommandError(
                f"{self.INVALID_POLICY} < {policy_path} >: {error}"
            ) from error
        if isinstance(policy, type):
            policy = policy()
        if not callable(getattr(policy, "protect_reason", None)):
            raise CommandError(
                f"{self.INVALID_POLICY} < {policy_path} >: a cleanup policy must "
                "provide a protect_reason() method"
            )
        return policy

    def _process(
        self, to_process, days_back=None, dry_run=True, policy=None, using=None
    ):
        start_date = timezone.now() - timezone.timedelta(days=days_back)
        for model, history_model in to_process:
            history_model_manager = history_model.objects
            if using is not None:
                history_model_manager = history_model_manager.using(using)
            expired = history_model_manager.filter(history_date__lt=start_date)
            found = expired.count()
            self.log(f"{model} has {found} old historical entries", 2)
            if not found:
                continue

            if policy is None:
                protected = []
                deletable = expired
                deletable_count = found
            else:
                # The policy is evaluated against the rules in force right now,
                # so rerunning a failed cleanup re-checks every record.
                protected, deletable_pks = policy.partition(expired)
                for item in protected:
                    self.log(
                        self.PROTECTED_RECORD_FOR_MODEL.format(
                            history_id=getattr(
                                item.record, "history_id", item.record.pk
                            ),
                            model=model,
                            reason=item.reason,
                        )
                    )
                if protected:
                    self.log(
                        self.PROTECTED_SUMMARY_FOR_MODEL.format(
                            model=model, count=len(protected)
                        )
                    )
                # Protected primary keys are excluded from the DELETE queryset,
                # so a frozen record can never be deleted by this command.
                deletable = expired.filter(pk__in=deletable_pks)
                deletable_count = len(deletable_pks)

            if not dry_run and deletable_count:
                db_alias = using or router.db_for_write(history_model)
                with transaction.atomic(using=db_alias):
                    deletable.delete()

            if deletable_count:
                self.log(
                    self.DONE_CLEANING_FOR_MODEL.format(
                        model=model, count=deletable_count
                    )
                )

    def log(self, message, verbosity_level=1):
        if self.verbosity >= verbosity_level:
            self.stdout.write(message)
