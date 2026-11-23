from django.core.management.base import CommandError

from ...exceptions import PseudonymizationError
from ...pseudonym import anonymize_history_user, identity_kind
from . import populate_history


class Command(populate_history.Command):
    args = "<app.model app.model ...>"
    help = (
        "Sever historical records from a departed user and replace the account "
        "link with a stable pseudonym."
    )

    DONE_ANONYMIZING_FOR_MODEL = (
        "Pseudonymized {count} historical records for {model} "
        "(already pseudonymized: {already})\n"
    )

    def add_arguments(self, parser):
        parser.add_argument("models", nargs="*", type=str)
        parser.add_argument(
            "--auto",
            action="store_true",
            default=False,
            help="Process every registered model with a history manager.",
        )
        parser.add_argument(
            "--user-id",
            dest="user_id",
            help="Primary key of the user account to sever.",
        )
        parser.add_argument(
            "--identity",
            action="append",
            dest="identities",
            default=[],
            help=(
                "Raw identity value for externally managed accounts. May be "
                "repeated for several identifiers of the same subject."
            ),
        )
        parser.add_argument(
            "--subject",
            help=(
                "Stable subject token used to derive the pseudonym when several "
                "identities belong to the same person."
            ),
        )
        parser.add_argument(
            "--namespace",
            default="default",
            help="Pseudonym namespace (default: %(default)s).",
        )
        parser.add_argument(
            "--watermark",
            type=int,
            help=(
                "Only process historical rows with a primary key lower than this "
                "value, so rows created while the batch runs stay untouched."
            ),
        )
        parser.add_argument(
            "--cutoff",
            help="Only process historical rows dated at or before this ISO datetime.",
        )
        parser.add_argument(
            "-d",
            "--dry-run",
            action="store_true",
            dest="dry_run",
            help="Report what would change without writing anything.",
        )

    def handle(self, *args, **options):
        self.verbosity = options["verbosity"]
        if not options.get("user_id") and not options.get("identities"):
            raise CommandError("Provide --user-id and/or --identity.")

        cutoff = self._parse_cutoff(options.get("cutoff"))
        to_process = self._selected_models(options, args)
        user = self._resolve_user(options.get("user_id"))
        if options["identities"]:
            for model, history_model in to_process:
                if identity_kind(history_model) == "foreign_key":
                    raise CommandError(
                        f"{model} tracks users with a foreign key; use --user-id."
                    )

        failed = False
        for model, _history_model in sorted(
            to_process, key=lambda pair: pair[0]._meta.label_lower
        ):
            try:
                result = anonymize_history_user(
                    model,
                    user=user,
                    identities=options["identities"] or None,
                    subject=options.get("subject"),
                    namespace=options["namespace"],
                    watermark=options.get("watermark"),
                    cutoff=cutoff,
                    dry_run=options["dry_run"],
                )
            except PseudonymizationError as exc:
                failed = True
                self.stderr.write(f"{model}: {exc}\n")
                continue
            self._report(model, result)

        if failed:
            raise CommandError("One or more models could not be pseudonymized.")

    @staticmethod
    def _parse_cutoff(value):
        if not value:
            return None
        from django.utils.dateparse import parse_datetime

        cutoff = parse_datetime(value)
        if cutoff is None:
            raise CommandError("--cutoff must be an ISO 8601 datetime.")
        return cutoff

    def _selected_models(self, options, args):
        model_strings = options.get("models", []) or args
        if model_strings:
            return set(self._handle_model_list(*model_strings))
        if options["auto"]:
            return self._auto_models()
        raise CommandError(self.COMMAND_HINT)

    @staticmethod
    def _resolve_user(user_id):
        if not user_id:
            return None
        from django.contrib.auth import get_user_model

        User = get_user_model()
        try:
            return User._default_manager.get(pk=user_id)
        except (User.DoesNotExist, ValueError):
            raise CommandError(f"User with primary key {user_id!r} does not exist.")

    def _report(self, model, result):
        if not result.pseudonymized and not result.already_pseudonymized:
            self.log(f"No historical records matched for {model}")
            return
        self.log(
            self.DONE_ANONYMIZING_FOR_MODEL.format(
                count=result.pseudonymized,
                already=result.already_pseudonymized,
                model=model,
            )
        )

    def log(self, message, verbosity_level=1):
        if self.verbosity >= verbosity_level:
            self.stdout.write(message)
