from django.core.management.base import BaseCommand
from django.db import DEFAULT_DB_ALIAS

from guardian.utils import delete_orphan_obj_perms, preview_orphan_obj_perms


class Command(BaseCommand):
    """Preview and remove object permissions entries pointing at non-existing targets.

    The cleanup first previews the orphan entries, then removes them in
    batches. Every previewed entry is re-checked right before deletion, so
    targets re-created after the preview keep their permissions. A failing
    batch is skipped and reported, and the remaining batches still run.

    Example:
        ```shell
        $ python manage.py clean_orphan_obj_perms --dry-run
        Found 11 object permission entries with no targets on database 'default' (dry run, nothing removed)

        $ python manage.py clean_orphan_obj_perms
        Removed 11 object permission entries with no targets

        $ python manage.py clean_orphan_obj_perms --batch-size 100 --max-batches 5
        Removed 500 object permission entries with no targets

        $ python manage.py clean_orphan_obj_perms --database replica --batch-size 50 --skip-batches 2
        Removed 200 object permission entries with no targets
        ```
    """

    help = "Removes object permissions with not existing targets"

    def add_arguments(self, parser):
        parser.add_argument(
            "--batch-size",
            type=int,
            help="Number of objects to process per batch. If not specified, all objects are processed at once.",
        )
        parser.add_argument(
            "--max-batches", type=int, help="Maximum number of batches to process. Use with --batch-size."
        )
        parser.add_argument(
            "--max-duration-secs", type=int, help="Maximum duration in seconds for the cleanup operation."
        )
        parser.add_argument(
            "--skip-batches",
            type=int,
            default=0,
            help="Number of batches to skip before starting cleanup. Use with --batch-size.",
        )
        parser.add_argument(
            "--database",
            default=DEFAULT_DB_ALIAS,
            help="Nominates a specific database to scan and clean. Defaults to the 'default' database.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Only preview the orphan object permissions that would be removed, without deleting anything.",
        )

    def handle(self, **options):
        using = options["database"]
        verbosity = options["verbosity"]

        preview = preview_orphan_obj_perms(using=using)

        if options["dry_run"]:
            if verbosity > 0:
                self.stdout.write(
                    "Found %d object permission entries with no targets on database '%s' (dry run, nothing removed)"
                    % (preview.count, preview.database)
                )
                if verbosity > 1:
                    for record in preview.records:
                        self.stdout.write(
                            "  %s permission pk=%s content_type_id=%s object_pk=%s"
                            % (record.model, record.pk, record.content_type_id, record.object_pk)
                        )
            return

        kwargs = {}

        if options["batch_size"] is not None:
            kwargs["batch_size"] = options["batch_size"]

        if options["max_batches"] is not None:
            kwargs["max_batches"] = options["max_batches"]

        if options["max_duration_secs"] is not None:
            kwargs["max_duration_secs"] = options["max_duration_secs"]

        if options["skip_batches"] > 0:
            kwargs["skip_batches"] = options["skip_batches"]

        result = delete_orphan_obj_perms(preview, using=using, **kwargs)

        if verbosity > 0:
            self.stdout.write("Removed %d object permission entries with no targets" % result.removed)
            if result.skipped:
                self.stdout.write(
                    "Skipped %d object permission entries whose targets reappeared after the preview" % result.skipped
                )
            if result.failed_batches:
                self.stdout.write(
                    self.style.WARNING(
                        "%d batch(es) failed; rerun the command to continue cleaning" % result.failed_batches
                    )
                )
