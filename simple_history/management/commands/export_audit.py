import json
from importlib import import_module

from django.core.management.base import BaseCommand, CommandError
from django.utils.dateparse import parse_datetime

from ...audit import AuditCursorError, AuditExportError, iter_audit_pages
from ...audit.exporter import write_audit_page
from ...exceptions import NotHistoricalModelError


class Command(BaseCommand):
    help = (
        "Export approved historical changes as minimal JSON Lines pages. "
        "Each row contains only event_time, change_type and object_ref; "
        "model fields and historical snapshots are never written."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "model",
            help="Dotted model pair whose history is exported, e.g. cases.casefile",
        )
        parser.add_argument("--page-size", type=int, default=500)
        parser.add_argument(
            "--start-time",
            help="Inclusive ISO-8601 lower bound on history_date.",
        )
        parser.add_argument(
            "--end-time",
            help="Exclusive ISO-8601 upper bound on history_date.",
        )
        parser.add_argument(
            "--cursor",
            help="Opaque cursor returned by a previous run to resume export.",
        )
        parser.add_argument(
            "--max-pages",
            type=int,
            default=1,
            help="Maximum number of pages emitted by this invocation (default 1).",
        )
        parser.add_argument(
            "--include-unapproved",
            action="store_true",
            help="Also export rows whose 'approved' flag is not true.",
        )
        parser.add_argument(
            "--access-callback",
            help=(
                "Dotted path 'module.function' returning a Q object against "
                "history columns that restricts which rows are visible."
            ),
        )
        parser.add_argument(
            "--out-dir",
            help=(
                "Directory for page files named audit-page-0001.jsonl etc. "
                "Defaults to writing a single page to stdout."
            ),
        )

    def handle(self, *args, **options):
        history_model = self._resolve_history_model(options["model"])
        start_time = self._parse_time(options["start_time"], "start_time")
        end_time = self._parse_time(options["end_time"], "end_time")
        access_q = self._resolve_access_callback(options["access_callback"])

        try:
            pages = iter_audit_pages(
                history_model,
                page_size=options["page_size"],
                start_time=start_time,
                end_time=end_time,
                approved_only=not options["include_unapproved"],
                access_q=access_q,
                cursor=options["cursor"],
                max_pages=options["max_pages"],
            )
            if options["out_dir"]:
                self._write_files(pages, options)
            else:
                self._write_stdout(pages, options)
        except (AuditExportError, AuditCursorError) as exc:
            raise CommandError(str(exc)) from exc

    def _resolve_history_model(self, model_label):
        try:
            app_label, model_name = model_label.split(".")
        except ValueError as exc:
            raise CommandError(
                "Model must be given as 'app_label.model_name'."
            ) from exc
        from django.apps import apps

        try:
            model = apps.get_model(app_label, model_name)
        except LookupError as exc:
            raise CommandError(f"Unknown model: {model_label}") from exc
        try:
            return model.history.model
        except AttributeError as exc:
            raise NotHistoricalModelError(
                f"{model_label} does not have a HistoricalRecords manager."
            ) from exc

    def _parse_time(self, value, name):
        if value is None:
            return None
        parsed = parse_datetime(value)
        if parsed is None:
            raise CommandError(f"{name} is not a valid ISO-8601 datetime.")
        from django.utils import timezone

        if timezone.is_naive(parsed):
            parsed = timezone.make_aware(parsed)
        return parsed

    def _resolve_access_callback(self, dotted_path):
        if not dotted_path:
            return None
        module_path, separator, function_name = dotted_path.rpartition(".")
        if not separator:
            raise CommandError(
                "Access callback must be a dotted 'module.function' path."
            )
        try:
            callback = getattr(import_module(module_path), function_name)
        except (ImportError, AttributeError) as exc:
            raise CommandError(f"Cannot import access callback: {dotted_path}") from exc
        return callback()

    def _write_files(self, pages, options):
        import os

        out_dir = options["out_dir"]
        os.makedirs(out_dir, exist_ok=True)
        for index, (rows, next_cursor, has_next) in enumerate(pages, start=1):
            path = os.path.join(out_dir, f"audit-page-{index:04d}.jsonl")
            with open(path, "w", encoding="utf-8") as handle:
                count = write_audit_page(rows, handle)
            self.stdout.write(f"wrote {path} ({count} rows)")
            if next_cursor:
                self.stderr.write(
                    json.dumps(
                        {
                            "page": index,
                            "has_next": has_next,
                            "next_cursor": next_cursor,
                        }
                    )
                    + "\n"
                )

    def _write_stdout(self, pages, options):
        total = 0
        next_cursor = None
        has_next = False
        for rows, next_cursor, has_next in pages:
            total += write_audit_page(rows, self.stdout)
        self.stderr.write(
            json.dumps(
                {"rows": total, "has_next": has_next, "next_cursor": next_cursor}
            )
            + "\n"
        )
