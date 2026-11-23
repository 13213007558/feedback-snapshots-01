import csv

from django.contrib import admin
from django.db.models import Q
from django.http import HttpRequest, HttpResponse
from django.utils.translation import gettext_lazy as _

from axes.conf import settings
from axes.deidentification import REDACTED, hash_identifier
from axes.models import AccessAttempt, AccessLog, AccessFailureLog
from axes.handlers.database import AxesDatabaseHandler

VIEW_MARKER_PERMISSION = "axes.view_identifier_marker"
APPROVE_EXPORT_PERMISSION = "axes.approve_identifier_export"
EXPORT_PERMISSION = "axes.export_audit_records"


class IsLockedOutFilter(admin.SimpleListFilter):
    title = _("Locked Out")
    parameter_name = "locked_out"

    def lookups(self, request, model_admin):
        return (
            ("yes", _("Yes")),
            ("no", _("No")),
        )

    def queryset(self, request, queryset):
        if self.value() == "yes":
            return queryset.filter(
                failures_since_start__gte=settings.AXES_FAILURE_LIMIT
            )
        if self.value() == "no":
            return queryset.filter(failures_since_start__lt=settings.AXES_FAILURE_LIMIT)
        return queryset


class DeidentifiedAuditAdminMixin:
    """
    Shared admin behaviour for the de-identification retention policy.

    The lockout machinery always correlates accounts on the hash columns,
    regardless of who is looking at the admin. Showing the pseudonymized
    markers to a human is a separate concern and is gated behind its own
    permission; everyone else only sees a redacted placeholder.
    """

    deidentified_list_display = (
        "username_display",
        "ip_address_display",
        "user_agent_display",
    )
    deidentified_search_fields = (
        "username_hash",
        "ip_address_hash",
        "user_agent_hash",
        "path_info",
    )

    def get_queryset(self, request):
        # Remember the request so the column renderers can apply the
        # marker-view permission to each row.
        self._audit_request = request
        return super().get_queryset(request)

    def _can_view_markers(self, request: HttpRequest) -> bool:
        return request.user.has_perm(VIEW_MARKER_PERMISSION)

    def _render_marker(self, obj, hash_field: str, cleartext_attr: str) -> str:
        request = getattr(self, "_audit_request", None)
        if request is not None and self._can_view_markers(request):
            digest = getattr(obj, hash_field)
            if digest:
                return digest
            cleartext = getattr(obj, cleartext_attr)
            return cleartext if cleartext is not None else "-"
        return REDACTED

    @admin.display(description=_("Username"))
    def username_display(self, obj):
        return self._render_marker(obj, "username_hash", "username")

    @admin.display(description=_("IP Address"))
    def ip_address_display(self, obj):
        return self._render_marker(obj, "ip_address_hash", "ip_address")

    @admin.display(description=_("User Agent"))
    def user_agent_display(self, obj):
        return self._render_marker(obj, "user_agent_hash", "user_agent")

    def get_list_display(self, request):
        list_display = super().get_list_display(request)
        if not settings.AXES_DEIDENTIFY_ENABLED:
            return list_display
        filtered = [
            field
            for field in list_display
            if field not in ("username", "ip_address", "user_agent")
        ]
        return filtered + list(self.deidentified_list_display)

    def get_search_fields(self, request):
        if settings.AXES_DEIDENTIFY_ENABLED:
            return self.deidentified_search_fields
        return super().get_search_fields(request)

    def get_search_results(self, request, queryset, search_term):
        if not settings.AXES_DEIDENTIFY_ENABLED or not search_term:
            return super().get_search_results(request, queryset, search_term)

        # A marker digest can be searched directly; a cleartext value is first
        # resolved to its deterministic digest so the lookup never needs the
        # cleartext column.
        queryset, use_distinct = super().get_search_results(
            request, queryset, search_term
        )
        digest_matches = Q()
        for field_name in ("username", "ip_address", "user_agent"):
            digest = hash_identifier(search_term, field_name)
            digest_matches |= Q(**{f"{field_name}_hash": digest})
        return queryset | self.model.objects.filter(digest_matches), True

    def get_actions(self, request):
        actions = super().get_actions(request)
        if settings.AXES_DEIDENTIFY_ENABLED:
            if request.user.has_perm(APPROVE_EXPORT_PERMISSION):
                actions["approve_for_export"] = self.approve_for_export
            if request.user.has_perm(EXPORT_PERMISSION):
                actions["export_approved_csv"] = self.export_approved_csv
        return actions

    @admin.action(description=_("Approve selected records for export"))
    def approve_for_export(self, request, queryset):
        count = queryset.update(export_approved=True)
        self.message_user(request, _(f"Approved {count} records for export."))

    @admin.action(description=_("Export approved records as CSV"))
    def export_approved_csv(self, request, queryset):
        # Only records that were explicitly approved carry their markers out.
        approved = queryset.filter(export_approved=True)
        can_view_markers = self._can_view_markers(request)

        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = (
            f'attachment; filename="{self.model._meta.model_name}_export.csv"'
        )
        writer = csv.writer(response)
        writer.writerow(
            [
                "id",
                "attempt_time",
                "username",
                "ip_address",
                "user_agent",
                "path_info",
            ]
        )
        for obj in approved.iterator():
            if can_view_markers:
                username = obj.username_hash or obj.username or REDACTED
                ip_address = obj.ip_address_hash or obj.ip_address or REDACTED
                user_agent = obj.user_agent_hash or obj.user_agent or REDACTED
            else:
                username = ip_address = user_agent = REDACTED
            writer.writerow(
                [
                    obj.pk,
                    obj.attempt_time,
                    username,
                    ip_address,
                    user_agent,
                    obj.path_info,
                ]
            )
        return response


class AccessAttemptAdmin(DeidentifiedAuditAdminMixin, admin.ModelAdmin):
    list_display = [
        "attempt_time",
        "ip_address",
        "user_agent",
        "username",
        "path_info",
        "failures_since_start",
    ]

    if settings.AXES_USE_ATTEMPT_EXPIRATION:
        list_display.append("expiration")

    list_filter = ["attempt_time", "path_info"]

    if isinstance(settings.AXES_FAILURE_LIMIT, int) and settings.AXES_FAILURE_LIMIT > 0:
        # This will only add the status field if AXES_FAILURE_LIMIT is set to a positive integer
        # Because callable failure limit requires scope of request object
        list_display.append("status")
        list_filter.append(IsLockedOutFilter)  # type: ignore[arg-type]

    search_fields = ["ip_address", "username", "user_agent", "path_info"]

    date_hierarchy = "attempt_time"

    fieldsets = (
        (
            None,
            {"fields": ("username", "path_info", "failures_since_start", "expiration")},
        ),
        (_("Form Data"), {"fields": ("get_data", "post_data")}),
        (_("Meta Data"), {"fields": ("user_agent", "ip_address", "http_accept")}),
        (
            _("De-identification"),
            {
                "fields": (
                    "username_hash",
                    "ip_address_hash",
                    "user_agent_hash",
                    "deidentified_at",
                    "export_approved",
                )
            },
        ),
    )

    readonly_fields = [
        "user_agent",
        "ip_address",
        "username",
        "http_accept",
        "path_info",
        "attempt_time",
        "get_data",
        "post_data",
        "failures_since_start",
        "expiration",
        "username_hash",
        "ip_address_hash",
        "user_agent_hash",
        "deidentified_at",
    ]

    actions = ["cleanup_expired_attempts"]

    @admin.action(description=_("Clean up expired attempts"))
    def cleanup_expired_attempts(self, request, queryset):  # noqa
        count = self.handler.clean_expired_user_attempts(request=request)
        self.message_user(request, _(f"Cleaned up {count} expired access attempts."))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.handler = AxesDatabaseHandler()

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def expiration(self, obj: AccessAttempt):
        return obj.expiration.expires_at if hasattr(obj, "expiration") else _("Not set")

    def status(self, obj: AccessAttempt):
        return (
            f"{settings.AXES_FAILURE_LIMIT - obj.failures_since_start} "
            + _("Attempt Remaining")
            if obj.failures_since_start < settings.AXES_FAILURE_LIMIT
            else _("Locked Out")
        )


class AccessLogAdmin(DeidentifiedAuditAdminMixin, admin.ModelAdmin):
    list_display = (
        "attempt_time",
        "logout_time",
        "ip_address",
        "username",
        "user_agent",
        "path_info",
    )

    list_filter = ["attempt_time", "logout_time", "path_info"]

    search_fields = ["ip_address", "user_agent", "username", "path_info"]

    date_hierarchy = "attempt_time"

    fieldsets = (
        (None, {"fields": ("username", "path_info")}),
        (_("Meta Data"), {"fields": ("user_agent", "ip_address", "http_accept")}),
        (
            _("De-identification"),
            {
                "fields": (
                    "username_hash",
                    "ip_address_hash",
                    "user_agent_hash",
                    "deidentified_at",
                    "export_approved",
                )
            },
        ),
    )

    readonly_fields = [
        "user_agent",
        "ip_address",
        "username",
        "http_accept",
        "path_info",
        "attempt_time",
        "logout_time",
        "username_hash",
        "ip_address_hash",
        "user_agent_hash",
        "deidentified_at",
    ]

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False


class AccessFailureLogAdmin(DeidentifiedAuditAdminMixin, admin.ModelAdmin):
    list_display = (
        "attempt_time",
        "ip_address",
        "username",
        "user_agent",
        "path_info",
        "locked_out",
    )

    list_filter = ["attempt_time", "locked_out", "path_info"]

    search_fields = ["ip_address", "user_agent", "username", "path_info"]

    date_hierarchy = "attempt_time"

    fieldsets = (
        (None, {"fields": ("username", "path_info")}),
        (_("Meta Data"), {"fields": ("user_agent", "ip_address", "http_accept")}),
        (
            _("De-identification"),
            {
                "fields": (
                    "username_hash",
                    "ip_address_hash",
                    "user_agent_hash",
                    "deidentified_at",
                    "export_approved",
                )
            },
        ),
    )

    readonly_fields = [
        "user_agent",
        "ip_address",
        "username",
        "http_accept",
        "path_info",
        "attempt_time",
        "locked_out",
        "username_hash",
        "ip_address_hash",
        "user_agent_hash",
        "deidentified_at",
    ]

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False


if settings.AXES_ENABLE_ADMIN:
    admin.site.register(AccessAttempt, AccessAttemptAdmin)
    admin.site.register(AccessLog, AccessLogAdmin)
    admin.site.register(AccessFailureLog, AccessFailureLogAdmin)
