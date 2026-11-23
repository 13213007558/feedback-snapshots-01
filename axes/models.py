from django.db import models
from django.utils.translation import gettext_lazy as _

# Distinguish "can look at the audit console" from "can see the pseudonymized
# markers that re-identify an account" and gate exports behind an explicit
# approval workflow. These are attached to each concrete audit model because
# Django does not propagate custom permissions from abstract base classes.
AUDIT_PERMISSIONS = (
    ("view_identifier_marker", _("Can view pseudonymized identifier markers")),
    ("approve_identifier_export", _("Can approve markers for export")),
    ("export_audit_records", _("Can export audit records")),
)


class AccessBase(models.Model):
    user_agent = models.CharField(
        _("User Agent"), max_length=255, db_index=True, null=True
    )

    ip_address = models.GenericIPAddressField(_("IP Address"), null=True, db_index=True)

    username = models.CharField(_("Username"), max_length=255, null=True, db_index=True)

    http_accept = models.CharField(_("HTTP Accept"), max_length=1025)

    path_info = models.CharField(_("Path"), max_length=255)

    attempt_time = models.DateTimeField(_("Attempt Time"), auto_now_add=True)

    # Deterministic keyed digests of the direct identifiers. These are the only
    # values used to correlate failures with an account once de-identification
    # is enabled; the cleartext columns above are cleared for new records.
    username_hash = models.CharField(
        _("Username Hash"), max_length=255, null=True, blank=True, db_index=True
    )
    ip_address_hash = models.CharField(
        _("IP Address Hash"), max_length=255, null=True, blank=True, db_index=True
    )
    user_agent_hash = models.CharField(
        _("User Agent Hash"), max_length=255, null=True, blank=True, db_index=True
    )

    # When the record was de-identified. ``None`` means the record still holds
    # cleartext direct identifiers and is waiting for the migration batch.
    deidentified_at = models.DateTimeField(
        _("Deidentified At"), null=True, blank=True
    )

    # Whether the pseudonymized markers of this record have been approved for
    # inclusion in an authorized export.
    export_approved = models.BooleanField(
        _("Export Approved"), null=False, blank=True, default=False
    )

    class Meta:
        app_label = "axes"
        abstract = True
        ordering = ["-attempt_time"]


class AccessFailureLog(AccessBase):
    locked_out = models.BooleanField(
        _("Access lock out"), null=False, blank=True, default=False
    )

    def __str__(self):
        locked_out_str = " locked out" if self.locked_out else ""
        return f"Failed access: user {self.username}{locked_out_str} on {self.attempt_time} from {self.ip_address}"

    class Meta:
        verbose_name = _("access failure")
        verbose_name_plural = _("access failures")
        permissions = AUDIT_PERMISSIONS


class AccessAttempt(AccessBase):
    get_data = models.TextField(_("GET Data"))

    post_data = models.TextField(_("POST Data"))

    failures_since_start = models.PositiveIntegerField(_("Failed Logins"))

    def __str__(self):
        return f"Attempted Access: {self.attempt_time}"

    class Meta:
        verbose_name = _("access attempt")
        verbose_name_plural = _("access attempts")
        unique_together = [["username", "ip_address", "user_agent"]]
        permissions = AUDIT_PERMISSIONS


class AccessAttemptExpiration(models.Model):
    access_attempt = models.OneToOneField(
        AccessAttempt,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name="expiration",
        verbose_name=_("Access Attempt"),
    )
    expires_at = models.DateTimeField(
        _("Expires At"),
        help_text=_("The time when access attempt expires and is no longer valid."),
    )

    class Meta:
        verbose_name = _("access attempt expiration")
        verbose_name_plural = _("access attempt expirations")


class AccessLog(AccessBase):
    logout_time = models.DateTimeField(_("Logout Time"), null=True, blank=True)
    session_hash = models.CharField(
        _("Session key hash (sha256)"), default="", blank=True, max_length=64
    )

    def __str__(self):
        return f"Access Log for {self.username} @ {self.attempt_time}"

    class Meta:
        verbose_name = _("access log")
        verbose_name_plural = _("access logs")
        permissions = AUDIT_PERMISSIONS
