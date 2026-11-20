from __future__ import annotations

from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser
from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.db.models import Q
from django.db.models.constraints import UniqueConstraint
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from allauth import app_settings as allauth_settings


if not allauth_settings.MFA_ENABLED:
    raise ImproperlyConfigured(
        "allauth.mfa not installed, yet its models are imported."
    )


class AuthenticatorManager(models.Manager):
    pass


class TrustedDeviceManager(models.Manager):
    def purge_and_list(self, user: AbstractBaseUser) -> list["TrustedDevice"]:
        from allauth.mfa import app_settings

        expired = [
            device
            for device in self.filter(user_id=user.pk)
            if device.created_at + app_settings.TRUST_COOKIE_AGE < timezone.now()
        ]
        for device in expired:
            device.delete()
        return list(self.filter(user_id=user.pk))


class Authenticator(models.Model):
    class Type(models.TextChoices):
        RECOVERY_CODES = "recovery_codes", _("Recovery codes")
        TOTP = "totp", _("TOTP Authenticator")
        WEBAUTHN = "webauthn", _("WebAuthn")

    objects = AuthenticatorManager()

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    type = models.CharField(max_length=20, choices=Type.choices)
    data = models.JSONField()
    created_at = models.DateTimeField(default=timezone.now)
    last_used_at = models.DateTimeField(null=True)

    class Meta:
        constraints = [
            UniqueConstraint(
                fields=["user", "type"],
                name="unique_authenticator_type",
                condition=Q(
                    type__in=(
                        "totp",
                        "recovery_codes",
                    )
                ),
            )
        ]

    def __str__(self) -> str:
        if self.type == self.Type.WEBAUTHN:
            return self.wrap().name
        return self.get_type_display()

    def wrap(self):
        from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
        from allauth.mfa.totp.internal.auth import TOTP
        from allauth.mfa.webauthn.internal.auth import WebAuthn

        return {
            self.Type.TOTP: TOTP,
            self.Type.RECOVERY_CODES: RecoveryCodes,
            self.Type.WEBAUTHN: WebAuthn,
        }[self.type](self)

    def record_usage(self) -> None:
        self.last_used_at = timezone.now()
        self.save(update_fields=["last_used_at"])


class TrustedDevice(models.Model):
    """A device for which MFA verification was explicitly bypassed.

    Two distinct trust scopes are kept apart:

    - ``BROWSER``: trust is handed out through a signed, httponly cookie and
      the record here merely allows the user to review/revoke that trust.
    - ``APP``: headless (mobile) clients cannot rely on cookies, so their trust
      is fully persisted server side and looked up per device.
    """

    class Scope(models.TextChoices):
        BROWSER = "browser", _("Browser")
        APP = "app", _("App")

    objects = TrustedDeviceManager()

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    scope = models.CharField(max_length=20, choices=Scope.choices)
    fingerprint = models.CharField(max_length=64)
    identifier = models.CharField(max_length=200)
    user_agent = models.CharField(max_length=200, default="")
    created_at = models.DateTimeField(default=timezone.now)
    last_seen_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [
            UniqueConstraint(
                fields=["user", "scope", "identifier"],
                name="unique_trusted_device",
            )
        ]

    def __str__(self) -> str:
        return f"{self.get_scope_display()}: {self.identifier}"

    @property
    def is_expired(self) -> bool:
        from allauth.mfa import app_settings

        return self.created_at + app_settings.TRUST_COOKIE_AGE <= timezone.now()
