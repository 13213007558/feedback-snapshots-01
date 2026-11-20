from __future__ import annotations

import time
from dataclasses import dataclass

from django.contrib.auth.base_user import AbstractBaseUser
from django.core.signing import BadSignature, Signer
from django.http import HttpRequest, HttpResponse
from django.utils import timezone
from django.utils.crypto import salted_hmac

from allauth.core.internal.httpkit import is_headless_request
from allauth.mfa import app_settings
from allauth.mfa.models import Authenticator, TrustedDevice


@dataclass
class IssuedTrust:
    fingerprint: str
    at: int


def create_config_fingerprint(user: AbstractBaseUser) -> str:
    """
    If the user changes anything about his security setup, we want to invalidate
    any trust that was issued before.
    """
    salt = "allauth.mfa.trust"
    parts: list[str] = []
    parts.append(str(user.pk))
    parts.append(user.password)
    for authenticator in Authenticator.objects.filter(user_id=user.pk).order_by("pk"):
        parts.append(str(authenticator.pk))
        parts.append(str(authenticator.type))
        seed = authenticator.data.get("seed")
        if seed is not None:
            parts.append(str(seed))
    return salted_hmac(salt, "|".join(parts), algorithm="sha256").hexdigest()


def get_device_identifier(request: HttpRequest) -> str:
    """
    A stable identifier for the device issuing the request. Headless app
    clients authenticate through session/JWT tokens rather than cookies, so
    their user agent is used to identify the physical device.
    """
    return request.META.get("HTTP_USER_AGENT", "")[
        0 : TrustedDevice._meta.get_field("identifier").max_length
    ]


def get_trust_scope(request: HttpRequest) -> str:
    client = is_headless_request(request)
    if client == "app":
        return TrustedDevice.Scope.APP
    return TrustedDevice.Scope.BROWSER


def decode_trust_cookie(request: HttpRequest) -> list[IssuedTrust]:
    value = request.COOKIES.get(app_settings.TRUST_COOKIE_NAME)
    if not value:
        return []
    signer = Signer()
    try:
        data = signer.unsign_object(value)
    except BadSignature:
        return []
    trusts = [IssuedTrust(fingerprint=entry[0], at=entry[1]) for entry in data]
    now = time.time()
    trusts = list(
        filter(
            lambda t: t.at + app_settings.TRUST_COOKIE_AGE.total_seconds() > now, trusts
        )
    )
    return trusts


def encode_trust_cookie(trusts: list[IssuedTrust]) -> str:
    signer = Signer()
    return signer.sign_object([(it.fingerprint, it.at) for it in trusts])


def _record_trusted_device(
    request: HttpRequest,
    user: AbstractBaseUser,
    scope: str,
    fingerprint: str,
) -> TrustedDevice:
    now = timezone.now()
    identifier = get_device_identifier(request)
    user_agent = request.META.get("HTTP_USER_AGENT", "")[
        0 : TrustedDevice._meta.get_field("user_agent").max_length
    ]
    device, _ = TrustedDevice.objects.update_or_create(
        user=user,
        scope=scope,
        identifier=identifier,
        defaults={
            "fingerprint": fingerprint,
            "user_agent": user_agent,
            "created_at": now,
            "last_seen_at": now,
        },
    )
    return device


def trust_browser(
    request: HttpRequest, user: AbstractBaseUser, response: HttpResponse
) -> None:
    fingerprint = create_config_fingerprint(user)
    scope = get_trust_scope(request)
    _record_trusted_device(request, user, scope, fingerprint)
    if scope != TrustedDevice.Scope.BROWSER:
        # App clients do not use cookies; trust is persisted server side.
        return
    trusts = decode_trust_cookie(request)
    trusts.append(IssuedTrust(fingerprint=fingerprint, at=int(time.time())))
    response.set_cookie(
        app_settings.TRUST_COOKIE_NAME,
        encode_trust_cookie(trusts),
        max_age=app_settings.TRUST_COOKIE_AGE,
        path=app_settings.TRUST_COOKIE_PATH,
        domain=app_settings.TRUST_COOKIE_DOMAIN,
        secure=app_settings.TRUST_COOKIE_SECURE,
        httponly=app_settings.TRUST_COOKIE_HTTPONLY,
        samesite=app_settings.TRUST_COOKIE_SAMESITE,
    )


def _is_trusted_app(request: HttpRequest, user: AbstractBaseUser) -> bool:
    fingerprint = create_config_fingerprint(user)
    device = TrustedDevice.objects.filter(
        user_id=user.pk,
        scope=TrustedDevice.Scope.APP,
        identifier=get_device_identifier(request),
    ).first()
    if not device:
        return False
    if device.is_expired or device.fingerprint != fingerprint:
        return False
    device.last_seen_at = timezone.now()
    device.save(update_fields=["last_seen_at"])
    return True


def _is_trusted_browser(request: HttpRequest, user: AbstractBaseUser) -> bool:
    fingerprint = create_config_fingerprint(user)
    trusts = decode_trust_cookie(request)
    if not any(t.fingerprint == fingerprint for t in trusts):
        return False
    # The cookie alone is not enough: the user may have revoked trust for this
    # device, in which case the matching server side record is gone.
    return TrustedDevice.objects.filter(
        user_id=user.pk,
        scope=TrustedDevice.Scope.BROWSER,
        identifier=get_device_identifier(request),
        fingerprint=fingerprint,
    ).exists()


def is_trusted_browser(request: HttpRequest, user: AbstractBaseUser) -> bool:
    if not app_settings._TRUST_STAGE_ENABLED:
        return False
    if get_trust_scope(request) == TrustedDevice.Scope.APP:
        return _is_trusted_app(request, user)
    return _is_trusted_browser(request, user)


def revoke_trust(
    request: HttpRequest,
    devices: list[TrustedDevice],
    response: HttpResponse | None = None,
) -> list[TrustedDevice]:
    """Revoke device trust.

    Existing sessions stay intact -- only the trust used to decide whether MFA
    verification is required at the next login is removed.
    """
    revoked_fingerprints = {
        device.fingerprint
        for device in devices
        if device.scope == TrustedDevice.Scope.BROWSER
    }
    if response is not None and revoked_fingerprints:
        trusts = [
            issued
            for issued in decode_trust_cookie(request)
            if issued.fingerprint not in revoked_fingerprints
        ]
        if trusts:
            response.set_cookie(
                app_settings.TRUST_COOKIE_NAME,
                encode_trust_cookie(trusts),
                max_age=app_settings.TRUST_COOKIE_AGE,
                path=app_settings.TRUST_COOKIE_PATH,
                domain=app_settings.TRUST_COOKIE_DOMAIN,
                secure=app_settings.TRUST_COOKIE_SECURE,
                httponly=app_settings.TRUST_COOKIE_HTTPONLY,
                samesite=app_settings.TRUST_COOKIE_SAMESITE,
            )
        else:
            response.delete_cookie(
                app_settings.TRUST_COOKIE_NAME,
                path=app_settings.TRUST_COOKIE_PATH,
                domain=app_settings.TRUST_COOKIE_DOMAIN,
            )
    for device in devices:
        device.delete()
    return devices
