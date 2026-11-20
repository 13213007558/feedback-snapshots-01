from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from django.utils.crypto import salted_hmac


class EmailVerificationDeliveryEvent(str, Enum):
    """
    Classifies the outcome of an email verification delivery attempt.

    Only the ``*_sent`` events represent an actual handoff to the email
    backend. The ``*_rate_limited`` and ``*_suppressed`` events are emitted
    when no mail was sent, so that delivery statistics can be reconciled.
    The ``*_suppressed`` events cover enumeration prevention, where the
    outside response intentionally does not reveal whether a mail was sent.
    """

    VERIFICATION_SENT = "verification_sent"
    VERIFICATION_RATE_LIMITED = "verification_rate_limited"
    VERIFICATION_SUPPRESSED = "verification_suppressed"
    ACCOUNT_ALREADY_EXISTS_SENT = "account_already_exists_sent"
    ACCOUNT_ALREADY_EXISTS_RATE_LIMITED = "account_already_exists_rate_limited"
    ACCOUNT_ALREADY_EXISTS_SUPPRESSED = "account_already_exists_suppressed"
    UNKNOWN_ACCOUNT_SENT = "unknown_account_sent"
    UNKNOWN_ACCOUNT_RATE_LIMITED = "unknown_account_rate_limited"
    UNKNOWN_ACCOUNT_SUPPRESSED = "unknown_account_suppressed"


@dataclass(frozen=True)
class EmailVerificationDelivery:
    """
    A forwardable record of an email verification delivery attempt.

    This record intentionally does not contain the recipient address, the
    confirmation key, or the activation URL. Those details remain available
    to the mail delivery side only.
    """

    event: EmailVerificationDeliveryEvent
    organization: str | None
    reference: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "event": self.event.value,
            "organization": self.organization,
            "reference": self.reference,
        }


def create_delivery_reference(email: str, organization: str | None) -> str:
    """
    Returns an opaque, organization scoped reference for an email address.

    The reference is stable for the same address within the same organization,
    allowing delivery events to be correlated without exposing the address
    itself.
    """
    value = f"{(organization or '').lower()}\0{email.lower()}"
    return salted_hmac(
        "allauth.account.email_verification_delivery", value, algorithm="sha256"
    ).hexdigest()
