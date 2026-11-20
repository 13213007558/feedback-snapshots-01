from django.contrib.auth.signals import user_logged_out  # noqa
from django.dispatch import Signal


# Emitted when a user logs in.
# Arguments:
# - request: HttpRequest
# - user: User
user_logged_in = Signal()

# Emitted when a user signs up for an account. Typically followed by
# `user_logged_in` (unless, email verification kicks in).
# Arguments:
# - request: HttpRequest
# - user: User
user_signed_up = Signal()

# Emitted when a password has been successfully set for the first time.
# Arguments:
# - request: HttpRequest
# - user: User
password_set = Signal()

# Emitted when a password has been successfully changed.
# Arguments:
# - request: HttpRequest
# - user: User
password_changed = Signal()

# Emitted when a password has been successfully reset.
# Arguments:
# - request: HttpRequest
# - user: User
password_reset = Signal()

# Emitted when the email address has been verified.
# Arguments:
# - request: HttpRequest
# - email_address: EmailAddress
email_confirmed = Signal()

# Emitted right after the email confirmation is sent.
# Arguments:
# - request: HttpRequest
# - confirmation: EmailConfirmation
# - signup: bool
#
# Note that the confirmation contains the recipient address and, depending on
# the confirmation model, the confirmation key. Do not forward this signal to
# systems that are not allowed to see those details. Use
# `email_verification_delivery` for that purpose instead.
email_confirmation_sent = Signal()

# Emitted once for every email verification delivery attempt, after the outcome
# is known. The `delivery` record is safe to forward to audit or statistics
# systems: it only contains an event classification, an organization identifier
# and an opaque reference, never the recipient address, confirmation key or
# activation URL. Note that no `request` is passed on purpose, as it may
# contain the address or other request data.
# Arguments:
# - delivery: EmailVerificationDelivery
# - event: str
# - organization: str | None
# - reference: str
email_verification_delivery = Signal()

# Emitted when a primary email address has been changed.
# Arguments:
# - request: HttpRequest
# - user: User
# - from_email_address: EmailAddress
# - to_email_address: EmailAddress
email_changed = Signal()

# Emitted when a new email address has been added.
# Arguments:
# - request: HttpRequest
# - user: User
# - email_address: EmailAddress
email_added = Signal()

# Emitted when an email address has been deleted.
# Arguments:
# - request: HttpRequest
# - user: User
# - email_address: EmailAddress
email_removed = Signal()

# Emitted when an authentication step was completed. Note that this does not
# imply that the user is fully signed in.
# Arguments:
# - request: HttpRequest
# - user: User
# - method: str
# - **kwargs: additional method dependent kwargs
authentication_step_completed = Signal()

# Internal/private signal.
_add_email = Signal()


# Emitted when an incorrect login code was entered.
# Arguments:
# - request: HttpRequest
# - user: User
# - last_attempt: bool
login_code_rejected = Signal()

# Emitted when an incorrect password reset code was entered.
# Arguments:
# - request: HttpRequest
# - user: User
# - last_attempt: bool
password_reset_code_rejected = Signal()

# Emitted when an incorrect email verification code was entered.
# Arguments:
# - request: HttpRequest
# - user: User
# - last_attempt: bool
email_verification_code_rejected = Signal()
