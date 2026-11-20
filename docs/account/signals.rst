Signals
=======

There are several signals emitted during authentication flows. You can
hook to them for your own needs.

- ``allauth.account.signals.authentication_step_completed(request, user, method, **kwargs)``
    Sent when an authentication step was completed. Note that this does not
    imply that the user is fully signed in. For example, consider a case where a
    user authenticates using a password, but still needs to complete the 2FA
    challenge.

- ``allauth.account.signals.user_logged_in(request, user)``
    Sent when a user logs in.

- ``allauth.account.signals.user_logged_out(request, user)``
    Sent when a user logs out.

- ``allauth.account.signals.user_signed_up(request, user)``
    Sent when a user signs up for an account. This signal is
    typically followed by a ``user_logged_in``, unless email verification
    prohibits the user to log in.

- ``allauth.account.signals.password_set(request, user)``
    Sent when a password has been successfully set for the first time.

- ``allauth.account.signals.password_changed(request, user)``
    Sent when a password has been successfully changed.

- ``allauth.account.signals.password_reset(request, user)``
    Sent when a password has been successfully reset.

- ``allauth.account.signals.email_confirmed(request, email_address)``
    Sent after the email address in the db was updated and set to confirmed.

- ``allauth.account.signals.email_confirmation_sent(request, confirmation, signup)``
    Sent right after the email confirmation is sent.

    Note that the ``confirmation`` carries the recipient address and, depending
    on the confirmation model, the confirmation key. Do not forward this signal
    to systems that are not allowed to see those details. Use
    ``email_verification_delivery`` for audit or statistics purposes instead.

- ``allauth.account.signals.email_verification_delivery(delivery, event, organization, reference)``
    Sent for every email verification delivery attempt, after the outcome is
    known. The ``delivery`` argument is an
    ``allauth.account.delivery.EmailVerificationDelivery`` record. It only
    contains the event classification (``event``), the organization and an
    opaque ``reference``, and is safe to forward to audit or statistics
    systems: it never contains the recipient address, the confirmation key or
    the activation URL.

    The signal does not receive the ``request`` on purpose, as request data may
    contain the address itself.

    The ``event`` values are defined by
    ``allauth.account.delivery.EmailVerificationDeliveryEvent``. Only the
    ``*_sent`` events represent an actual handoff to the email backend; the
    ``*_rate_limited`` events are emitted when a mail was suppressed by the
    ``confirm_email`` rate limit, and the ``*_suppressed`` events are emitted
    when enumeration prevention intentionally skips or replaces the mail.

    Organization and reference are obtained through the adapter methods
    ``get_email_verification_delivery_organization()`` and
    ``get_email_verification_delivery_reference()``. The default reference is a
    keyed hash derived from the address and the organization, so the same
    address maps to the same reference within an organization without exposing
    the address itself.

- ``allauth.account.signals.email_changed(request, user, from_email_address, to_email_address)``
    Sent when a primary email address has been changed.

- ``allauth.account.signals.email_added(request, user, email_address)``
    Sent when a new email address has been added.

- ``allauth.account.signals.email_removed(request, user, email_address)``
    Sent when an email address has been deleted.

- ``allauth.account.signals.login_code_rejected(request, user, last_attempt)``
    Sent when an incorrect login code was entered. The ``last_attempt`` boolean
    indicates whether the maximum number of attempts has been reached.

- ``allauth.account.signals.password_reset_code_rejected(request, user, last_attempt)``
    Sent when an incorrect password reset code was entered. The ``last_attempt``
    boolean indicates whether the maximum number of attempts has been reached.

- ``allauth.account.signals.email_verification_code_rejected(request, user, last_attempt)``
    Sent when an incorrect email verification code was entered. The
    ``last_attempt`` boolean indicates whether the maximum number of attempts has
    been reached.
