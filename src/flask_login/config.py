from datetime import timedelta

#: The default name of the "remember me" cookie (``remember_token``)
COOKIE_NAME = "remember_token"

#: The default time before the "remember me" cookie expires (365 days).
COOKIE_DURATION = timedelta(days=365)

#: Whether the "remember me" cookie requires Secure; defaults to ``False``
COOKIE_SECURE = False

#: Whether the "remember me" cookie uses HttpOnly or not; defaults to ``True``
COOKIE_HTTPONLY = True

#: Whether the "remember me" cookie requires same origin; defaults to ``None``
COOKIE_SAMESITE = None

#: The default flash message to display when users need to log in.
LOGIN_MESSAGE = "Please log in to access this page."

#: The default flash message category to display when users need to log in.
LOGIN_MESSAGE_CATEGORY = "message"

#: The default flash message to display when users need to reauthenticate.
REFRESH_MESSAGE = "Please reauthenticate to access this page."

#: The default flash message category to display when users need to
#: reauthenticate.
REFRESH_MESSAGE_CATEGORY = "message"

#: The default attribute to retrieve the str id of the user
ID_ATTRIBUTE = "get_id"

#: A set of session keys that are populated by Flask-Login. Use this set to
#: purge keys safely and accurately.
SESSION_KEYS = {
    "_user_id",
    "_remember",
    "_remember_seconds",
    "_id",
    "_fresh",
    "next",
    "continuation",
    "continuation_tokens",
    "continuation_entries",
    "continuation_entry",
}

#: A set of HTTP methods which are exempt from `login_required` and
#: `fresh_login_required`. By default, this is just ``OPTIONS``.
EXEMPT_METHODS = {"OPTIONS"}

#: If true, the page the user is attempting to access is stored in the session
#: rather than a url parameter when redirecting to the login view; defaults to
#: ``False``.
USE_SESSION_FOR_NEXT = False

#: The default query string / form field used to carry a continuation flow
#: identifier to the login page.
CONTINUATION_PARAM = "continuation"

#: The default query string / form field used to carry the entry point of a
#: continuation to the login page. This lets a losing concurrent confirmation
#: fall back to the right entry's safe home.
CONTINUATION_ENTRY_PARAM = "continuation_entry"

#: The default lifetime of a continuation record. ``None`` disables expiry
#: (records remain single-use).
CONTINUATION_TTL = timedelta(minutes=30)

#: The default landing page used when a continuation is missing, expired, or
#: no longer authorized.
CONTINUATION_SAFE_HOME = "/"

#: Whether the optional continuation mechanism is enabled.
CONTINUATION_ENABLED = False
