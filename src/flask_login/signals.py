from flask.signals import Namespace

_signals = Namespace()

#: Sent when a user is logged in. In addition to the app (which is the
#: sender), it is passed `user`, which is the user being logged in.
user_logged_in = _signals.signal("logged-in")

#: Sent when a user is logged out. In addition to the app (which is the
#: sender), it is passed `user`, which is the user being logged out.
user_logged_out = _signals.signal("logged-out")

#: Sent when the user is loaded from the cookie. In addition to the app (which
#: is the sender), it is passed `user`, which is the user being reloaded.
user_loaded_from_cookie = _signals.signal("loaded-from-cookie")

#: Sent when the user is loaded from the request. In addition to the app (which
#: is the #: sender), it is passed `user`, which is the user being reloaded.
user_loaded_from_request = _signals.signal("loaded-from-request")

#: Sent when restoring a user fails. In addition to the app (which is the
#: sender), it is passed a :class:`~flask_login.LoadResult` as `result`. The
#: result only records the load source, a categorical failure reason and the
#: user id (never the raw cookie, a password or network credentials), so it is
#: safe to forward to an event collector.
user_load_failed = _signals.signal("load-failed")

#: Sent when a user's login is confirmed, marking it as fresh. (It is not
#: called for a normal login.)
#: It receives no additional arguments besides the app.
user_login_confirmed = _signals.signal("login-confirmed")

#: Sent when the `unauthorized` method is called on a `LoginManager`. It
#: receives no additional arguments besides the app.
user_unauthorized = _signals.signal("unauthorized")

#: Sent when the `needs_refresh` method is called on a `LoginManager`. It
#: receives no additional arguments besides the app.
user_needs_refresh = _signals.signal("needs-refresh")

#: Sent whenever the user is accessed/loaded
#: receives no additional arguments besides the app.
user_accessed = _signals.signal("accessed")

#: Sent whenever session protection takes effect, and a session is either
#: marked non-fresh or deleted. It receives no additional arguments besides
#: the app.
session_protected = _signals.signal("session-protected")
