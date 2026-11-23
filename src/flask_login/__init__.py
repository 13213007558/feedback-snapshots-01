from .config import CONTINUATION_ENABLED
from .config import CONTINUATION_ENTRY_PARAM
from .config import CONTINUATION_PARAM
from .config import CONTINUATION_SAFE_HOME
from .config import CONTINUATION_TTL
from .config import COOKIE_DURATION
from .config import COOKIE_HTTPONLY
from .config import COOKIE_NAME
from .config import COOKIE_SECURE
from .config import ID_ATTRIBUTE
from .config import LOGIN_MESSAGE
from .config import LOGIN_MESSAGE_CATEGORY
from .config import REFRESH_MESSAGE
from .config import REFRESH_MESSAGE_CATEGORY
from .continuation import Continuation
from .continuation import ContinuationPolicy
from .continuation import ContinuationStore
from .continuation import consume_continuation
from .continuation import continuation_token
from .continuation import MemoryContinuationStore
from .continuation import pending_continuations
from .login_manager import LoginManager
from .mixins import AnonymousUserMixin
from .mixins import UserMixin
from .signals import session_protected
from .signals import user_accessed
from .signals import user_loaded_from_cookie
from .signals import user_loaded_from_request
from .signals import user_logged_in
from .signals import user_logged_out
from .signals import user_login_confirmed
from .signals import user_needs_refresh
from .signals import user_unauthorized
from .test_client import FlaskLoginClient
from .utils import confirm_login
from .utils import current_user
from .utils import decode_cookie
from .utils import encode_cookie
from .utils import fresh_login_required
from .utils import login_fresh
from .utils import login_remembered
from .utils import login_required
from .utils import login_url
from .utils import login_user
from .utils import logout_user
from .utils import make_next_param
from .utils import set_login_view

__all__ = [
    "CONTINUATION_ENABLED",
    "CONTINUATION_ENTRY_PARAM",
    "CONTINUATION_PARAM",
    "CONTINUATION_SAFE_HOME",
    "CONTINUATION_TTL",
    "COOKIE_DURATION",
    "COOKIE_HTTPONLY",
    "COOKIE_NAME",
    "COOKIE_SECURE",
    "ID_ATTRIBUTE",
    "LOGIN_MESSAGE",
    "LOGIN_MESSAGE_CATEGORY",
    "REFRESH_MESSAGE",
    "REFRESH_MESSAGE_CATEGORY",
    "Continuation",
    "ContinuationPolicy",
    "ContinuationStore",
    "MemoryContinuationStore",
    "LoginManager",
    "AnonymousUserMixin",
    "UserMixin",
    "session_protected",
    "user_accessed",
    "user_loaded_from_cookie",
    "user_loaded_from_request",
    "user_logged_in",
    "user_logged_out",
    "user_login_confirmed",
    "user_needs_refresh",
    "user_unauthorized",
    "FlaskLoginClient",
    "confirm_login",
    "consume_continuation",
    "continuation_token",
    "current_user",
    "decode_cookie",
    "encode_cookie",
    "fresh_login_required",
    "login_fresh",
    "login_remembered",
    "login_required",
    "login_url",
    "login_user",
    "logout_user",
    "make_next_param",
    "pending_continuations",
    "set_login_view",
]


def __getattr__(name):
    if name == "__version__":
        import importlib.metadata
        import warnings

        warnings.warn(
            "'__version__' is deprecated and will be removed in Flask-Login 1.0. Use"
            " 'importlib.metadata.version(\"flask-login\")' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return importlib.metadata.version("flask-login")

    raise AttributeError(name)
