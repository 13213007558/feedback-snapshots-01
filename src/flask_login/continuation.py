"""Optional continuation support for parallel login flows.

A continuation is a short-lived, single-use record of where a navigation was
heading when the user was sent to authenticate. Records are registered per
entry point (usually a blueprint) and are re-authorized when they are
consumed, using the subject that just completed the login or confirmation.
"""

import secrets
import threading
import time
from dataclasses import dataclass
from dataclasses import field
from datetime import timedelta
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

from flask import current_app
from flask import has_request_context
from flask import request
from flask import session
from flask import url_for

from .config import CONTINUATION_ENTRY_PARAM
from .config import CONTINUATION_PARAM
from .config import CONTINUATION_SAFE_HOME
from .config import CONTINUATION_TTL

#: Session key holding the most recently issued flow identifier.
SESSION_CONTINUATION = "continuation"

#: Session key holding every flow identifier issued in this browser session.
SESSION_CONTINUATION_TOKENS = "continuation_tokens"

#: Session key mapping an entry point to its most recent flow identifier.
SESSION_CONTINUATION_ENTRIES = "continuation_entries"

#: Session key holding the entry point of the most recent flow.
SESSION_CONTINUATION_ENTRY = "continuation_entry"


@dataclass
class Continuation:
    """A registered candidate destination for a login or confirmation flow."""

    token: str
    entry: object
    target: str
    endpoint: object = None
    created_at: float = field(default_factory=time.time)
    expires_at: object = None
    subject_id: object = None

    def is_expired(self, now=None):
        if self.expires_at is None:
            return False
        if now is None:
            now = time.time()
        return now >= self.expires_at


@dataclass
class ContinuationPolicy:
    """Per-entry configuration for continuations.

    :param ttl: How long a record remains valid. Accepts a
        :class:`datetime.timedelta`, seconds as a number, or ``None`` for no
        expiry.
    :param allowed_endpoints: Endpoints (or ``"blueprint.*"`` prefixes, or
        absolute paths) that may be used as a landing page. ``None`` allows
        any endpoint, subject to ``authorizer``.
    :param safe_home: Where to send the user when the candidate destination
        is not allowed. Accepts a URL/path or an endpoint name.
    :param authorizer: Optional callable ``(user, continuation) -> bool``
        evaluated at consumption time.
    """

    ttl: object = CONTINUATION_TTL
    allowed_endpoints: object = None
    safe_home: object = None
    authorizer: object = None


class ContinuationStore:
    """Interface for continuation storage.

    Applications that need shared storage (for example Redis or a database)
    can subclass this and assign an instance to
    :attr:`LoginManager.continuation_store`. Only :meth:`issue` and
    :meth:`claim` are required; :meth:`claim` must atomically remove the
    record so that at most one concurrent confirmation can win it.
    """

    def issue(self, continuation):
        """Store ``continuation``."""
        raise NotImplementedError

    def claim(self, token, subject_id=None):
        """Atomically remove and return a matching record, or ``None``.

        Implementations must ensure that a token can be claimed at most
        once. If a record is bound to a subject, it must only be returned
        when ``subject_id`` matches; otherwise the record should be left
        untouched.
        """
        raise NotImplementedError

    def peek(self, token):
        """Return a record without consuming it, or ``None``."""
        return None

    def now(self):
        """Return the current time used for expiry checks."""
        return time.time()

    def discard(self, token):
        """Remove a record if present."""
        return None

    def __len__(self):
        return 0


class MemoryContinuationStore(ContinuationStore):
    """Thread-safe in-process store used by default.

    This store is shared by every request handled by the same
    :class:`LoginManager` instance. It is suitable for a single process; use
    a shared store for multi-process deployments.
    """

    def __init__(self, clock=None):
        self._records = {}
        self._lock = threading.Lock()
        self._clock = clock or time.time

    def issue(self, continuation):
        with self._lock:
            self._records[continuation.token] = continuation

    def claim(self, token, subject_id=None):
        if not token:
            return None

        with self._lock:
            continuation = self._records.get(token)
            if continuation is None:
                return None

            if continuation.is_expired(self._clock()):
                del self._records[token]
                return None

            if continuation.subject_id is not None and subject_id != continuation.subject_id:
                return None

            del self._records[token]
            return continuation

    def peek(self, token):
        if not token:
            return None

        with self._lock:
            return self._records.get(token)

    def now(self):
        return self._clock()

    def discard(self, token):
        with self._lock:
            self._records.pop(token, None)

    def __len__(self):
        with self._lock:
            return len(self._records)

    def __contains__(self, token):
        return self.peek(token) is not None


def new_token():
    """Return an unguessable flow identifier."""
    return secrets.token_urlsafe(32)


def add_query_param(url, field, value):
    """Return ``url`` with ``field=value`` added or replaced."""
    parsed = urlsplit(url)
    args = parse_qs(parsed.query, keep_blank_values=True)
    args[field] = value
    return urlunsplit(parsed._replace(query=urlencode(args, doseq=True)))


def coerce_policy(value):
    """Normalize a configuration mapping or policy object."""
    if value is None:
        return ContinuationPolicy()
    if isinstance(value, ContinuationPolicy):
        return value
    if isinstance(value, dict):
        return ContinuationPolicy(
            ttl=value.get("ttl", value.get("max_age", CONTINUATION_TTL)),
            allowed_endpoints=value.get(
                "allowed_endpoints", value.get("allowed_routes")
            ),
            safe_home=value.get("safe_home"),
            authorizer=value.get("authorizer"),
        )
    raise TypeError("continuation policy must be a mapping or ContinuationPolicy")


def policy_for(config, entry):
    """Return the policy configured for ``entry``."""
    if config is None:
        return ContinuationPolicy()
    if isinstance(config, ContinuationPolicy):
        return config
    if callable(config):
        return coerce_policy(config(entry))
    if isinstance(config, dict):
        if any(
            key in config
            for key in ("ttl", "max_age", "allowed_endpoints", "allowed_routes", "safe_home")
        ):
            return coerce_policy(config)
        if entry in config:
            return coerce_policy(config[entry])
        if "*" in config:
            return coerce_policy(config["*"])
        return coerce_policy(config.get(None))
    raise TypeError("continuation_config must be a mapping, callable, or policy")


def _mapping_home(value, entry):
    if isinstance(value, dict):
        for key in (entry, "*", None):
            if key in value and value[key]:
                return value[key]
        return None
    return value


def safe_home(policy, fallback=None, entry=None):
    """Resolve a policy's safe home to a URL or relative path."""
    target = _mapping_home(policy.safe_home, entry)
    if callable(target):
        target = target()
    if not target:
        target = _mapping_home(fallback, entry)
    if not target:
        target = CONTINUATION_SAFE_HOME
    if target.startswith(("/", "http://", "https://")):
        return target
    try:
        return url_for(target)
    except Exception:
        return CONTINUATION_SAFE_HOME


def endpoint_allowed(continuation, allowed):
    """Return whether a continuation's endpoint is in an allow-list."""
    if allowed is None:
        return True
    if callable(allowed):
        return bool(allowed(continuation))
    if isinstance(allowed, str):
        allowed = {allowed}
    endpoint = continuation.endpoint
    path = continuation.target.split("?", 1)[0]
    for item in allowed:
        if item == endpoint or item == path:
            return True
        if isinstance(item, str) and item.endswith(".*") and endpoint:
            if endpoint.startswith(item[:-1]):
                return True
    return False


def _entry_key(entry):
    return entry or ""


def remember_in_session(token, entry):
    """Expose a flow identifier to the login page through the session."""
    tokens = session.get(SESSION_CONTINUATION_TOKENS)
    if not isinstance(tokens, list):
        tokens = []
    if token not in tokens:
        tokens.append(token)
    session[SESSION_CONTINUATION_TOKENS] = tokens[-20:]
    session[SESSION_CONTINUATION] = token

    entries = session.get(SESSION_CONTINUATION_ENTRIES)
    if not isinstance(entries, dict):
        entries = {}
    entries[_entry_key(entry)] = token
    session[SESSION_CONTINUATION_ENTRIES] = entries
    session[SESSION_CONTINUATION_ENTRY] = entry


def forget_in_session(token):
    """Remove a flow identifier from the session, if it is there."""
    tokens = session.get(SESSION_CONTINUATION_TOKENS)
    if isinstance(tokens, list) and token in tokens:
        remain = [item for item in tokens if item != token]
        if remain:
            session[SESSION_CONTINUATION_TOKENS] = remain
        else:
            session.pop(SESSION_CONTINUATION_TOKENS, None)
        if session.get(SESSION_CONTINUATION) == token:
            if remain:
                session[SESSION_CONTINUATION] = remain[-1]
            else:
                session.pop(SESSION_CONTINUATION, None)

    entries = session.get(SESSION_CONTINUATION_ENTRIES)
    if isinstance(entries, dict):
        removed = [key for key, value in entries.items() if value == token]
        for key in removed:
            del entries[key]
        if entries:
            session[SESSION_CONTINUATION_ENTRIES] = entries
        elif removed:
            session.pop(SESSION_CONTINUATION_ENTRIES, None)

    if session.get(SESSION_CONTINUATION_ENTRY) and not session.get(
        SESSION_CONTINUATION_TOKENS
    ):
        session.pop(SESSION_CONTINUATION_ENTRY, None)


def resolve_token(flow_id=None, entry=None):
    """Find the flow identifier supplied by the login page.

    The identifier can be passed explicitly, through the query string or
    form (``continuation=...``), or through the session.
    """
    if flow_id:
        return flow_id, False

    param = current_app.config.get("CONTINUATION_PARAM", CONTINUATION_PARAM)
    value = request.values.get(param)
    if value:
        return value, False

    if entry is not None:
        entries = session.get(SESSION_CONTINUATION_ENTRIES)
        if isinstance(entries, dict):
            value = entries.get(_entry_key(entry))
            if value:
                return value, True

    value = session.get(SESSION_CONTINUATION)
    if isinstance(value, (list, tuple)):
        value = value[-1] if value else None
    if value:
        return value, True

    return None, False


def _ttl_seconds(ttl):
    if ttl is None:
        return None
    if isinstance(ttl, timedelta):
        return ttl.total_seconds()
    if isinstance(ttl, (int, float)):
        return float(ttl)
    raise TypeError(f"continuation ttl must be a timedelta, number, or None, got: {ttl!r}")


def relative_target(target):
    """Reduce ``target`` to a relative path and query string."""
    if not target:
        return "/"
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc:
        path = parsed.path or "/"
        query = parsed.query
        return urlunsplit(("", "", path, query, ""))
    if not target.startswith("/") or target.startswith("//"):
        return "/" + target.lstrip("/")
    return target


def build_continuation(
    target,
    entry=None,
    endpoint=None,
    subject_id=None,
    policy=None,
    clock=None,
):
    """Create a continuation record without storing it."""
    if clock is None:
        clock = time.time
    created_at = clock()
    seconds = _ttl_seconds((policy or ContinuationPolicy()).ttl)
    expires_at = None if seconds is None else created_at + seconds
    return Continuation(
        token=new_token(),
        entry=entry,
        target=relative_target(target),
        endpoint=endpoint,
        created_at=created_at,
        expires_at=expires_at,
        subject_id=subject_id,
    )


def current_subject_id(user):
    """Return the identifier Flask-Login uses for ``user``."""
    if user is None or not getattr(user, "is_authenticated", False):
        return None
    attribute = current_app.login_manager.id_attribute
    identifier = getattr(user, attribute, None)
    if callable(identifier):
        identifier = identifier()
    return identifier


def consume_continuation(flow_id=None, entry=None, user=None):
    """Consume a continuation record and return its landing URL.

    This is the public interface a login or confirmation view should call
    after the user has been authenticated or their login confirmed.

    :param flow_id: The flow identifier. When omitted it is read from the
        query string/form (``continuation``) or from the session.
    :param entry: The current entry point (usually the blueprint name). When
        supplied together with session storage, it selects that entry's
        pending flow instead of the most recent one.
    :param user: The subject completing the flow. Defaults to
        ``current_user``. The subject must be authenticated.
    :return: The registered landing path (including its query string) when
        the record is valid and still authorized, otherwise the entry's safe
        home.
    """
    from .utils import _get_user

    login_manager = current_app.login_manager
    stored_policy = login_manager.continuation_config()

    fallback_home = current_app.config.get("CONTINUATION_SAFE_HOME", CONTINUATION_SAFE_HOME)

    if user is None:
        user = _get_user()

    # An explicit entry (argument, form/query field) identifies the entry
    # the confirmation is happening under. It must match the record; a
    # record registered for another entry cannot be redeemed here.
    requested_entry = entry
    if requested_entry is None:
        requested_entry = request.values.get(
            current_app.config.get("CONTINUATION_ENTRY_PARAM", CONTINUATION_ENTRY_PARAM)
        )
    explicit_entry = requested_entry is not None

    entry = requested_entry
    if entry is None:
        entry = session.get(SESSION_CONTINUATION_ENTRY)
    if entry is None:
        entry = request.blueprint

    token, from_session = resolve_token(flow_id, entry)
    if not token:
        return safe_home(policy_for(stored_policy, entry), fallback_home, entry)

    subject_id = current_subject_id(user)
    if subject_id is None:
        # Consuming a record is only ever done for an authenticated
        # subject; never reveal a landing to an anonymous request.
        return safe_home(policy_for(stored_policy, entry), fallback_home, entry)

    pending = login_manager.continuation_store.peek(token)
    effective_entry = pending.entry if pending is not None else entry
    if explicit_entry and pending is not None and pending.entry != requested_entry:
        # Do not consume a flow registered for a different entry; the
        # fallback belongs to the record's own entry.
        return safe_home(
            policy_for(stored_policy, effective_entry), fallback_home, effective_entry
        )

    continuation = login_manager.continuation_store.claim(token, subject_id=subject_id)
    if continuation is None:
        # A record bound to another subject is left in place for that
        # subject; an expired or already consumed one is simply gone.
        if pending is None or pending.is_expired(login_manager.continuation_store.now()):
            forget_in_session(token)
        return safe_home(
            policy_for(stored_policy, effective_entry), fallback_home, effective_entry
        )

    # Only the consumed record is removed from the session; any other
    # pending flow (for example another tab) is left untouched.
    forget_in_session(token)

    policy = policy_for(stored_policy, continuation.entry)
    if not endpoint_allowed(continuation, policy.allowed_endpoints):
        return safe_home(policy, fallback_home, continuation.entry)

    if policy.authorizer is not None and not policy.authorizer(user, continuation):
        return safe_home(policy, fallback_home, continuation.entry)

    return continuation.target


def continuation_token(entry=None):
    """Return the pending flow identifier for the login page, or ``None``.

    The identifier is read from the ``continuation`` query string/form field
    first, then from the session. When ``entry`` is given, that entry's
    pending flow is preferred over the most recent one.
    """
    if not has_request_context():
        return None
    token, _ = resolve_token(None, entry)
    return token


def pending_continuations(entry=None):
    """Return pending flow identifiers visible in the current session.

    :param entry: Restrict the result to this entry point.
    :return: A list of flow identifiers, oldest first.
    """
    if not has_request_context():
        return []

    tokens = session.get(SESSION_CONTINUATION_TOKENS)
    if not isinstance(tokens, list):
        return []

    if entry is None:
        return list(tokens)

    entries = session.get(SESSION_CONTINUATION_ENTRIES)
    if not isinstance(entries, dict):
        return []
    token = entries.get(_entry_key(entry))
    return [token] if token else []
