import json
import re
import threading
import time
import uuid
from dataclasses import dataclass, field


# A browser login is an explicit, short-lived transaction.  The state value is
# kept server-side so that several login windows can be open at once without
# the last one overwriting the others.  A ticket is bound to the provider that
# issued it and to the browser session that started it.
LOGIN_STATE_TTL = 600
MAX_LOGIN_STATES = 1024

SESSION_COOKIE = 'flower_session'
IDENTITY_COOKIE = 'flower_identity'


class LoginStateError(ValueError):
    "a login callback could not be tied to its pending request"

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


@dataclass
class LoginTicket:
    state: str
    provider: str
    handler_path: str
    session_id: str
    redirect_uri: str
    next_url: str
    created_at: float
    expires_at: float
    status: str = 'pending'
    consumed_at: float = None
    handler_class: object = field(default=None, compare=False, repr=False)

    def is_expired(self, now=None):
        return (now or time.time()) >= self.expires_at

    @property
    def pending(self):
        return self.status == 'pending' and not self.is_expired()


class LoginTicketRegistry:
    "process-local registry of pending browser login transactions"

    def __init__(self, ttl=LOGIN_STATE_TTL, max_states=MAX_LOGIN_STATES):
        self.ttl = ttl
        self.max_states = max_states
        self._tickets = {}
        self._lock = threading.RLock()

    def _purge(self, now):
        expired = [state for state, ticket in self._tickets.items()
                   if (ticket.status in ('consumed', 'revoked')
                       and (now - (ticket.consumed_at or 0)) >= self.ttl)
                   or (ticket.status == 'failed'
                       and (now - (ticket.consumed_at or 0)) >= 60)
                   or (ticket.is_expired(now)
                       and (now - ticket.expires_at) >= self.ttl)]
        for state in expired:
            del self._tickets[state]
        # Never let an unauthenticated endpoint grow this without bound.
        while len(self._tickets) >= self.max_states:
            oldest = min(self._tickets.values(), key=lambda item: item.created_at)
            self._tickets.pop(oldest.state, None)

    def issue(self, provider, handler_path, session_id, redirect_uri,
              next_url, ttl=None, state=None, handler_class=None):
        now = time.time()
        state = state or str(uuid.uuid4())
        ticket = LoginTicket(
            state=state,
            provider=provider,
            handler_path=handler_path,
            session_id=session_id or '',
            redirect_uri=redirect_uri or '',
            next_url=next_url or '/',
            created_at=now,
            expires_at=now + (self.ttl if ttl is None else ttl),
            handler_class=handler_class,
        )
        with self._lock:
            self._purge(now)
            self._tickets[state] = ticket
        return ticket

    def get(self, state):
        if not state:
            return None
        with self._lock:
            return self._tickets.get(state)

    def claim(self, state, provider, session_id=None):
        "reserve a matching pending ticket for this callback"
        now = time.time()
        with self._lock:
            ticket = self._tickets.get(state)
            if ticket is None:
                raise LoginStateError('unknown')
            if ticket.status in ('consumed', 'failed', 'revoked'):
                raise LoginStateError('already finished')
            if ticket.status == 'claimed':
                # Another callback is still using this window; leave its
                # state alone so the first one can finish normally.
                raise LoginStateError('already in progress')
            if ticket.is_expired(now):
                ticket.status = 'expired'
                raise LoginStateError('expired')
            # A callback that does not belong to this transaction must not
            # consume it; the legitimate window can still finish.
            if ticket.provider != provider:
                raise LoginStateError('provider mismatch')
            if ticket.session_id and ticket.session_id != (session_id or ''):
                raise LoginStateError('session mismatch')
            ticket.status = 'claimed'
            return ticket

    def finish(self, state, status):
        "record the terminal status of a claimed login window"
        if status not in ('consumed', 'failed', 'expired', 'revoked'):
            raise ValueError(f'invalid login state status: {status}')
        now = time.time()
        with self._lock:
            ticket = self._tickets.get(state)
            if ticket is None:
                return None
            if ticket.status in ('consumed', 'failed', 'revoked'):
                return ticket
            ticket.status = status
            ticket.consumed_at = now
            return ticket

    def consume(self, state, provider, session_id=None):
        "claim and immediately consume one matching login window"
        ticket = self.claim(state, provider, session_id)
        return self.finish(ticket.state, 'consumed')

    def revoke_session(self, session_id):
        if not session_id:
            return 0
        revoked = 0
        now = time.time()
        with self._lock:
            for ticket in self._tickets.values():
                if ticket.session_id != session_id:
                    continue
                if ticket.status in ('pending', 'claimed'):
                    ticket.status = 'revoked'
                    ticket.consumed_at = now
                    revoked += 1
        return revoked

    def clear(self):
        with self._lock:
            self._tickets.clear()


login_tickets = LoginTicketRegistry()


@dataclass(frozen=True)
class LoginIdentity:
    provider: str
    subject: str
    email: str
    issued_at: float = 0.0

    def cookie_value(self):
        return json.dumps({
            'v': 1,
            'provider': self.provider,
            'subject': self.subject,
            'email': self.email,
            'issued_at': self.issued_at,
        }, separators=(',', ':'), sort_keys=True)

    @classmethod
    def from_cookie(cls, raw):
        if raw is None:
            return None
        if isinstance(raw, bytes):
            try:
                raw = raw.decode('utf-8')
            except UnicodeDecodeError:
                return None
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            return None
        if not isinstance(data, dict) or data.get('v') != 1:
            return None
        provider = data.get('provider')
        subject = data.get('subject')
        email = data.get('email')
        if not all(isinstance(item, str) and item
                   for item in (provider, subject, email)):
            return None
        try:
            issued_at = float(data.get('issued_at') or 0)
        except (ValueError, TypeError):
            issued_at = 0.0
        return cls(provider=provider, subject=subject, email=email,
                   issued_at=issued_at)


class UserIdentity(str):
    "display identity that also carries the trusted provider and subject"

    def __new__(cls, email, provider, subject):
        value = super().__new__(cls, email)
        value.provider = provider
        value.subject = subject
        return value


def authenticate(pattern, email):
    if '|' in pattern:
        return email in pattern.split('|')
    if '*' in pattern:
        pattern = re.escape(pattern).replace(r'\.\*', r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.\-]*")
        return re.fullmatch(pattern, email)
    return pattern == email


def validate_auth_option(pattern):
    if pattern.count('*') > 1:
        return False
    if '*' in pattern and '|' in pattern:
        return False
    return '*' not in pattern.rsplit('@', 1)[-1]
