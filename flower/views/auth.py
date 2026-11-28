import json
import os
import time
import uuid
from urllib.parse import urlencode, urlparse

import tornado.auth
import tornado.web
from celery.utils.imports import instantiate
from tornado.options import options

from ..utils.authentication import (
    IDENTITY_COOKIE,
    SESSION_COOKIE,
    LoginIdentity,
    LoginStateError,
    authenticate,
    login_tickets,
)
from ..views import BaseHandler
from ..views.error import NotFoundErrorHandler

# pylint: disable=invalid-name


def is_safe_redirect(target):
    "check if target is a same-origin local path"
    if not target or not target.startswith('/'):
        return False
    if target.startswith(('//', '/\\')):
        return False
    parsed = urlparse(target)
    return not parsed.scheme and not parsed.netloc


def get_next_url(handler):
    url_prefix = handler.application.options.url_prefix
    default = '/' + url_prefix.strip('/') if url_prefix else '/'
    next_ = handler.get_argument('next', default)
    if url_prefix and next_ and next_[0] != '/':
        next_ = '/' + next_
    return next_ if is_safe_redirect(next_) else default


def _query_argument(request, name):
    values = request.query_arguments.get(name) if request else None
    if not values:
        return None
    value = values[0]
    if isinstance(value, bytes):
        try:
            value = value.decode('utf-8')
        except UnicodeDecodeError:
            return None
    return value


def _configured_login_handler():
    configured = getattr(options, 'auth_provider', None) or NotFoundErrorHandler
    if isinstance(configured, str):
        from celery.utils.imports import symbol_by_name
        configured = symbol_by_name(configured)
    return configured


def _ticket_handler(ticket):
    "the class that owns a window, falling back to its import path"
    handler = ticket.handler_class
    if handler is not None and ticket.handler_path == \
            f'{handler.__module__}.{handler.__qualname__}':
        return handler
    from celery.utils.imports import symbol_by_name
    return symbol_by_name(ticket.handler_path)


class OAuth2StateMixin:
    "Mixin binding each OAuth callback to the login window that started it"

    _OAUTH_PROVIDER_ID = None

    @property
    def login_provider(self):
        "stable identity of this authentication source"
        return self._OAUTH_PROVIDER_ID or self.login_handler_path

    @property
    def login_handler_path(self):
        return f'{type(self).__module__}.{type(self).__qualname__}'

    def _login_session_id(self):
        cached = getattr(self, '_login_session', None)
        if cached:
            return cached
        current = self.get_secure_cookie(SESSION_COOKIE)
        if current:
            if isinstance(current, bytes):
                current = current.decode()
            session_id = str(current)
        else:
            session_id = str(uuid.uuid4())
            self.set_secure_cookie(SESSION_COOKIE, session_id, expires_days=1)
        self._login_session = session_id
        return session_id

    def login_entry_retired(self):
        "true when this source may only finish requests issued before migration"
        if type(self).__dict__.get('_OAUTH_RETIRED', False):
            return True
        retired = self.settings.get('oauth_retired_providers') or ()
        if isinstance(retired, str):
            retired = [item.strip() for item in retired.split(',') if item.strip()]
        # A provider may be identified either by its stable id or by the
        # import path configured in previous releases.
        return bool({self.login_provider, self.login_handler_path} & set(retired))

    def start_login(self, redirect_uri, next_url=None):
        "register one pending login window and return its state"
        return login_tickets.issue(
            provider=self.login_provider,
            handler_path=self.login_handler_path,
            session_id=self._login_session_id(),
            redirect_uri=redirect_uri,
            next_url=next_url if next_url is not None else get_next_url(self),
            handler_class=type(self),
        )

    def _login_state_argument(self):
        return _query_argument(self.request, 'state')

    def is_login_callback(self):
        if not self.request:
            return bool(self.get_argument('code', False))
        return any(_query_argument(self.request, name) is not None
                   for name in ('code', 'state', 'error'))

    def claim_login_callback(self):
        "atomically claim the callback belonging to this window"
        state = self._login_state_argument()
        try:
            ticket = login_tickets.claim(
                state, self.login_provider, self._login_session_id())
        except LoginStateError as exc:
            raise tornado.auth.AuthError(
                f'OAuth authenticator error: login state {exc.reason}') from exc
        error = self.get_argument('error', None)
        if error:
            login_tickets.finish(ticket.state, 'failed')
            raise tornado.auth.AuthError(
                'OAuth authenticator error: the provider declined the login')
        return ticket

    def complete_login(self, email, subject=None):
        "establish a fresh browser session for the claimed login window"
        ticket = self._login_ticket
        # Finalize before writing cookies so a window revoked by a concurrent
        # logout cannot still create a session when the provider returns.
        ticket = login_tickets.finish(ticket.state, 'consumed')
        if ticket is None or ticket.status != 'consumed':
            raise tornado.auth.AuthError(
                'OAuth authenticator error: login window was ended')
        identity = LoginIdentity(
            provider=ticket.provider,
            subject=str(subject or email),
            email=str(email),
            issued_at=time.time(),
        )
        self.set_secure_cookie('user', identity.email)
        self.set_secure_cookie(IDENTITY_COOKIE, identity.cookie_value())
        self.redirect(ticket.next_url)

    def fail_login(self):
        "end only the claimed window; other windows keep their state"
        ticket = getattr(self, '_login_ticket', None)
        if ticket is not None:
            login_tickets.finish(ticket.state, 'failed')

    def begin_authorization(self, redirect_uri, extra_params=None):
        "start a login or reject a retired source's new entry"
        if self.login_entry_retired():
            raise tornado.web.HTTPError(
                404, 'This authentication entry is no longer available')
        ticket = self.start_login(redirect_uri)
        params = dict(extra_params or {})
        params['state'] = ticket.state
        return params

    # Kept for custom providers written against the old single-cookie API.
    # Built-in handlers use provider-bound tickets instead, so these helpers
    # do not claim a state and cannot bypass the migration rules.
    def set_oauth_state(self):
        state = str(uuid.uuid4())
        self.set_secure_cookie('oauth_state', state)
        return state

    def verify_oauth_state(self):
        expected = (self.get_secure_cookie('oauth_state') or b'').decode()
        if not expected or self.get_argument('state', None) != expected:
            raise tornado.auth.AuthError(
                'OAuth authenticator error: State tokens do not match')
        self.clear_cookie('oauth_state')


class GoogleAuth2LoginHandler(BaseHandler, OAuth2StateMixin,
                              tornado.auth.GoogleOAuth2Mixin):
    _OAUTH_SETTINGS_KEY = 'oauth'

    async def get(self):
        redirect_uri = self.settings[self._OAUTH_SETTINGS_KEY]['redirect_uri']
        if self.is_login_callback():
            self._login_ticket = self.claim_login_callback()
            try:
                user = await self.get_authenticated_user(
                    redirect_uri=redirect_uri,
                    code=self.get_argument('code'),
                )
                await self._on_auth(user)
            except Exception:
                self.fail_login()
                raise
        else:
            self.authorize_redirect(
                redirect_uri=redirect_uri,
                client_id=self.settings[self._OAUTH_SETTINGS_KEY]['key'],
                scope=['profile', 'email'],
                response_type='code',
                extra_params=self.begin_authorization(
                    redirect_uri, {'approval_prompt': ''})
            )

    async def _on_auth(self, user):
        if not user:
            raise tornado.web.HTTPError(403, 'Google auth failed')
        access_token = user['access_token']

        try:
            response = await self.get_auth_http_client().fetch(
                'https://www.googleapis.com/userinfo/v2/me',
                headers={'Authorization': f'Bearer {access_token}'})
        except Exception as e:
            raise tornado.web.HTTPError(403, f'Google auth failed: {e}')

        email = json.loads(response.body.decode('utf-8'))['email']
        if not authenticate(self.application.options.auth, email):
            message = f"Access denied to '{email}'. Please use another account or ask your admin to add your email to flower --auth."
            raise tornado.web.HTTPError(403, message)

        self.complete_login(email)


def resolve_login_handler(request):
    "pick the provider that owns this request, preserving in-flight callbacks"
    configured = _configured_login_handler()
    if request is None:
        return configured
    if _query_argument(request, 'code') is None and \
            _query_argument(request, 'error') is None:
        return configured
    state = _query_argument(request, 'state')
    ticket = login_tickets.get(state)
    # A callback belongs to the provider and window that issued its state.
    # This lets a login started before a migration finish on its original
    # provider even after the default entry points at the new one.
    if ticket is not None:
        return _ticket_handler(ticket)
    return configured


class LoginHandler(BaseHandler):
    def __new__(cls, application, request, **kwargs):
        handler = resolve_login_handler(request)
        return instantiate(handler, application, request, **kwargs)


class LogoutHandler(BaseHandler):
    def get(self):
        session_id = self.get_secure_cookie(SESSION_COOKIE)
        if session_id:
            if isinstance(session_id, bytes):
                session_id = session_id.decode()
            login_tickets.revoke_session(session_id)
        for name in ('user', IDENTITY_COOKIE, SESSION_COOKIE, 'oauth_state'):
            self.clear_cookie(name)
        self.current_user = None
        self.render('logout.html')


class GithubLoginHandler(BaseHandler, OAuth2StateMixin, tornado.auth.OAuth2Mixin):

    _OAUTH_DOMAIN = os.getenv(
        "FLOWER_GITHUB_OAUTH_DOMAIN", "github.com")
    _OAUTH_AUTHORIZE_URL = f'https://{_OAUTH_DOMAIN}/login/oauth/authorize'
    _OAUTH_ACCESS_TOKEN_URL = f'https://{_OAUTH_DOMAIN}/login/oauth/access_token'
    _OAUTH_NO_CALLBACKS = False
    _OAUTH_SETTINGS_KEY = 'oauth'

    async def get_authenticated_user(self, redirect_uri, code):
        body = urlencode({
            "redirect_uri": redirect_uri,
            "code": code,
            "client_id": self.settings[self._OAUTH_SETTINGS_KEY]['key'],
            "client_secret": self.settings[self._OAUTH_SETTINGS_KEY]['secret'],
            "grant_type": "authorization_code",
        })

        response = await self.get_auth_http_client().fetch(
            self._OAUTH_ACCESS_TOKEN_URL,
            method="POST",
            headers={'Content-Type': 'application/x-www-form-urlencoded',
                     'Accept': 'application/json'}, body=body)

        if response.error:
            raise tornado.auth.AuthError(f'OAuth authenticator error: {response}')

        return json.loads(response.body.decode('utf-8'))

    async def get(self):
        redirect_uri = self.settings[self._OAUTH_SETTINGS_KEY]['redirect_uri']
        if self.is_login_callback():
            self._login_ticket = self.claim_login_callback()
            try:
                user = await self.get_authenticated_user(
                    redirect_uri=redirect_uri,
                    code=self.get_argument('code'),
                )
                await self._on_auth(user)
            except Exception:
                self.fail_login()
                raise
        else:
            self.authorize_redirect(
                redirect_uri=redirect_uri,
                client_id=self.settings[self._OAUTH_SETTINGS_KEY]['key'],
                scope=['user:email'],
                response_type='code',
                extra_params=self.begin_authorization(
                    redirect_uri, {'approval_prompt': ''})
            )

    @classmethod
    def _email_api_url(cls):
        if cls._OAUTH_DOMAIN == 'github.com':
            return 'https://api.github.com/user/emails'
        # GitHub Enterprise Server serves the API under /api/v3
        return f'https://{cls._OAUTH_DOMAIN}/api/v3/user/emails'

    async def _on_auth(self, user):
        if not user:
            raise tornado.web.HTTPError(500, 'OAuth authentication failed')
        access_token = user['access_token']

        try:
            response = await self.get_auth_http_client().fetch(
                self._email_api_url(),
                headers={'Authorization': 'token ' + access_token,
                         'User-agent': 'Tornado auth'})
        except Exception as e:
            raise tornado.web.HTTPError(
                403,
                'Failed to fetch user emails from GitHub. '
                'Make sure the GitHub OAuth app has permission '
                'to read email addresses (Account permissions > Email addresses > Read-only).'
            ) from e

        emails = [email['email'].lower() for email in json.loads(response.body.decode('utf-8'))
                  if email['verified'] and authenticate(self.application.options.auth, email['email'])]

        if not emails:
            message = (
                "Access denied. Please use another account or "
                "ask your admin to add your email to flower --auth."
            )
            raise tornado.web.HTTPError(403, message)

        self.complete_login(emails.pop())


class GitLabLoginHandler(BaseHandler, OAuth2StateMixin, tornado.auth.OAuth2Mixin):

    _OAUTH_GITLAB_DOMAIN = os.getenv(
        "FLOWER_GITLAB_OAUTH_DOMAIN", "gitlab.com")
    _OAUTH_AUTHORIZE_URL = f'https://{_OAUTH_GITLAB_DOMAIN}/oauth/authorize'
    _OAUTH_ACCESS_TOKEN_URL = f'https://{_OAUTH_GITLAB_DOMAIN}/oauth/token'
    _OAUTH_NO_CALLBACKS = False

    async def get_authenticated_user(self, redirect_uri, code):
        body = urlencode({
            'redirect_uri': redirect_uri,
            'code': code,
            'client_id': self.settings['oauth']['key'],
            'client_secret': self.settings['oauth']['secret'],
            'grant_type': 'authorization_code',
        })
        response = await self.get_auth_http_client().fetch(
            self._OAUTH_ACCESS_TOKEN_URL,
            method='POST',
            headers={'Content-Type': 'application/x-www-form-urlencoded',
                     'Accept': 'application/json'},
            body=body
        )
        if response.error:
            raise tornado.auth.AuthError(f'OAuth authenticator error: {response}')
        return json.loads(response.body.decode('utf-8'))

    async def get(self):
        redirect_uri = self.settings['oauth']['redirect_uri']
        if self.is_login_callback():
            self._login_ticket = self.claim_login_callback()
            try:
                user = await self.get_authenticated_user(
                    redirect_uri=redirect_uri,
                    code=self.get_argument('code'),
                )
                await self._on_auth(user)
            except Exception:
                self.fail_login()
                raise
        else:
            self.authorize_redirect(
                redirect_uri=redirect_uri,
                client_id=self.settings['oauth']['key'],
                scope=['read_api'],
                response_type='code',
                extra_params=self.begin_authorization(
                    redirect_uri, {'approval_prompt': ''}),
            )

    async def _on_auth(self, user):
        if not user:
            raise tornado.web.HTTPError(500, 'OAuth authentication failed')
        access_token = user['access_token']
        allowed_groups = os.environ.get('FLOWER_GITLAB_AUTH_ALLOWED_GROUPS', '')
        allowed_groups = [group.strip() for group in allowed_groups.split(',') if group]

        # Check user email address against regexp
        try:
            response = await self.get_auth_http_client().fetch(
                f'https://{self._OAUTH_GITLAB_DOMAIN}/api/v4/user',
                headers={'Authorization': 'Bearer ' + access_token,
                         'User-agent': 'Tornado auth'}
            )
        except Exception as e:
            raise tornado.web.HTTPError(403, f'GitLab auth failed: {e}')

        user_email = json.loads(response.body.decode('utf-8'))['email']
        email_allowed = authenticate(self.application.options.auth, user_email)

        # Check user's groups against list of allowed groups
        matching_groups = []
        if allowed_groups:
            min_access_level = os.environ.get('FLOWER_GITLAB_MIN_ACCESS_LEVEL', '20')
            response = await self.get_auth_http_client().fetch(
                f'https://{self._OAUTH_GITLAB_DOMAIN}/api/v4/groups?min_access_level={min_access_level}',
                headers={
                    'Authorization': 'Bearer ' + access_token,
                    'User-agent': 'Tornado auth'
                }
            )
            matching_groups = [
                group['id']
                for group in json.loads(response.body.decode('utf-8'))
                if group['full_path'] in allowed_groups
            ]

        if not email_allowed or (allowed_groups and len(matching_groups) == 0):
            message = 'Access denied. Please use another account or contact your admin.'
            raise tornado.web.HTTPError(403, message)

        self.complete_login(user_email)


class OktaLoginHandler(BaseHandler, OAuth2StateMixin, tornado.auth.OAuth2Mixin):
    _OAUTH_NO_CALLBACKS = False
    _OAUTH_SETTINGS_KEY = 'oauth'

    @property
    def base_url(self):
        return os.environ.get('FLOWER_OAUTH2_OKTA_BASE_URL')

    @property
    def _OAUTH_AUTHORIZE_URL(self):
        return f"{self.base_url}/v1/authorize"

    @property
    def _OAUTH_ACCESS_TOKEN_URL(self):
        return f"{self.base_url}/v1/token"

    @property
    def _OAUTH_USER_INFO_URL(self):
        return f"{self.base_url}/v1/userinfo"

    async def get_access_token(self, redirect_uri, code):
        body = urlencode({
            "redirect_uri": redirect_uri,
            "code": code,
            "client_id": self.settings[self._OAUTH_SETTINGS_KEY]['key'],
            "client_secret": self.settings[self._OAUTH_SETTINGS_KEY]['secret'],
            "grant_type": "authorization_code",
        })

        response = await self.get_auth_http_client().fetch(
            self._OAUTH_ACCESS_TOKEN_URL,
            method="POST",
            headers={'Content-Type': 'application/x-www-form-urlencoded',
                     'Accept': 'application/json'}, body=body)

        if response.error:
            raise tornado.auth.AuthError(f'OAuth authenticator error: {response}')

        return json.loads(response.body.decode('utf-8'))

    async def get(self):
        redirect_uri = self.settings[self._OAUTH_SETTINGS_KEY]['redirect_uri']
        if self.is_login_callback():
            self._login_ticket = self.claim_login_callback()
            try:
                access_token_response = await self.get_access_token(
                    redirect_uri=redirect_uri,
                    code=self.get_argument('code'),
                )
                await self._on_auth(access_token_response)
            except Exception:
                self.fail_login()
                raise
        else:
            self.authorize_redirect(
                redirect_uri=redirect_uri,
                client_id=self.settings[self._OAUTH_SETTINGS_KEY]['key'],
                scope=['openid email'],
                response_type='code',
                extra_params=self.begin_authorization(redirect_uri)
            )

    async def _on_auth(self, access_token_response):
        if not access_token_response:
            raise tornado.web.HTTPError(500, 'OAuth authentication failed')
        access_token = access_token_response['access_token']

        response = await self.get_auth_http_client().fetch(
            self._OAUTH_USER_INFO_URL,
            headers={'Authorization': 'Bearer ' + access_token,
                     'User-agent': 'Tornado auth'})

        decoded_body = json.loads(response.body.decode('utf-8'))
        email = (decoded_body.get('email') or '').strip()
        email_verified = (
            decoded_body.get('email_verified') and
            authenticate(self.application.options.auth, email)
        )

        if not email_verified:
            message = (
                "Access denied. Please use another account or "
                "ask your admin to add your email to flower --auth."
            )
            raise tornado.web.HTTPError(403, message)

        self.complete_login(email)
