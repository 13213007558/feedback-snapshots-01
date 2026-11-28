import base64
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

import tornado.auth
import tornado.httputil
from tornado.httputil import HTTPHeaders, HTTPServerRequest, RequestStartLine
from tornado.options import options
from tornado.web import Application, create_signed_value, decode_signed_value

from flower.urls import settings
from flower.utils.authentication import (
    IDENTITY_COOKIE,
    SESSION_COOKIE,
    LoginIdentity,
    LoginStateError,
    LoginTicketRegistry,
    authenticate,
    login_tickets,
    validate_auth_option,
)
from flower.views import BaseHandler
from flower.views.auth import (
    GithubLoginHandler,
    get_next_url,
    is_safe_redirect,
    resolve_login_handler,
)
from tests.unit import AsyncHTTPTestCase


class DummyLoginHandler(BaseHandler):
    def get(self):
        self.write('login page')


class GithubEmailApiUrlTests(TestCase):
    def test_github_com_uses_api_subdomain(self):
        with patch.object(GithubLoginHandler, '_OAUTH_DOMAIN', 'github.com'):
            self.assertEqual('https://api.github.com/user/emails',
                             GithubLoginHandler._email_api_url())

    def test_enterprise_server_uses_api_v3_path(self):
        with patch.object(GithubLoginHandler, '_OAUTH_DOMAIN',
                          'ghe.example.com'):
            self.assertEqual('https://ghe.example.com/api/v3/user/emails',
                             GithubLoginHandler._email_api_url())


class LoginRouteTests(AsyncHTTPTestCase):
    def test_login_trailing_slash(self):
        provider = f'{DummyLoginHandler.__module__}.DummyLoginHandler'
        with self.mock_option('auth_provider', provider):
            r = self.fetch('/login')
            self.assertEqual(200, r.code)
            r = self.fetch('/login/')
            self.assertEqual(200, r.code)


class LogoutTests(AsyncHTTPTestCase):
    @staticmethod
    def session_cookie(email='user@example.com'):
        signed = create_signed_value(settings['cookie_secret'], 'user', email)
        return {'Cookie': 'user=' + signed.decode()}

    def test_logout_clears_the_session_cookie(self):
        with self.mock_option('auth', '.*@example.com'):
            r = self.fetch('/logout', headers=self.session_cookie())
            self.assertEqual(200, r.code)
            cleared = [c for c in r.headers.get_list('Set-Cookie') if c.startswith('user=')]
            self.assertEqual(1, len(cleared))
            self.assertIn('expires=', cleared[0].lower())
            body = r.body.decode('utf-8')
            self.assertIn('You have been logged out', body)
            self.assertIn('app-navbar', body)
            self.assertNotIn('/logout"', body)

    def test_logout_page_needs_no_session(self):
        with self.mock_option('auth', '.*@example.com'):
            r = self.fetch('/logout', follow_redirects=False)
            self.assertEqual(200, r.code)

    def test_navbar_shows_logout_for_oauth_sessions(self):
        with self.mock_option('auth', '.*@example.com'):
            r = self.fetch('/', headers=self.session_cookie())
            self.assertEqual(200, r.code)
            body = r.body.decode('utf-8')
            self.assertIn('href="/logout"', body)
            self.assertIn('Log out user@example.com', body)

    def test_navbar_hides_logout_without_oauth(self):
        r = self.fetch('/')
        self.assertEqual(200, r.code)
        self.assertNotIn('/logout', r.body.decode('utf-8'))

    def test_navbar_hides_logout_for_basic_auth(self):
        with self.mock_option('basic_auth', ['user:pass']):
            r = self.fetch('/', auth_username='user', auth_password='pass')
            self.assertEqual(200, r.code)
            self.assertNotIn('/logout', r.body.decode('utf-8'))


def _handler(next_value, url_prefix=''):
    options = SimpleNamespace(url_prefix=url_prefix)
    return SimpleNamespace(
        application=SimpleNamespace(options=options),
        get_argument=lambda name, default: (
            default if next_value is None else next_value),
    )


class BasicAuthTests(AsyncHTTPTestCase):
    def test_with_single_creds(self):
        with self.mock_option('basic_auth', ['foo:bar']):
            r = self.fetch('/')
            self.assertEqual(401, r.code)
            r = self.fetch('/', auth_username='foo', auth_password='bar')
            self.assertEqual(200, r.code)
            r = self.fetch('/', auth_username='foo', auth_password='bar2')
            self.assertEqual(401, r.code)

    def test_with_multiple_creds(self):
        with self.mock_option('basic_auth', ['user1:pswd1', 'user2:pswd2']):
            r = self.fetch('/')
            self.assertEqual(401, r.code)
            r = self.fetch('/', auth_username='user1', auth_password='pswd1')
            self.assertEqual(200, r.code)
            r = self.fetch('/', auth_username='user2', auth_password='pswd2')
            self.assertEqual(200, r.code)
            r = self.fetch('/', auth_username='user1', auth_password='pswd2')
            self.assertEqual(401, r.code)


class AuthTests(TestCase):
    def test_validate_auth_option(self):
        self.assertTrue(validate_auth_option("mail@example.com"))
        self.assertTrue(validate_auth_option(".*@example.com"))
        self.assertTrue(validate_auth_option("one.*@example.com"))
        self.assertTrue(validate_auth_option("one.*two@example.com"))
        self.assertFalse(validate_auth_option(".*@.*example.com"))
        self.assertFalse(validate_auth_option("one@domain1.com|.*@domain2.com"))
        self.assertTrue(validate_auth_option("one@example.com|two@example.com"))
        self.assertFalse(validate_auth_option("mail@.*example.com"))
        self.assertFalse(validate_auth_option(".*example.com"))

    def test_authenticate_single_email(self):
        self.assertTrue(authenticate("mail@example.com", "mail@example.com"))
        self.assertFalse(authenticate("mail@example.com", "foo@example.com"))
        self.assertFalse(authenticate("mail@example.com", "long.mail@example.com"))
        self.assertFalse(authenticate("mail@example.com", ""))
        self.assertFalse(authenticate("me@gmail.com", "me@gmail.com.attacker.com"))
        self.assertFalse(authenticate("me@gmail.com", "*"))

    def test_authenticate_email_list(self):
        self.assertTrue(authenticate("one@example.com|two@example.net", "one@example.com"))
        self.assertTrue(authenticate("one@example.com|two@example.net", "two@example.net"))
        self.assertFalse(authenticate("one@example.com|two@example.net", "two@example.com"))
        self.assertFalse(authenticate("one@example.com|two@example.net", "one@example.net"))
        self.assertFalse(authenticate("one@example.com|two@example.net", "mail@gmail.com"))
        self.assertFalse(authenticate("one@example.com|two@example.net", ""))
        self.assertFalse(authenticate("one@example.com|two@example.net", "*"))

    def test_is_safe_redirect(self):
        self.assertTrue(is_safe_redirect('/'))
        self.assertTrue(is_safe_redirect('/workers'))
        self.assertTrue(is_safe_redirect('/tasks?state=SUCCESS'))
        self.assertFalse(is_safe_redirect(''))
        self.assertFalse(is_safe_redirect('workers'))
        self.assertFalse(is_safe_redirect('//evil.com'))
        self.assertFalse(is_safe_redirect('/\\evil.com'))
        self.assertFalse(is_safe_redirect('https://evil.com'))
        self.assertFalse(is_safe_redirect('http:evil.com'))

    def test_get_next_url_rejects_open_redirects(self):
        self.assertEqual('/', get_next_url(_handler('//evil.com')))
        self.assertEqual('/', get_next_url(_handler('https://evil.com')))
        self.assertEqual('/flower', get_next_url(_handler('//evil.com', 'flower')))

    def test_get_next_url_allows_local_paths(self):
        self.assertEqual('/tasks', get_next_url(_handler('/tasks')))
        self.assertEqual('/', get_next_url(_handler(None)))
        self.assertEqual('/flower', get_next_url(_handler(None, 'flower')))
        # a bare path is normalized under the prefix, matching prior behavior
        self.assertEqual('/workers', get_next_url(_handler('workers', 'flower')))

    def test_authenticate_wildcard_email(self):
        self.assertTrue(authenticate(".*@example.com", "one@example.com"))
        self.assertTrue(authenticate("one.*@example.com", "one@example.com"))
        self.assertTrue(authenticate("one.*@example.com", "one.two@example.com"))
        self.assertFalse(authenticate(".*@example.com", "attacker@example.com.attacker.com"))
        self.assertFalse(authenticate(".*@corp.example.com", "attacker@corpZexample.com"))
        self.assertFalse(authenticate(r".*@corp\.example\.com", "attacker@corpZexample.com"))


class LoginTicketRegistryTests(TestCase):
    def setUp(self):
        self.registry = LoginTicketRegistry()

    def issue(self, provider='old', session='session-a', **kwargs):
        return self.registry.issue(
            provider=provider,
            handler_path=f'tests.{provider}',
            session_id=session,
            redirect_uri='http://localhost/login',
            next_url='/',
            **kwargs,
        )

    def test_two_windows_keep_independent_states(self):
        first = self.issue()
        second = self.issue(provider='new')
        self.assertNotEqual(first.state, second.state)
        self.assertTrue(self.registry.get(first.state).pending)
        self.assertTrue(self.registry.get(second.state).pending)

    def test_successful_callback_claims_and_consumes_only_its_own(self):
        first = self.issue()
        second = self.issue(provider='new')
        self.registry.claim(second.state, 'new', 'session-a')
        self.registry.finish(second.state, 'consumed')
        self.assertEqual('consumed', self.registry.get(second.state).status)
        self.assertTrue(self.registry.get(first.state).pending)
        ticket = self.registry.consume(first.state, 'old', 'session-a')
        self.assertEqual('old', ticket.provider)

    def test_callback_cannot_consume_a_ticket_from_another_provider(self):
        first = self.issue()
        with self.assertRaises(LoginStateError) as raised:
            self.registry.claim(first.state, 'new', 'session-a')
        self.assertEqual('provider mismatch', raised.exception.reason)
        self.assertTrue(self.registry.get(first.state).pending)

    def test_callback_cannot_consume_a_ticket_from_another_session(self):
        first = self.issue()
        with self.assertRaises(LoginStateError) as raised:
            self.registry.claim(first.state, 'old', 'session-b')
        self.assertEqual('session mismatch', raised.exception.reason)
        self.assertTrue(self.registry.get(first.state).pending)

    def test_replaying_a_finished_window_is_rejected(self):
        first = self.issue()
        self.registry.consume(first.state, 'old', 'session-a')
        with self.assertRaises(LoginStateError) as raised:
            self.registry.claim(first.state, 'old', 'session-a')
        self.assertEqual('already finished', raised.exception.reason)

    def test_unknown_state_is_rejected(self):
        with self.assertRaises(LoginStateError) as raised:
            self.registry.claim('missing', 'old', 'session-a')
        self.assertEqual('unknown', raised.exception.reason)

    def test_expired_window_is_rejected(self):
        first = self.issue(ttl=-1)
        with self.assertRaises(LoginStateError) as raised:
            self.registry.claim(first.state, 'old', 'session-a')
        self.assertEqual('expired', raised.exception.reason)

    def test_logout_revokes_pending_windows_for_that_session(self):
        mine = self.issue()
        theirs = self.issue(provider='new', session='session-b')
        self.assertEqual(1, self.registry.revoke_session('session-a'))
        self.assertFalse(self.registry.get(mine.state).pending)
        self.assertTrue(self.registry.get(theirs.state).pending)


class LoginIdentityTests(TestCase):
    def test_identity_roundtrip_keeps_provider_and_subject(self):
        identity = LoginIdentity('github', '42', 'user@example.com', 123.0)
        decoded = LoginIdentity.from_cookie(identity.cookie_value())
        self.assertEqual(identity, decoded)

    def test_display_name_does_not_replace_identity(self):
        first = LoginIdentity('old-provider', '1', 'same@example.com')
        second = LoginIdentity('new-provider', '2', 'same@example.com')
        self.assertEqual(first.email, second.email)
        self.assertNotEqual(
            LoginIdentity.from_cookie(first.cookie_value()),
            LoginIdentity.from_cookie(second.cookie_value()))

    def test_malformed_identity_is_ignored(self):
        for raw in (None, b'', '{}', 'not json',
                    '{"v":1,"provider":"","subject":"1","email":"e"}',
                    '{"v":1,"provider":"p","subject":"1"}',
                    '{"v":2,"provider":"p","subject":"1","email":"e"}'):
            self.assertIsNone(LoginIdentity.from_cookie(raw))


class _FakeProvider(GithubLoginHandler):
    "Github handler with the network calls replaced by a local return"

    email = 'same@example.com'
    subject = 'subject'

    async def get_authenticated_user(self, redirect_uri, code):
        return {'access_token': code}

    async def _on_auth(self, user):
        if user['access_token'] == 'denied':
            raise tornado.web.HTTPError(403, 'Access denied')
        self.complete_login(self.email, subject=self.subject)

    def get(self):
        redirect_uri = self.settings['oauth']['redirect_uri']
        if self.is_login_callback():
            self._login_ticket = self.claim_login_callback()
            try:
                if self.get_argument('code', None) == 'denied':
                    raise tornado.web.HTTPError(403, 'Access denied')
                self.complete_login(self.email, subject=self.subject)
            except Exception:
                self.fail_login()
                raise
        else:
            self.authorize_redirect(
                redirect_uri=redirect_uri,
                client_id='key',
                scope=['user:email'],
                response_type='code',
                extra_params=self.begin_authorization(redirect_uri),
            )


class LegacyProvider(_FakeProvider):
    _OAUTH_PROVIDER_ID = 'legacy-provider'


class CurrentProvider(_FakeProvider):
    _OAUTH_PROVIDER_ID = 'current-provider'


class LoginFlowHarness:
    "drive real handlers without opening a listening socket"

    def __init__(self, testcase):
        self.testcase = testcase
        self.cookies = {}
        self.options = SimpleNamespace(
            url_prefix='', basic_auth=None, auth='.*@example.com')

    def settings(self):
        return {
            'cookie_secret': 'login-flow-test-secret',
            'xsrf_cookies': False,
            'oauth': {
                'key': 'key',
                'secret': 'secret',
                'redirect_uri': 'http://localhost/login',
            },
            'oauth_retired_providers': (),
        }

    def request(self, uri):
        headers = HTTPHeaders({'Host': 'localhost'})
        if self.cookies:
            headers.add('Cookie', '; '.join(
                f'{name}={value}' for name, value in self.cookies.items()))
        return HTTPServerRequest(
            start_line=RequestStartLine('GET', uri, 'HTTP/1.1'),
            headers=headers,
            connection=Mock())

    def call(self, handler_cls, uri):
        app = Application([(r'/login', handler_cls)], **self.settings())
        app.options = self.options
        handler = handler_cls(app, self.request(uri))
        handler._transforms = []
        try:
            handler.get()  # sync; providers fake out every awaitable step
        except (tornado.web.HTTPError, tornado.auth.AuthError) as exc:
            if isinstance(exc, tornado.auth.AuthError):
                return 403, None
            return exc.status_code, None
        self._merge_cookies(handler, self.cookies)
        return handler.get_status(), handler._headers.get('Location')

    @staticmethod
    def _merge_cookies(handler, jar):
        for raw in handler._headers.get_list('Set-Cookie'):
            name, _, rest = raw.partition('=')
            value = rest.split(';', 1)[0]
            # Tornado quotes Set-Cookie values; request parsing unquotes them.
            value = tornado.httputil._unquote_cookie(value)
            if value in ('', '""'):
                jar.pop(name, None)
            else:
                jar[name] = value
        return jar

    def start(self, handler_cls):
        status, location = self.call(handler_cls, '/login')
        self.testcase.assertEqual(302, status)
        return parse_qs(urlparse(location).query)['state'][0]

    def finish(self, handler_cls, state, code='code', jar=None):
        saved = self.cookies
        if jar is not None:
            self.cookies = jar
        try:
            app = Application([(r'/login', handler_cls)], **self.settings())
            app.options = self.options
            handler = handler_cls(
                app, self.request(f'/login?code={code}&state={state}'))
            handler._transforms = []
            try:
                handler.get()
            except (tornado.web.HTTPError, tornado.auth.AuthError) as exc:
                if isinstance(exc, tornado.auth.AuthError):
                    return 403, None
                return exc.status_code, None
            self._merge_cookies(handler, self.cookies)
            return handler.get_status(), handler._headers.get('Location')
        finally:
            self.cookies = saved

    def identity(self, jar=None):
        raw = (jar or self.cookies).get(IDENTITY_COOKIE)
        if raw is None:
            return None
        unsigned = decode_signed_value(
            self.settings()['cookie_secret'], IDENTITY_COOKIE, raw)
        return LoginIdentity.from_cookie(unsigned)


class TwoProviderLoginFlowTests(TestCase):
    def setUp(self):
        self.harness = LoginFlowHarness(self)
        login_tickets.clear()

    def test_reversed_callbacks_keep_their_own_window(self):
        old_state = self.harness.start(LegacyProvider)
        old_jar = dict(self.harness.cookies)
        new_state = self.harness.start(CurrentProvider)
        new_jar = dict(self.harness.cookies)
        self.assertNotEqual(old_state, new_state)

        # The newer login returns first; it must not disturb the older one.
        self.assertEqual((302, '/'), self.harness.finish(
            CurrentProvider, new_state, jar=new_jar))
        self.assertEqual('consumed',
                         login_tickets.get(new_state).status)
        self.assertEqual('pending', login_tickets.get(old_state).status)

        # The older window still completes on the provider that issued it.
        self.assertEqual((302, '/'), self.harness.finish(
            LegacyProvider, old_state, jar=old_jar))
        self.assertEqual('consumed', login_tickets.get(old_state).status)

        old_identity = self.harness.identity(old_jar)
        new_identity = self.harness.identity(new_jar)
        self.assertEqual('same@example.com', old_identity.email)
        self.assertEqual('same@example.com', new_identity.email)
        self.assertEqual('legacy-provider', old_identity.provider)
        self.assertEqual('current-provider', new_identity.provider)

    def test_replaying_a_finished_window_fails_without_touching_others(self):
        state = self.harness.start(CurrentProvider)
        jar = dict(self.harness.cookies)
        self.harness.finish(CurrentProvider, state, jar=jar)
        status, _ = self.harness.finish(CurrentProvider, state, jar=jar)
        self.assertEqual(403, status)
        self.assertEqual('consumed', login_tickets.get(state).status)
        self.assertEqual('current-provider',
                         self.harness.identity(jar).provider)

    def test_failed_callback_ends_only_its_window(self):
        first = self.harness.start(LegacyProvider)
        first_jar = dict(self.harness.cookies)
        second = self.harness.start(CurrentProvider)
        second_jar = dict(self.harness.cookies)

        status, _ = self.harness.finish(
            LegacyProvider, first, code='denied', jar=first_jar)
        self.assertEqual(403, status)
        self.assertEqual('failed', login_tickets.get(first).status)
        self.assertEqual('pending', login_tickets.get(second).status)

        status, _ = self.harness.finish(
            CurrentProvider, second, jar=second_jar)
        self.assertEqual(302, status)
        self.assertEqual('consumed', login_tickets.get(second).status)

    def test_callback_with_another_window_state_can_not_be_reused(self):
        old_state = self.harness.start(LegacyProvider)
        old_jar = dict(self.harness.cookies)
        new_state = self.harness.start(CurrentProvider)
        new_jar = dict(self.harness.cookies)

        # The old window's state presented to the new provider is rejected
        # and leaves both windows available for their real callbacks.
        status, _ = self.harness.finish(
            CurrentProvider, old_state, jar=new_jar)
        self.assertEqual(403, status)
        self.assertTrue(login_tickets.get(old_state).pending)
        self.assertTrue(login_tickets.get(new_state).pending)

        self.assertEqual((302, '/'), self.harness.finish(
            LegacyProvider, old_state, jar=old_jar))
        self.assertEqual((302, '/'), self.harness.finish(
            CurrentProvider, new_state, jar=new_jar))

    def test_a_window_cannot_return_through_a_foreign_browser_session(self):
        state = self.harness.start(CurrentProvider)
        status, _ = self.harness.finish(
            CurrentProvider, state, jar={})
        self.assertEqual(403, status)
        self.assertTrue(login_tickets.get(state).pending)

    def test_retired_provider_can_finish_but_not_start_new_logins(self):
        self.harness.settings = lambda: {
            'cookie_secret': 'login-flow-test-secret',
            'xsrf_cookies': False,
            'oauth': {
                'key': 'key',
                'secret': 'secret',
                'redirect_uri': 'http://localhost/login',
            },
            'oauth_retired_providers': ('legacy-provider',),
        }
        # Pre-issue the window as a login started before the migration.
        pre_migration = login_tickets.issue(
            provider='legacy-provider',
            handler_path='tests.unit.views.test_auth.LegacyProvider',
            session_id='pre-migration-session',
            redirect_uri='http://localhost/login',
            next_url='/',
        )
        jar = {SESSION_COOKIE: create_signed_value(
            'login-flow-test-secret', SESSION_COOKIE,
            'pre-migration-session').decode()}
        status, _ = self.harness.finish(
            LegacyProvider, pre_migration.state, jar=jar)
        self.assertEqual(302, status)
        self.assertEqual('consumed',
                         login_tickets.get(pre_migration.state).status)

        # A new entry through the retired provider is closed.
        status, _ = self.harness.call(LegacyProvider, '/login')
        self.assertEqual(404, status)


class SessionResolutionTests(TestCase):
    "provider-bound browser sessions are distinct from machine credentials"

    def handler(self, cookies=None, authorization=None, basic_auth=None,
                auth='.*@example.com',
                auth_provider='tests.unit.views.test_auth.LegacyProvider'):
        options = SimpleNamespace(
            basic_auth=basic_auth, auth=auth, url_prefix='',
            auth_provider=auth_provider)
        app = Application([], cookie_secret='session-test-secret')
        app.options = options
        app.settings['oauth_retired_providers'] = ()
        headers = HTTPHeaders({'Host': 'localhost'})
        if cookies:
            headers.add('Cookie', '; '.join(
                f'{name}={value}' for name, value in cookies.items()))
        if authorization:
            headers.add('Authorization', authorization)
        handler = BaseHandler(app, HTTPServerRequest(
            start_line=RequestStartLine('GET', '/', 'HTTP/1.1'),
            headers=headers, connection=Mock()))
        return handler

    @staticmethod
    def signed(name, value):
        return create_signed_value(
            'session-test-secret', name, value).decode()

    def session(self, provider='current-provider',
                subject='42', email='user@example.com'):
        identity = LoginIdentity(provider, subject, email)
        return {IDENTITY_COOKIE: self.signed(
            IDENTITY_COOKIE, identity.cookie_value())}

    @staticmethod
    def basic(username, password):
        token = base64.b64encode(f'{username}:{password}'.encode()).decode()
        return 'Basic ' + token

    def test_browser_session_exposes_provider_and_subject(self):
        user = self.handler(cookies=self.session()).get_current_user()
        self.assertEqual('user@example.com', user)
        self.assertEqual('current-provider', user.provider)
        self.assertEqual('42', user.subject)

    def test_display_cookie_is_a_local_identity_not_a_federated_source(self):
        legacy = {'user': self.signed('user', 'user@example.com')}
        user = self.handler(cookies=legacy).get_current_user()
        self.assertEqual('user@example.com', user)
        self.assertEqual('local', user.provider)

    def test_same_display_name_from_another_source_is_not_this_session(self):
        browser = self.session(provider='current-provider', subject='42')
        machine = self.session(provider='legacy-provider', subject='7')
        # Both decode, but each keeps its own source and subject.
        self.assertEqual(
            'current-provider',
            self.handler(cookies=browser).get_current_user().provider)
        self.assertEqual(
            'legacy-provider',
            self.handler(cookies=machine).get_current_user().provider)
        self.assertNotEqual(
            self.handler(cookies=browser).get_current_user().subject,
            self.handler(cookies=machine).get_current_user().subject)

    def test_machine_basic_auth_survives_a_browser_cookie(self):
        handler = self.handler(
            cookies=self.session(), authorization=self.basic('machine', 'key'),
            basic_auth=['machine:key'])
        self.assertTrue(handler.get_current_user())

    def test_machine_and_browser_both_configured_without_a_header(self):
        # Opening the web UI must keep working when Basic is also enabled.
        user = self.handler(
            cookies=self.session(), basic_auth=['machine:key']
        ).get_current_user()
        self.assertEqual('user@example.com', user)

    def test_wrong_machine_credentials_are_rejected_even_with_a_session(self):
        handler = self.handler(
            cookies=self.session(), authorization=self.basic('machine', 'bad'),
            basic_auth=['machine:key'])
        with self.assertRaises(tornado.web.HTTPError) as raised:
            handler.get_current_user()
        self.assertEqual(401, raised.exception.status_code)

    def test_missing_machine_credentials_are_rejected_in_basic_mode(self):
        handler = self.handler(basic_auth=['machine:key'], auth='')
        with self.assertRaises(tornado.web.HTTPError) as raised:
            handler.get_current_user()
        self.assertEqual(401, raised.exception.status_code)

    def test_session_from_a_retired_provider_is_not_renewed(self):
        handler = self.handler(cookies=self.session(provider='legacy-provider'))
        handler.application.settings['oauth_retired_providers'] = (
            'legacy-provider',)
        self.assertIsNone(handler.get_current_user())


class CallbackDispatchTests(TestCase):
    "a callback is routed to the provider that issued its state"

    @staticmethod
    def request(uri):
        return HTTPServerRequest(
            start_line=RequestStartLine('GET', uri, 'HTTP/1.1'),
            headers=HTTPHeaders({'Host': 'localhost'}),
            connection=Mock())

    def setUp(self):
        login_tickets.clear()

    @staticmethod
    def provider_name(handler_class):
        return f'{handler_class.__module__}.{handler_class.__qualname__}'

    def test_plain_entry_uses_the_configured_provider(self):
        with patch.object(
                options.mockable(), 'auth_provider',
                self.provider_name(CurrentProvider)):
            self.assertIs(
                CurrentProvider,
                resolve_login_handler(self.request('/login')))
            self.assertIs(
                CurrentProvider,
                resolve_login_handler(None))

    def test_callback_uses_the_provider_bound_to_its_state(self):
        ticket = login_tickets.issue(
            provider='legacy-provider',
            handler_path=self.provider_name(LegacyProvider),
            session_id='s', redirect_uri='http://localhost/login',
            next_url='/', handler_class=LegacyProvider)
        with patch.object(
                options.mockable(), 'auth_provider',
                self.provider_name(CurrentProvider)):
            self.assertIs(
                LegacyProvider,
                resolve_login_handler(
                    self.request(f'/login?code=x&state={ticket.state}')))
            # An unrecognized callback still goes to the current provider,
            # which then rejects the state instead of trusting it.
            self.assertIs(
                CurrentProvider,
                resolve_login_handler(
                    self.request('/login?code=x&state=unknown')))


class LogoutDuringCallbackTests(TestCase):
    "ending a browser session also ends its in-flight login windows"

    def setUp(self):
        login_tickets.clear()

    def test_revoked_window_cannot_establish_a_session(self):
        ticket = login_tickets.issue(
            provider='current-provider',
            handler_path='tests.unit.views.test_auth.CurrentProvider',
            session_id='browser-session',
            redirect_uri='http://localhost/login',
            next_url='/', handler_class=CurrentProvider)
        claimed = login_tickets.claim(
            ticket.state, 'current-provider', 'browser-session')
        self.assertEqual(1, login_tickets.revoke_session('browser-session'))
        finished = login_tickets.finish(claimed.state, 'consumed')
        self.assertEqual('revoked', finished.status)
