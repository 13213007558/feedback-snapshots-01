from importlib import import_module
from unittest.mock import Mock

import pytest
from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.middleware import AuthenticationMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import PermissionDenied
from django.db import DatabaseError
from django.dispatch import receiver
from django.test import RequestFactory
from django_cas_ng.backends import CASBackend
from django_cas_ng.models import ProxyGrantingTicket, SessionTicket
from django_cas_ng.signals import cas_user_authenticated
from django_cas_ng.utils import RedirectException
from django_cas_ng.views import CallbackView, LoginView, LogoutView, is_local_url, clean_next_page

SessionStore = import_module(settings.SESSION_ENGINE).SessionStore


class FakeCASClient:
    """Return a fixed set of approved-looking CAS attributes."""

    def verify_ticket(self, ticket):
        return (
            'test@example.com',
            {
                'first_name': 'Grace',
                'is_staff': 'True',
                'affiliation': ['faculty'],
            },
            None,
        )


class AllowAllHookBackend(CASBackend):
    """Fake project hook that approves immediately."""


class RetryingHookBackend(CASBackend):
    """Fake project hook: reject the first approval, allow the next."""

    approvals = []

    def user_can_authenticate(self, user):
        self.approvals.append(user.pk)
        if len(self.approvals) == 1:
            return False
        return ModelBackend.user_can_authenticate(self, user)


def _get_fake_cas_client(*args, **kwargs):
    return FakeCASClient()


# function takes a request and applies a middleware process
def process_request_for_middleware(request, middleware_cls):
    middleware = middleware_cls(lambda r: None)
    middleware.process_request(request)
    if hasattr(request, 'session'):
        request.session.save()


def test_is_local_url():
    assert not is_local_url('https://a.com', 'https://b.com')
    assert not is_local_url('https://a.com', 'https://a.com.fake')
    assert not is_local_url('https://a.com', 'http://a.com')
    assert not is_local_url('https://a.com', 'http://b.a.com')
    assert not is_local_url('https://a.com', 'https://b.a.com')
    assert not is_local_url('//a.com', 'http://a.com')
    assert not is_local_url('//a.com', 'https://a.com')
    assert not is_local_url('https://a.com', '//a.com.fake')
    assert not is_local_url('https://a.com', '//b.com')
    assert not is_local_url('https://sub.a.com', '//a.com')
    assert not is_local_url('https://a.com/path', 'https://a.com')
    assert not is_local_url('https://a.com/fa', 'https://a.com/fa-ke')

    assert is_local_url('//a.com', '//a.com')
    assert is_local_url('http://a.com', '//a.com')
    assert is_local_url('https://a.com', '//a.com')
    assert is_local_url('https://a.com', '//a.com/path')
    assert is_local_url('https://a.com', '/path')
    assert is_local_url('https://a.com', '/')
    assert is_local_url('https://a.com/', '/path')
    assert is_local_url('https://a.com/', 'https://a.com')
    assert is_local_url('https://a.com/path', 'https://a.com/path/folder')


def test_clean_next_page(rf):
    request = rf.get('/login/')
    next_page = clean_next_page(request=request, next_page='testserver/next/path')
    assert next_page == 'testserver/next/path'


def test_clean_next_page_invalid(rf):
    request = rf.get('/login/')
    with pytest.raises(RedirectException):
        clean_next_page(request=request, next_page='http://invalid.com')


def test_clean_next_page_invalid_override(rf, settings):
    request = rf.get('/login/')
    settings.CAS_CHECK_NEXT = False
    next_page = clean_next_page(request=request, next_page='http://invalid.com')
    assert next_page == 'http://invalid.com'


@pytest.mark.parametrize('configured_next', [None, ''])
def test_login_validates_next_when_setting_is_unset(
    rf, settings, monkeypatch, configured_next
):
    """Unset redirect settings still validate the requested next parameter."""
    settings.CAS_LOGIN_NEXT_PAGE = configured_next
    settings.CAS_LOGGED_MSG = None
    request = rf.get('/login/', {'next': 'https://other.example/after-login/'})
    request.user = Mock(is_authenticated=True)
    request.session = {}
    monkeypatch.setattr('django_cas_ng.views.get_cas_client', Mock())

    with pytest.raises(RedirectException):
        LoginView().get(request)


@pytest.mark.parametrize('configured_next, expected', [
    (None, '/requested/'),
    ('', '/requested/'),
    ('/configured/', '/configured/'),
])
def test_login_next_setting_precedence(
    rf, settings, monkeypatch, configured_next, expected
):
    """The chosen redirect is used by both the response and CAS service URL."""
    settings.CAS_LOGIN_NEXT_PAGE = configured_next
    settings.CAS_LOGGED_MSG = None
    request = rf.get('/login/', {'next': '/requested/'})
    request.user = Mock(is_authenticated=True)
    request.session = {}
    get_client = Mock()
    monkeypatch.setattr('django_cas_ng.views.get_cas_client', get_client)

    response = LoginView().get(request)

    assert response['Location'] == expected
    assert get_client.call_args.kwargs['service_url'].endswith(
        '?next=' + expected.replace('/', '%2F'))


def test_login_validates_configured_next(rf, settings):
    """Configured redirects go through the same local URL validation."""
    settings.CAS_LOGIN_NEXT_PAGE = 'https://other.example/after-login/'
    request = rf.get('/login/', {'next': '/requested/'})

    with pytest.raises(RedirectException):
        LoginView().get(request)


@pytest.mark.django_db
def test_login_post_logout(django_user_model, settings):
    """
    Test that when CAS authentication creates a user, the signal is called with
    `created = True`
    """
    settings.CAS_VERSION = 'CAS_2_SAML_1_0'

    data = {'logoutRequest': '<samlp:LogoutRequest '
                             'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
                             '<samlp:SessionIndex>fake-ticket'
                             '</samlp:SessionIndex></samlp:LogoutRequest>'
            }
    session = SessionStore()
    session['fake_session'] = 'fake-session'
    session.save()
    assert SessionStore(session_key=session.session_key) is not None

    factory = RequestFactory()
    request = factory.post('/login/', data)
    request.session = session

    # Create a fake session ticket and make sure it exists in the db
    session_ticket = SessionTicket.objects.create(
        session_key=session.session_key,
        ticket='fake-ticket'
    )
    assert session_ticket is not None
    assert SessionTicket.objects.filter(session_key=session.session_key,
                                        ticket='fake-ticket').exists() is True
    user = django_user_model.objects.create(username='test-user', email='test@example.com')
    assert user is not None
    assert django_user_model.objects.filter(username='test-user').exists() is True
    request.user = user

    # Create a fake pgt
    pgt = ProxyGrantingTicket.objects.create(session_key=session.session_key,
                                             user=user, pgtiou='fake-ticket-iou',
                                             pgt='fake-ticket')
    assert pgt is not None
    assert ProxyGrantingTicket.objects.filter(session_key=session.session_key,
                                              user=user, pgtiou='fake-ticket-iou',
                                              pgt='fake-ticket').exists() is True

    LoginView().post(request)
    assert SessionTicket.objects.filter(session_key=session.session_key,
                                        ticket='fake-ticket').exists() is False
    assert ProxyGrantingTicket.objects.filter(session_key=session.session_key,
                                              user=user, pgtiou='fake-ticket-iou',
                                              pgt='fake-ticket').exists() is False
    assert SessionTicket.objects.filter(session_key=session.session_key,
                                        ticket='fake-ticket').exists() is False


@pytest.mark.django_db
def test_login_authenticate_and_create_user(monkeypatch, django_user_model, settings):
    """
    Test the case where the login view authenticates a new user.
    """
    # No need to test the message framework
    settings.CAS_LOGIN_MSG = None
    # Make sure we use our backend
    settings.AUTHENTICATION_BACKENDS = ['django_cas_ng.backends.CASBackend']

    factory = RequestFactory()
    request = factory.get('/login/', {'ticket': 'fake-ticket',
                                      'service': 'fake-service'})

    # Create a session object from the middleware
    process_request_for_middleware(request, SessionMiddleware)
    # Create a user object from middleware
    process_request_for_middleware(request, AuthenticationMiddleware)

    mock_client = Mock()
    mock_client.verify_ticket.return_value = (
        'test@example.com',
        {'ticket': 'fake-ticket'},
        None)
    mock_client.verify_ssl_certificate = False

    monkeypatch.setattr('django_cas_ng.backends.get_cas_client',
                        lambda *args, **kwargs: mock_client)

    response = LoginView().get(request)
    assert response.status_code == 302
    assert response['Location'] == '/'
    assert django_user_model.objects.get(username='test@example.com').is_authenticated is True


@pytest.mark.django_db
def test_login_authenticate_do_not_create_user(monkeypatch, django_user_model, settings):
    """
    Test the case where the login view authenticates a user, but does not
    create a user based on the CAS_CREATE_USER setting.
    """
    # No need to test the message framework
    settings.CAS_CREATE_USER = False
    # No need to test the message framework
    settings.CAS_LOGIN_MSG = None
    # Make sure we use our backend
    settings.AUTHENTICATION_BACKENDS = ['django_cas_ng.backends.CASBackend']

    def mock_verify(ticket, service):
        return 'test@example.com', {'ticket': ticket, 'service': service}, None
    monkeypatch.setattr('cas.CASClientV2.verify_ticket', mock_verify)

    factory = RequestFactory()
    request = factory.get('/login/', {'ticket': 'fake-ticket',
                                      'service': 'fake-service'})

    # Create a session object from the middleware
    process_request_for_middleware(request, SessionMiddleware)
    # Create a user object from middleware
    process_request_for_middleware(request, AuthenticationMiddleware)

    with pytest.raises(PermissionDenied):
        LoginView().get(request)
    assert django_user_model.objects.filter(username='test@example.com').exists() is False


@pytest.mark.django_db
def test_login_proxy_callback(monkeypatch, django_user_model, settings):
    """
    Test the case where the login view has a pgtiou.
    """
    # No need to test the message framework
    settings.CAS_PROXY_CALLBACK = True
    # No need to test the message framework
    settings.CAS_LOGIN_MSG = None
    # Make sure we use our backend
    settings.AUTHENTICATION_BACKENDS = ['django_cas_ng.backends.CASBackend']

    def mock_verify(ticket, service=None):
        return 'test@example.com', {'ticket': ticket, 'service': service}, None

    mock_client = Mock()
    mock_client.verify_ticket.side_effect = mock_verify
    monkeypatch.setattr('django_cas_ng.backends.get_cas_client',
                        lambda *args, **kwargs: mock_client)

    factory = RequestFactory()
    request = factory.get('/login/', {'ticket': 'fake-ticket',
                                      'service': 'fake-service'})

    # Create a session object from the middleware
    process_request_for_middleware(request, SessionMiddleware)
    # Create a user object from middleware
    process_request_for_middleware(request, AuthenticationMiddleware)
    request.session['pgtiou'] = 'fake-pgtiou'
    request.session.save()

    user = django_user_model.objects.create_user('test@example.com', '')
    assert user is not None
    pgt = ProxyGrantingTicket.objects.create(session_key=request.session.session_key,
                                             user=user, pgtiou='fake-pgtiou',
                                             pgt='fake-pgt')
    assert pgt is not None

    response = LoginView().get(request)
    assert response.status_code == 302
    assert django_user_model.objects.get(username='test@example.com').is_authenticated is True
    assert ProxyGrantingTicket.objects.filter(pgtiou='fake-pgtiou').exists() is True
    assert ProxyGrantingTicket.objects.filter(pgtiou='fake-pgtiou').count() == 1


@pytest.mark.django_db
def test_login_redirect_based_on_cookie(monkeypatch, django_user_model, settings):
    """
    Test the case where the login view authenticates a new user and redirects them based on cookie.
    """
    # No need to test the message framework
    settings.CAS_LOGIN_MSG = None
    # Make sure we use our backend
    settings.AUTHENTICATION_BACKENDS = ['django_cas_ng.backends.CASBackend']
    # Store next as cookie
    settings.CAS_STORE_NEXT = True

    def mock_verify(ticket, service=None):
        return 'test@example.com', {'ticket': ticket, 'service': service}, None

    mock_client = Mock()
    mock_client.verify_ticket.side_effect = mock_verify
    monkeypatch.setattr('django_cas_ng.backends.get_cas_client',
                        lambda *args, **kwargs: mock_client)

    factory = RequestFactory()
    request = factory.get('/login/', {'ticket': 'fake-ticket',
                                      'service': 'fake-service'})

    # Create a session object from the middleware
    process_request_for_middleware(request, SessionMiddleware)
    # Create a user object from middleware
    process_request_for_middleware(request, AuthenticationMiddleware)
    # Add the next pointer
    request.session['CASNEXT'] = '/admin/'

    response = LoginView().get(request)
    assert response.status_code == 302
    assert response['Location'] == '/admin/'

    assert request.session['CASNEXT'] is None
    assert django_user_model.objects.get(username='test@example.com').is_authenticated is True


@pytest.mark.django_db
def test_login_no_ticket():
    """
    Test the case where we try to login with no ticket
    """
    factory = RequestFactory()
    request = factory.get('/login/')

    # Create a session object from the middleware
    process_request_for_middleware(request, SessionMiddleware)
    # Create a user object from middleware
    process_request_for_middleware(request, AuthenticationMiddleware)

    response = LoginView().get(request)
    assert response.status_code == 302


@pytest.mark.django_db
def test_login_no_ticket_stores_default_next(settings):
    """
    When there is no explicit next pointer, it gets stored in a cookie
    """
    settings.CAS_STORE_NEXT = True

    factory = RequestFactory()
    request = factory.get('/login/')

    # Create a session object from the middleware
    process_request_for_middleware(request, SessionMiddleware)
    # Create a user object from middleware
    process_request_for_middleware(request, AuthenticationMiddleware)

    response = LoginView().get(request)
    assert response.status_code == 302

    assert 'CASNEXT' in request.session
    assert request.session['CASNEXT'] == '/'


@pytest.mark.django_db
def test_login_no_ticket_stores_explicit_next(settings):
    """
    When there is an explicit next pointer, it gets stored in the cookie
    """
    settings.CAS_STORE_NEXT = True

    factory = RequestFactory()
    request = factory.get('/login/', {'next': '/admin/'})

    # Create a session object from the middleware
    process_request_for_middleware(request, SessionMiddleware)
    # Create a user object from middleware
    process_request_for_middleware(request, AuthenticationMiddleware)

    response = LoginView().get(request)
    assert response.status_code == 302

    assert 'CASNEXT' in request.session
    assert request.session['CASNEXT'] == '/admin/'


@pytest.mark.django_db
def test_logout_not_completely(django_user_model, settings):
    """
    Test the case where the user logs out, without the logout_completely flag.
    """
    settings.CAS_LOGOUT_COMPLETELY = False

    factory = RequestFactory()
    request = factory.get('/logout/')
    # Create a session object from the middleware
    process_request_for_middleware(request, SessionMiddleware)

    user = django_user_model.objects.create_user('test@example.com', '')
    assert user is not None
    request.user = user

    response = LogoutView().get(request)
    assert response.status_code == 302
    assert request.user.is_anonymous is True


@pytest.mark.django_db
def test_logout_completely(django_user_model, settings):
    """
    Test the case where the user logs out.
    """
    settings.CAS_LOGOUT_COMPLETELY = True

    factory = RequestFactory()
    request = factory.get('/logout/')
    # Create a session object from the middleware
    process_request_for_middleware(request, SessionMiddleware)

    user = django_user_model.objects.create_user('test@example.com', '')
    assert user is not None
    request.user = user

    response = LogoutView().get(request)
    assert response.status_code == 302
    assert request.user.is_anonymous is True


@pytest.mark.django_db
def test_post_logout(django_user_model, settings):
    """
    Test Django 4.1+ POST logout view.
    """
    factory = RequestFactory()
    request = factory.post('/logout/')
    # Create a session object from the middleware
    process_request_for_middleware(request, SessionMiddleware)

    user = django_user_model.objects.create_user('test@example.com', '')
    assert user is not None
    request.user = user

    response = LogoutView().post(request)
    assert response.status_code == 302
    assert request.user.is_anonymous is True


@pytest.mark.django_db
def test_callback_create_pgt():
    """
    Test the case where a pgt callback is used.
    """
    factory = RequestFactory()
    request = factory.get('/callback/', {'pgtId': 'fake-pgtId',
                                         'pgtIou': 'fake-pgtIou'})

    response = CallbackView().get(request)
    assert response.status_code == 200
    assert ProxyGrantingTicket.objects.filter(pgt='fake-pgtId',
                                              pgtiou='fake-pgtIou'
                                              ).exists() is True


@pytest.mark.django_db
def test_callback_post_logout(django_user_model, settings):
    """
    Test that when logout is from a callback
    """
    settings.CAS_VERSION = 'CAS_2_SAML_1_0'

    data = {'logoutRequest': '<samlp:LogoutRequest '
                             'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
                             '<samlp:SessionIndex>fake-ticket'
                             '</samlp:SessionIndex></samlp:LogoutRequest>'
            }
    session = SessionStore()
    session['fake_session'] = 'fake-session'
    session.save()
    assert SessionStore(session_key=session.session_key) is not None

    factory = RequestFactory()
    request = factory.post('/callback/', data)
    request.session = session

    # Create a fake session ticket and make sure it exists in the db
    session_ticket = SessionTicket.objects.create(
        session_key=session.session_key,
        ticket='fake-ticket'
    )
    assert session_ticket is not None
    assert SessionTicket.objects.filter(session_key=session.session_key,
                                        ticket='fake-ticket').exists() is True
    user = django_user_model.objects.create(username='test-user', email='test@example.com')
    assert user is not None
    assert django_user_model.objects.filter(username='test-user').exists() is True
    request.user = user

    # Create a fake pgt
    pgt = ProxyGrantingTicket.objects.create(session_key=session.session_key,
                                             user=user, pgtiou='fake-ticket-iou',
                                             pgt='fake-ticket')
    assert pgt is not None
    assert ProxyGrantingTicket.objects.filter(session_key=session.session_key,
                                              user=user, pgtiou='fake-ticket-iou',
                                              pgt='fake-ticket').exists() is True

    CallbackView().post(request)
    assert SessionTicket.objects.filter(session_key=session.session_key,
                                        ticket='fake-ticket').exists() is False
    assert ProxyGrantingTicket.objects.filter(session_key=session.session_key,
                                              user=user, pgtiou='fake-ticket-iou',
                                              pgt='fake-ticket').exists() is False
    assert SessionTicket.objects.filter(session_key=session.session_key,
                                        ticket='fake-ticket').exists() is False


@pytest.mark.django_db
def test_login_view_rejected_hook_then_approved_existing_account(
    monkeypatch, settings, django_user_model
):
    """
    Drive LoginView with a fake CAS for an existing account whose approval hook
    rejects once and then allows. Only the approved attempt should update the
    account, establish the session and notify subscribers.
    """
    settings.AUTHENTICATION_BACKENDS = ['tests.test_views.RetryingHookBackend']
    settings.CAS_APPLY_ATTRIBUTES_TO_USER = True
    settings.CAS_MAP_AFFILIATIONS = True
    settings.CAS_LOGIN_MSG = None
    monkeypatch.setattr(
        'django_cas_ng.backends.get_cas_client', _get_fake_cas_client)

    existing = django_user_model.objects.create_user('test@example.com', '')
    existing.first_name = 'Existing'
    existing.save()

    events = []

    @receiver(cas_user_authenticated)
    def callback(sender, request, user, created, **kwargs):
        events.append({
            'user_id': user.pk,
            'created': created,
            'first_name': user.first_name,
            'logged_in': bool(request.session.get('_auth_user_id')),
            'ticket_saved': SessionTicket.objects.filter(
                session_key=request.session.session_key,
                ticket='fake-ticket',
            ).exists(),
        })

    RetryingHookBackend.approvals = []
    login = LoginView()

    def build_request():
        request = RequestFactory().get(
            '/login/', {'ticket': 'fake-ticket', 'service': 'fake-service'})
        process_request_for_middleware(request, SessionMiddleware)
        process_request_for_middleware(request, AuthenticationMiddleware)
        return request

    rejected = build_request()
    with pytest.raises(PermissionDenied):
        login.get(rejected)

    rejected.session.save()
    stored = django_user_model.objects.get(pk=existing.pk)
    assert RetryingHookBackend.approvals == [existing.pk]
    assert stored.first_name == 'Existing'
    assert events == []
    assert rejected.session.get('_auth_user_id') is None
    assert 'attributes' not in rejected.session

    approved = build_request()
    response = login.get(approved)

    assert response.status_code == 302
    assert RetryingHookBackend.approvals == [existing.pk, existing.pk]
    stored = django_user_model.objects.get(pk=existing.pk)
    assert stored.first_name == 'Grace'
    assert events == [{
        'user_id': existing.pk,
        'created': False,
        'first_name': 'Grace',
        'logged_in': True,
        'ticket_saved': True,
    }]
    assert approved.session['_auth_user_id'] == str(existing.pk)
    assert approved.session['attributes']['first_name'] == 'Grace'


@pytest.mark.django_db
def test_login_view_rejected_new_account_leaves_no_user_or_login(
    monkeypatch, settings, django_user_model
):
    """
    Same fake CAS reject-then-allow drive for a brand-new account: the rejected
    attempt must leave no user, no session login and no notification; the
    approved retry publishes all three together.
    """
    settings.AUTHENTICATION_BACKENDS = ['tests.test_views.RetryingHookBackend']
    settings.CAS_APPLY_ATTRIBUTES_TO_USER = True
    settings.CAS_LOGIN_MSG = None
    monkeypatch.setattr(
        'django_cas_ng.backends.get_cas_client', _get_fake_cas_client)

    events = []

    @receiver(cas_user_authenticated)
    def callback(sender, request, user, created, **kwargs):
        events.append({
            'created': created,
            'stored': django_user_model.objects.filter(pk=user.pk).exists(),
            'logged_in': bool(request.session.get('_auth_user_id')),
            'ticket_saved': SessionTicket.objects.filter(
                session_key=request.session.session_key,
                ticket='fake-ticket',
            ).exists(),
        })

    RetryingHookBackend.approvals = []
    login = LoginView()

    def build_request():
        request = RequestFactory().get(
            '/login/', {'ticket': 'fake-ticket', 'service': 'fake-service'})
        process_request_for_middleware(request, SessionMiddleware)
        process_request_for_middleware(request, AuthenticationMiddleware)
        return request

    rejected = build_request()
    with pytest.raises(PermissionDenied):
        login.get(rejected)

    rejected.session.save()
    assert events == []
    assert not django_user_model.objects.filter(username='test@example.com').exists()
    assert rejected.session.get('_auth_user_id') is None
    assert 'attributes' not in rejected.session
    assert not SessionTicket.objects.exists()

    approved = build_request()
    response = login.get(approved)

    assert response.status_code == 302
    created = django_user_model.objects.get(username='test@example.com')
    assert events == [{
        'created': True,
        'stored': True,
        'logged_in': True,
        'ticket_saved': True,
    }]
    assert approved.session['_auth_user_id'] == str(created.pk)
    assert approved.session['attributes']['first_name'] == 'Grace'
    assert SessionTicket.objects.get().ticket == 'fake-ticket'


@pytest.mark.django_db
def test_login_view_storage_failure_rolls_back_new_account(
    monkeypatch, settings, django_user_model
):
    """
    If login bookkeeping cannot be saved, the freshly-created account, session
    login, ticket row and notification must all be absent.
    """
    from django.db import DatabaseError

    settings.AUTHENTICATION_BACKENDS = ['tests.test_views.AllowAllHookBackend']
    settings.CAS_APPLY_ATTRIBUTES_TO_USER = True
    settings.CAS_LOGIN_MSG = None
    monkeypatch.setattr(
        'django_cas_ng.backends.get_cas_client', _get_fake_cas_client)

    events = []

    @receiver(cas_user_authenticated)
    def callback(sender, **kwargs):
        events.append(kwargs)

    monkeypatch.setattr(
        'django_cas_ng.views.SessionTicket.objects.create',
        Mock(side_effect=DatabaseError('storage unavailable')),
    )

    request = RequestFactory().get(
        '/login/', {'ticket': 'fake-ticket', 'service': 'fake-service'})
    process_request_for_middleware(request, SessionMiddleware)
    process_request_for_middleware(request, AuthenticationMiddleware)

    with pytest.raises(DatabaseError):
        LoginView().get(request)

    assert events == []
    assert not django_user_model.objects.filter(username='test@example.com').exists()
    assert request.session.get('_auth_user_id') is None
    assert 'attributes' not in request.session
    assert not SessionTicket.objects.exists()
