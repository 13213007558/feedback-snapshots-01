from importlib import import_module
from datetime import timedelta
from unittest.mock import Mock

import pytest
from django.conf import settings
from django.contrib.auth.middleware import AuthenticationMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import PermissionDenied
from django.test import RequestFactory
from django.utils import timezone
from django_cas_ng.models import (
    SESSION_KEY_MAXLENGTH,
    ProxyError,
    ProxyGrantingTicket,
    SessionTicket,
)
from django_cas_ng.utils import RedirectException
from django_cas_ng.views import CallbackView, LoginView, LogoutView, is_local_url, clean_next_page

SessionStore = import_module(settings.SESSION_ENGINE).SessionStore


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
def test_proxy_callback_interleaved_delivery(monkeypatch, django_user_model, settings):
    """
    PGT callbacks and browser logins may interleave in any order. Each PGT
    must end up bound only to the session that performed the matching login,
    and a replayed notification must not disturb existing or later bindings.
    """
    settings.CAS_PROXY_CALLBACK = True
    settings.CAS_LOGIN_MSG = None
    settings.AUTHENTICATION_BACKENDS = ['django_cas_ng.backends.CASBackend']

    usernames = {'ST-user-a': 'user-a@example.com', 'ST-user-b': 'user-b@example.com'}
    pgtious = {'ST-user-a': 'IOU-user-a', 'ST-user-b': 'IOU-user-b'}

    def mock_verify(ticket, service=None):
        return usernames[ticket], {'ticket': ticket}, pgtious[ticket]

    mock_client = Mock()
    mock_client.verify_ticket.side_effect = mock_verify
    monkeypatch.setattr('django_cas_ng.backends.get_cas_client',
                        lambda *args, **kwargs: mock_client)

    factory = RequestFactory()

    def deliver_callback(pgtid, pgtiou):
        request = factory.get('/callback/', {'pgtId': pgtid, 'pgtIou': pgtiou})
        response = CallbackView().get(request)
        assert response.status_code == 200

    def browser_login(ticket):
        request = factory.get('/login/', {'ticket': ticket, 'service': 'fake-service'})
        process_request_for_middleware(request, SessionMiddleware)
        process_request_for_middleware(request, AuthenticationMiddleware)
        response = LoginView().get(request)
        assert response.status_code == 302
        return request

    user_a = django_user_model.objects.create_user('user-a@example.com', '')
    user_b = django_user_model.objects.create_user('user-b@example.com', '')

    # 1. CAS delivers user A's PGT before A's browser login shows up.
    deliver_callback('PGT-user-a', 'IOU-user-a')
    # 2. User B logs in while B's callback is still in flight: a pending
    #    binding is recorded for the callback to complete.
    request_b = browser_login('ST-user-b')
    # 3. B's callback arrives late and fills in the pending binding.
    deliver_callback('PGT-user-b', 'IOU-user-b')
    # 4. B's old notification is replayed after B already logged in.
    deliver_callback('PGT-user-b', 'IOU-user-b')
    # 5. User A logs in afterwards; the waiting PGT is bound to A's session
    #    and the replayed notification must not alter this later login.
    request_a = browser_login('ST-user-a')

    session_key_a = request_a.session.session_key[:SESSION_KEY_MAXLENGTH]
    session_key_b = request_b.session.session_key[:SESSION_KEY_MAXLENGTH]
    assert session_key_a != session_key_b

    # Each PGT is stored exactly once, bound to its own login session.
    assert ProxyGrantingTicket.objects.count() == 2
    pgt_a = ProxyGrantingTicket.objects.get(pgtiou='IOU-user-a')
    pgt_b = ProxyGrantingTicket.objects.get(pgtiou='IOU-user-b')
    assert (pgt_a.user_id, pgt_a.session_key, pgt_a.pgt) == \
        (user_a.pk, session_key_a, 'PGT-user-a')
    assert (pgt_b.user_id, pgt_b.session_key, pgt_b.pgt) == \
        (user_b.pk, session_key_b, 'PGT-user-b')

    # Proxy ticket retrieval still goes through the Django user and the
    # active session: each session obtains its own proxy ticket.
    proxy_client = Mock()
    proxy_client.get_proxy_ticket.side_effect = lambda pgt: 'PT-for-' + pgt
    monkeypatch.setattr('django_cas_ng.models.get_cas_client',
                        lambda *args, **kwargs: proxy_client)

    request_a.user = user_a
    request_b.user = user_b
    assert ProxyGrantingTicket.retrieve_pt(request_a, 'fake-service') == 'PT-for-PGT-user-a'
    assert ProxyGrantingTicket.retrieve_pt(request_b, 'fake-service') == 'PT-for-PGT-user-b'

    # A session cannot retrieve the proxy ticket bound to the other session.
    request_a.user = user_b
    with pytest.raises(ProxyError):
        ProxyGrantingTicket.retrieve_pt(request_a, 'fake-service')


@pytest.mark.django_db
def test_callback_expires_stale_pending_entries(django_user_model):
    """
    Pending entries whose other side never arrived are invalidated after the
    timeout, both for unbound callbacks and for unconsumed login bindings.
    """
    user = django_user_model.objects.create_user('test@example.com', '')
    stale_date = timezone.now() - timedelta(seconds=120)

    # A callback whose login never happened.
    orphan_callback = ProxyGrantingTicket.objects.create(
        pgtiou='stale-callback-iou', pgt='stale-callback-pgt')
    # A login binding whose callback never arrived.
    orphan_login = ProxyGrantingTicket.objects.create(
        pgtiou='stale-login-iou', user=user, session_key='stale-session')
    ProxyGrantingTicket.objects.filter(
        pk__in=[orphan_callback.pk, orphan_login.pk]).update(date=stale_date)

    factory = RequestFactory()
    request = factory.get('/callback/', {'pgtId': 'fresh-pgtId',
                                         'pgtIou': 'fresh-pgtIou'})
    response = CallbackView().get(request)

    assert response.status_code == 200
    assert not ProxyGrantingTicket.objects.filter(pgtiou='stale-callback-iou').exists()
    assert not ProxyGrantingTicket.objects.filter(pgtiou='stale-login-iou').exists()
    assert ProxyGrantingTicket.objects.filter(pgtiou='fresh-pgtIou').exists()
