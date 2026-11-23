"""Tests for session-scoped proxy ticket admission.

These cover the security properties of
``ProxyGrantingTicket.retrieve_pt``:

* only services explicitly granted to the *current* browser session are
  reachable, and the target service is fixed before any CAS call;
* a proxy ticket is only delivered to a session that is still alive, even
  when the CAS answer lands after a single logout;
* transient transport failures are retryable (``ProxyError``) while every
  ineligibility decision is a definitive, non-retryable ``ProxyDenied``.
"""

from importlib import import_module
from unittest.mock import Mock

import pytest
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory
from requests import RequestException

from django_cas_ng.models import (
    ProxyDenied,
    ProxyError,
    ProxyGrantingTicket,
    SessionServiceGrant,
)

SessionStore = import_module(settings.SESSION_ENGINE).SessionStore

SERVICE_A = 'https://service-a.example/entry'
SERVICE_B = 'https://service-b.example/entry'
PROXY_TICKET = 'PT-fake-proxy-ticket'


@pytest.fixture
def user(django_user_model):
    return django_user_model.objects.create_user('proxy-user', '')


def make_session_request(session_key=None):
    """Build a request backed by a real persisted Django session."""
    request = RequestFactory().get('/proxy/')
    request.session = SessionStore(session_key=session_key)
    request.session.save()
    request.user = AnonymousUser()
    return request


def grant_proxy_setup(request, user, service):
    """Attach a PGT and a service grant to the request's session."""
    request.user = user
    pgt = ProxyGrantingTicket.objects.create(
        session_key=request.session.session_key,
        user=user,
        pgtiou='fake-pgtiou',
        pgt='fake-pgt',
    )
    ProxyGrantingTicket.allow_service(request, service)
    return pgt


@pytest.mark.django_db
def test_allow_service_is_session_scoped_and_idempotent(user):
    request = make_session_request()
    grant_proxy_setup(request, user, SERVICE_A)

    assert SessionServiceGrant.objects.filter(
        session_key=request.session.session_key, service=SERVICE_A
    ).count() == 1

    # Re-granting the same service must not create a duplicate row.
    ProxyGrantingTicket.allow_service(request, SERVICE_A)
    assert SessionServiceGrant.objects.filter(
        session_key=request.session.session_key, service=SERVICE_A
    ).count() == 1


@pytest.mark.django_db
def test_retrieve_pt_returns_ticket_for_granted_service(monkeypatch, user):
    request = make_session_request()
    grant_proxy_setup(request, user, SERVICE_A)

    get_ticket = Mock(return_value=PROXY_TICKET)
    client = Mock()
    client.get_proxy_ticket = get_ticket
    monkeypatch.setattr(
        'django_cas_ng.models.get_cas_client',
        lambda *args, **kwargs: client,
    )

    assert ProxyGrantingTicket.retrieve_pt(request, SERVICE_A) == PROXY_TICKET

    # The exact target service requested is the one handed to the CAS client.
    assert get_ticket.call_args.args == ('fake-pgt',)


@pytest.mark.django_db
def test_retrieve_pt_rejects_service_not_granted_to_session(monkeypatch, user):
    request = make_session_request()
    grant_proxy_setup(request, user, SERVICE_A)

    get_ticket = Mock()
    client = Mock()
    client.get_proxy_ticket = get_ticket
    monkeypatch.setattr(
        'django_cas_ng.models.get_cas_client',
        lambda *args, **kwargs: client,
    )

    with pytest.raises(ProxyDenied) as excinfo:
        ProxyGrantingTicket.retrieve_pt(request, SERVICE_B)

    assert excinfo.value.args[0] == 'SERVICE_NOT_AUTHORIZED'
    # The remote CAS server must never be contacted for an unauthorized target.
    get_ticket.assert_not_called()


@pytest.mark.django_db
def test_grant_of_one_session_does_not_authorize_another(user):
    first = make_session_request()
    grant_proxy_setup(first, user, SERVICE_A)

    second = make_session_request()
    second.user = user
    ProxyGrantingTicket.objects.create(
        session_key=second.session.session_key,
        user=user,
        pgtiou='other-pgtiou',
        pgt='other-pgt',
    )

    with pytest.raises(ProxyDenied) as excinfo:
        ProxyGrantingTicket.retrieve_pt(second, SERVICE_A)

    assert excinfo.value.args[0] == 'SERVICE_NOT_AUTHORIZED'


@pytest.mark.django_db
def test_transport_failure_is_retryable_then_succeeds(monkeypatch, user):
    request = make_session_request()
    grant_proxy_setup(request, user, SERVICE_A)

    client = Mock()
    client.get_proxy_ticket = Mock(
        side_effect=[RequestException('connection reset'), PROXY_TICKET]
    )
    monkeypatch.setattr(
        'django_cas_ng.models.get_cas_client',
        lambda *args, **kwargs: client,
    )

    # First attempt: transient transport failure, the caller may retry.
    with pytest.raises(ProxyError):
        ProxyGrantingTicket.retrieve_pt(request, SERVICE_A)

    # Retry the very same request once the connection is back.
    assert ProxyGrantingTicket.retrieve_pt(request, SERVICE_A) == PROXY_TICKET


@pytest.mark.django_db
def test_cas_error_is_a_definitive_denial(monkeypatch, user):
    from cas import CASError

    request = make_session_request()
    grant_proxy_setup(request, user, SERVICE_A)

    client = Mock()
    client.get_proxy_ticket = Mock(
        side_effect=CASError('INVALID_TICKET', 'bad pgt')
    )
    monkeypatch.setattr(
        'django_cas_ng.models.get_cas_client',
        lambda *args, **kwargs: client,
    )

    for _ in range(2):
        with pytest.raises(ProxyDenied) as excinfo:
            ProxyGrantingTicket.retrieve_pt(request, SERVICE_A)
        assert excinfo.value.args[0] == 'INVALID_TICKET'


@pytest.mark.django_db
def test_missing_pgt_is_denied(monkeypatch, user):
    request = make_session_request()
    request.user = user
    ProxyGrantingTicket.allow_service(request, SERVICE_A)

    with pytest.raises(ProxyDenied) as excinfo:
        ProxyGrantingTicket.retrieve_pt(request, SERVICE_A)

    assert excinfo.value.args[0] == 'INVALID_TICKET'


@pytest.mark.django_db
def test_retrieve_pt_rejects_when_session_already_gone(monkeypatch, user):
    request = make_session_request()
    grant_proxy_setup(request, user, SERVICE_A)
    session_key = request.session.session_key

    # Simulate a single logout having destroyed the session beforehand.
    SessionStore(session_key=session_key).delete(session_key)

    client = Mock()
    client.get_proxy_ticket = Mock(return_value=PROXY_TICKET)
    monkeypatch.setattr(
        'django_cas_ng.models.get_cas_client',
        lambda *args, **kwargs: client,
    )

    with pytest.raises(ProxyDenied) as excinfo:
        ProxyGrantingTicket.retrieve_pt(request, SERVICE_A)

    assert excinfo.value.args[0] == 'SESSION_TERMINATED'
    client.get_proxy_ticket.assert_not_called()


@pytest.mark.django_db
def test_ticket_not_delivered_when_logout_lands_while_cas_is_answering(
    monkeypatch, user
):
    """The CAS reply arrives after the session's single logout.

    A fake CAS server holds the (otherwise allowed) proxy-ticket request, the
    session completes its single logout while it is pending, and only then the
    server answers. The ticket must be refused even though the call itself
    succeeded.
    """
    request = make_session_request()
    grant_proxy_setup(request, user, SERVICE_A)
    session_key = request.session.session_key

    def delayed_ticket(_pgt):
        # Single logout of this session happens while the CAS call is in flight.
        SessionStore(session_key=session_key).delete(session_key)
        ProxyGrantingTicket.objects.filter(session_key=session_key).delete()
        return PROXY_TICKET

    client = Mock()
    client.get_proxy_ticket = Mock(side_effect=delayed_ticket)
    monkeypatch.setattr(
        'django_cas_ng.models.get_cas_client',
        lambda *args, **kwargs: client,
    )

    with pytest.raises(ProxyDenied) as excinfo:
        ProxyGrantingTicket.retrieve_pt(request, SERVICE_A)

    assert excinfo.value.args[0] == 'SESSION_TERMINATED'
    # A retry after logout keeps getting the definitive ineligibility result.
    with pytest.raises(ProxyDenied):
        ProxyGrantingTicket.retrieve_pt(request, SERVICE_A)


@pytest.mark.django_db
def test_logout_of_one_session_keeps_other_session_allowed(monkeypatch, user):
    first = make_session_request()
    grant_proxy_setup(first, user, SERVICE_A)
    first_session_key = first.session.session_key

    second = make_session_request()
    grant_proxy_setup(second, user, SERVICE_B)
    second_session_key = second.session.session_key

    # Single logout terminates only the first session.
    SessionStore(session_key=first_session_key).delete(first_session_key)
    ProxyGrantingTicket.objects.filter(
        session_key=first_session_key
    ).delete()
    SessionServiceGrant.objects.filter(
        session_key=first_session_key
    ).delete()

    # The first, now logged-out session cannot get its ticket delivered.
    client = Mock()
    client.get_proxy_ticket = Mock(return_value=PROXY_TICKET)
    monkeypatch.setattr(
        'django_cas_ng.models.get_cas_client',
        lambda *args, **kwargs: client,
    )
    with pytest.raises(ProxyDenied):
        ProxyGrantingTicket.retrieve_pt(first, SERVICE_A)

    # The other still-active session keeps using its own allowed target.
    assert ProxyGrantingTicket.retrieve_pt(second, SERVICE_B) == PROXY_TICKET
    assert second_session_key != first_session_key
