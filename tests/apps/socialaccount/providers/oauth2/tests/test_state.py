"""Connector (app configuration) context of pending social login states.

A site can configure multiple apps for one and the same (sub)provider, e.g. one
per partner organization. Pending authorization states must then remember which
app configuration the flow was started with, and the callback must continue with
that same configuration. A callback (or a cancellation) for one flow must never
consume the pending state of another legitimate flow.
"""

import time
from http import HTTPStatus
from urllib.parse import parse_qs, urlparse

from django.test import RequestFactory
from django.views.generic import TemplateView
from django.urls import path, reverse
from django.utils.http import urlencode

import pytest

from allauth.socialaccount import providers
from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.internal import statekit
from allauth.socialaccount.models import SocialAccount
from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider
from allauth.socialaccount.providers.oauth2.views import (
    OAuth2Adapter,
    OAuth2CallbackView,
    OAuth2LoginView,
)
from tests.mocking import MockedResponse, mocked_response


PROVIDER_ID = "connector"
SHARED_IDP_ID = "shared-idp"
ORG_A_CLIENT_ID = "acme-client-id"
ORG_A_SECRET = "acme-secret"  # nosec
ORG_B_CLIENT_ID = "globex-client-id"
ORG_B_SECRET = "globex-secret"  # nosec


class ConnectorOAuth2Adapter(OAuth2Adapter):
    provider_id = PROVIDER_ID
    authorize_url = "https://idp.example.com/authorize"
    access_token_url = "https://idp.example.com/token"

    def complete_login(self, request, app, token, **kwargs):
        # The mocked response identifies which app configuration performed the
        # token exchange; the callback must have used the same one as the flow.
        data = kwargs["response"]
        assert data["client_id"] == app.client_id
        assert token.token == f"access-token-for-{app.client_id}"
        data.update(
            {
                "sub": data["uid"],
                "email": data["email"],
                "email_verified": True,
            }
        )
        return self.get_provider().sociallogin_from_response(request, data)


class ConnectorProvider(OAuth2Provider):
    id = PROVIDER_ID
    name = "Connector"
    oauth2_adapter_class = ConnectorOAuth2Adapter

    def extract_uid(self, data):
        return str(data["sub"])

    def extract_email_addresses(self, data):
        return []


provider_classes = [ConnectorProvider]


oauth2_login = OAuth2LoginView.adapter_view(ConnectorOAuth2Adapter)
oauth2_callback = OAuth2CallbackView.adapter_view(ConnectorOAuth2Adapter)

urlpatterns = [
    path(
        "cancelled/",
        TemplateView.as_view(template_name="socialaccount/login_cancelled.html"),
        name="socialaccount_login_cancelled",
    ),
    path(f"{PROVIDER_ID}/login/", oauth2_login, name=f"{PROVIDER_ID}_login"),
    path(
        f"{PROVIDER_ID}/login/callback/",
        oauth2_callback,
        name=f"{PROVIDER_ID}_callback",
    ),
]


@pytest.fixture(autouse=True)
def _registered_provider():
    # Not using `providers.registry.register()`: the registry is global and
    # would leak the (test-only) provider into all other tests.
    providers.registry.provider_map[PROVIDER_ID] = ConnectorProvider
    try:
        yield
    finally:
        providers.registry.provider_map.pop(PROVIDER_ID, None)


@pytest.fixture
def connector_settings(settings):
    settings.SOCIALACCOUNT_PROVIDERS = {
        PROVIDER_ID: {
            "APPS": [
                {
                    # Both organizations share one and the same (sub)provider
                    # ID. Only the app configuration (client ID) differs.
                    "provider_id": SHARED_IDP_ID,
                    "name": "Acme",
                    "client_id": ORG_A_CLIENT_ID,
                    "secret": ORG_A_SECRET,
                },
                {
                    "provider_id": SHARED_IDP_ID,
                    "name": "Globex",
                    "client_id": ORG_B_CLIENT_ID,
                    "secret": ORG_B_SECRET,
                },
            ]
        }
    }
    return settings.SOCIALACCOUNT_PROVIDERS[PROVIDER_ID]


@pytest.fixture(autouse=True)
def connector_urls(settings):
    settings.ROOT_URLCONF = "tests.apps.socialaccount.providers.oauth2.tests.test_state"
    return urlpatterns


@pytest.fixture(autouse=True)
def _connector_settings(connector_settings):
    return connector_settings


def _start_flow(client, org, *, process="login", next_url="/done/"):
    provider = get_adapter().get_provider(
        None, provider=org["provider_id"], client_id=org["client_id"]
    )
    url = provider.get_login_url(None, process=process, next=next_url)
    assert f"client_id={org['client_id']}" in url
    resp = client.post(url)
    assert resp.status_code == HTTPStatus.FOUND, resp.content
    location = resp["location"]
    assert location.startswith("https://idp.example.com/authorize?")
    query = parse_qs(urlparse(location).query)
    assert query["client_id"] == [org["client_id"]]
    return query["state"][0]


def _callback(client, state, org, *, code="the-code"):
    with mocked_response(
        MockedResponse(
            HTTPStatus.OK,
            {
                "access_token": f"access-token-for-{org['client_id']}",
                "client_id": org["client_id"],
                "uid": f"uid-{org['client_id']}",
                "email": f"{org['client_id']}@example.com",
            },
            {"content-type": "application/json"},
        )
    ):
        return client.get(
            reverse(f"{PROVIDER_ID}_callback")
            + "?"
            + urlencode({"code": code, "state": state})
        )


def _pending_state_ids(client):
    return set(statekit.get_states(_session_request(client)).keys())


def _session_request(client):
    request = RequestFactory().get("/")
    request.session = client.session
    return request


def _org_a():
    return {"provider_id": SHARED_IDP_ID, "client_id": ORG_A_CLIENT_ID}


def _org_b():
    return {"provider_id": SHARED_IDP_ID, "client_id": ORG_B_CLIENT_ID}


@pytest.mark.django_db
def test_pending_state_remembers_app_configuration(client, connector_settings):
    org_a = _org_a()
    org_b = _org_b()
    state_a = _start_flow(client, org_a)
    state_b = _start_flow(client, org_b)

    states = statekit.get_states(_session_request(client))
    assert state_a in states
    assert state_b in states
    # Both flows share the same provider ID, but are bound to their own app.
    assert states[state_a][2] == states[state_b][2] == SHARED_IDP_ID
    assert states[state_a][3] == ORG_A_CLIENT_ID
    assert states[state_b][3] == ORG_B_CLIENT_ID


@pytest.mark.django_db
def test_concurrent_flows_complete_with_their_own_app(client, connector_settings):
    org_a = _org_a()
    org_b = _org_b()
    state_a = _start_flow(client, org_a)
    state_b = _start_flow(client, org_b)

    # Complete B first, then A: completing one must not consume the state of
    # the other pending flow.
    resp_b = _callback(client, state_b, org_b)
    assert resp_b.status_code == HTTPStatus.FOUND, resp_b.content
    assert SocialAccount.objects.filter(
        provider=SHARED_IDP_ID, uid=f"uid-{ORG_B_CLIENT_ID}"
    ).exists()
    assert not SocialAccount.objects.filter(
        provider=SHARED_IDP_ID, uid=f"uid-{ORG_A_CLIENT_ID}"
    ).exists()
    assert _pending_state_ids(client) == {state_a}

    resp_a = _callback(client, state_a, org_a)
    assert resp_a.status_code == HTTPStatus.FOUND, resp_a.content
    assert SocialAccount.objects.filter(
        provider=SHARED_IDP_ID, uid=f"uid-{ORG_A_CLIENT_ID}"
    ).exists()
    assert _pending_state_ids(client) == set()


@pytest.mark.django_db
def test_callback_does_not_use_other_app_credentials(client, connector_settings):
    """The token exchange must use the app identified by the pending state.

    Popping the "most recent" state instead would make flow A complete with the
    credentials of app B (and vice versa) -- exactly what must not happen.
    """
    org_a = _org_a()
    org_b = _org_b()
    state_a = _start_flow(client, org_a)
    state_b = _start_flow(client, org_b)

    # Callback for the *first* flow (A) while B is still pending.
    resp = _callback(client, state_a, org_a)
    assert resp.status_code == HTTPStatus.FOUND, resp.content
    assert _pending_state_ids(client) == {state_b}
    assert SocialAccount.objects.filter(
        provider=SHARED_IDP_ID, uid=f"uid-{ORG_A_CLIENT_ID}"
    ).exists()

    resp = _callback(client, state_b, org_b)
    assert resp.status_code == HTTPStatus.FOUND, resp.content
    assert _pending_state_ids(client) == set()


@pytest.mark.django_db
def test_replayed_callback_is_rejected_without_consuming_other_states(
    client, connector_settings
):
    org_a = _org_a()
    org_b = _org_b()
    state_a = _start_flow(client, org_a)
    state_b = _start_flow(client, org_b)

    _callback(client, state_a, org_a)
    # A replay of state A must fail and leave B pending.
    resp = _callback(client, state_a, org_a)
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert _pending_state_ids(client) == {state_b}

    # B can still complete.
    resp = _callback(client, state_b, org_b)
    assert resp.status_code == HTTPStatus.FOUND, resp.content


@pytest.mark.django_db
def test_unknown_state_is_rejected_without_consuming_pending_states(
    client, connector_settings
):
    state_a = _start_flow(client, _org_a())
    resp = client.get(
        reverse(f"{PROVIDER_ID}_callback")
        + "?"
        + urlencode({"code": "x", "state": "nope"})
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert _pending_state_ids(client) == {state_a}


@pytest.mark.django_db
def test_cancelled_callback_does_not_consume_other_flows(client, connector_settings):
    """A canceled request must not consume another legitimate flow's state."""
    org_b = _org_b()
    state_a = _start_flow(client, _org_a())
    state_b = _start_flow(client, org_b)

    # The user cancels flow A at the provider.
    resp = client.get(
        reverse(f"{PROVIDER_ID}_callback")
        + "?"
        + urlencode({"error": "access_denied", "state": state_a})
    )
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"] == reverse("socialaccount_login_cancelled")
    # Only A's own state is dropped; B remains pending and usable.
    assert _pending_state_ids(client) == {state_b}

    resp = _callback(client, state_b, org_b)
    assert resp.status_code == HTTPStatus.FOUND, resp.content


@pytest.mark.django_db
def test_cancelled_callback_without_state_keeps_pending_flows(
    client, connector_settings
):
    state_a = _start_flow(client, _org_a())
    state_b = _start_flow(client, _org_b())

    # Without a state, the callback cannot tell which flow was cancelled.
    # Stay conservative: reject and leave both pending flows untouched.
    resp = client.get(
        reverse(f"{PROVIDER_ID}_callback") + "?" + urlencode({"error": "access_denied"})
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert _pending_state_ids(client) == {state_a, state_b}


@pytest.mark.django_db
def test_expired_state_is_reclaimed(client, connector_settings):
    """Expired states must be reclaimed, not left behind forever."""
    org_a = _org_a()
    state_a = _start_flow(client, org_a)
    request = _session_request(client)
    states = statekit.get_states(request)
    states[state_a] = (states[state_a][0], 0.0, SHARED_IDP_ID, ORG_A_CLIENT_ID)
    request.session[statekit.STATES_SESSION_KEY] = states
    request.session.save()

    resp = _callback(client, state_a, org_a)
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert _pending_state_ids(client) == set()
    assert not SocialAccount.objects.exists()


@pytest.mark.django_db
def test_provider_without_state_round_trip_matches_unique_flow_only(
    client, connector_settings, monkeypatch
):
    """Callbacks without state info must not steal another flow's state."""
    state_a = _start_flow(client, _org_a())
    state_b = _start_flow(client, _org_b())

    monkeypatch.setattr(ConnectorOAuth2Adapter, "supports_state", False)

    # Ambiguous: two pending states for the provider, no way to tell which one
    # belongs to this callback. Stay conservative.
    resp = client.get(
        reverse(f"{PROVIDER_ID}_callback") + "?" + urlencode({"code": "x"})
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert _pending_state_ids(client) == {state_a, state_b}

    # The app-specific pending state can still be identified and consumed.
    state = statekit.unstash_last_state(
        _session_request(client),
        provider_id=SHARED_IDP_ID,
        app_id=ORG_B_CLIENT_ID,
        unique=True,
    )
    assert state is not None
    assert _pending_state_ids(client) == {state_a}


ORG_A_PROVIDER_ID = "acme-idp"
ORG_B_PROVIDER_ID = "globex-idp"


@pytest.fixture
def connector_settings_distinct_ids(settings):
    """Two partner organizations, each with their own subprovider ID.

    This is the canonical setup (e.g. as for SAML): the provider class is the
    same, but each organization has its own app, identified by provider ID.
    """
    settings.SOCIALACCOUNT_PROVIDERS = {
        PROVIDER_ID: {
            "APPS": [
                {
                    "provider_id": ORG_A_PROVIDER_ID,
                    "name": "Acme",
                    "client_id": ORG_A_CLIENT_ID,
                    "secret": ORG_A_SECRET,
                },
                {
                    "provider_id": ORG_B_PROVIDER_ID,
                    "name": "Globex",
                    "client_id": ORG_B_CLIENT_ID,
                    "secret": ORG_B_SECRET,
                },
            ]
        }
    }
    return settings.SOCIALACCOUNT_PROVIDERS[PROVIDER_ID]


@pytest.mark.django_db
def test_concurrent_organizations_complete_with_their_own_connector(
    client, connector_settings_distinct_ids
):
    org_a = {"provider_id": ORG_A_PROVIDER_ID, "client_id": ORG_A_CLIENT_ID}
    org_b = {"provider_id": ORG_B_PROVIDER_ID, "client_id": ORG_B_CLIENT_ID}
    state_a = _start_flow(client, org_a)
    state_b = _start_flow(client, org_b)

    states = statekit.get_states(_session_request(client))
    assert states[state_a][2] == ORG_A_PROVIDER_ID
    assert states[state_a][3] == ORG_A_CLIENT_ID
    assert states[state_b][2] == ORG_B_PROVIDER_ID
    assert states[state_b][3] == ORG_B_CLIENT_ID

    # Complete A first, while B is pending.
    resp = _callback(client, state_a, org_a)
    assert resp.status_code == HTTPStatus.FOUND, resp.content
    assert _pending_state_ids(client) == {state_b}

    resp = _callback(client, state_b, org_b)
    assert resp.status_code == HTTPStatus.FOUND, resp.content
    assert _pending_state_ids(client) == set()


@pytest.mark.django_db
def test_callback_without_app_information_is_conservative(
    client, connector_settings_distinct_ids
):
    """A pending state without connector info cannot be pinned to an app.

    With multiple app configurations there is no way to tell which one the
    callback belongs to. It must be rejected without consuming the state, so
    that the legitimate flow (or a later, explicit retry) can still complete.
    """
    org_a = {"provider_id": ORG_A_PROVIDER_ID, "client_id": ORG_A_CLIENT_ID}
    org_b = {"provider_id": ORG_B_PROVIDER_ID, "client_id": ORG_B_CLIENT_ID}
    state_a = _start_flow(client, org_a)
    state_b = _start_flow(client, org_b)

    # Simulate a state stashed by an older allauth version: no app recorded.
    request = _session_request(client)
    states = statekit.get_states(request)
    legacy_id = "legacy-state"
    states[legacy_id] = ({"process": "login"}, time.time(), ORG_A_PROVIDER_ID)
    request.session[statekit.STATES_SESSION_KEY] = states
    request.session.save()

    resp = _callback(client, legacy_id, org_a)
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert _pending_state_ids(client) == {state_a, state_b, legacy_id}

    # The genuine flows still complete.
    assert _callback(client, state_a, org_a).status_code == HTTPStatus.FOUND
    assert _callback(client, state_b, org_b).status_code == HTTPStatus.FOUND
