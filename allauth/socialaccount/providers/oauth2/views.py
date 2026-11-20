from __future__ import annotations

from datetime import timedelta
from requests import RequestException
from typing import Any

from django.conf import settings
from django.core.exceptions import MultipleObjectsReturned, PermissionDenied
from django.http import HttpRequest
from django.shortcuts import render
from django.urls import reverse
from django.utils import timezone

from allauth.account import app_settings as account_settings
from allauth.account.internal.decorators import login_not_required
from allauth.core.exceptions import ImmediateHttpResponse
from allauth.core.internal.httpkit import add_query_params
from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.helpers import (
    complete_social_login,
    render_authentication_error,
)
from allauth.socialaccount.internal import statekit
from allauth.socialaccount.models import SocialApp, SocialToken
from allauth.socialaccount.providers.base import ProviderException
from allauth.socialaccount.providers.base.constants import AuthError
from allauth.socialaccount.providers.base.views import BaseLoginView
from allauth.socialaccount.providers.oauth2.client import OAuth2Client, OAuth2Error
from allauth.utils import build_absolute_uri, get_request_param


class OAuth2Adapter:
    expires_in_key = "expires_in"
    client_class = OAuth2Client
    supports_state = True
    redirect_uri_protocol: str | None = None
    access_token_method = "POST"  # nosec
    login_cancelled_error = "access_denied"
    scope_delimiter = " "
    basic_auth = False
    headers: dict[str, str] | None = None
    provider_id: str
    access_token_url: str

    def __init__(self, request: HttpRequest) -> None:
        self.request = request
        self.did_fetch_access_token = False
        # App configuration resolved for this flow, when known (e.g. from the
        # pending state in the callback). Providers use it so that subsequent
        # `get_provider()` calls continue with the very same app.
        self.app_client_id: str | None = None

    def get_provider(self):
        # Continue with the app configuration resolved for this flow, if any
        # (e.g. the one recorded in a pending callback state or selected by
        # the login request).
        return get_adapter(self.request).get_provider(
            self.request,
            provider=self.provider_id,
            client_id=self.app_client_id,
        )

    def complete_login(self, request: HttpRequest, app, token: SocialToken, **kwargs):
        """
        Returns a SocialLogin instance
        """
        raise NotImplementedError

    def get_callback_url(self, request: HttpRequest, app):
        callback_url = reverse(f"{self.provider_id}_callback")
        protocol = self.redirect_uri_protocol
        return build_absolute_uri(request, callback_url, protocol)

    def parse_token(self, data):
        token = SocialToken(token=data["access_token"])
        token.token_secret = data.get("refresh_token", "")
        expires_in = data.get(self.expires_in_key, None)
        if expires_in:
            token.expires_at = timezone.now() + timedelta(seconds=int(expires_in))
        return token

    def get_access_token_data(
        self, request: HttpRequest, app, client, pkce_code_verifier=None
    ):
        code = get_request_param(self.request, "code")
        data = client.get_access_token(code, pkce_code_verifier=pkce_code_verifier)
        self.did_fetch_access_token = True
        return data

    def get_client(self, request: HttpRequest, app):
        callback_url = self.get_callback_url(request, app)
        client = self.client_class(
            self.request,
            app.client_id,
            app.secret,
            self.access_token_method,
            self.access_token_url,
            callback_url,
            scope_delimiter=self.scope_delimiter,
            headers=self.headers,
            basic_auth=self.basic_auth,
        )
        return client


class OAuth2View:
    request: HttpRequest
    adapter: OAuth2Adapter

    @classmethod
    def adapter_view(cls, adapter):
        @login_not_required
        def view(request: HttpRequest, *args: Any, **kwargs: Any):
            self = cls()
            self.request = request
            if not isinstance(adapter, OAuth2Adapter):
                self.adapter = adapter(request)
            else:
                self.adapter = adapter
            try:
                return self.dispatch(  # type:ignore[attr-defined]
                    request, *args, **kwargs
                )
            except ImmediateHttpResponse as e:
                return e.response

        return view


class OAuth2LoginView(OAuth2View, BaseLoginView):
    def get_provider(self):
        # An app can be selected explicitly by passing its client ID. This is
        # needed to tell multiple app configurations for one and the same
        # provider apart.
        self.adapter.app_client_id = get_request_param(self.request, "client_id")
        return self.adapter.get_provider()


class OAuth2CallbackView(OAuth2View):
    adapter: OAuth2Adapter

    def _fallback_provider(self, request: HttpRequest):
        """Returns a provider suitable for rendering an authentication error.

        When multiple app configurations exist and the callback does not reveal
        which one it belongs to, no provider can be resolved unambiguously.
        Rendering still needs a provider; picking one is fine here because no
        state is consumed and no credentials are used.
        """
        try:
            return self.adapter.get_provider()
        except (SocialApp.DoesNotExist, MultipleObjectsReturned):
            apps = get_adapter().list_apps(request, provider=self.adapter.provider_id)
            if not apps:
                raise
            return get_adapter().get_provider(
                request,
                provider=self.adapter.provider_id,
                client_id=apps[0].client_id,
            )

    def _resolve_provider(self, request: HttpRequest):
        """Resolves the provider (app configuration) the callback belongs to.

        The pending state records which app configuration initiated the flow.
        Continuing with that same configuration matters when multiple apps
        exist for one and the same provider: the token exchange must use the
        credentials (and endpoints) of the app the authorization code was
        issued to.
        """
        if self.adapter.supports_state:
            state_id = get_request_param(request, "state")
            if state_id:
                state_app_id = statekit.get_state_app_id(request, state_id=state_id)
                # Continue with the app configuration the state was stashed
                # for, also for any subsequent provider lookups.
                self.adapter.app_client_id = state_app_id
                try:
                    provider = self.adapter.get_provider()
                except (SocialApp.DoesNotExist, MultipleObjectsReturned):
                    return None
                if state_app_id is not None:
                    if provider.app_id != state_app_id:
                        # Do not continue with an app other than the one the
                        # state was stashed for.
                        return None
                return provider
        try:
            return self.adapter.get_provider()
        except (SocialApp.DoesNotExist, MultipleObjectsReturned):
            # No (unambiguous) app: stay conservative and reject.
            return None

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any):
        state_id = get_request_param(request, "state")
        if state_id:
            peeked = statekit.peek_state(request, state_id=state_id)
            if peeked is not None and statekit.is_expired(peeked[1]):
                # Expired states are of no use to any flow; reclaim by ID.
                statekit.drop_state(request, state_id=state_id)
        provider = self._resolve_provider(request)
        if provider is None:
            # Do not pass the state ID on: error handling would consume that
            # state, and it is unclear whether it even belongs to this
            # callback. Leave all pending states untouched.
            return render_authentication_error(
                request,
                self._fallback_provider(request),
                extra_context={"callback_view": self},
            )
        is_error = "error" in request.GET or "code" not in request.GET
        state = None
        if not (is_error and not self.adapter.supports_state):
            # Providers without state support can only match a pending state
            # on whatever the callback happens to carry. A cancelled or failed
            # callback (which typically carries nothing) must not consume the
            # pending state of another, still legitimate, flow.
            state, resp = self._get_state(request, provider)
            if resp:
                return resp
        if is_error:
            # Distinguish cancel from error
            auth_error = request.GET.get("error", None)
            if auth_error == self.adapter.login_cancelled_error:
                error = AuthError.CANCELLED
            else:
                error = AuthError.UNKNOWN
            return render_authentication_error(
                request,
                provider,
                error=error,
                extra_context={
                    "state": state,
                    "callback_view": self,
                },
            )
        app = provider.app
        client = self.adapter.get_client(self.request, app)

        try:
            access_token = self.adapter.get_access_token_data(
                request, app, client, pkce_code_verifier=state.get("pkce_code_verifier")
            )
            token = self.adapter.parse_token(access_token)
            if app.pk:
                token.app = app
            login = self.adapter.complete_login(
                request, app, token, response=access_token
            )
            login.token = token
            login.state = state
            return complete_social_login(request, login)
        except (
            PermissionDenied,
            OAuth2Error,
            RequestException,
            ProviderException,
        ) as e:
            return render_authentication_error(
                request, provider, exception=e, extra_context={"state": state}
            )

    def _redirect_strict_samesite(self, request: HttpRequest, provider):
        if (
            "_redir" in request.GET
            or (
                isinstance(settings.SESSION_COOKIE_SAMESITE, str)
                and settings.SESSION_COOKIE_SAMESITE.lower() != "strict"
            )
            or request.method != "GET"
        ):
            return
        redirect_to = request.get_full_path()
        redirect_to = add_query_params(redirect_to, {"_redir": ""})
        return render(
            request,
            f"socialaccount/login_redirect.{account_settings.TEMPLATE_EXTENSION}",
            {
                "provider": provider,
                "redirect_to": redirect_to,
            },
        )

    def _state_matches_callback(self, state: dict[str, Any]) -> bool:
        """Whether a stashed state can be matched to this callback.

        Providers with ``supports_state = False`` do not round-trip a state
        ID, so the state must be matched on information the callback carries.
        By default there is none, which means the match is only safe when
        exactly one pending state is eligible (see ``unique=True``).
        """
        return True

    def _get_state(self, request: HttpRequest, provider):
        state = None
        state_id = get_request_param(request, "state")
        if self.adapter.supports_state:
            if state_id:
                state = statekit.unstash_state(
                    request,
                    provider_id=provider.sub_id,
                    app_id=provider.app_id,
                    state_id=state_id,
                )
                if state is None:
                    # The state belongs to another app configuration of this
                    # provider. Stay conservative: reclaim it only once it is
                    # expired; a legitimate callback for that app must still be
                    # able to complete.
                    peeked = statekit.peek_state(request, state_id=state_id)
                    if peeked is not None and statekit.is_expired(peeked[1]):
                        statekit.drop_state(request, state_id=state_id)
        else:
            state = statekit.unstash_last_state(
                request,
                provider_id=provider.sub_id,
                app_id=provider.app_id,
                matcher=self._state_matches_callback,
                unique=True,
            )
        if state is None:
            resp = self._redirect_strict_samesite(request, provider)
            if resp:
                # 'Strict' is in effect, let's try a redirect and then another
                # shot at finding our state...
                return None, resp
            return None, render_authentication_error(
                request,
                provider,
                extra_context={
                    "state_id": state_id,
                    "callback_view": self,
                },
            )
        return state, None
