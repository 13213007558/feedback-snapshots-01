from __future__ import annotations

import secrets
from contextlib import contextmanager
from contextvars import ContextVar
from inspect import Parameter, signature
from typing import TYPE_CHECKING, Any, Generic, TypeAlias, TypeVar, cast

from .backends.base import ResponseT_co

# Preserve the historical import path for integrations and tests.
from .backends.utils import get_backend
from .exceptions import AuthConfigurationError, AuthInvitationError, ErrorStage
from .groups import validate_group_mapping
from .invitations import (
    INVITATION_PARTIAL_TOKENS_SESSION_NAME,
    InvitationCheck,
    InvitationDecision,
)
from .pipeline import DEFAULT_AUTH_PIPELINE, DEFAULT_DISCONNECT_PIPELINE
from .pipeline.utils import partial_load, to_plain_dict
from .response_types import HttpResponseProtocol as _HttpResponseProtocol
from .store import OpenIdSessionWrapper, OpenIdStore
from .utils import (
    PARTIAL_TOKEN_PENDING_CONFIRMATION_SESSION_NAME,
    PARTIAL_TOKEN_PENDING_REQUEST_SESSION_NAME,
    PARTIAL_TOKEN_PENDING_SESSION_NAME,
    PARTIAL_TOKEN_SESSION_NAME,
    module_member,
    setting_name,
)

HttpResponseProtocol: TypeAlias = _HttpResponseProtocol


if TYPE_CHECKING:
    from collections.abc import Generator, Mapping

    from .backends.base import BaseAuth
    from .storage import BaseStorage, CodeMixin, PartialMixin, UserProtocol


_BackendResponseT = TypeVar("_BackendResponseT")


def _call_invitation_callable(
    validator: Any, check: InvitationCheck, *, backend: BaseAuth[object] | None
) -> Any:
    context_kwargs = dict(check.context)
    kwargs = {
        **context_kwargs,
        "check": check,
        "invitation_id": check.invitation_id,
        "stage": check.stage,
        "provider": check.provider,
        "backend": backend,
        "user": check.user,
        "user_id": check.user_id,
        "session_key": check.session_key,
        "partial": check.partial,
        "partial_token": check.partial_token,
        "uid": check.uid,
        "changed_fields": check.changed_fields,
    }
    try:
        parameters = signature(validator).parameters
    except (TypeError, ValueError):
        return validator(check)

    if any(
        parameter.kind is Parameter.VAR_KEYWORD for parameter in parameters.values()
    ):
        return validator(**kwargs)

    accepted = {name: value for name, value in kwargs.items() if name in parameters}
    try:
        signature(validator).bind(**accepted)
    except TypeError:
        return validator(check)
    return validator(**accepted)


class BaseTemplateStrategy:
    def __init__(self, strategy) -> None:
        self.strategy = strategy

    def render(
        self,
        tpl: str | None = None,
        html: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> str:
        context = context or {}
        if tpl:
            return self.render_template(tpl, context)
        if not html:
            raise ValueError("Missing template or html parameters")
        return self.render_string(html, context)

    def render_template(self, tpl: str, context: dict[str, Any] | None) -> str:
        raise NotImplementedError("Implement in subclass")

    def render_string(self, html: str, context: dict[str, Any] | None) -> str:
        raise NotImplementedError("Implement in subclass")


class BaseStrategy(Generic[ResponseT_co]):
    ALLOWED_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    DEFAULT_TEMPLATE_STRATEGY = BaseTemplateStrategy
    EXPIRE_PARTIAL_PIPELINES_ON_LOAD = False

    def __init__(
        self,
        storage: type[BaseStorage] | None = None,
        tpl: type[BaseTemplateStrategy] | None = None,
    ) -> None:
        self._storage = storage
        self._pipeline_request_data: ContextVar[dict[str, Any] | None] = ContextVar(
            "pipeline_request_data", default=None
        )
        self.invitation_validator: Any = None
        self.tpl = (tpl or self.DEFAULT_TEMPLATE_STRATEGY)(self)

    @property
    def storage(self) -> type[BaseStorage]:
        if self._storage is None:
            raise AuthConfigurationError(code="missing_setting", parameter="storage")
        return self._storage

    def get_storage(self, *, stage: ErrorStage) -> type[BaseStorage]:
        """Resolve storage while reporting failures at the calling operation."""
        try:
            storage = self.storage
        except AuthConfigurationError as error:
            error.stage = stage
            raise
        if storage is None:
            raise AuthConfigurationError(
                code="missing_setting", parameter="storage", stage=stage
            )
        return storage

    def setting(
        self, name: str, default=None, backend: BaseAuth[object] | str | None = None
    ):
        names = [setting_name(name), name]
        if backend:
            backend_name = backend if isinstance(backend, str) else backend.name
            names.insert(0, setting_name(backend_name, name))
        for value in names:
            try:
                return self.get_setting(value)
            except (AttributeError, KeyError):
                pass
        return default

    def create_user(self, *args, **kwargs):
        return self.storage.user.create_user(*args, **kwargs)

    def get_user(self, *args, **kwargs):
        return self.storage.user.get_user(*args, **kwargs)

    def sync_user_groups(
        self,
        user,
        groups: list[str] | None,
        *,
        backend: BaseAuth[object],
        response,
        **kwargs,
    ) -> None:
        """Override to apply configured external memberships to local groups."""
        if validate_group_mapping(
            backend, backend.get_group_setting("GROUPS_MAP", response, {})
        ):
            raise AuthConfigurationError(
                backend,
                code="unsupported_feature",
                parameter="GROUPS_MAP",
                stage="pipeline",
            )

    def session_setdefault(self, name: str, value):
        self.session_set(name, value)
        return self.session_get(name)

    def openid_session_dict(self, name: str) -> OpenIdSessionWrapper:
        # python3-openid expects class instances; sessions contain explicit,
        # JSON-compatible snapshots instead. Persist writes and deletions so
        # framework sessions notice changes to this nested dictionary.
        return OpenIdSessionWrapper(
            self.session_get(name, {}),
            on_change=lambda values: self.session_set(name, values),
        )

    def to_session_value(self, val):
        return val

    def from_session_value(self, val):
        return val

    def partial_load(self, token: str) -> PartialMixin | None:
        partial = partial_load(self, token)
        if partial is None or not self.EXPIRE_PARTIAL_PIPELINES_ON_LOAD:
            return partial
        expiry = self.setting(
            "PARTIAL_PIPELINE_EXPIRED_THRESHOLD",
            self.setting(
                "EMAIL_VALIDATION_EXPIRED_THRESHOLD",
                7 * 24 * 60 * 60,
                backend=partial.backend,
            ),
            backend=partial.backend,
        )
        is_expired = getattr(partial, "is_expired", None)
        if expiry and is_expired is not None and is_expired(expiry):
            self.clean_partial_pipeline(token)
            return None
        return partial

    def clean_partial_pipeline(self, token) -> None:
        self.storage.partial.destroy(token)
        current_token_in_session = self.session_get(PARTIAL_TOKEN_SESSION_NAME)
        if current_token_in_session == token:
            self.session_pop(PARTIAL_TOKEN_SESSION_NAME)
        pending_token_in_session = self.session_get(PARTIAL_TOKEN_PENDING_SESSION_NAME)
        if pending_token_in_session == token:
            self.session_pop(PARTIAL_TOKEN_PENDING_SESSION_NAME)
            self.session_pop(PARTIAL_TOKEN_PENDING_REQUEST_SESSION_NAME)
            self.session_pop(PARTIAL_TOKEN_PENDING_CONFIRMATION_SESSION_NAME)

        invitation_tokens = (
            self.session_get(INVITATION_PARTIAL_TOKENS_SESSION_NAME, {}) or {}
        )
        if isinstance(invitation_tokens, dict):
            for invitation_id, stored_token in list(invitation_tokens.items()):
                if stored_token == token:
                    invitation_tokens.pop(invitation_id, None)
            self.session_set(INVITATION_PARTIAL_TOKENS_SESSION_NAME, invitation_tokens)

    def get_session_key(self) -> str | None:
        """Return the application's stable session identifier when available."""
        try:
            session_key = self.session_get("session_key")
        except NotImplementedError:
            return None
        return session_key if isinstance(session_key, str) else None

    def validate_invitation(
        self,
        invitation_id: str | None,
        *,
        stage: str,
        backend: BaseAuth[object] | None = None,
        user: UserProtocol | object | int | str | None = None,
        partial: PartialMixin | None = None,
        session_key: str | None = None,
        **context: Any,
    ) -> InvitationDecision | None:
        """Ask the application whether this flow's invitation is still valid.

        The default implementation is a compatibility no-op. Applications can
        assign an object with ``validate_invitation(check)`` or a callable to
        ``strategy.invitation_validator``, configure
        ``INVITATION_VALIDATOR`` as a dotted path/callable, or override this
        method. Checks must be live at each write boundary rather than caching
        a decision from an earlier pipeline stage.
        """
        if invitation_id is None:
            return None

        validator = getattr(self, "invitation_validator", None)
        if validator is None:
            validator = self.setting("INVITATION_VALIDATOR", None, backend=backend)
        if isinstance(validator, str):
            validator = module_member(validator)
        if validator is None:
            return None
        if not callable(validator) and not hasattr(validator, "validate_invitation"):
            raise AuthConfigurationError(
                backend,
                code="unsupported_feature",
                parameter="INVITATION_VALIDATOR",
                stage="pipeline",
            )

        principal_id = getattr(user, "id", user)
        check = InvitationCheck(
            invitation_id=invitation_id,
            stage=stage,
            provider=getattr(backend, "name", None),
            user=user,
            user_id=principal_id,
            session_key=session_key
            if session_key is not None
            else self.get_session_key(),
            partial=partial,
            partial_token=getattr(partial, "token", None),
            uid=context.get("uid"),
            changed_fields=frozenset(context.get("changed_fields") or ()),
            context=context,
        )

        if hasattr(validator, "validate_invitation"):
            result = validator.validate_invitation(check)
        else:
            result = _call_invitation_callable(validator, check, backend=backend)

        if isinstance(result, InvitationDecision):
            decision = result
        elif result is False:
            decision = InvitationDecision(
                invitation_id=invitation_id,
                stage=stage,
                allowed=False,
                status="invalid",
            )
        else:
            decision = InvitationDecision(
                invitation_id=invitation_id,
                stage=stage,
                allowed=True,
                status="approved",
            )

        if not decision.allowed:
            raise AuthInvitationError(
                backend,
                code="invitation_revoked"
                if decision.end_state == "revoked"
                else "invitation_invalid",
                stage="callback"
                if stage.startswith("partial_")
                else "pipeline",
                invitation_id=invitation_id,
            )
        return decision

    def partial_pipeline_external_resume_confirmation(
        self,
        backend: BaseAuth[object],
        partial: PartialMixin,
        request_data: dict[str, Any],
    ) -> ResponseT_co | None:
        return None

    def partial_pipeline_external_resume_confirmed(
        self,
        backend: BaseAuth[object],
        request_data: dict[str, Any],
    ) -> bool:
        return False

    def openid_store(self) -> OpenIdStore:
        return OpenIdStore(self)

    def get_pipeline(self, backend: BaseAuth[object] | None = None) -> list[str]:
        return cast(
            "list[str]", self.setting("PIPELINE", DEFAULT_AUTH_PIPELINE, backend)
        )

    def get_disconnect_pipeline(
        self, backend: BaseAuth[object] | None = None
    ) -> list[str]:
        return cast(
            "list[str]",
            self.setting("DISCONNECT_PIPELINE", DEFAULT_DISCONNECT_PIPELINE, backend),
        )

    def random_string(self, length: int = 12, chars: str = ALLOWED_CHARS) -> str:
        return "".join([secrets.choice(chars) for i in range(length)])

    def absolute_uri(self, path: str | None = None) -> str:
        uri = self.build_absolute_uri(path)
        if uri and self.setting("REDIRECT_IS_HTTPS"):
            uri = uri.replace("http://", "https://")
        return uri

    def get_language(self) -> str:
        """Return current language"""
        return ""

    def send_email_validation(
        self, backend: BaseAuth[object], email: str, partial_token: str | None = None
    ) -> CodeMixin:
        email_validation = self.setting("EMAIL_VALIDATION_FUNCTION")
        if not email_validation:
            raise AuthConfigurationError(
                None,
                parameter="EMAIL_VALIDATION_FUNCTION",
                code="missing_setting",
                stage="pipeline",
            )
        send_email = module_member(email_validation)
        code = self.storage.code.make_code(email)
        send_email(self, backend, code, partial_token)
        return code

    def validate_email(self, email: str, code: str) -> bool:
        verification_code = self.storage.code.get_code(code)
        if not verification_code or verification_code.code != code:
            return False
        if verification_code.email != email:
            return False
        if verification_code.verified:
            return False
        expiry = self.setting("EMAIL_VALIDATION_EXPIRED_THRESHOLD", 7 * 24 * 60 * 60)
        if expiry and verification_code.is_expired(expiry):
            return False
        verification_code.verify()
        return True

    def render_html(
        self,
        tpl: str | None = None,
        html: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> str:
        """Render given template or raw html with given context"""
        return self.tpl.render(tpl, html, context)

    def authenticate(
        self, backend: BaseAuth[_BackendResponseT], *args, **kwargs
    ) -> UserProtocol | _BackendResponseT | None:
        """Trigger authentication using a backend created by this strategy."""
        kwargs["strategy"] = self
        kwargs["storage"] = self.storage
        kwargs["backend"] = backend
        args, kwargs = self.clean_authenticate_args(*args, **kwargs)
        return backend.authenticate(*args, **kwargs)

    def clean_authenticate_args(self, *args, **kwargs):
        """Take authenticate arguments and return a "cleaned" version
        of them"""
        return args, kwargs

    def get_backends(self) -> list[str]:
        """Return configured backends"""
        return cast("list[str]", self.setting("AUTHENTICATION_BACKENDS", []))

    def get_backend_class(self, name: str) -> type[BaseAuth[ResponseT_co]]:
        """Return a configured backend class"""
        return get_backend(self.get_backends(), name)

    def get_backend(
        self, name: str, redirect_uri: str | None = None, **kwargs
    ) -> BaseAuth[ResponseT_co]:
        """Return a configured backend instance"""
        backend_class = self.get_backend_class(name)
        kwargs["redirect_uri"] = redirect_uri
        return backend_class(self, **kwargs)

    # Implement the following methods on strategies sub-classes

    def redirect(self, url: str) -> ResponseT_co:
        """Return a response redirect to the given URL"""
        raise NotImplementedError("Implement in subclass")

    def get_setting(self, name: str):
        """Return value for given setting name"""
        raise NotImplementedError("Implement in subclass")

    def html(self, content: str) -> ResponseT_co:
        """Return HTTP response with given content"""
        raise NotImplementedError("Implement in subclass")

    def html_with_headers(
        self, content: str, headers: Mapping[str, str]
    ) -> ResponseT_co:
        """Return HTML with required headers; integrations must implement this."""
        raise AuthConfigurationError(
            None,
            "Strategy does not support HTML response headers",
            code="unsupported_feature",
            stage="callback",
        )

    def request_data(self, merge: bool = True) -> dict[str, Any]:
        """Return effective pipeline data, or data from the current request.

        During a partial resume, merge does not change the replayed mapping.
        Use get_request_data(), request_get(), or request_post() to read the
        current framework request without replayed data.
        """
        data = self._pipeline_request_data.get()
        if data is not None:
            return data
        return self.get_request_data(merge=merge)

    @contextmanager
    def pipeline_request_data(
        self, data: Mapping[str, Any] | None
    ) -> Generator[None, None, None]:
        """Scope effective request data to one pipeline execution."""
        token = self._pipeline_request_data.set(
            to_plain_dict(data) if data is not None else None
        )
        try:
            yield
        finally:
            self._pipeline_request_data.reset(token)

    def get_request_data(self, merge: bool = True) -> dict[str, Any]:
        """Return data from the current framework request (POST or GET)."""
        raise NotImplementedError("Implement in subclass")

    def request_host(self) -> str:
        """Return current host value"""
        raise NotImplementedError("Implement in subclass")

    def session_get(self, name: str, default=None):
        """Return session value for given key"""
        raise NotImplementedError("Implement in subclass")

    def session_set(self, name: str, value):
        """Set session value for given key"""
        raise NotImplementedError("Implement in subclass")

    def session_pop(self, name: str):
        """Pop session value for given key"""
        raise NotImplementedError("Implement in subclass")

    def build_absolute_uri(self, path: str | None = None) -> str:
        """Build absolute URI with given (optional) path"""
        raise NotImplementedError("Implement in subclass")

    def request_is_secure(self) -> bool:
        """Is the request using HTTPS?"""
        raise NotImplementedError("Implement in subclass")

    def request_path(self) -> str:
        """path of the current request"""
        raise NotImplementedError("Implement in subclass")

    def request_port(self) -> int:
        """Port in use for this request"""
        raise NotImplementedError("Implement in subclass")

    def request_get(self):
        """Request GET data"""
        raise NotImplementedError("Implement in subclass")

    def request_post(self):
        """Request POST data"""
        raise NotImplementedError("Implement in subclass")
