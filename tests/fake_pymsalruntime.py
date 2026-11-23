"""An in-memory fake of the ``pymsalruntime`` broker package.

The real package is a native extension (WAM on Windows, broker on Mac/Linux)
and is intentionally unavailable in this offline test environment. This fake
implements just enough of its surface for ``msal.broker`` to run, so that the
Proof-of-Possession (PoP) behavior can be exercised without a device broker.

Design goals, mapped to the security review in this change:

* Every broker entry point records the *actual* method invoked and the exact
  PoP parameters handed over (HTTP method, host, path, nonce), i.e. the
  per-request binding. Two operations sharing the same account and scopes but
  carrying different PoP challenges therefore stay distinguishable.
* Only pre-approved requests are fulfilled; anything else produces a broker
  error, so the controlled fallback in ``msal.application`` can be observed.
* PoP results are returned as a Signed HTTP Request (SHR, a compact JWT-like
  string) whose payload repeats the binding, mirroring how the real broker
  answers via ``get_authorization_header()``.

This module is test-only infrastructure; it is not imported by the library.
"""
import base64
import json
import threading
import time
import uuid


class LogLevel(object):
    TRACE = 0
    DEBUG = 1
    INFO = 2
    WARNING = 3
    ERROR = 4
    FATAL = 5


class Response_Status(object):
    Status_Ok = 0
    Status_AccountUnusable = 1
    Status_InteractionRequired = 2
    Status_ApiContractViolation = 3


def register_logging_callback(callback):
    FakeRuntimeState.logging_callbacks.append(callback)


def set_is_pii_enabled(enabled):
    FakeRuntimeState.pii_enabled = bool(enabled)


def get_console_window():
    return "fake-console-window"


def get_desktop_window():
    return "fake-desktop-window"


class MSALRuntimeAuthParameters(object):
    def __init__(self, client_id, authority):
        self.client_id = client_id
        self.authority = authority
        self.scopes = []
        self.redirect_uri = None
        self.claims = None
        self.pop_params = None
        self.additional_parameters = {}

    def set_requested_scopes(self, scopes):
        self.scopes = list(scopes or [])

    def set_redirect_uri(self, redirect_uri):
        self.redirect_uri = redirect_uri

    def set_decoded_claims(self, claims):
        self.claims = claims

    def set_pop_params(self, http_method, host, path, nonce):
        self.pop_params = {
            "http_method": http_method,
            "host": host,
            "path": path,
            "nonce": nonce,
        }

    def set_additional_parameter(self, key, value):
        self.additional_parameters[key] = value


class _Signal(object):
    def __init__(self):
        self._event = threading.Event()

    def wait(self):
        self._event.wait()

    def complete(self):
        self._event.set()


class CallbackData(object):
    def __init__(self, is_interactive=False):
        self.is_interactive = is_interactive
        self.signal = _Signal()
        self.result = None

    def complete(self, result):
        self.result = result
        self.signal.complete()


class MSALRuntimeError(object):
    def __init__(self, context, status, error_code, tag):
        self._context = context
        self._status = status
        self._error_code = error_code
        self._tag = tag

    def get_context(self):
        return self._context

    def get_status(self):
        return self._status

    def get_error_code(self):
        return self._error_code

    def get_tag(self):
        return self._tag


class MSALRuntimeAccount(object):
    def __init__(self, account_id, client_info):
        self._account_id = account_id
        self._client_info = client_info

    def get_account_id(self):
        return self._account_id

    def get_client_info(self):
        return self._client_info


def _b64url(raw_bytes):
    return base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")


def _build_shr(pop_params, scopes, client_id):
    """Mint a Signed HTTP Request that embeds the request binding.

    The real broker signs this with a device-held key. We cannot sign here, so
    the third segment is a synthetic tag; what matters for binding tests is
    that the signed payload (``m``/``u``/``p``/``nonce``) is carried verbatim.
    """
    header = _b64url(json.dumps({"typ": "pop", "alg": "fake"}).encode("utf-8"))
    now = int(time.time())
    payload = {
        "at": _b64url(b"fake-bound-at"),
        "m": pop_params["http_method"],
        "u": pop_params["host"],
        "p": pop_params["path"],
        "nonce": pop_params["nonce"],
        "aud": client_id,
        "ts": now,
        "exp": now + 3600,
        "scope": " ".join(scopes),
        "jti": str(uuid.uuid4()),
    }
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = _b64url(b"fake-signature-" + uuid.uuid4().bytes)
    return "{}.{}.{}".format(header, body, signature), payload


def _client_info_for(account_id):
    return base64.b64encode(json.dumps({
        "uid": "uid-{}".format(account_id),
        "utid": "utid",
    }).encode("utf-8")).decode("utf-8")


def _raw_id_token(account_id):
    payload = {
        "iss": "https://login.microsoftonline.com/utid/v2.0",
        "sub": "subject-{}".format(account_id),
        "preferred_username": "operator-{}@contoso.com".format(account_id),
        "tid": "utid",
        "oid": "uid-{}".format(account_id),
        "exp": int(time.time()) + 3600,
    }
    body = _b64url(json.dumps(payload).encode("utf-8"))
    return "header.{}.signature".format(body), payload


class MSALRuntimeResult(object):
    def __init__(self, params, account_id, *, is_error=False, error=None):
        self._params = params
        self._account_id = account_id
        self._error = error
        self._is_pop = bool(params.pop_params)
        if is_error:
            self._shr = None
            self._shr_payload = None
            self._access_token = None
        elif self._is_pop:
            self._shr, self._shr_payload = _build_shr(
                params.pop_params, params.scopes, params.client_id)
            self._access_token = None
        else:
            self._shr = None
            self._shr_payload = None
            self._access_token = "fake-bearer-at-{}".format(uuid.uuid4().hex)
        raw_id_token, id_token_claims = _raw_id_token(account_id)
        self._raw_id_token = raw_id_token
        self._id_token_claims = id_token_claims
        self._expiry = int(time.time()) + 3600

    def get_error(self):
        return self._error

    def is_pop_authorization(self):
        return self._is_pop and self._error is None

    def get_authorization_header(self):
        return "pop {}".format(self._shr)

    def get_access_token(self):
        return self._access_token

    def get_access_token_expiry_time(self):
        return self._expiry

    def get_raw_id_token(self):
        return self._raw_id_token

    def get_id_token(self):
        return json.dumps(self._id_token_claims)

    def get_account(self):
        return MSALRuntimeAccount(
            self._account_id, _client_info_for(self._account_id))

    def get_granted_scopes(self):
        return list(self._params.scopes)

    def get_telemetry_data(self):
        return {"wam_telemetry": "redacted", "fake_broker": True}


class FakeRuntimeState(object):
    """Process-wide state of the fake broker; reset between tests."""
    lock = threading.RLock()
    calls = []
    accounts = {}
    approved_bindings = set()
    fail_next_silent = 0
    init_error = None
    logging_callbacks = []
    pii_enabled = False

    @classmethod
    def reset(cls):
        with cls.lock:
            cls.calls = []
            cls.accounts = {}
            cls.approved_bindings = set()
            cls.fail_next_silent = 0
            cls.init_error = None
            cls.logging_callbacks = []
            cls.pii_enabled = False

    @classmethod
    def approve(cls, http_method, host, path, nonce):
        cls.approved_bindings.add((http_method, host, path, nonce))

    @classmethod
    def _binding_approved(cls, pop_params):
        if pop_params is None:
            return True  # Bearer requests do not carry a PoP challenge
        return (
            pop_params["http_method"], pop_params["host"],
            pop_params["path"], pop_params["nonce"],
        ) in cls.approved_bindings


def _record(method_name, params, account_id=None):
    entry = {
        "method": method_name,
        "client_id": params.client_id,
        "authority": params.authority,
        "scopes": list(params.scopes),
        "pop": dict(params.pop_params) if params.pop_params else None,
        "account_id": account_id,
        "claims": params.claims,
        "thread": threading.current_thread().name,
    }
    FakeRuntimeState.calls.append(entry)
    return entry


def _new_account_id():
    return str(uuid.uuid4())


def _make_error_result(params, account_id, context, status=Response_Status.Status_ApiContractViolation):
    error = MSALRuntimeError(context, status, 3399614473, "fake-tag")
    return MSALRuntimeResult(params, account_id, is_error=True, error=error)


def _resolve_or_create_account(params):
    account_id = _new_account_id()
    FakeRuntimeState.accounts[account_id] = MSALRuntimeAccount(
        account_id, _client_info_for(account_id))
    return account_id


def _dispatch(params, method_name, account_id=None):
    """Shared approval/failure gate used by every broker entry point."""
    _record(method_name, params, account_id=account_id)
    if not FakeRuntimeState._binding_approved(params.pop_params):
        return _make_error_result(
            params, account_id or _new_account_id(),
            "Fake broker: this PoP challenge was not pre-approved")
    if account_id is None:
        account_id = _resolve_or_create_account(params)
    return MSALRuntimeResult(params, account_id)


def signin_silently(params, correlation_id, callback):
    result = _dispatch(params, "signin_silently")
    callback(result)


def signin_interactively(
        parent_window_handle, params, correlation_id, login_hint, callback):
    FakeRuntimeState.calls.append({
        "method": "signin_interactively",
        "client_id": params.client_id,
        "authority": params.authority,
        "scopes": list(params.scopes),
        "pop": dict(params.pop_params) if params.pop_params else None,
        "account_id": None,
        "claims": params.claims,
        "parent_window_handle": parent_window_handle,
        "login_hint": login_hint,
        "thread": threading.current_thread().name,
        })
    if not FakeRuntimeState._binding_approved(params.pop_params):
        result = _make_error_result(
            params, _new_account_id(),
            "Fake broker: this PoP challenge was not pre-approved")
    else:
        result = MSALRuntimeResult(
            params, _resolve_or_create_account(params))
    callback(result)


def acquire_token_silently(params, correlation_id, account, callback):
    account_id = account.get_account_id()
    _record("acquire_token_silently", params, account_id=account_id)
    if FakeRuntimeState.fail_next_silent > 0:
        FakeRuntimeState.fail_next_silent -= 1
        callback(_make_error_result(
            params, account_id,
            "Fake broker: injected silent failure",
            status=Response_Status.Status_InteractionRequired))
        return
    if not FakeRuntimeState._binding_approved(params.pop_params):
        callback(_make_error_result(
            params, account_id,
            "Fake broker: this PoP challenge was not pre-approved"))
        return
    callback(MSALRuntimeResult(params, account_id))


def read_account_by_id(account_id, correlation_id, callback):
    _record_object = {
        "method": "read_account_by_id",
        "account_id": account_id,
        "pop": None,
        "scopes": [],
        "client_id": None,
        "authority": None,
        "claims": None,
        "thread": threading.current_thread().name,
    }
    FakeRuntimeState.calls.append(_record_object)
    callback_data = _ReadAccountResult(FakeRuntimeState.accounts.get(account_id))
    callback(callback_data)


def signout_silently(client_id, correlation_id, account, callback):
    account_id = account.get_account_id()
    FakeRuntimeState.calls.append({
        "method": "signout_silently",
        "client_id": client_id,
        "authority": None,
        "scopes": [],
        "pop": None,
        "account_id": account_id,
        "claims": None,
        "thread": threading.current_thread().name,
        })
    FakeRuntimeState.accounts.pop(account_id, None)
    callback(_ReadAccountResult(None))


class _ReadAccountResult(object):
    def __init__(self, account):
        self._account = account

    def get_error(self):
        return None

    def get_account(self):
        return self._account
