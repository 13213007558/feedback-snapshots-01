from __future__ import annotations

import base64
import http.client as http_client
import os
import warnings
from dataclasses import asdict, dataclass
from functools import partial
from typing import TYPE_CHECKING, Callable

from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import SimpleLazyObject, empty

from csp.constants import HEADER, HEADER_REPORT_ONLY
from csp.exceptions import CSPNonceError
from csp.utils import DIRECTIVES_T, build_policy

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase

# Stable decision reasons reported to the diagnostics callback.
DECISION_GENERATED = "generated"  # The middleware built the policy and set the header.
DECISION_PRESET = "preset"  # The response already contained the header, set by the view.
DECISION_EXEMPT = "exempt"  # The view was exempted via the csp_exempt decorator.
DECISION_EXCLUDED = "excluded"  # The path matched EXCLUDE_URL_PREFIXES.
DECISION_NOT_CONFIGURED = "not_configured"  # No policy was configured for this header.
DECISION_DEBUG_EXEMPT = "debug_exempt"  # A debug error response (404/500 with DEBUG on).


@dataclass
class PolicyParts:
    # A dataclass is used rather than a namedtuple so that the attributes are mutable
    config: DIRECTIVES_T | None = None
    update: DIRECTIVES_T | None = None
    replace: DIRECTIVES_T | None = None
    nonce: str | None = None


@dataclass(frozen=True)
class PolicyDecision:
    """
    The middleware's final decision for one of the two policies of a response.

    Intentionally contains neither the nonce nor any header values, so records
    are safe to log or aggregate.
    """

    header: str  # The name of the header the decision applies to.
    report_only: bool  # Whether the decision concerns the report-only policy.
    decision: str  # One of the DECISION_* constants.
    path: str  # The request path, to help locate the route.


class CheckableLazyObject(SimpleLazyObject):
    """A SimpleLazyObject where bool(obj) returns True if no longer lazy"""

    def __bool__(self) -> bool:
        """
        If the wrapped function has been evaluated, return True.
        If the wrapped function has not been evalated, return False.
        """
        return getattr(self, "_wrapped") is not empty


class CSPMiddleware(MiddlewareMixin):
    """
    Implements the Content-Security-Policy response header, which
    conforming user-agents can use to restrict the permitted sources
    of various content.

    See http://www.w3.org/TR/CSP/

    Can be customised by subclassing and extending the get_policy_parts method.

    Set ``diagnostics_callback`` (typically on a subclass) to a callable accepting
    a ``PolicyDecision`` to be told, for each of the two policies, why a response
    did or did not get a header.
    """

    diagnostics_callback: Callable[[PolicyDecision], None] | None = None

    def _make_nonce(self, request: HttpRequest) -> str:
        # Ensure that any subsequent calls to request.csp_nonce return the same value
        stored_nonce = getattr(request, "_csp_nonce", None)
        if isinstance(stored_nonce, str):
            return stored_nonce
        nonce = base64.b64encode(os.urandom(16)).decode("ascii")
        setattr(request, "_csp_nonce", nonce)
        return nonce

    @staticmethod
    def _csp_nonce_post_response() -> None:
        raise CSPNonceError(
            "The 'csp_nonce' attribute is not available after the CSP header has been written. Consider adjusting your MIDDLEWARE order."
        )

    def process_request(self, request: HttpRequest) -> None:
        nonce = partial(self._make_nonce, request)
        setattr(request, "csp_nonce", CheckableLazyObject(nonce))

    def process_response(self, request: HttpRequest, response: HttpResponseBase) -> HttpResponseBase:
        # Check for debug view
        exempted_debug_codes = (
            http_client.INTERNAL_SERVER_ERROR,
            http_client.NOT_FOUND,
        )
        if response.status_code in exempted_debug_codes and settings.DEBUG:
            self._record_decision(request, report_only=False, decision=DECISION_DEBUG_EXEMPT)
            self._record_decision(request, report_only=True, decision=DECISION_DEBUG_EXEMPT)
            return response

        self._apply_policy(request, response, report_only=False)
        self._apply_policy(request, response, report_only=True)

        # Once we've written the header, accessing the `request.csp_nonce` will no longer trigger
        # the nonce to be added to the header. Instead we throw an error here to catch this since
        # this has security implications.
        if getattr(request, "_csp_nonce", None) is None:
            setattr(request, "csp_nonce", CheckableLazyObject(self._csp_nonce_post_response))

        return response

    def _apply_policy(self, request: HttpRequest, response: HttpResponseBase, report_only: bool) -> None:
        header = HEADER_REPORT_ONLY if report_only else HEADER
        policy_parts = self.get_policy_parts(request=request, response=response, report_only=report_only)
        csp = build_policy(**asdict(policy_parts), report_only=report_only)
        if not csp:
            decision = DECISION_NOT_CONFIGURED
        elif getattr(response, "_csp_exempt_ro" if report_only else "_csp_exempt", False):
            decision = DECISION_EXEMPT
        else:
            setting = "CONTENT_SECURITY_POLICY_REPORT_ONLY" if report_only else "CONTENT_SECURITY_POLICY"
            policy = getattr(settings, setting, None) or {}
            prefixes = policy.get("EXCLUDE_URL_PREFIXES", None) or ()
            if request.path_info.startswith(tuple(prefixes)):
                decision = DECISION_EXCLUDED
            elif header in response:
                # The view set the header itself; leave it untouched.
                decision = DECISION_PRESET
            else:
                response[header] = csp
                decision = DECISION_GENERATED
        self._record_decision(request, report_only=report_only, decision=decision)

    def _record_decision(self, request: HttpRequest, report_only: bool, decision: str) -> None:
        callback = self.diagnostics_callback
        if callback is not None:
            header = HEADER_REPORT_ONLY if report_only else HEADER
            callback(PolicyDecision(header=header, report_only=report_only, decision=decision, path=request.path_info))

    def build_policy(self, request: HttpRequest, response: HttpResponseBase) -> str:
        warnings.warn("deprecated in favor of get_policy_parts", DeprecationWarning)
        policy_parts = self.get_policy_parts(request=request, response=response, report_only=False)
        return build_policy(**asdict(policy_parts))

    def build_policy_ro(self, request: HttpRequest, response: HttpResponseBase) -> str:
        warnings.warn("deprecated in favor of get_policy_parts", DeprecationWarning)
        policy_parts_ro = self.get_policy_parts(request=request, response=response, report_only=True)
        return build_policy(**asdict(policy_parts_ro), report_only=True)

    def get_policy_parts(
        self,
        request: HttpRequest,
        response: HttpResponseBase,
        report_only: bool = False,
    ) -> PolicyParts:
        if report_only:
            config = getattr(response, "_csp_config_ro", None)
            update = getattr(response, "_csp_update_ro", None)
            replace = getattr(response, "_csp_replace_ro", None)
        else:
            config = getattr(response, "_csp_config", None)
            update = getattr(response, "_csp_update", None)
            replace = getattr(response, "_csp_replace", None)

        nonce = getattr(request, "_csp_nonce", None)

        return PolicyParts(config, update, replace, nonce)
