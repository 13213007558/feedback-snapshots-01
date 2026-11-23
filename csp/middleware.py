from __future__ import annotations

import base64
import http.client as http_client
import logging
import os
import warnings
from dataclasses import asdict, dataclass
from functools import partial
from typing import TYPE_CHECKING

from django.conf import settings
from django.http import StreamingHttpResponse
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import SimpleLazyObject, empty

from csp.constants import HEADER, HEADER_REPORT_ONLY
from csp.exceptions import CSPNonceConflictError, CSPNonceError
from csp.utils import (
    DIRECTIVES_T,
    build_policy,
    get_nonces_from_body,
    get_nonces_from_policy,
)

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase

logger = logging.getLogger(__name__)


@dataclass
class PolicyParts:
    # A dataclass is used rather than a namedtuple so that the attributes are mutable
    config: DIRECTIVES_T | None = None
    update: DIRECTIVES_T | None = None
    replace: DIRECTIVES_T | None = None
    nonce: str | None = None


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
    """

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

    def _get_upstream_nonce(self, request: HttpRequest) -> str | None:
        """Return a nonce minted by a trusted reverse proxy, if one is configured.

        Only the request header named in ``CONTENT_SECURITY_POLICY.UPSTREAM_NONCE_HEADER``
        is consulted, so a nonce is never guessed from generic request fields or an
        untrusted header.
        """
        policy = getattr(settings, "CONTENT_SECURITY_POLICY", None) or {}
        header = policy.get("UPSTREAM_NONCE_HEADER")
        if not header:
            return None
        nonce = request.headers.get(header)
        return nonce or None

    def process_request(self, request: HttpRequest) -> None:
        # A trusted upstream proxy may own the nonce. Pin it onto the request so
        # templates and the policy builder use exactly that value.
        upstream_nonce = self._get_upstream_nonce(request)
        if upstream_nonce is not None:
            setattr(request, "_csp_nonce", upstream_nonce)
            setattr(request, "_csp_nonce_upstream", True)
        nonce = partial(self._make_nonce, request)
        setattr(request, "csp_nonce", CheckableLazyObject(nonce))

    def process_response(self, request: HttpRequest, response: HttpResponseBase) -> HttpResponseBase:
        # Check for debug view
        exempted_debug_codes = (
            http_client.INTERNAL_SERVER_ERROR,
            http_client.NOT_FOUND,
        )
        if response.status_code in exempted_debug_codes and settings.DEBUG:
            return response

        policy_parts = self.get_policy_parts(request=request, response=response)
        csp = build_policy(**asdict(policy_parts))
        if csp:
            # Only set header if not already set and not an excluded prefix and not exempted.
            is_not_exempt = getattr(response, "_csp_exempt", False) is False
            no_header = HEADER not in response
            policy = getattr(settings, "CONTENT_SECURITY_POLICY", None) or {}
            prefixes = policy.get("EXCLUDE_URL_PREFIXES", None) or ()
            is_not_excluded = not request.path_info.startswith(tuple(prefixes))
            if no_header and is_not_exempt and is_not_excluded:
                response[HEADER] = csp

        policy_parts_ro = self.get_policy_parts(request=request, response=response, report_only=True)
        csp_ro = build_policy(**asdict(policy_parts_ro), report_only=True)
        if csp_ro:
            # Only set header if not already set and not an excluded prefix and not exempted.
            is_not_exempt = getattr(response, "_csp_exempt_ro", False) is False
            no_header = HEADER_REPORT_ONLY not in response
            policy = getattr(settings, "CONTENT_SECURITY_POLICY_REPORT_ONLY", None) or {}
            prefixes = policy.get("EXCLUDE_URL_PREFIXES", None) or ()
            is_not_excluded = not request.path_info.startswith(tuple(prefixes))
            if no_header and is_not_exempt and is_not_excluded:
                response[HEADER_REPORT_ONLY] = csp_ro

        # Reconcile the nonce the rendered body actually used with the enforced
        # policy before the response is released. This never consumes a lazy or
        # streaming response body.
        response = self._reconcile_nonce(request=request, response=response)

        # Once we've written the header, accessing the `request.csp_nonce` will no longer trigger
        # the nonce to be added to the header. Instead we throw an error here to catch this since
        # this has security implications.
        if getattr(request, "_csp_nonce", None) is None:
            setattr(request, "csp_nonce", CheckableLazyObject(self._csp_nonce_post_response))

        return response

    def _reconcile_nonce(self, request: HttpRequest, response: HttpResponseBase) -> HttpResponseBase:
        # A streaming body must not be read just to inspect its nonces; doing so
        # would consume its iterator. Only fully rendered, in-memory responses are
        # reconciled, and `response.content` does not trigger any lazy work.
        if isinstance(response, StreamingHttpResponse):
            setattr(response, "_csp_nonce_reconciled", "skipped-streaming")
            return response

        body_nonces = get_nonces_from_body(response.content)
        if not body_nonces:
            setattr(response, "_csp_nonce_reconciled", "no-nonce-in-body")
            return response

        # If neither policy header is emitted (e.g. the view is CSP-exempt), there
        # is no policy to reconcile against, so leave the response untouched.
        if response.get(HEADER) is None and response.get(HEADER_REPORT_ONLY) is None:
            setattr(response, "_csp_nonce_reconciled", "no-policy-header")
            return response

        header_nonces = get_nonces_from_policy(response.get(HEADER))

        # The enforced policy is the one that actually gates execution in the
        # browser. When it carries a nonce-bearing policy, an unresolved conflict
        # fails closed and never ships a page that merely looks approved.
        if response.get(HEADER) is not None:
            if body_nonces != header_nonces:
                self._log_conflict(request, body_nonces, header_nonces)
                setattr(response, "_csp_nonce_reconciled", "conflict")
                raise CSPNonceConflictError(
                    "The nonce rendered into the response body is not covered by the enforced "
                    f"Content-Security-Policy header (nonce owner: {self._nonce_owner(request)})."
                )
        else:
            # No enforced header is emitted; fall back to reconciling the
            # report-only policy so a nonced body is still checked against the
            # policy that advertises nonces.
            header_nonces = get_nonces_from_policy(response.get(HEADER_REPORT_ONLY))
            if response.get(HEADER_REPORT_ONLY) is not None and body_nonces != header_nonces:
                setattr(response, "_csp_nonce_reconciled", "report-only-conflict")
                logger.warning(
                    "CSP report-only nonce conflict for %s: body nonce(s) %s do not match report-only policy nonce(s) %s.",
                    request.path_info,
                    sorted(body_nonces),
                    sorted(header_nonces),
                )

        # The report-only header is checked independently and never blocks delivery
        # when an enforced policy is also present.
        report_header_nonces = get_nonces_from_policy(response.get(HEADER_REPORT_ONLY))
        if response.get(HEADER) is not None and body_nonces != report_header_nonces:
            logger.warning(
                "CSP report-only nonce mismatch for %s: body nonce(s) %s do not match report-only policy nonce(s) %s.",
                request.path_info,
                sorted(body_nonces),
                sorted(report_header_nonces),
            )

        # Explicit, inspectable release result for the already-rendered body.
        setattr(
            response,
            "_csp_nonce_reconciled",
            {
                "status": "released",
                "owner": self._nonce_owner(request),
                "body_nonces": body_nonces,
                "enforced_nonces": get_nonces_from_policy(response.get(HEADER)),
            },
        )
        return response

    @staticmethod
    def _nonce_owner(request: HttpRequest) -> str:
        return "upstream proxy" if getattr(request, "_csp_nonce_upstream", False) else "Django"

    def _log_conflict(self, request: HttpRequest, body_nonces: set[str], header_nonces: set[str]) -> None:
        logger.error(
            "CSP nonce conflict for %s: body nonce(s) %s do not match enforced policy nonce(s) %s.",
            request.path_info,
            sorted(body_nonces),
            sorted(header_nonces),
        )

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
