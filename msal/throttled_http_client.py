import json
import logging
import math
import re
import time
from threading import Lock
from hashlib import sha256
try:
    from urllib.parse import urlparse
except ImportError:  # Fall back to Python 2
    from urlparse import urlparse

from .individual_cache import _IndividualCache as IndividualCache
from .individual_cache import _ExpiringMapping as ExpiringMapping
from .oauth2cli.http import Response
from .exceptions import MsalServiceError


logger = logging.getLogger(__name__)

# https://datatracker.ietf.org/doc/html/rfc8628#section-3.4
DEVICE_AUTH_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

# Entra ID has historically exposed the same authorization service through a
# number of equivalent host names.  They must share one service-level budget,
# otherwise a platform-wide throttle learned on one host could be bypassed by
# simply switching to another host for the same service.
_KNOWN_SERVICE_ALIASES = {
    "login.windows.net": "login.microsoftonline.com",
    "login.microsoft.com": "login.microsoftonline.com",
    "sts.windows.net": "login.microsoftonline.com",
    "login.partner.microsoftonline.cn": "login.partner.microsoftonline.cn",
    "login.chinacloudapi.cn": "login.partner.microsoftonline.cn",
    "login.usgovcloudapi.net": "login.microsoftonline.us",
}

# A regional authorization host (e.g. westus2.login.microsoft.com) belongs to
# the same service as its non-regional form.
_REGIONAL_SERVICE_SUFFIXES = (
    (".login.microsoftonline.com", "login.microsoftonline.com"),
    (".login.microsoft.com", "login.microsoftonline.com"),
    (".login.windows.net", "login.microsoftonline.com"),
    (".login.microsoftonline.us", "login.microsoftonline.us"),
    (".login.partner.microsoftonline.cn", "login.partner.microsoftonline.cn"),
    (".login.sovcloud-identity.fr", "login.sovcloud-identity.fr"),
    (".login.sovcloud-identity.de", "login.sovcloud-identity.de"),
    (".login.sovcloud-identity.sg", "login.sovcloud-identity.sg"),
)

# These path segments select a routing/account mode rather than a concrete
# tenant, so a response for them can never be attributed to one tenant.
_NON_TENANT_PATH_SEGMENTS = frozenset(
    ["common", "organizations", "consumers", "adfs"])

_SERVICE_SCOPE_MARKERS = frozenset(
    ["global", "service", "platform", "server", "all"])

_VERSION_PATH_RE = re.compile(r"^v[0-9.]+$", re.IGNORECASE)
_CIAM_ROUTE_SEGMENTS = frozenset(["oauth2", "common", "discovery", "metadata"])


def _get_headers(response):
    # MSAL's HttpResponse did not have headers until 1.23.0
    # https://github.com/AzureAD/microsoft-authentication-library-for-python/pull/581/files#diff-28866b706bc3830cd20485685f20fe79d45b58dce7050e68032e9d9372d68654R61
    # This helper ensures graceful degradation to {} without exception
    return getattr(response, "headers", {})


def _lowercase_headers(response):
    return {k.lower(): v for k, v in _get_headers(response).items()}


def _builtin_canonical_service(host):
    if host in _KNOWN_SERVICE_ALIASES:
        return _KNOWN_SERVICE_ALIASES[host]
    for suffix, canonical in _REGIONAL_SERVICE_SUFFIXES:
        if host.endswith(suffix):
            return canonical
    return host


def _canonical_service(host, aliases=None):
    """Return a stable name for the authorization service behind *host*."""
    host = (host or "").lower().rstrip(".")
    if not host:
        return ""
    if aliases:
        resolved = aliases(host) if callable(aliases) else aliases.get(host)
        if resolved:
            # Re-apply the built-in table so a caller-supplied alias group and
            # the well-known equivalents always land on the same key.
            return _builtin_canonical_service(resolved.lower().rstrip("."))
    return _builtin_canonical_service(host)


def _request_context(url, aliases=None):
    """Return (service, tenant) for an authorization request, or None.

    The tenant is deliberately normalized to its lower-case path segment (or
    CIAM/B2C host), so two aliases of the same tenant produce the same key.
    """
    try:
        parsed = urlparse(url)
    except (TypeError, ValueError):
        return None
    host = (parsed.hostname or "").lower()
    if not host:
        return None
    service = _canonical_service(host, aliases)
    segments = [segment for segment in parsed.path.split("/") if segment]
    if host.endswith(".ciamlogin.com"):
        # Both https://tenant.ciamlogin.com/ and
        # https://tenant.ciamlogin.com/tenant.onmicrosoft.com/ denote the
        # same tenant, so normalize the path-less form to the latter.
        # A path that begins with a protocol version (e.g. /v2.0/...)
        # is a route, not a tenant.
        tenant = segments[0] if segments and not (
            _VERSION_PATH_RE.match(segments[0])
            or segments[0].lower() in _CIAM_ROUTE_SEGMENTS
            ) else "{}.onmicrosoft.com".format(host[:-len(".ciamlogin.com")])
    elif host.endswith(".b2clogin.com"):
        tenant = segments[0] if segments else None
    else:
        tenant = segments[0] if segments else None
    tenant = tenant.lower() if tenant else None
    if tenant in _NON_TENANT_PATH_SEGMENTS:
        tenant = None
    return service, tenant


def _parse_scope_markers(headers):
    """Extract throttle scope marker(s) from any *-throttle-*scope header.

    The exact header name has changed across Microsoft services.  Looking for
    both words preserves the security property: only an explicit attribution
    may widen a response beyond the tenant named in the request URL.
    """
    markers = []
    for name, value in headers.items():
        if "throttle" in name and "scope" in name and value:
            markers.extend(
                part.strip().lower() for part in str(value).split(",")
                if part.strip())
    return markers


def _classify_throttle(response, context, parser, now=None):
    """Return (scope, deadline) for a response that may widen a gate.

    The deadline is absolute (epoch seconds) when computed at first sight, and
    is carried on the normalized response so that later replays from the
    per-request cache cannot re-arm it relative to a newer "now".

    * 5xx is a platform failure, so it applies to the whole authorization
      service (all hosts that are aliases of each other).
    * A 429 explicitly attributed to the service/global scope also applies to
      the whole service.
    * Any other 429 is tenant-scoped only when the request URL names a concrete
      tenant.  Requests to ``common``/``organizations``/``consumers`` cannot be
      attributed to one tenant, so they only keep their existing per-request
      cache behavior and never change tenant pacing.
    * Other statuses (including 400 with Retry-After) keep their existing
      per-request semantics.
    """
    status = getattr(response, "status_code", None)
    headers = _lowercase_headers(response)
    delay = parser.parse(result=response)
    if not delay:
        return None
    deadline = getattr(response, "_msal_throttle_deadline", None)
    if deadline is None:
        deadline = (time.time() if now is None else now) + delay
    if isinstance(status, int) and status >= 500:
        return "service", deadline
    if status == 429:
        markers = _parse_scope_markers(headers)
        if any(marker in _SERVICE_SCOPE_MARKERS for marker in markers):
            return "service", deadline
        if context[1]:  # A concrete tenant is named by the request URL
            return "tenant", deadline
    return None


class _ThrottleGate(object):
    """Deadline bookkeeping shared by all requests of one http client.

    Deadlines are stored per canonical service and, when attributable, per
    (service, tenant).  No tenant name, URL, or client id is exposed through
    diagnostics or logs; only the allowed scope labels and times are surfaced.
    """
    def __init__(self, clock=None):
        self._clock = clock
        self._lock = Lock()
        self._tenant_deadlines = {}  # (service, tenant) -> epoch seconds
        self._service_deadlines = {}  # service -> epoch seconds

    def _now(self):
        return time.time() if self._clock is None else self._clock()

    def _purge(self, now):
        for mapping in (self._tenant_deadlines, self._service_deadlines):
            for key, deadline in list(mapping.items()):
                if deadline <= now:
                    del mapping[key]

    def check(self, context):
        """Return (scope, remaining_seconds) if this request must wait."""
        service, tenant = context
        now = self._now()
        with self._lock:
            self._purge(now)
            candidates = []
            if tenant:
                deadline = self._tenant_deadlines.get((service, tenant))
                if deadline is not None:
                    candidates.append(("tenant", deadline))
            deadline = self._service_deadlines.get(service)
            if deadline is not None:
                candidates.append(("service", deadline))
            if not candidates:
                return None
            scope, deadline = max(candidates, key=lambda item: item[1])
            return scope, max(0, deadline - now)

    def record_until(self, context, scope, deadline):
        """Set a gate deadline to an absolute time, never shortening it.

        Absolute time matters when a cached upstream response is replayed:
        the original upstream release time must keep winning instead of being
        re-armed relative to each replay.
        """
        service, tenant = context
        now = self._now()
        if deadline <= now:
            return
        with self._lock:
            self._purge(now)
            if scope == "tenant":
                if not tenant:
                    return
                key = (service, tenant)
                existing = self._tenant_deadlines.get(key)
                if existing is None or deadline > existing:
                    self._tenant_deadlines[key] = deadline
            elif scope == "service":
                existing = self._service_deadlines.get(service)
                if existing is None or deadline > existing:
                    self._service_deadlines[service] = deadline
        # Diagnostics intentionally expose only the allowed categories.
        logger.debug("Throttle scope=%s until %.0f", scope, deadline)

    def diagnostics(self):
        now = self._now()
        with self._lock:
            self._purge(now)
            def summarize(mapping):
                active = [deadline for deadline in mapping.values()
                          if deadline > now]
                if not active:
                    return {"active": 0, "release_in": 0, "release_at": None}
                deadline = max(active)
                return {
                    "active": len(active),
                    "release_in": max(0, deadline - now),
                    "release_at": deadline,
                }
            return {
                "tenant": summarize(self._tenant_deadlines),
                "service": summarize(self._service_deadlines),
            }


class RetryAfterParser(object):
    FIELD_NAME_LOWER = "Retry-After".lower()
    def __init__(self, default_value=None):
        self._default_value = 5 if default_value is None else default_value

    def parse(self, *, result, **ignored):
        """Return seconds to throttle"""
        response = result
        if getattr(response, "_msal_throttle_synthetic", False):
            return 0  # A local gate block must not extend its own deadline
        lowercase_headers = _lowercase_headers(response)
        if not (response.status_code == 429 or response.status_code >= 500
                or self.FIELD_NAME_LOWER in lowercase_headers):
            return 0  # Quick exit
        retry_after = lowercase_headers.get(self.FIELD_NAME_LOWER, self._default_value)
        try:
            # AAD's retry_after uses integer format only
            # https://stackoverflow.microsoft.com/questions/264931/264932
            delay_seconds = int(retry_after)
        except (ValueError, TypeError):
            delay_seconds = self._default_value
        return min(3600, delay_seconds)


def _extract_data(kwargs, key, default=None):
    data = kwargs.get("data", {})  # data is usually a dict, but occasionally a string
    return data.get(key) if isinstance(data, dict) else default


class NormalizedResponse(Response):
    """A http response with the shape defined in Response,
    but contains only the data we will store in cache.
    """
    def __init__(self, raw_response):
        super().__init__()
        self.status_code = raw_response.status_code
        self.text = raw_response.text
        self.headers = {
            k.lower(): v for k, v in _get_headers(raw_response).items()
            # Attempted storing only a small set of headers (such as Retry-After),
            # but it tends to lead to missing information (such as WWW-Authenticate).
            # So we store all headers, which are expected to contain only public info,
            # because we throttle only error responses and public responses.
        }
        if getattr(raw_response, "_msal_throttle_synthetic", False):
            # Keep the marker so the cache never mistakes a local gate block
            # for a server-issued Retry-After.
            self._msal_throttle_synthetic = True
        if hasattr(raw_response, "_msal_throttle_deadline"):
            self._msal_throttle_deadline = raw_response._msal_throttle_deadline

    ## Note: Don't use the following line,
    ## because when being pickled, it will indirectly pickle the whole raw_response
    # self.raise_for_status = raw_response.raise_for_status
    def raise_for_status(self):
        if self.status_code >= 400:
            raise MsalServiceError(
                "HTTP Error: {}".format(self.status_code),
                error=None, error_description=None,  #  Historically required, keeping them for now
            )


class _ThrottledResponse(NormalizedResponse):
    """A locally generated 429 that never reached the transport."""
    def __init__(self, scope, remaining):
        # Do not call NormalizedResponse.__init__, because there is no raw
        # response to normalize.  All fields below are plain cache-safe data.
        self.status_code = 429
        self.text = json.dumps({
            "error": "temporarily_unavailable",
            "error_description": "The request was throttled.",
        })
        self.headers = {
            "retry-after": str(max(1, int(math.ceil(remaining)))),
        }
        self._msal_throttle_synthetic = True


class ThrottledHttpClientBase(object):
    """Throttle the given http_client by storing and retrieving data from cache.

    This base exists so that:
    1. These base post() and get() will return a NormalizedResponse
    2. The base __init__() will NOT re-throttle even if caller accidentally nested ThrottledHttpClient.

    Subclasses shall only need to dynamically decorate their post() and get() methods
    in their __init__() method.
    """
    def __init__(self, http_client, *, http_cache=None, clock=None):
        self.http_client = http_client.http_client if isinstance(
            # If it is already a ThrottledHttpClientBase, we use its raw (unthrottled) http client
            http_client, ThrottledHttpClientBase) else http_client
        self._expiring_mapping = ExpiringMapping(  # It will automatically clean up
            mapping=http_cache if http_cache is not None else {},
            capacity=1024,  # To prevent cache blowing up especially for CCA
            lock=Lock(),  # TODO: This should ideally also allow customization
            clock=clock,
            )

    def post(self, *args, **kwargs):
        return NormalizedResponse(self.http_client.post(*args, **kwargs))

    def get(self, *args, **kwargs):
        return NormalizedResponse(self.http_client.get(*args, **kwargs))

    def close(self):
        return self.http_client.close()

    @staticmethod
    def _hash(raw):
        return sha256(repr(raw).encode("utf-8")).hexdigest()


class ThrottledHttpClient(ThrottledHttpClientBase):
    """A throttled http client that is used by MSAL's non-managed identity clients."""

    def __init__(self, *args, default_throttle_time=None,
            authority_aliases=None, clock=None, **kwargs):
        """Decorate self.post() and self.get() dynamically

        :param authority_aliases:
            Optional mapping (or callable) from an authorization host to any
            stable shared name for its alias group. Known Entra ID equivalents
            and regional hosts are already built in; this is for other clouds.
        :param clock:
            Optional zero-argument callable returning epoch seconds. It drives
            every expiry and throttle deadline of this client, which makes
            local-clock driven testing possible.
        """
        super(ThrottledHttpClient, self).__init__(*args, clock=clock, **kwargs)
        self._throttle_gate = _ThrottleGate(clock)
        _context = lambda url: _request_context(url, authority_aliases)
        _parser = RetryAfterParser(default_throttle_time or 5)
        # The gate is the innermost layer: an already cached upstream response
        # (including a per-request Retry-After one) must keep winning, and a
        # local gate block must never be stored as if the server said it.
        # It applies to both POST (token requests) and GET (discovery), because
        # a service-wide block constrains every eligible request from this
        # client to that authorization service.
        self.post = self._throttled(self.post, _context, _parser)
        self.get = self._throttled(self.get, _context, _parser)

        self.post = IndividualCache(
            # Internal specs requires throttling on at least token endpoint,
            # here we have a generic patch for POST on all endpoints.
            mapping=self._expiring_mapping,
            key_maker=lambda func, args, kwargs:
                "POST {} client_id={} scope={} hash={} 429/5xx/Retry-After".format(
                    args[0],  # It is the url, typically containing authority and tenant
                    _extract_data(kwargs, "client_id"),  # Per internal specs
                    _extract_data(kwargs, "scope"),  # Per internal specs
                    self._hash(
                        # The followings are all approximations of the "account" concept
                        # to support per-account throttling.
                        # TODO: We may want to disable it for confidential client, though
                        _extract_data(kwargs, "refresh_token",  # "account" during refresh
                            _extract_data(kwargs, "code",  # "account" of auth code grant
                                _extract_data(kwargs, "username",  # "account" of ROPC
                                    _extract_data(kwargs, "user_id"))))),  # "account" of user_fic (OID path)
                    ),
            expires_in=_parser.parse,
            )(self.post)

        self.post = IndividualCache(  # It covers the "UI required cache"
            mapping=self._expiring_mapping,
            key_maker=lambda func, args, kwargs: "POST {} hash={} 400".format(
                args[0],  # It is the url, typically containing authority and tenant
                self._hash(
                    # Here we use literally all parameters, even those short-lived
                    # parameters containing timestamps (WS-Trust or POP assertion),
                    # because they will automatically be cleaned up by ExpiringMapping.
                    #
                    # Furthermore, there is no need to implement
                    # "interactive requests would reset the cache",
                    # because acquire_token_silent()'s would be automatically unblocked
                    # due to token cache layer operates on top of http cache layer.
                    #
                    # And, acquire_token_silent(..., force_refresh=True) will NOT
                    # bypass http cache, because there is no real gain from that.
                    # We won't bother implement it, nor do we want to encourage
                    # acquire_token_silent(..., force_refresh=True) pattern.
                    str(kwargs.get("params")) + str(kwargs.get("data"))),
                ),
            expires_in=lambda result=None, kwargs=None, **ignored:
                60
                if result.status_code == 400
                    # Here we choose to cache exact HTTP 400 errors only (rather than 4xx)
                    # because they are the ones defined in OAuth2
                    # (https://datatracker.ietf.org/doc/html/rfc6749#section-5.2)
                    # Other 4xx errors might have different requirements e.g.
                    # "407 Proxy auth required" would need a key including http headers.
                and not(  # Exclude Device Flow whose retry is expected and regulated
                    isinstance(kwargs.get("data"), dict)
                    and kwargs["data"].get("grant_type") == DEVICE_AUTH_GRANT
                    )
                and RetryAfterParser.FIELD_NAME_LOWER not in set(  # Otherwise leave it to the Retry-After decorator
                    h.lower() for h in _get_headers(result))
                else 0,
            )(self.post)

        self.get = IndividualCache(  # Typically those discovery GETs
            mapping=self._expiring_mapping,
            key_maker=lambda func, args, kwargs: "GET {} hash={} 2xx".format(
                args[0],  # It is the url, sometimes containing inline params
                self._hash(kwargs.get("params", "")),
                ),
            expires_in=lambda result=None, **ignored:
                3600*24 if 200 <= result.status_code < 300 else 0,
            )(self.get)

    def _throttled(self, call, context_of, parser):
        def wrapper(*args, **kwargs):
            context = context_of(args[0]) if args else None
            if context:
                blocked = self._throttle_gate.check(context)
                if blocked:
                    scope, remaining = blocked
                    logger.debug(
                        "Request skipped by throttle scope=%s remaining=%.0fs",
                        scope, remaining)
                    return _ThrottledResponse(scope, remaining)
            response = call(*args, **kwargs)
            if context and not getattr(response, "_msal_throttle_synthetic", False):
                classified = _classify_throttle(
                    response, context, parser, self._throttle_gate._now())
                if classified:
                    scope, deadline = classified
                    # Stamp the absolute upstream release time so replays from
                    # the per-request cache keep the original deadline.
                    try:
                        response._msal_throttle_deadline = deadline
                    except AttributeError:  # A slotted/exotic response object
                        pass
                    self._throttle_gate.record_until(context, scope, deadline)
            return response
        return wrapper

    def throttle_diagnostics(self):
        """Return only the allow-listed throttle categories and release times.

        The returned structure contains no tenant identifiers, urls, client
        ids, or raw response headers.
        """
        return self._throttle_gate.diagnostics()
