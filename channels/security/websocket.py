from urllib.parse import urlparse

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http.request import is_same_domain
from django.urls.exceptions import Resolver404
from django.urls.resolvers import RegexPattern, RoutePattern

from ..generic.websocket import AsyncWebsocketConsumer


class OriginValidator:
    """
    Validates that the incoming connection has an Origin header that
    is in an allowed list.

    When ``allow_no_origin`` is ``True``, connections that do not send an
    ``Origin`` header at all (for example, a non-browser command line client)
    are accepted. Connections that do send an ``Origin`` are still validated
    against ``allowed_origins``.
    """

    def __init__(self, application, allowed_origins, allow_no_origin=False):
        self.application = application
        self.allowed_origins = allowed_origins
        self.allow_no_origin = allow_no_origin

    async def __call__(self, scope, receive, send):
        # Make sure the scope is of type websocket
        if scope["type"] != "websocket":
            raise ValueError(
                "You cannot use OriginValidator on a non-WebSocket connection"
            )
        # Extract the Origin header
        parsed_origin = None
        for header_name, header_value in scope.get("headers", []):
            if header_name == b"origin":
                try:
                    # Set ResultParse
                    parsed_origin = urlparse(header_value.decode("latin1"))
                except UnicodeDecodeError:
                    pass
        # Check to see if the origin header is valid
        if self.valid_origin(parsed_origin):
            # Pass control to the application
            return await self.application(scope, receive, send)
        else:
            # Deny the connection
            denier = WebsocketDenier()
            return await denier(scope, receive, send)

    def valid_origin(self, parsed_origin):
        """
        Checks parsed origin is None.

        Pass control to the validate_origin function.

        Returns ``True`` if validation function was successful, ``False`` otherwise.
        """
        # A connection without an Origin header is allowed when the rule
        # explicitly opts in (e.g. non-browser command line collectors)
        # or when every origin is allowed via the "*" wildcard.
        if parsed_origin is None:
            return self.allow_no_origin or "*" in self.allowed_origins
        return self.validate_origin(parsed_origin)

    def validate_origin(self, parsed_origin):
        """
        Validate the given origin for this site.

        Check than the origin looks valid and matches the origin pattern in
        specified list ``allowed_origins``. Any pattern begins with a scheme.
        After the scheme there must be a domain. Any domain beginning with a
        period corresponds to the domain and all its subdomains (for example,
        ``http://.example.com``). After the domain there must be a port,
        but it can be omitted. ``*`` matches anything and anything
        else must match exactly.

        Note. This function assumes that the given origin has a schema, domain
        and port, but port is optional.

        Returns ``True`` for a valid host, ``False`` otherwise.
        """
        return any(
            pattern == "*" or self.match_allowed_origin(parsed_origin, pattern)
            for pattern in self.allowed_origins
        )

    def match_allowed_origin(self, parsed_origin, pattern):
        """
        Returns ``True`` if the origin is either an exact match or a match
        to the wildcard pattern. Compares scheme, domain, port of origin and pattern.

        Any pattern can be begins with a scheme. After the scheme must be a domain,
        or just domain without scheme.
        Any domain beginning with a period corresponds to the domain and all
        its subdomains (for example, ``.example.com`` ``example.com``
        and any subdomain). Also with scheme (for example, ``http://.example.com``
        ``http://example.com``). After the domain there must be a port,
        but it can be omitted.

        Note. This function assumes that the given origin is either None, a
        schema-domain-port string, or just a domain string
        """
        if parsed_origin is None:
            return False

        # Get ResultParse object
        parsed_pattern = urlparse(pattern.lower())
        if parsed_origin.hostname is None:
            return False
        if not parsed_pattern.scheme:
            pattern_hostname = urlparse("//" + pattern).hostname or pattern
            return is_same_domain(parsed_origin.hostname, pattern_hostname)
        # Get origin.port or default ports for origin or None
        origin_port = self.get_origin_port(parsed_origin)
        # Get pattern.port or default ports for pattern or None
        pattern_port = self.get_origin_port(parsed_pattern)
        # Compares hostname, scheme, ports of pattern and origin
        if (
            parsed_pattern.scheme == parsed_origin.scheme
            and origin_port == pattern_port
            and is_same_domain(parsed_origin.hostname, parsed_pattern.hostname)
        ):
            return True
        return False

    def get_origin_port(self, origin):
        """
        Returns the origin.port or port for this schema by default.
        Otherwise, it returns None.
        """
        if origin.port is not None:
            # Return origin.port
            return origin.port
        # if origin.port doesn`t exists
        if origin.scheme == "http" or origin.scheme == "ws":
            # Default port return for http, ws
            return 80
        elif origin.scheme == "https" or origin.scheme == "wss":
            # Default port return for https, wss
            return 443
        else:
            return None


def AllowedHostsOriginValidator(application):
    """
    Factory function which returns an OriginValidator configured to use
    settings.ALLOWED_HOSTS.
    """
    allowed_hosts = settings.ALLOWED_HOSTS
    if settings.DEBUG and not allowed_hosts:
        allowed_hosts = ["localhost", "127.0.0.1", "[::1]"]
    return OriginValidator(application, allowed_hosts)


class OriginRule:
    """
    Origin policy for one or more WebSocket routes.

    ``allowed_origins`` uses the same format as :class:`OriginValidator`.
    When ``allow_no_origin`` is ``True``, connections without an ``Origin``
    header (typical of non-browser command line collectors) are accepted,
    while any origin that is present is still checked against
    ``allowed_origins``.
    """

    def __init__(self, allowed_origins, allow_no_origin=False):
        self.allowed_origins = allowed_origins
        self.allow_no_origin = allow_no_origin

    def __call__(self, *args, **kwargs):
        # OriginRule is used as a route callback marker; only
        # OriginValidatorRouter consumes it, so it is never invoked directly.
        raise RuntimeError(
            "An OriginRule cannot serve requests on its own. Wrap it in an "
            "OriginValidatorRouter."
        )

    @classmethod
    def allowed_hosts(cls, allow_no_origin=False):
        """
        Build a rule backed by the Django ``ALLOWED_HOSTS`` setting, mirroring
        :func:`AllowedHostsOriginValidator` (local hosts are also allowed when
        ``DEBUG`` is enabled and no hosts are configured).
        """
        allowed_hosts = settings.ALLOWED_HOSTS
        if settings.DEBUG and not allowed_hosts:
            allowed_hosts = ["localhost", "127.0.0.1", "[::1]"]
        return cls(allowed_hosts, allow_no_origin=allow_no_origin)


class OriginValidatorRouter:
    """
    ASGI middleware that enforces a distinct :class:`OriginValidator` per
    mount point rather than a single global origin policy.

    ``application`` is the inner WebSocket application shared by every route.
    ``routes`` is a list of Django ``path()``/``re_path()`` entries whose
    callback is an :class:`OriginRule`. The first matching route wins, and
    ``default_rule`` covers any path without an explicit route, so every
    connection is still validated.

    Route patterns are rewritten to match a path prefix (the same treatment
    :class:`~channels.routing.URLRouter` gives nested routers), so
    ``path("collector/", rule)`` also matches ``/collector/anything/else``.

    A rejected connection is handed to :class:`WebsocketDenier` during the
    handshake; the inner application (and therefore its consumer) is never
    initialized for that connection.
    """

    #: Allows nesting inside a URLRouter, which rewrites the parent pattern.
    _path_routing = True

    def __init__(self, application, routes, default_rule):
        self.application = application
        self.routes = routes
        self.default_validator = self._build_validator(default_rule)
        self.route_validators = []
        for route in self.routes:
            if not isinstance(route.callback, OriginRule):
                raise ImproperlyConfigured(
                    "%s: every OriginValidatorRouter route must be a path()/"
                    "re_path() entry whose callback is an OriginRule." % (route,)
                )
            pattern = route.pattern
            if isinstance(pattern, RegexPattern):
                arg = pattern._regex
            elif isinstance(pattern, RoutePattern):
                arg = pattern._route
            else:
                raise ValueError(f"Unsupported pattern type: {type(pattern)}")
            route.pattern = pattern.__class__(arg, pattern.name, is_endpoint=False)
            self.route_validators.append(
                (route, self._build_validator(route.callback))
            )

    def _build_validator(self, rule):
        if not isinstance(rule, OriginRule):
            raise ImproperlyConfigured(
                "OriginValidatorRouter expects OriginRule instances, got %r"
                % (rule,)
            )
        return OriginValidator(
            self.application,
            rule.allowed_origins,
            allow_no_origin=rule.allow_no_origin,
        )

    async def __call__(self, scope, receive, send):
        if scope["type"] != "websocket":
            raise ValueError(
                "You cannot use OriginValidatorRouter on a non-WebSocket connection"
            )
        path = scope.get("path_remaining", scope.get("path", None))
        if path is None:
            raise ValueError("No 'path' key in connection scope, cannot route URLs")
        # Remove leading / to match Django's handling
        path = path.lstrip("/")
        for route, validator in self.route_validators:
            try:
                if route.pattern.match(path):
                    return await validator(scope, receive, send)
            except Resolver404:
                pass
        return await self.default_validator(scope, receive, send)


class WebsocketDenier(AsyncWebsocketConsumer):
    """
    Simple application which denies all requests to it.
    """

    async def connect(self):
        await self.close()
