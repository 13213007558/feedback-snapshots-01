# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""DNS Cookies (RFC 7873) policy support.

DNS Cookies are a lightweight UDP anti-spoofing mechanism.  They are
*not* a replacement for DNSSEC: a Cookie only shows that a response was
sent by an endpoint which saw the client's Cookie (and, when a server
Cookie is present, that the server has bound its Cookie to this client).
It does not authenticate the DNS data in the response, and it does not
protect against an on-path attacker.

This module is opt-in.  A resolver does not use Cookies unless a
:class:`CookiePolicy` is explicitly assigned to
:attr:`dns.resolver.BaseResolver.cookie_policy` or passed to
:class:`dns.nameserver.Do53Nameserver`.  The default policy is
:attr:`CookieMode.OPPORTUNISTIC`: missing server Cookies are accepted,
but such responses are marked as not bound and are not put in the
resolver's answer cache.
"""

import dataclasses
import enum
import hashlib
import hmac
import os
import threading
from typing import Any

import dns.edns
import dns.exception
import dns.inet
import dns.message


class CookieError(dns.exception.DNSException):
    """A DNS Cookie policy requirement was not met."""


class CookieMode(enum.Enum):
    """How a :class:`CookiePolicy` treats responses.

    ``OFF``
        Do not use DNS Cookies.  This is equivalent to not configuring a
        policy at all.

    ``OPPORTUNISTIC``
        Send a client Cookie.  Use a server Cookie when the server returns
        one.  Accept a response without a server Cookie, but mark it as
        unbound and do not cache it.

    ``REQUIRED``
        Send a client Cookie and require every accepted response to echo the
        client Cookie and contain a server Cookie.  Responses without a
        server Cookie are rejected with :exc:`CookieError`.
    """

    OFF = "off"
    OPPORTUNISTIC = "opportunistic"
    REQUIRED = "required"


def _canonical_address(address: str | None) -> str | None:
    """Return a stable textual form of an address for endpoint keys.

    IPv6 scoped addresses are kept, but the address portion is
    canonicalized.  Hostnames (which should not normally be used for a
    Do53 endpoint) are lowercased.
    """

    if address is None:
        return None
    scope = ""
    host = address
    if "%" in address:
        host, scope = address.split("%", 1)
        scope = "%" + scope
    try:
        return dns.inet.canonicalize(host) + scope
    except ValueError:
        return address.lower()


@dataclasses.dataclass(frozen=True)
class Endpoint:
    """The network endpoint a Cookie is bound to.

    A Cookie is never shared between endpoints.  The endpoint includes the
    destination address and port, the transport kind, and the source address
    (when the caller selected one).  The source port is deliberately not
    included: server Cookies are bound to the client address, not to an
    ephemeral source port.
    """

    address: str
    port: int
    transport: str = "Do53"
    source_address: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "address", _canonical_address(self.address))
        object.__setattr__(self, "port", int(self.port))
        object.__setattr__(self, "transport", str(self.transport).lower())
        object.__setattr__(
            self, "source_address", _canonical_address(self.source_address)
        )


@dataclasses.dataclass(frozen=True)
class CookieValidation:
    """The result of applying a Cookie policy to one response.

    ``bound`` is true only when the response echoed the client Cookie and
    contained a server Cookie.  A bound response is eligible for the
    resolver's answer cache.  This flag says nothing about whether the DNS
    data itself is trustworthy; that requires DNSSEC or a protected
    transport.

    ``client_cookie`` is the Cookie the client actually sent, and
    ``server_cookie`` is the server Cookie from the response, if any.
    ``rcode`` is the response's rcode.  ``response_cookie`` is the full
    COOKIE option from the response, including when the response was
    accepted unbound.
    """

    #: The client Cookie sent in the query.
    client_cookie: bytes
    #: The server Cookie from the response, or ``None``.
    server_cookie: bytes | None
    #: ``True`` only if the response completed endpoint binding.
    bound: bool
    #: The response rcode.
    rcode: int
    #: The COOKIE option from the response, or ``None``.
    response_cookie: dns.edns.CookieOption | None = None
    #: ``True`` if the response was sent with EDNS, so that a Cookie
    #: exchange was possible at all.
    used_edns: bool = False

    @property
    def data_authenticated(self) -> bool:
        """DNS Cookies do not authenticate DNS data; this is always false."""

        return False


class CookiePolicy:
    """An explicit DNS Cookie policy and per-endpoint Cookie store.

    The client Cookie is derived from *secret* and the endpoint, so the same
    endpoint receives a stable client Cookie while different upstreams (or
    the same upstream reached through a different source address) receive
    different client Cookies.  Server Cookies returned by an upstream are
    stored only for that endpoint.

    :param mode: The policy mode.  The default is
        :attr:`CookieMode.OPPORTUNISTIC`.
    :param secret: A secret used to derive client Cookies.  If ``None``, a
        random secret is generated.  It must be at least 16 bytes.  If
        several processes need to share Cookies (which is rarely desirable),
        supply the same secret.
    :param max_entries: The maximum number of endpoints whose server Cookies
        are remembered.  The least recently stored entry is discarded when
        the limit is exceeded.  The default is 4096.
    """

    def __init__(
        self,
        mode: CookieMode | str = CookieMode.OPPORTUNISTIC,
        secret: bytes | None = None,
        max_entries: int = 4096,
    ) -> None:
        self.mode = CookieMode(mode)
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self._max_entries = max_entries
        if secret is None:
            secret = os.urandom(32)
        if len(secret) < 16:
            raise ValueError("cookie secret must be at least 16 bytes")
        self._secret = bytes(secret)
        self._server_cookies: dict[Endpoint, bytes] = {}
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        """Is Cookie processing enabled?"""

        return self.mode is not CookieMode.OFF

    def endpoint(
        self,
        address: str,
        port: int,
        source: str | None = None,
        transport: str = "Do53",
    ) -> Endpoint:
        """Make an endpoint key for a query.

        :param address: The destination address.
        :param port: The destination port.
        :param source: The selected source address, or ``None``.
        :param transport: The transport name, normally ``"Do53"``.
        :rtype: :py:class:`Endpoint`
        """

        return Endpoint(address, port, transport, source)

    def client_cookie(self, endpoint: Endpoint) -> bytes:
        """Return the client Cookie for *endpoint*.

        The value is deterministic for a given policy secret and endpoint,
        and deliberately differs between endpoints.

        :rtype: bytes
        """

        material = (
            f"{endpoint.transport}\0{endpoint.address}\0{endpoint.port}\0"
            f"{endpoint.source_address or ''}"
        ).encode()
        return hmac.new(self._secret, material, hashlib.sha256).digest()[:8]

    def server_cookie(self, endpoint: Endpoint) -> bytes:
        """Return the stored server Cookie for *endpoint*, or ``b""``."""

        with self._lock:
            return self._server_cookies.get(endpoint, b"")

    def set_server_cookie(self, endpoint: Endpoint, server_cookie: bytes) -> None:
        """Store a server Cookie for *endpoint*.

        An empty *server_cookie* removes the stored value.  A non-empty value
        must be between 8 and 32 bytes, as required by RFC 7873.
        """

        server_cookie = bytes(server_cookie)
        if server_cookie and not 8 <= len(server_cookie) <= 32:
            raise ValueError("server cookie must be empty or between 8 and 32 bytes")
        with self._lock:
            self._server_cookies.pop(endpoint, None)
            if server_cookie:
                self._server_cookies[endpoint] = server_cookie
                if len(self._server_cookies) > self._max_entries:
                    oldest = next(iter(self._server_cookies))
                    del self._server_cookies[oldest]

    def clear(self, endpoint: Endpoint | None = None) -> None:
        """Forget server Cookies for *endpoint*, or for all endpoints."""

        with self._lock:
            if endpoint is None:
                self._server_cookies.clear()
            else:
                self._server_cookies.pop(endpoint, None)

    def request_cookie(self, endpoint: Endpoint) -> dns.edns.CookieOption:
        """Make the COOKIE option to put in a query for *endpoint*."""

        return dns.edns.CookieOption(
            self.client_cookie(endpoint), self.server_cookie(endpoint)
        )

    def validate_response(
        self,
        response: dns.message.Message,
        endpoint: Endpoint,
        client_cookie: bytes,
    ) -> CookieValidation:
        """Validate the Cookie in *response* for *endpoint*.

        A response with no Cookie, or with only a client Cookie, is accepted
        in ``OPPORTUNISTIC`` mode but marked unbound.  In ``REQUIRED`` mode it
        raises :exc:`CookieError`.  A response whose Cookie does not echo
        *client_cookie* always raises :exc:`CookieError`.

        A valid server Cookie is stored for *endpoint* immediately, which is
        how server-side rotation is followed.  The stored value is replaced
        with the newest server Cookie returned by that endpoint.

        :rtype: :py:class:`CookieValidation`
        """

        cookie = get_cookie_option(response)
        if cookie is None:
            return self._unbound(response, client_cookie, "response has no COOKIE")
        if not hmac.compare_digest(cookie.client, client_cookie):
            raise CookieError("response COOKIE did not echo the client cookie")
        if len(cookie.server) == 0:
            return self._unbound(
                response,
                client_cookie,
                "response COOKIE has no server cookie",
                cookie,
            )
        self.set_server_cookie(endpoint, cookie.server)
        return CookieValidation(
            client_cookie=bytes(client_cookie),
            server_cookie=bytes(cookie.server),
            bound=True,
            rcode=response.rcode(),
            response_cookie=cookie,
            used_edns=response.edns >= 0,
        )

    def _unbound(
        self,
        response: dns.message.Message,
        client_cookie: bytes,
        reason: str,
        cookie: dns.edns.CookieOption | None = None,
    ) -> CookieValidation:
        if self.mode is CookieMode.REQUIRED:
            raise CookieError(f"{reason}; a server cookie is required")
        return CookieValidation(
            client_cookie=bytes(client_cookie),
            server_cookie=None,
            bound=False,
            rcode=response.rcode(),
            response_cookie=cookie,
            used_edns=response.edns >= 0,
        )


def validation_for_message(
    message: dns.message.Message,
) -> CookieValidation | None:
    """Return the Cookie validation attached to *message*, if any.

    Responses processed by a :class:`dns.nameserver.Do53Nameserver` with a
    Cookie policy have their validation result stored on the message.  This
    helper is the stable accessor; the underlying attribute is
    :attr:`dns.message.Message.cookie_validation`.
    """

    return message.cookie_validation


def validate_udp_response(
    query: dns.message.Message,
    response: dns.message.Message,
    policy: CookiePolicy,
    address: str,
    port: int,
    source: str | None = None,
) -> CookieValidation:
    """Validate one UDP response and attach the result to it.

    The endpoint is built from *address*, *port*, and *source*.  The client
    Cookie is taken from *query*, so this function can be called after the
    query has been sent.  It stores a rotated server Cookie for the endpoint
    and sets :attr:`dns.message.Message.cookie_validation` on *response*.

    The caller is responsible for adding the Cookie to the query (for
    example with :func:`set_cookie_option` and
    :meth:`CookiePolicy.request_cookie`), for retrying on BADCOOKIE when the
    validation is bound, and for restoring the request's EDNS state.  Most
    callers should use :py:class:`dns.nameserver.Do53Nameserver`, which does
    all of this.

    :rtype: :py:class:`CookieValidation`
    """

    endpoint = policy.endpoint(address, port, source)
    sent = get_cookie_option(query)
    if sent is None:
        raise CookieError("query has no COOKIE option")
    validation = policy.validate_response(response, endpoint, sent.client)
    response.cookie_validation = validation
    return validation


def get_cookie_option(message: dns.message.Message) -> dns.edns.CookieOption | None:
    """Return the COOKIE option in *message*, or ``None``.

    Multiple COOKIE options, or a malformed COOKIE option, raise
    :exc:`CookieError`.  RFC 7873 permits at most one COOKIE option.
    """

    cookies: list[dns.edns.CookieOption] = []
    for option in message.options:
        if option.otype != dns.edns.OptionType.COOKIE:
            continue
        if isinstance(option, dns.edns.CookieOption):
            cookies.append(option)
            continue
        raw = option.to_wire()
        assert raw is not None
        if len(raw) < 8:
            raise CookieError("malformed COOKIE option")
        try:
            cookies.append(dns.edns.CookieOption(raw[:8], raw[8:]))
        except ValueError as e:
            raise CookieError("malformed COOKIE option") from e
    if len(cookies) > 1:
        raise CookieError("multiple COOKIE options")
    if not cookies:
        return None
    return cookies[0]


def set_cookie_option(
    message: dns.message.Message, cookie: dns.edns.CookieOption
) -> None:
    """Replace any COOKIE option in *message* with *cookie*.

    Other EDNS options, the EDNS flags, the payload size, request payload,
    and padding configuration are preserved.  If EDNS was not enabled, EDNS0
    is enabled with the default payload, since a COOKIE option requires EDNS.
    """

    options = [
        option
        for option in message.options
        if option.otype != dns.edns.OptionType.COOKIE
    ]
    options.append(cookie)
    if message.edns < 0:
        message.use_edns(
            0,
            0,
            dns.message.DEFAULT_EDNS_PAYLOAD,
            options=options,
        )
    else:
        message.use_edns(
            message.edns,
            message.ednsflags,
            message.payload,
            request_payload=message.request_payload,
            options=options,
            pad=message.pad,
        )


def save_edns_state(message: dns.message.Message) -> tuple[Any, int, int]:
    """Save the EDNS state that :func:`set_cookie_option` may replace."""

    return (message.opt, message.request_payload, message.pad)


def restore_edns_state(
    message: dns.message.Message, state: tuple[Any, int, int]
) -> None:
    """Restore EDNS state saved by :func:`save_edns_state`."""

    message.opt, message.request_payload, message.pad = state
