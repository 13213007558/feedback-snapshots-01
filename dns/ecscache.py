# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2026
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""EDNS Client Subnet (ECS) aware answer caching.

A security-aware resolver that forwards ECS (RFC 7871) cannot treat a
``(name, type, class)`` tuple as a complete cache key: an answer produced
for one client subnet must never be served to a client in a different
subnet.  This module implements that separation as a self-contained
adapter around :mod:`dns.resolver`.

The reuse decision is based on the *scope* of the cached answer, not on
the raw ECS option bytes.  Each cached entry is stored against the
canonical client subnet (the masked source network) it was obtained for,
and is reused only when a new client's masked address falls inside the
network the upstream resolver said the answer covers:

* an answer whose response scope is zero, or whose response carries no
  ECS option at all, is treated as globally reusable (RFC 7871 7.3);
* otherwise the response scope is clamped so it never reaches beyond the
  network that was actually queried, and entries are matched by longest
  covered prefix;
* malformed ECS options are never cached, so a corrupt upstream message
  cannot poison a different client's lookup;
* only the masked network is ever retained; full client addresses are
  never stored anywhere in the cache.
"""

import enum
import ipaddress
import threading
import time
from typing import Callable, NamedTuple

import dns.edns
import dns.exception
import dns.inet
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver

__all__ = [
    "ECSError",
    "ECSMalformed",
    "ECSEvent",
    "WiderScopePolicy",
    "NoECSPolicy",
    "ECSData",
    "ParsedECS",
    "client_subnet",
    "extract_ecs",
    "make_ecs_option",
    "parse_ecs_wire",
    "ECSCache",
    "ECSResolver",
]

#: Address family number used in the ECS wire format for IPv4 (RFC 7871).
FAMILY_IPV4 = 1
#: Address family number used in the ECS wire format for IPv6 (RFC 7871).
FAMILY_IPV6 = 2

_FAMILY_BITS: dict[int, int] = {FAMILY_IPV4: 32, FAMILY_IPV6: 128}
_FAMILY_AF: dict[int, int] = {
    FAMILY_IPV4: dns.inet.AF_INET,
    FAMILY_IPV6: dns.inet.AF_INET6,
}
_AF_FAMILY: dict[int, int] = {value: key for key, value in _FAMILY_AF.items()}


class ECSError(dns.exception.DNSException):
    """Base class of ECS cache errors."""


class ECSMalformed(ECSError):
    """An ECS option could not be parsed or failed validation.

    The offending message is treated fail-closed: it is never cached and
    never used to widen the reach of another client's answer.
    """


class ECSEvent(enum.Enum):
    """Observability events emitted while processing ECS options."""

    #: A query option had non-zero host bits; they were masked off.
    QUERY_HOST_BITS_MASKED = "query-host-bits-masked"
    #: A response option had non-zero host bits; they were masked off.
    RESPONSE_HOST_BITS_MASKED = "response-host-bits-masked"
    #: The response scope was zero, so the answer is globally reusable.
    SCOPE_ZERO_GLOBAL = "scope-zero-global"
    #: The response had no ECS option; per RFC 7871 the answer is global.
    NO_ECS_GLOBAL = "no-ecs-global"
    #: The response scope was wider than the queried source prefix and
    #: was clamped to it.
    SCOPE_CLAMPED = "scope-clamped"
    #: A malformed ECS option was encountered; the answer was not cached.
    MALFORMED_NOT_CACHED = "malformed-not-cached"


class WiderScopePolicy(enum.Enum):
    """What to do when the response scope exceeds the requested prefix."""

    #: Clamp the reuse scope to the queried source prefix.  This is the
    #: secure default: an upstream can never make an answer reach clients
    #: outside the network that was actually asked about.
    CLAMP = "clamp"
    #: Trust the upstream's scope without clamping.  This permits wider
    #: reuse exactly as the server asserted, and should only be used with
    #: trusted resolvers.
    TRUST = "trust"


class NoECSPolicy(enum.Enum):
    """How to cache a response that carries no ECS option."""

    #: Treat the answer as global, as permitted by RFC 7871 section 7.3.
    GLOBAL = "global"
    #: Do not cache the answer at all; every client triggers a fresh query.
    NEVER_CACHE = "never-cache"


class ECSData(NamedTuple):
    """A masked network safe to use as cache identity.

    :ivar family: The ECS address family number (1 for IPv4, 2 for IPv6).
    :ivar prefixlen: The prefix length of *network*.
    :ivar network: The masked network; host bits are always zero, so this
        never carries a full client address.
    """

    family: int
    prefixlen: int
    network: ipaddress.IPv4Network | ipaddress.IPv6Network

    def wire_key(self) -> tuple[int, int, bytes]:
        """Return a stable hashable key derived from the masked network."""
        return (self.family, self.prefixlen, self.network.network_address.packed)


class ParsedECS(NamedTuple):
    """The fully decoded contents of one ECS option.

    Both the source prefix (significant in queries) and the scope prefix
    (significant in responses) are preserved; callers decide which one
    governs their decision instead of having one overwrite the other.

    :ivar family: The ECS address family number (1 for IPv4, 2 for IPv6).
    :ivar srclen: The source prefix length.
    :ivar scopelen: The scope prefix length.
    :ivar network: The source network, with all host bits masked off.
    """

    family: int
    srclen: int
    scopelen: int
    network: ipaddress.IPv4Network | ipaddress.IPv6Network

    def source(self) -> ECSData:
        """Return the source network as :class:`ECSData`."""
        return ECSData(self.family, self.srclen, self.network)


def _family_for_rdtype(rdtype: dns.rdatatype.RdataType) -> int | None:
    """Return the ECS family implied by *rdtype*, or ``None`` if neither."""
    if rdtype == dns.rdatatype.A:
        return FAMILY_IPV4
    if rdtype == dns.rdatatype.AAAA:
        return FAMILY_IPV6
    return None


def client_subnet(
    address: str, prefixlen: int | None = None
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Build the masked client network for *address*.

    Host bits beyond *prefixlen* are discarded, so the returned network
    never contains a full client address.  *prefixlen* defaults to 24 for
    IPv4 and 56 for IPv6, matching :class:`dns.edns.ECSOption`.

    :raises ValueError: if *address* is not a valid IP address or
        *prefixlen* is out of range.
    """
    ip = ipaddress.ip_address(address)
    if prefixlen is None:
        prefixlen = 24 if ip.version == 4 else 56
    return ipaddress.ip_network(f"{address}/{prefixlen}", strict=False)


def _check_prefixlen(family: int, prefixlen: int) -> None:
    if not isinstance(prefixlen, int) or isinstance(prefixlen, bool):
        raise ECSMalformed("ECS prefix length is not an integer")
    if not 0 <= prefixlen <= _FAMILY_BITS[family]:
        raise ECSMalformed("ECS prefix length exceeds address family width")


def parse_ecs_wire(data: bytes) -> ParsedECS:
    """Parse and validate a raw ECS option body straight off the wire.

    The body is the ECS option value following the EDNS option code and
    length: ``FAMILY (2 octets), SOURCE PREFIX-LENGTH, SCOPE PREFIX-LENGTH,
    ADDRESS...``.  Host bits beyond the source prefix are masked off rather
    than trusted.

    :raises ECSMalformed: if the option is structurally invalid.
    """
    if len(data) < 4:
        raise ECSMalformed("ECS option shorter than the fixed header")
    family = int.from_bytes(data[0:2], "big")
    if family not in _FAMILY_BITS:
        raise ECSMalformed(f"unsupported ECS address family {family}")
    srclen = data[2]
    scopelen = data[3]
    _check_prefixlen(family, srclen)
    _check_prefixlen(family, scopelen)
    expected_len = (srclen + 7) // 8
    raw = data[4:]
    if len(raw) != expected_len:
        raise ECSMalformed(f"ECS address is {len(raw)} bytes, expected {expected_len}")
    bits = _FAMILY_BITS[family]
    padded = raw + b"\x00" * (bits // 8 - len(raw))
    if family == FAMILY_IPV4:
        text = dns.ipv4.inet_ntoa(padded)
    else:
        text = dns.ipv6.inet_ntoa(padded)
    # strict=False is what discards the invalid trailing host bits.
    network = ipaddress.ip_network(f"{text}/{srclen}", strict=False)
    return ParsedECS(family, srclen, scopelen, network)


def _option_wire(option: dns.edns.Option) -> bytes:
    if isinstance(option, dns.edns.ECSOption):
        wire = option.to_wire()
        assert wire is not None
        return wire
    if isinstance(option, dns.edns.GenericOption):
        return option.data
    raise ECSMalformed("ECS option has an unexpected option class")


def _has_host_bits(data: bytes) -> bool:
    """Whether the significant last address byte has non-zero padding."""
    if len(data) < 5:
        return False
    trailing = data[2] % 8
    return bool(trailing and data[-1] & (0xFF >> trailing))


def extract_ecs(
    message: dns.message.Message,
    on_event: Callable[[ECSEvent], None] | None = None,
    *,
    host_bits_event: ECSEvent = ECSEvent.QUERY_HOST_BITS_MASKED,
) -> ParsedECS | None:
    """Extract and validate the ECS option from *message*.

    Returns the parsed :class:`ParsedECS`, or ``None`` if the message has
    no ECS option.  A malformed option raises :class:`ECSMalformed` rather
    than being silently ignored.

    :param on_event: Optional callback receiving :class:`ECSEvent`
        values, e.g. for auditing masked host bits.
    :param host_bits_event: The event emitted when non-zero padding bits
        are found; responses pass
        :data:`ECSEvent.RESPONSE_HOST_BITS_MASKED`.
    """
    ecs_options = [
        option for option in message.options if option.otype == dns.edns.OptionType.ECS
    ]
    if not ecs_options:
        return None
    if len(ecs_options) > 1:
        raise ECSMalformed("message contains multiple ECS options")
    data = _option_wire(ecs_options[0])
    if _has_host_bits(data) and on_event is not None:
        on_event(host_bits_event)
    return parse_ecs_wire(data)


def make_ecs_option(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> dns.edns.ECSOption:
    """Build a query ECS option for *network*.

    The network address and prefix length are taken from *network*, so
    host bits can never leak into the forwarded option.  The scope length
    is zero as required for a query.
    """
    return dns.edns.ECSOption(str(network.network_address), network.prefixlen, 0)


class _Entry(NamedTuple):
    answer: dns.resolver.Answer


QKey = tuple[dns.name.Name, dns.rdatatype.RdataType, dns.rdataclass.RdataClass]


class ECSCache:
    """A thread-safe cache keyed by query tuple and client subnet.

    Entries are indexed by ``(name, rdtype, rdclass)`` and, within that,
    by the network the answer is reusable for.  A lookup returns the most
    specific (longest prefix) network that covers the client, falling
    back to a globally reusable entry if one exists.  Nothing here ever
    stores a full client address: every network is masked.
    """

    def __init__(
        self,
        wider_scope_policy: WiderScopePolicy = WiderScopePolicy.CLAMP,
        no_ecs_policy: NoECSPolicy = NoECSPolicy.GLOBAL,
        cleaning_interval: float = 300.0,
    ) -> None:
        self.wider_scope_policy = wider_scope_policy
        self.no_ecs_policy = no_ecs_policy
        self.cleaning_interval = cleaning_interval
        self.next_cleaning = time.time() + cleaning_interval
        self.lock = threading.Lock()
        self.statistics = dns.resolver.CacheStatistics()
        self.data: dict[QKey, dict[tuple[int, int, bytes], _Entry]] = {}

    def reset_statistics(self) -> None:
        """Reset hit/miss statistics."""
        with self.lock:
            self.statistics.reset()

    def hits(self) -> int:
        """How many lookups have hit an in-scope cached entry."""
        with self.lock:
            return self.statistics.hits

    def misses(self) -> int:
        """How many lookups found no reusable entry."""
        with self.lock:
            return self.statistics.misses

    def get_statistics_snapshot(self) -> dns.resolver.CacheStatistics:
        """Return a consistent hit/miss snapshot."""
        with self.lock:
            return self.statistics.clone()

    def _maybe_clean(self) -> None:
        now = time.time()
        if self.next_cleaning > now:
            return
        empty = []
        for qkey, entries in self.data.items():
            expired = [
                key for key, entry in entries.items() if entry.answer.expiration <= now
            ]
            for key in expired:
                del entries[key]
            if not entries:
                empty.append(qkey)
        for qkey in empty:
            del self.data[qkey]
        self.next_cleaning = time.time() + self.cleaning_interval

    def get(self, qkey: QKey, client: ECSData) -> dns.resolver.Answer | None:
        """Return a cached answer reusable by *client*, or ``None``.

        An entry matches only when the client's masked address is inside
        the entry's scope network.  Among matching entries the longest
        scope prefix wins; a zero-length (global) entry matches everyone.
        """
        with self.lock:
            self._maybe_clean()
            entries = self.data.get(qkey)
            if not entries:
                self.statistics.misses += 1
                return None
            now = time.time()
            best: tuple[int, int, bytes] | None = None
            best_prefix = -1
            client_address = client.network.network_address
            for key, entry in entries.items():
                if entry.answer.expiration <= now:
                    continue
                family, prefixlen, packed = key
                if family != client.family:
                    continue
                network = ipaddress.ip_network(
                    (ipaddress.ip_address(packed), prefixlen), strict=False
                )
                if client_address in network and prefixlen > best_prefix:
                    best = key
                    best_prefix = prefixlen
            if best is None:
                self.statistics.misses += 1
                return None
            self.statistics.hits += 1
            return entries[best].answer

    def _global_network(self, family: int) -> ECSData:
        if family == FAMILY_IPV4:
            network = ipaddress.ip_network("0.0.0.0/0")
        else:
            network = ipaddress.ip_network("::/0")
        return ECSData(family, 0, network)

    def put(
        self,
        qkey: QKey,
        client: ECSData,
        answer: dns.resolver.Answer,
        response: dns.message.Message,
        on_event: Callable[[ECSEvent], None] | None = None,
    ) -> bool:
        """Cache *answer* according to the response's real ECS scope.

        Returns ``True`` if the answer was stored, ``False`` otherwise (a
        malformed option, a family mismatch, or a
        :data:`NoECSPolicy.NEVER_CACHE` answer).  The stored network is
        derived from the response scope, never from raw option bytes, so
        reuse follows what the upstream asserted.
        """
        try:
            response_ecs = extract_ecs(
                response,
                on_event,
                host_bits_event=ECSEvent.RESPONSE_HOST_BITS_MASKED,
            )
        except ECSMalformed:
            if on_event is not None:
                on_event(ECSEvent.MALFORMED_NOT_CACHED)
            return False

        if response_ecs is None:
            if self.no_ecs_policy is NoECSPolicy.NEVER_CACHE:
                return False
            if on_event is not None:
                on_event(ECSEvent.NO_ECS_GLOBAL)
            scope_data = self._global_network(client.family)
        else:
            if response_ecs.family != client.family:
                if on_event is not None:
                    on_event(ECSEvent.MALFORMED_NOT_CACHED)
                return False
            if response_ecs.scopelen == 0:
                if on_event is not None:
                    on_event(ECSEvent.SCOPE_ZERO_GLOBAL)
                scope_data = self._global_network(client.family)
            else:
                scope_len = response_ecs.scopelen
                # A shorter scope prefix than the source we asked about
                # means the upstream claims the answer is reusable across a
                # wider block than we queried.  That is the dangerous case,
                # so by default clamp reuse back to the queried prefix.
                if (
                    scope_len < client.prefixlen
                    and self.wider_scope_policy is WiderScopePolicy.CLAMP
                ):
                    if on_event is not None:
                        on_event(ECSEvent.SCOPE_CLAMPED)
                    scope_len = client.prefixlen
                # Reuse follows the address the upstream actually carried,
                # masked to the effective scope length.  This is a semantic
                # scope network, never the raw option bytes or a full client
                # address.
                scope_network = ipaddress.ip_network(
                    (response_ecs.network.network_address, scope_len),
                    strict=False,
                )
                scope_data = ECSData(client.family, scope_len, scope_network)

        entry = _Entry(answer)
        with self.lock:
            self._maybe_clean()
            self.data.setdefault(qkey, {})[scope_data.wire_key()] = entry
        return True

    def flush(self, qkey: QKey | None = None) -> None:
        """Flush one query tuple's entries, or the whole cache."""
        with self.lock:
            if qkey is None:
                self.data = {}
                self.next_cleaning = time.time() + self.cleaning_interval
            else:
                self.data.pop(qkey, None)


def _default_upstream(
    resolver: dns.resolver.Resolver,
    qname: dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
    rdclass: dns.rdataclass.RdataClass,
    ecs_option: dns.edns.ECSOption,
) -> dns.resolver.Answer:
    """Attach *ecs_option* to a resolver query without altering it."""
    previous = resolver.ednsoptions
    resolver.use_edns(edns=0, options=[ecs_option])
    try:
        return resolver.resolve(qname, rdtype, rdclass)
    finally:
        resolver.use_edns(edns=resolver.edns, options=previous)


class ECSResolver:
    """Resolve names through an upstream resolver with ECS-aware caching.

    :param upstream: Callable performing the actual resolution.  It must
        accept ``(qname, rdtype, rdclass, ecs_option=...)`` and return a
        :class:`~dns.resolver.Answer`.  Defaults to a plain
        :class:`dns.resolver.Resolver` whose queries carry the ECS option.
    :param cache: The :class:`ECSCache` to use, or ``None`` to create one.
    :param on_event: Optional :class:`ECSEvent` audit callback.
    """

    def __init__(
        self,
        upstream: Callable[..., dns.resolver.Answer] | None = None,
        cache: ECSCache | None = None,
        on_event: Callable[[ECSEvent], None] | None = None,
    ) -> None:
        self._resolver: dns.resolver.Resolver | None = None
        if upstream is None:
            self._resolver = dns.resolver.Resolver()
            bound_resolver = self._resolver

            def upstream(
                qname: dns.name.Name,
                rdtype: dns.rdatatype.RdataType,
                rdclass: dns.rdataclass.RdataClass,
                ecs_option: dns.edns.ECSOption,
            ) -> dns.resolver.Answer:
                return _default_upstream(
                    bound_resolver, qname, rdtype, rdclass, ecs_option
                )

        self.upstream = upstream
        self.cache = cache if cache is not None else ECSCache()
        self.on_event = on_event

    def _emit(self, event: ECSEvent) -> None:
        if self.on_event is not None:
            self.on_event(event)

    def resolve(
        self,
        qname: dns.name.Name | str,
        rdtype: dns.rdatatype.RdataType | str = dns.rdatatype.A,
        rdclass: dns.rdataclass.RdataClass | str = dns.rdataclass.IN,
        client_address: str | None = None,
        source_prefix: int | None = None,
    ) -> dns.resolver.Answer:
        """Resolve *qname* for the subnet implied by *client_address*.

        The client address is masked to *source_prefix* immediately and is
        never retained.  A lookup returns an in-scope cached answer when
        one exists; otherwise the upstream is queried with a correctly
        formed ECS option and the response is cached according to its
        scope.

        :raises ECSError: if *client_address* is missing or its address
            family does not match *rdtype*.
        """
        if isinstance(qname, str):
            qname = dns.name.from_text(qname)
        rdtype = dns.rdatatype.RdataType.make(rdtype)
        rdclass = dns.rdataclass.RdataClass.make(rdclass)

        if client_address is None:
            raise ECSError("client_address is required for ECS resolution")
        network = client_subnet(client_address, source_prefix)
        family = _AF_FAMILY[dns.inet.af_for_address(str(network.network_address))]
        implied_family = _family_for_rdtype(rdtype)
        if implied_family is not None and implied_family != family:
            raise ECSError("ECS address family does not match the query address family")
        client = ECSData(family, network.prefixlen, network)
        qkey = (qname, rdtype, rdclass)

        cached = self.cache.get(qkey, client)
        if cached is not None:
            return cached

        ecs_option = make_ecs_option(network)
        answer = self.upstream(qname, rdtype, rdclass, ecs_option=ecs_option)
        self.cache.put(qkey, client, answer, answer.response, self._emit)
        return answer
