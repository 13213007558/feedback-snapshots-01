"""DNS Response Policy Zone (RPZ) interpretation.

This module implements a small, *offline* interpreter for the RPZ
mechanisms that are needed to pre-rehearse which policy rules in a set of
policy zones actually take effect for a given name lookup or a given set of
response addresses.  It never starts a name server, never sends queries, and
does not mark the synthetic policy answers it describes as authoritative
data of the original zone.

The supported feature set is deliberately limited:

* triggers: QNAME triggers (exact owners and the DNS-style leftmost-label
  wildcard) and response address triggers (``rpz-ip`` IPv4 and
  ``rpz-ip6`` IPv6 prefixes);
* actions, expressed through CNAME action RRs: ``NXDOMAIN`` (also via the
  legacy root-target CNAME form), ``NODATA``, and ``PASSTHRU``;
* rule selection: longest-match specificity within a policy zone, then the
  configured order of the policy zones, taken as trusted configuration.

Everything outside this scope is retained rather than guessed.  NSDNAME and
NSIP triggers, wildcard address triggers, QNAME-redirect/local-data style
actions (including the legacy DROP form), and unknown action names are
reported as pending.  Pending items are matched against every probe and
surfaced in each evaluation, so a rule whose semantics are not interpreted
here can never silently look like a miss.
"""

import enum
import ipaddress
from dataclasses import dataclass
from typing import Any

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rcode
import dns.rrset
import dns.zone

RPZ_IP = dns.name.from_text("rpz-ip.")
RPZ_IP6 = dns.name.from_text("rpz-ip6.")
RPZ_NSDNAME = dns.name.from_text("rpz-nsdname.")
RPZ_NSIP = dns.name.from_text("rpz-nsip.")

RPZ_NXDOMAIN = "rpz-nxdomain"
RPZ_NODATA = "rpz-nodata"
RPZ_PASSTHRU = "rpz-passthru"
RPZ_DROP = "rpz-drop"


class RPZError(dns.exception.DNSException):
    """An error was encountered while loading or evaluating policy zones."""


class TriggerType(enum.StrEnum):
    """The kind of RPZ trigger owner attached to a rule."""

    QNAME = "qname"
    RPZ_IP = "rpz-ip"
    RPZ_IP6 = "rpz-ip6"
    RPZ_NSDNAME = "rpz-nsdname"
    RPZ_NSIP = "rpz-nsip"


class PendingReason(enum.StrEnum):
    """Why a rule or a matched trigger could not be enforced."""

    UNSUPPORTED_TRIGGER = "unsupported-trigger"
    MALFORMED_ADDRESS_TRIGGER = "malformed-address-trigger"
    WILDCARD_ADDRESS = "wildcard-address-trigger"
    UNSUPPORTED_ACTION_RRTYPE = "unsupported-action-rrtype"
    UNKNOWN_ACTION = "unknown-action"


class Action(enum.StrEnum):
    """The policy actions this interpreter knows how to apply."""

    NXDOMAIN = "nxdomain"
    NODATA = "nodata"
    PASSTHRU = "passthru"


@dataclass(frozen=True)
class Rule:
    """One enforceable policy rule, built from a single action RR.

    :param zone_name: Name of the policy zone containing the rule.
    :param owner: Absolute trigger owner name.
    :param trigger: Parsed trigger type.
    :param action: Decoded policy action.
    :param source_rr: Presentation-format source RR, for traceability.
    :param network: Trigger network for address triggers, else ``None``.
    :param wildcard: Whether the QNAME trigger is a wildcard owner.
    :param sequence: Load order of the rule within its zone; used as a
        deterministic tie-breaker.
    """

    zone_name: str
    owner: dns.name.Name
    trigger: TriggerType
    action: Action
    source_rr: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    wildcard: bool = False
    sequence: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "zone": self.zone_name,
            "owner": self.owner.to_text(),
            "trigger": str(self.trigger),
            "action": str(self.action),
            "network": str(self.network) if self.network is not None else None,
            "wildcard": self.wildcard,
            "source_rr": self.source_rr,
        }


@dataclass(frozen=True)
class PendingRule:
    """A rule whose trigger or action this interpreter does not apply.

    Pending rules are never enforced; they are matched against probes so
    callers can see exactly which zone content still needs out-of-scope
    processing.

    :param network: Parsed trigger network for address triggers when the
        owner itself was valid, else ``None``.
    :param wildcard: Whether the owner is a wildcard QNAME trigger.
    """

    zone_name: str
    owner: dns.name.Name
    trigger: TriggerType
    reason: PendingReason
    detail: str
    source_rr: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    wildcard: bool = False

    def matches_qname(self, qname: dns.name.Name) -> bool:
        if self.trigger != TriggerType.QNAME:
            return False
        if self.wildcard:
            parent = dns.name.Name(self.owner.labels[1:])
            return qname != parent and qname.is_subdomain(parent)
        return qname == self.owner

    def matches_address(
        self, address: ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> bool:
        if self.network is None:
            return False
        if isinstance(address, ipaddress.IPv4Address) != isinstance(
            self.network, ipaddress.IPv4Network
        ):
            return False
        return address in self.network

    def to_dict(self) -> dict[str, Any]:
        return {
            "zone": self.zone_name,
            "owner": self.owner.to_text(),
            "trigger": str(self.trigger),
            "reason": str(self.reason),
            "detail": self.detail,
            "source_rr": self.source_rr,
        }


@dataclass(frozen=True)
class Match:
    """The enforced outcome of one evaluation."""

    rule: Rule
    synthetic: bool
    rcode: dns.rcode.Rcode | None

    def to_dict(self) -> dict[str, Any]:
        result = self.rule.to_dict()
        result["synthetic"] = self.synthetic
        result["authoritative"] = False
        result["rcode"] = self.rcode
        return result


@dataclass(frozen=True)
class OverriddenRule:
    """A rule that matched but was not applied because another won."""

    rule: Rule
    by: str

    def to_dict(self) -> dict[str, Any]:
        result = self.rule.to_dict()
        result["overridden_by"] = self.by
        return result


@dataclass(frozen=True)
class Evaluation:
    """The full offline interpretation result for one probe.

    :param qname: The probed QNAME, or ``None`` for an address-only probe.
    :param rdtype: The query RR type as text, or ``None``.
    :param addresses: Response addresses exercised by the probe.
    :param applied: The enforced match, or ``None`` when nothing enforceable
        fired.
    :param overridden: Matches that lost to :attr:`applied` or to an earlier
        winning zone.
    :param pending_matched: Pending rules whose triggers matched this probe.
    :param pending_all: All pending rules present in the configured zones.
    """

    qname: dns.name.Name | None
    rdtype: str | None
    addresses: tuple[str, ...]
    applied: Match | None
    overridden: tuple[OverriddenRule, ...]
    pending_matched: tuple[PendingRule, ...]
    pending_all: tuple[PendingRule, ...]

    def action(self) -> Action | None:
        if self.applied is None:
            return None
        return self.applied.rule.action

    def to_dict(self) -> dict[str, Any]:
        return {
            "qname": self.qname.to_text() if self.qname is not None else None,
            "rdtype": self.rdtype,
            "addresses": list(self.addresses),
            "action": str(self.action()) if self.action() is not None else None,
            "applied": self.applied.to_dict() if self.applied is not None else None,
            "overridden": [item.to_dict() for item in self.overridden],
            "pending_matched": [item.to_dict() for item in self.pending_matched],
            "pending_all": [item.to_dict() for item in self.pending_all],
        }


def _source_rr(owner: dns.name.Name, rdata: Any, ttl: int) -> str:
    return (
        f"{owner.to_text()} {ttl} IN "
        f"{dns.rdatatype.to_text(rdata.rdtype)} {rdata.to_text()}"
    )


def _decode_action(rdata: Any) -> tuple[Action | None, PendingReason | None, str]:
    if rdata.rdtype != dns.rdatatype.CNAME:
        return (
            None,
            PendingReason.UNSUPPORTED_ACTION_RRTYPE,
            "only CNAME action records are supported, got "
            f"{dns.rdatatype.to_text(rdata.rdtype)}",
        )
    target = rdata.target
    if target == dns.name.root:
        return Action.NXDOMAIN, None, ""
    label = target.labels[0].decode("ascii").lower()
    if label == RPZ_NXDOMAIN:
        return Action.NXDOMAIN, None, ""
    if label == RPZ_NODATA:
        return Action.NODATA, None, ""
    if label == RPZ_PASSTHRU:
        return Action.PASSTHRU, None, ""
    if label == RPZ_DROP:
        return (
            None,
            PendingReason.UNKNOWN_ACTION,
            "rpz-drop requires TCP-only/DROP semantics which are not implemented",
        )
    return (
        None,
        PendingReason.UNKNOWN_ACTION,
        f"unknown policy action target {target.to_text()!r}",
    )


def _parse_v4_trigger(
    labels: tuple[bytes, ...],
) -> tuple[ipaddress.IPv4Network | None, PendingReason | None, str]:
    try:
        prefix = int(labels[0])
    except ValueError:
        return (
            None,
            PendingReason.MALFORMED_ADDRESS_TRIGGER,
            "prefix length is not a number",
        )
    if not 0 <= prefix <= 32:
        return (
            None,
            PendingReason.MALFORMED_ADDRESS_TRIGGER,
            f"IPv4 prefix length {prefix} is outside 0..32",
        )
    # RPZ owners are reversed high-order octets with arbitrary truncation:
    # trailing zero octets may be omitted, so up to four labels may follow
    # the prefix length.
    octet_labels = labels[1:]
    if len(octet_labels) > 4:
        return (
            None,
            PendingReason.MALFORMED_ADDRESS_TRIGGER,
            f"an IPv4 trigger holds at most 4 octet labels, got {len(octet_labels)}",
        )
    octets: list[int] = []
    for label in octet_labels:
        try:
            octet = int(label)
        except ValueError:
            return (
                None,
                PendingReason.MALFORMED_ADDRESS_TRIGGER,
                f"non-numeric IPv4 label {label!r}",
            )
        if not 0 <= octet <= 255:
            return (
                None,
                PendingReason.MALFORMED_ADDRESS_TRIGGER,
                f"IPv4 octet {octet} is outside 0..255",
            )
        octets.append(octet)
    # Labels are the high-order octets in reverse order; omitted trailing
    # octets (and host bits inside the final octet) default to zero.
    octets.reverse()
    octets.extend([0] * (4 - len(octets)))
    try:
        network = ipaddress.IPv4Network(
            (ipaddress.IPv4Address(bytes(octets)), prefix), strict=False
        )
    except ValueError as error:
        return None, PendingReason.MALFORMED_ADDRESS_TRIGGER, str(error)
    return network, None, ""


def _parse_v6_trigger(
    labels: tuple[bytes, ...],
) -> tuple[ipaddress.IPv6Network | None, PendingReason | None, str]:
    try:
        prefix = int(labels[0])
    except ValueError:
        return (
            None,
            PendingReason.MALFORMED_ADDRESS_TRIGGER,
            "prefix length is not a number",
        )
    if not 0 <= prefix <= 128:
        return (
            None,
            PendingReason.MALFORMED_ADDRESS_TRIGGER,
            f"IPv6 prefix length {prefix} is outside 0..128",
        )
    # Reversed high-order nibbles, truncated arbitrarily at 32 labels.
    nibble_labels = labels[1:]
    if len(nibble_labels) > 32:
        return (
            None,
            PendingReason.MALFORMED_ADDRESS_TRIGGER,
            f"an IPv6 trigger holds at most 32 nibble labels, got {len(nibble_labels)}",
        )
    nibbles: list[str] = []
    for label in nibble_labels:
        if len(label) != 1 or label not in b"0123456789abcdefABCDEF":
            return (
                None,
                PendingReason.MALFORMED_ADDRESS_TRIGGER,
                f"non-hex-nibble IPv6 label {label!r}",
            )
        nibbles.append(label.decode("ascii"))
    # Labels are the high-order nibbles in reverse order; omitted trailing
    # nibbles default to zero.
    nibbles.reverse()
    hexdigits = "".join(nibbles).ljust(32, "0")
    try:
        network = ipaddress.IPv6Network(
            (ipaddress.IPv6Address(bytes.fromhex(hexdigits)), prefix), strict=False
        )
    except ValueError as error:
        return None, PendingReason.MALFORMED_ADDRESS_TRIGGER, str(error)
    return network, None, ""


class PolicyZone:
    """A parsed RPZ policy zone and its rule indexes.

    :param name: Stable name used in reports and trusted configuration.
    :param zone: A loaded :class:`dns.zone.Zone`; names are read in their
        absolute form.
    """

    def __init__(self, name: str, zone: dns.zone.Zone):
        self.name = name
        self.origin = zone.origin
        self._exact: dict[dns.name.Name, list[Rule]] = {}
        self._wildcards: list[Rule] = []
        self._v4: list[Rule] = []
        self._v6: list[Rule] = []
        self.pending: list[PendingRule] = []
        self._load(zone)

    def _policy_name(self, owner: dns.name.Name) -> dns.name.Name:
        # A QNAME trigger owner is "<policy-data-name>.<zone-origin>"; the
        # name that must match a probe is the part before the zone origin.
        # Address/NS trigger suffixes are not QNAME data and never reach this
        # helper.  The apex itself has no data name and is skipped by the
        # SOA/NS metadata filter in _load().
        if self.origin is not None and owner.is_subdomain(self.origin):
            policy = owner.relativize(self.origin)
        else:
            policy = owner
        if not policy.is_absolute():
            policy = dns.name.Name(policy.labels + (b"",))
        return policy

    @classmethod
    def from_file(
        cls,
        name: str,
        filename: str,
        origin: dns.name.Name | str | None = None,
        rdclass: dns.rdataclass.RdataClass = dns.rdataclass.IN,
    ) -> "PolicyZone":
        """Load a policy zone from a master file.

        The zone is loaded without relativization so that all trigger owners
        stay absolute.
        """
        zone = dns.zone.from_file(
            filename, origin=origin, rdclass=rdclass, relativize=False
        )
        return cls(name, zone)

    @classmethod
    def from_text(
        cls,
        name: str,
        text: str,
        origin: dns.name.Name | str | None = None,
        rdclass: dns.rdataclass.RdataClass = dns.rdataclass.IN,
        filename: str | None = None,
    ) -> "PolicyZone":
        """Load a policy zone from master-file-format text."""
        zone = dns.zone.from_text(
            text,
            origin=origin,
            rdclass=rdclass,
            relativize=False,
            filename=filename,
        )
        return cls(name, zone)

    def _load(self, zone: dns.zone.Zone) -> None:
        sequence = 0
        for owner, rdataset in zone.iterate_rdatasets():
            if (
                self.origin is not None
                and owner == self.origin
                and rdataset.rdtype in (dns.rdatatype.SOA, dns.rdatatype.NS)
            ):
                # Zone metadata, not policy triggers.
                continue
            trigger, suffix_labels = self._classify_owner(owner, self.origin)
            if trigger in (TriggerType.RPZ_NSDNAME, TriggerType.RPZ_NSIP):
                for rdata in rdataset:
                    self.pending.append(
                        PendingRule(
                            self.name,
                            owner,
                            trigger,
                            PendingReason.UNSUPPORTED_TRIGGER,
                            f"{trigger} triggers are outside the supported scope",
                            _source_rr(owner, rdata, rdataset.ttl),
                        )
                    )
                continue
            if trigger in (TriggerType.RPZ_IP, TriggerType.RPZ_IP6):
                sequence = self._load_address_owner(
                    owner, rdataset, trigger, suffix_labels, sequence
                )
                continue
            sequence = self._load_qname_owner(owner, rdataset, sequence)

    def _load_address_owner(
        self,
        owner: dns.name.Name,
        rdataset: dns.rdataset.Rdataset,
        trigger: TriggerType,
        suffix_labels: tuple[bytes, ...],
        sequence: int,
    ) -> int:
        # Parse the network first so that even pending rules can be matched
        # against probe addresses for reporting.  Wildcard address owners
        # carry one leading '*' label that is not part of the address text.
        address_labels = suffix_labels[1:] if owner.is_wild() else suffix_labels
        parser = (
            _parse_v4_trigger if trigger == TriggerType.RPZ_IP else _parse_v6_trigger
        )
        network, reason, detail = parser(address_labels)
        if reason is not None:
            for rdata in rdataset:
                self.pending.append(
                    PendingRule(
                        self.name,
                        owner,
                        trigger,
                        reason,
                        detail,
                        _source_rr(owner, rdata, rdataset.ttl),
                    )
                )
            return sequence
        if owner.is_wild():
            for rdata in rdataset:
                self.pending.append(
                    PendingRule(
                        self.name,
                        owner,
                        trigger,
                        PendingReason.WILDCARD_ADDRESS,
                        "wildcard address triggers are not interpreted",
                        _source_rr(owner, rdata, rdataset.ttl),
                        network=network,
                    )
                )
            return sequence
        for rdata in rdataset:
            source = _source_rr(owner, rdata, rdataset.ttl)
            action, action_reason, action_detail = _decode_action(rdata)
            if action is None:
                assert action_reason is not None
                self.pending.append(
                    PendingRule(
                        self.name,
                        owner,
                        trigger,
                        action_reason,
                        action_detail,
                        source,
                        network=network,
                    )
                )
                continue
            rule = Rule(
                self.name,
                owner,
                trigger,
                action,
                source,
                network=network,
                sequence=sequence,
            )
            sequence += 1
            if trigger == TriggerType.RPZ_IP:
                self._v4.append(rule)
            else:
                self._v6.append(rule)
        return sequence

    def _load_qname_owner(
        self,
        owner: dns.name.Name,
        rdataset: dns.rdataset.Rdataset,
        sequence: int,
    ) -> int:
        is_wildcard = owner.is_wild()
        policy_owner = self._policy_name(owner)
        for rdata in rdataset:
            source = _source_rr(owner, rdata, rdataset.ttl)
            action, reason, detail = _decode_action(rdata)
            if action is None:
                assert reason is not None
                self.pending.append(
                    PendingRule(
                        self.name,
                        policy_owner,
                        TriggerType.QNAME,
                        reason,
                        detail,
                        source,
                        wildcard=is_wildcard,
                    )
                )
                continue
            rule = Rule(
                self.name,
                policy_owner,
                TriggerType.QNAME,
                action,
                source,
                wildcard=is_wildcard,
                sequence=sequence,
            )
            sequence += 1
            if is_wildcard:
                self._wildcards.append(rule)
            else:
                self._exact.setdefault(policy_owner, []).append(rule)
        return sequence

    @staticmethod
    def _classify_owner(
        owner: dns.name.Name, origin: dns.name.Name | None
    ) -> tuple[TriggerType, tuple[bytes, ...]]:
        # RPZ policy owners end in one of the reserved trigger suffixes,
        # which themselves sit under the policy zone origin.  Compare label
        # sequences rather than text suffixes so that ordinary data names
        # sharing an incidental textual ending stay QNAME triggers.
        relative = owner.relativize(origin) if origin is not None else owner

        def ends_with(suffix: dns.name.Name) -> bool:
            # The suffix constants are absolute names; their final root label
            # is absent from the relativized owner.
            suffix_labels = suffix.labels[:-1]
            return relative.labels[-len(suffix_labels) :] == suffix_labels

        def prefix_of(suffix: dns.name.Name) -> tuple[bytes, ...]:
            suffix_labels = suffix.labels[:-1]
            return relative.labels[: -len(suffix_labels)]

        if ends_with(RPZ_NSIP):
            return TriggerType.RPZ_NSIP, prefix_of(RPZ_NSIP)
        if ends_with(RPZ_NSDNAME):
            return TriggerType.RPZ_NSDNAME, prefix_of(RPZ_NSDNAME)
        if ends_with(RPZ_IP6):
            return TriggerType.RPZ_IP6, prefix_of(RPZ_IP6)
        if ends_with(RPZ_IP):
            return TriggerType.RPZ_IP, prefix_of(RPZ_IP)
        return TriggerType.QNAME, relative.labels

    def match_qname(self, qname: dns.name.Name) -> list[Rule]:
        """Return enforceable QNAME rules matching *qname*, best first."""
        candidates = list(self._exact.get(qname, ()))
        for rule in self._wildcards:
            parent = dns.name.Name(rule.owner.labels[1:])
            if qname != parent and qname.is_subdomain(parent):
                candidates.append(rule)
        candidates.sort(
            key=lambda rule: self._qname_specificity(rule, qname), reverse=True
        )
        return candidates

    @staticmethod
    def _qname_specificity(rule: Rule, qname: dns.name.Name) -> tuple[int, int]:
        if rule.wildcard:
            return (len(rule.owner) - 1, -rule.sequence)
        return (len(qname), -rule.sequence)

    def match_address(
        self, address: ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> list[Rule]:
        """Return enforceable address rules containing *address*, best first."""
        rules = self._v4 if isinstance(address, ipaddress.IPv4Address) else self._v6
        matches = [
            rule
            for rule in rules
            if rule.network is not None and address in rule.network
        ]
        matches.sort(
            key=lambda rule: (
                rule.network.prefixlen if rule.network is not None else -1,
                -rule.sequence,
            ),
            reverse=True,
        )
        return matches

    def match_pending(
        self,
        qname: dns.name.Name | None,
        addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    ) -> list[PendingRule]:
        """Return pending rules whose triggers match the given probe."""
        matches: list[PendingRule] = []
        for item in self.pending:
            if qname is not None and item.matches_qname(qname):
                matches.append(item)
            elif any(item.matches_address(address) for address in addresses):
                matches.append(item)
        return matches


def _as_name(value: dns.name.Name | str) -> dns.name.Name:
    if isinstance(value, dns.name.Name):
        return value
    return dns.name.from_text(value)


def _as_address(
    value: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(value)
    except ValueError as error:
        raise RPZError(f"invalid IP address {value!r}: {error}") from error


def _action_rcode(action: Action) -> dns.rcode.Rcode | None:
    if action == Action.PASSTHRU:
        return None
    if action == Action.NXDOMAIN:
        return dns.rcode.NXDOMAIN
    return dns.rcode.NOERROR


def synthetic_response(
    qname: dns.name.Name | str,
    action: Action,
    rdtype: dns.rdatatype.RdataType | str = dns.rdatatype.A,
    rdclass: dns.rdataclass.RdataClass = dns.rdataclass.IN,
) -> dns.message.Message:
    """Build the synthetic answer a resolver would return for *action*.

    The message is generated solely from policy data; the AA bit is never
    set, so this response cannot be confused with authoritative data of the
    original zone.  ``PASSTHRU`` has no synthesized answer and raises
    :class:`RPZError`.
    """
    if action == Action.PASSTHRU:
        raise RPZError("PASSTHRU does not synthesize a response")
    rcode = _action_rcode(action)
    assert rcode is not None
    name = _as_name(qname)
    message = dns.message.Message()
    message.flags = dns.flags.QR | dns.flags.RD
    message.set_rcode(rcode)
    message.question.append(
        dns.rrset.RRset(name, rdclass, dns.rdatatype.RdataType.make(rdtype))
    )
    return message


class PolicyEngine:
    """Evaluate probes against an ordered list of policy zones.

    The order of *zones* is trusted configuration: the first zone has the
    highest policy priority.  Within one zone the most specific matching
    trigger wins (exact QNAME over wildcard, longest address prefix over
    shorter ones).
    """

    def __init__(self, zones: list[PolicyZone]):
        if not zones:
            raise RPZError("at least one policy zone is required")
        self.zones = list(zones)

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "PolicyEngine":
        """Build an engine from a trusted configuration mapping.

        The mapping has the shape ``{"zones": [{"name": str, "file": str,
        "origin": str?}, ...]}`` where zone order fixes policy priority.
        """
        entries = config.get("zones")
        if not isinstance(entries, list) or not entries:
            raise RPZError("config requires a non-empty 'zones' list")
        zones: list[PolicyZone] = []
        for entry in entries:
            if (
                not isinstance(entry, dict)
                or "name" not in entry
                or "file" not in entry
            ):
                raise RPZError("each zone entry needs string 'name' and 'file' fields")
            zones.append(
                PolicyZone.from_file(
                    entry["name"], entry["file"], origin=entry.get("origin")
                )
            )
        return cls(zones)

    @property
    def zone_names(self) -> tuple[str, ...]:
        return tuple(zone.name for zone in self.zones)

    def pending_rules(self) -> tuple[PendingRule, ...]:
        items: list[PendingRule] = []
        for zone in self.zones:
            items.extend(zone.pending)
        return tuple(items)

    def evaluate(
        self,
        qname: dns.name.Name | str | None = None,
        rdtype: dns.rdatatype.RdataType | str | None = None,
        addresses: list[str] | tuple[str, ...] | None = None,
    ) -> Evaluation:
        """Interpret one offline probe.

        A probe with *qname* exercises QNAME triggers; *addresses* exercise
        response address triggers.  Both may be supplied together, matching
        how a resolver first applies QNAME policy and then policy on the
        addresses in the answer.
        """
        if qname is None and not addresses:
            raise RPZError("a probe needs a qname and/or at least one address")
        probe_name = _as_name(qname) if qname is not None else None
        probe_rdtype = (
            dns.rdatatype.to_text(dns.rdatatype.RdataType.make(rdtype))
            if rdtype is not None
            else None
        )
        probe_addresses = tuple(addresses if addresses is not None else ())
        parsed_addresses = [_as_address(value) for value in probe_addresses]

        best: Rule | None = None
        overridden: list[OverriddenRule] = []
        pending_matched: list[PendingRule] = []
        pending_all: list[PendingRule] = []

        for zone in self.zones:
            pending_all.extend(zone.pending)
            pending_matched.extend(zone.match_pending(probe_name, parsed_addresses))
            zone_rules: list[Rule] = []
            if probe_name is not None:
                zone_rules.extend(zone.match_qname(probe_name))
            for address in parsed_addresses:
                zone_rules.extend(zone.match_address(address))
            if not zone_rules:
                continue
            # A rule can match several probe addresses at once; keep the first
            # occurrence so candidates and overrides are reported once.
            zone_rules = list(dict.fromkeys(zone_rules))
            zone_best = self._most_specific(zone_rules)
            for rule in zone_rules:
                if rule == zone_best:
                    continue
                overridden.append(
                    OverriddenRule(rule, f"more specific rule in zone {zone.name!r}")
                )
            if best is None:
                # First matching zone wins by trusted zone priority.  We keep
                # scanning the remaining zones so every lower-priority
                # candidate is still reported as overridden rather than lost.
                best = zone_best
            else:
                overridden.append(
                    OverriddenRule(
                        zone_best, f"higher-priority zone {best.zone_name!r}"
                    )
                )

        applied = None
        if best is not None:
            applied = Match(
                best,
                best.action != Action.PASSTHRU,
                _action_rcode(best.action),
            )
        return Evaluation(
            probe_name,
            probe_rdtype,
            probe_addresses,
            applied,
            tuple(overridden),
            tuple(pending_matched),
            tuple(pending_all),
        )

    @staticmethod
    def _most_specific(rules: list[Rule]) -> Rule:
        # QNAME policy is evaluated before response-address policy, so any
        # matching QNAME rule outranks an address rule regardless of how the
        # label count and prefix length happen to compare numerically.
        # Within a trigger class, longest specificity wins and load order is
        # the deterministic tie-breaker.
        def key(rule: Rule) -> tuple[int, int, int]:
            if rule.network is not None:
                return (0, rule.network.prefixlen, -rule.sequence)
            specificity = len(rule.owner) - 1 if rule.wildcard else len(rule.owner)
            return (1, specificity, -rule.sequence)

        return max(rules, key=key)

    def run(self, probes: list[dict[str, Any]]) -> dict[str, Any]:
        """Evaluate a list of probe mappings and return a JSON-ready report."""
        results = [
            self.evaluate(
                probe.get("qname"),
                probe.get("rdtype"),
                probe.get("addresses"),
            ).to_dict()
            for probe in probes
        ]
        return {
            "zone_priority": list(self.zone_names),
            "supported_actions": [str(action) for action in Action],
            "supported_triggers": [
                str(TriggerType.QNAME),
                str(TriggerType.RPZ_IP),
                str(TriggerType.RPZ_IP6),
            ],
            "pending_rules": [item.to_dict() for item in self.pending_rules()],
            "evaluations": results,
        }
