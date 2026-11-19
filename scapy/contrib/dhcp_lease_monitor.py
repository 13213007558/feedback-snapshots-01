# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information

"""
Offline DHCP lease evidence analyzer.

This module inspects captured BOOTP/DHCP traffic together with trusted
capture-point metadata and derives which lease bindings are provable
from the observed evidence alone.  It is deliberately limited:

- it is offline only: it never sends packets and never scans a network,
- trust comes exclusively from the monitor configuration; self-reported
  packet fields (the server identifier option, the Option 82 payload)
  are treated as claims, never as proof of ingress or identity,
- packet loss is never inferred as an attack or as a successful
  binding; half-observed exchanges are reported as inconclusive,
- lease lifetimes are evaluated against a fixed clock provided in the
  configuration, not against the wall clock.
"""

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import str2mac

_DHCP_DISCOVER = 1
_DHCP_OFFER = 2
_DHCP_REQUEST = 3
_DHCP_ACK = 5
_DHCP_NAK = 6

_SERVER_MESSAGES = frozenset((_DHCP_OFFER, _DHCP_ACK, _DHCP_NAK))

_ZERO_IP = "0.0.0.0"


class DhcpLeaseMonitorConfig(object):
    """Trusted capture-point and server configuration.

    :param server_ports: capture ports on which DHCP server messages
        (Offer/ACK/NAK) are allowed to appear.
    :param relay_ports: capture ports on which relayed messages
        (giaddr set and/or Option 82 present) are allowed to appear.
    :param trusted_servers: IP addresses of legitimate DHCP servers.
        This is the only source of server trust; the server identifier
        option inside packets is never used as configuration.
    :param known_relays: allowed giaddr values of legitimate relays.
    :param now: fixed clock value used to evaluate lease lifetimes.
    """

    def __init__(self, server_ports, relay_ports, trusted_servers,
                 known_relays=(), now=0.0):
        self.server_ports = frozenset(server_ports)
        self.relay_ports = frozenset(relay_ports)
        self.trusted_servers = frozenset(trusted_servers)
        self.known_relays = frozenset(known_relays)
        self.now = float(now)


class CapturedFrame(object):
    """One captured packet plus trusted capture-point metadata."""

    def __init__(self, data, port, timestamp):
        self.data = data
        self.port = port
        self.timestamp = float(timestamp)


class DhcpAlert(object):
    """A suspicious condition with the evidence positions behind it."""

    def __init__(self, kind, reason, positions):
        self.kind = kind
        self.reason = reason
        self.positions = tuple(positions)

    def __repr__(self):
        return "<DhcpAlert %s packets=%s>" % (self.kind,
                                              list(self.positions))


class DhcpLeaseBinding(object):
    """A lease binding that is provable from the observed evidence."""

    def __init__(self, client, mac, address, server, xid, giaddr, phase,
                 lease_time, bound_at, positions):
        self.client = client
        self.mac = mac
        self.address = address
        self.server = server
        self.xid = xid
        self.giaddr = giaddr
        self.phase = phase
        self.lease_time = lease_time
        self.bound_at = bound_at
        self.expires_at = bound_at + lease_time
        self.positions = tuple(positions)

    def remaining(self, now):
        return self.expires_at - now

    def __repr__(self):
        return "<DhcpLeaseBinding %s -> %s via %s (%s)>" % (
            self.client, self.address, self.server, self.phase)


class DhcpLeaseReport(object):
    """Result of an analysis pass."""

    def __init__(self, bindings, alerts, incomplete, evaluated_at):
        self.bindings = bindings
        self.alerts = alerts
        self.incomplete = incomplete
        self.evaluated_at = evaluated_at

    def render(self):
        lines = ["provable bindings: %d" % len(self.bindings)]
        for binding in self.bindings:
            lines.append(
                "  %s (%s) -> %s via %s, %s phase, xid 0x%08x, "
                "giaddr %s, packets %s, lease %ds, remaining %.0fs" % (
                    binding.client, binding.mac, binding.address,
                    binding.server, binding.phase, binding.xid,
                    binding.giaddr, list(binding.positions),
                    binding.lease_time,
                    binding.remaining(self.evaluated_at)))
        lines.append("alerts: %d" % len(self.alerts))
        for alert in self.alerts:
            lines.append("  [%s] %s (packets %s)" % (
                alert.kind, alert.reason, list(alert.positions)))
        lines.append("inconclusive exchanges: %d" % len(self.incomplete))
        for note in self.incomplete:
            lines.append("  %s" % note)
        return "\n".join(lines)


class _DhcpMessage(object):
    __slots__ = ("pos", "timestamp", "port", "mtype", "xid", "mac",
                 "client_key", "client_desc", "giaddr", "ciaddr", "yiaddr",
                 "ip_src", "server_id", "requested_addr", "lease_time",
                 "opt82")


class DhcpLeaseEvidenceAnalyzer(object):
    """Correlates captured DHCP messages into provable lease evidence."""

    def __init__(self, config):
        self.config = config

    def analyze(self, frames):
        alerts = []
        messages = []
        for pos, frame in enumerate(frames):
            if not isinstance(frame, CapturedFrame):
                frame = CapturedFrame(*frame)
            msg = self._parse(frame, pos, alerts)
            if msg is not None:
                messages.append(msg)
        bindings, incomplete = self._correlate(messages, alerts)
        return DhcpLeaseReport(bindings, alerts, incomplete,
                               self.config.now)

    def _parse(self, frame, pos, alerts):
        cfg = self.config
        try:
            pkt = Ether(frame.data)
        except Exception as exc:
            alerts.append(DhcpAlert(
                "undecodable-frame",
                "frame %d cannot be decoded: %s" % (pos, exc), (pos,)))
            return None
        bootp = pkt.getlayer(BOOTP)
        dhcp = pkt.getlayer(DHCP)
        if bootp is None or dhcp is None:
            return None
        udp = pkt.getlayer(UDP)
        if udp is not None and 67 not in (udp.sport, udp.dport) \
                and 68 not in (udp.sport, udp.dport):
            return None
        opts = {}
        for opt in dhcp.options:
            if isinstance(opt, tuple) and len(opt) == 2:
                opts[opt[0]] = opt[1]
        mtype = opts.get("message-type")
        if mtype is None:
            return None
        mac = str2mac(bytes(bootp.chaddr)[:6])
        client_id = opts.get("client_id")
        if isinstance(client_id, str):
            client_id = client_id.encode("utf8", "replace")
        if client_id and len(client_id) == 7 and client_id[0] == 1:
            # RFC 2132 hardware-type-1 client id: normalize to the MAC so
            # that client messages (with option 61) and server messages
            # (without it) resolve to the same client identity.
            client_key = ("mac", str2mac(client_id[1:7]))
            client_desc = "mac %s" % client_key[1]
        elif client_id:
            client_key = ("cid", client_id)
            client_desc = "client-id %s" % client_id.hex()
        else:
            client_key = ("mac", mac)
            client_desc = "mac %s" % mac
        opt82 = opts.get("relay_agent_information")
        if isinstance(opt82, str):
            opt82 = opt82.encode("utf8", "replace")
        giaddr = bootp.giaddr
        relayed = giaddr != _ZERO_IP or opt82 is not None
        if relayed and frame.port not in cfg.relay_ports:
            alerts.append(DhcpAlert(
                "untrusted-relay-context",
                "packet %d carries relay state (giaddr=%s, option82=%s) on "
                "port %r which is not a configured relay port; the Option "
                "82 value itself does not prove trusted ingress" % (
                    pos, giaddr, opt82 is not None, frame.port), (pos,)))
        elif relayed and cfg.known_relays and giaddr != _ZERO_IP \
                and giaddr not in cfg.known_relays:
            alerts.append(DhcpAlert(
                "untrusted-relay-agent",
                "packet %d is relayed by giaddr %s which is not in the "
                "configured known relays" % (pos, giaddr), (pos,)))
        if mtype in _SERVER_MESSAGES and frame.port not in cfg.server_ports \
                and frame.port not in cfg.relay_ports:
            alerts.append(DhcpAlert(
                "server-message-on-untrusted-port",
                "server message (type %d) in packet %d arrived on port %r "
                "which allows neither servers nor relays" % (
                    mtype, pos, frame.port), (pos,)))
        msg = _DhcpMessage()
        msg.pos = pos
        msg.timestamp = frame.timestamp
        msg.port = frame.port
        msg.mtype = mtype
        msg.xid = bootp.xid
        msg.mac = mac
        msg.client_key = client_key
        msg.client_desc = client_desc
        msg.giaddr = giaddr
        msg.ciaddr = bootp.ciaddr
        msg.yiaddr = bootp.yiaddr
        msg.ip_src = pkt[IP].src if pkt.getlayer(IP) is not None else None
        msg.server_id = opts.get("server_id")
        msg.requested_addr = opts.get("requested_addr")
        msg.lease_time = opts.get("lease_time") or 0
        msg.opt82 = opt82
        return msg

    def _correlate(self, messages, alerts):
        cfg = self.config
        xid_clients = {}
        for msg in messages:
            xid_clients.setdefault(msg.xid, {}).setdefault(
                msg.client_key, []).append(msg.pos)
        for xid in sorted(xid_clients):
            clients = xid_clients[xid]
            if len(clients) > 1:
                positions = []
                for poss in clients.values():
                    positions.extend(poss)
                alerts.append(DhcpAlert(
                    "xid-shared-by-multiple-clients",
                    "xid 0x%08x is used by %d distinct client identities; a "
                    "transaction id does not authenticate a client" % (
                        xid, len(clients)), sorted(positions)))
        exchanges = {}
        for msg in messages:
            key = (msg.xid, msg.client_key, msg.giaddr)
            exchanges.setdefault(key, []).append(msg)
        bindings = []
        incomplete = []
        groups = sorted(exchanges.values(), key=lambda ms: ms[0].pos)
        for msgs in groups:
            discovers = [m for m in msgs if m.mtype == _DHCP_DISCOVER]
            requests = [m for m in msgs if m.mtype == _DHCP_REQUEST]
            acks = [m for m in msgs if m.mtype == _DHCP_ACK]
            naks = [m for m in msgs if m.mtype == _DHCP_NAK]
            phase = "initial" if discovers else "renewal"
            head = msgs[0]
            confirmed = False
            for nak in naks:
                incomplete.append(
                    "xid 0x%08x %s: NAK at packet %d refuses the request; "
                    "no binding" % (nak.xid, head.client_desc, nak.pos))
            for ack in acks:
                req = None
                for cand in requests:
                    if cand.pos < ack.pos:
                        req = cand
                if req is None:
                    incomplete.append(
                        "xid 0x%08x %s: ACK at packet %d without an "
                        "observed request; possible packet loss, no "
                        "binding inferred" % (
                            ack.xid, head.client_desc, ack.pos))
                    continue
                selected = req.server_id
                claimed = ack.server_id
                if selected and claimed and selected != claimed:
                    alerts.append(DhcpAlert(
                        "ack-from-unselected-server",
                        "client selected server %s in packet %d but the "
                        "ACK in packet %d claims server %s" % (
                            selected, req.pos, ack.pos, claimed),
                        (req.pos, ack.pos)))
                    continue
                if claimed not in cfg.trusted_servers:
                    alerts.append(DhcpAlert(
                        "ack-from-untrusted-server",
                        "ACK in packet %d claims server %s which is not in "
                        "the configured trusted servers; the self-reported "
                        "server identifier is not trust configuration" % (
                            ack.pos, claimed), (req.pos, ack.pos)))
                    continue
                if ack.ip_src is not None and ack.ip_src != claimed:
                    alerts.append(DhcpAlert(
                        "ack-server-identity-mismatch",
                        "ACK in packet %d claims server %s but its IP "
                        "source is %s" % (
                            ack.pos, claimed, ack.ip_src),
                        (req.pos, ack.pos)))
                    continue
                address = ack.yiaddr
                if address == _ZERO_IP:
                    address = req.requested_addr or req.ciaddr
                positions = [m.pos for m in msgs if m.pos <= ack.pos]
                bindings.append(DhcpLeaseBinding(
                    head.client_desc, head.mac, address, claimed, ack.xid,
                    ack.giaddr, phase, ack.lease_time, ack.timestamp,
                    positions))
                confirmed = True
            if not confirmed and not naks:
                seen = ",".join(str(m.pos) for m in msgs)
                kinds = ",".join(str(m.mtype) for m in msgs)
                incomplete.append(
                    "xid 0x%08x %s: only message types [%s] observed at "
                    "packets [%s]; half-observed exchange, possible packet "
                    "loss; neither an attack nor a successful binding is "
                    "inferred" % (head.xid, head.client_desc, kinds, seen))
        return bindings, incomplete
