"""Trusted provisioning for the IGMPv3 offline evidence demo.

Everything in this module represents data that the monitoring point is
provisioned with out of band: which ingress port identities exist, which
multicast groups each port may join and which source addresses are permitted
for those groups. None of it is learned from receiver reports.

A receiver's self-announced group or source address is therefore never an
authorization by itself. The policy below is the sole source of permission.
"""

from dataclasses import dataclass, field
import json


@dataclass(frozen=True)
class PortPolicy:
    """Groups and sources that one ingress port is provisioned to receive."""

    port_id: str
    groups: dict[str, frozenset[str]]

    def permitted_sources(self, group: str) -> frozenset[str] | None:
        """Return the allowed source set, or None if the group is not provisioned."""
        return self.groups.get(group)


@dataclass(frozen=True)
class TrustedConfig:
    """Immutable provisioning snapshot plus the fixed membership timer."""

    group_membership_interval: int
    port_policies: dict[str, PortPolicy] = field(default_factory=dict)

    def policy_lookup(self, port_id: str, group: str, source: str) -> str:
        """Classify a triple against provisioning.

        Returns a stable reason code:
          PORT_NOT_PROVISIONED, GROUP_NOT_PERMITTED,
          SOURCE_NOT_PERMITTED or PERMITTED.
        """
        policy = self.port_policies.get(port_id)
        if policy is None:
            return "PORT_NOT_PROVISIONED"
        sources = policy.permitted_sources(group)
        if sources is None:
            return "GROUP_NOT_PERMITTED"
        if source not in sources:
            return "SOURCE_NOT_PERMITTED"
        return "PERMITTED"

    def triples(self) -> list[tuple[str, str, str]]:
        """Enumerate every provisioned (port, group, source) triple."""
        result = []
        for port_id, policy in sorted(self.port_policies.items()):
            for group, sources in sorted(policy.groups.items()):
                for source in sorted(sources):
                    result.append((port_id, group, source))
        return result

    def to_json(self) -> str:
        return json.dumps(
            {
                "group_membership_interval": self.group_membership_interval,
                "ports": {
                    port_id: {
                        group: sorted(sources)
                        for group, sources in sorted(policy.groups.items())
                    }
                    for port_id, policy in sorted(self.port_policies.items())
                },
            },
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )


def demo_config() -> TrustedConfig:
    """Two ports, two protected groups/sources, plus an explicit non-member.

    Port p1 may only receive G1 from S1 and S2.
    Port p2 may only receive G2 from S21 and S22.
    The fixed Group Membership Interval is 260 s, matching the RFC 3376
    default of robustness 2 and query interval 125 s.
    """
    g1 = "232.0.0.1"
    g2 = "232.0.0.2"
    s1 = "192.0.2.11"
    s2 = "192.0.2.12"
    s21 = "192.0.2.21"
    s22 = "192.0.2.22"
    return TrustedConfig(
        group_membership_interval=260,
        port_policies={
            "p1": PortPolicy("p1", {g1: frozenset({s1, s2})}),
            "p2": PortPolicy("p2", {g2: frozenset({s21, s22})}),
        },
    )
