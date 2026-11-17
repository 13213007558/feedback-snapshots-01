#!/usr/bin/env python3

"""Demonstrate the ECS-aware cache adapter without any network access.

A simulated authoritative resolver returns a different A record depending
on the EDNS Client Subnet it receives.  The ECSResolver forwards the
masked client subnet, and the ECSCache keeps the two subnets' answers
isolated while reusing each answer only inside the scope the server
asserted.
"""

import dns.edns
import dns.ecscache
import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver

QNAME = dns.name.from_text("geo.example.")

# What the simulated server hands out per client subnet, plus the scope it
# says each answer is valid for.
POLICY = {
    "203.0.113.0/24": ("198.18.0.10", 24),
    "198.51.100.0/24": ("198.18.0.20", 24),
}


def fake_upstream(qname, rdtype, rdclass, ecs_option):
    """Pretend to be an ECS-aware recursive resolver."""
    import ipaddress

    network = ipaddress.ip_network(
        f"{ecs_option.address}/{ecs_option.srclen}", strict=False
    )
    answer_ip, scope = POLICY[str(network)]

    request = dns.message.make_query(qname, rdtype, rdclass)
    response = dns.message.make_response(request)
    rrset = response.find_rrset(response.answer, qname, rdclass, rdtype, create=True)
    rrset.ttl = 300
    rrset.add(dns.rdata.from_text(rdclass, rdtype, answer_ip))
    # Echo the source prefix and assert the response scope.
    response.use_edns(
        options=[
            dns.edns.ECSOption(str(network.network_address), network.prefixlen, scope)
        ]
    )
    return dns.resolver.Answer(qname, rdtype, rdclass, response)


def show(resolver, client_ip, label):
    answer = resolver.resolve(QNAME, "A", client_address=client_ip)
    print(f"  {label:<28} client={client_ip:<15} -> {answer[0].address}")
    return answer


def main():
    resolver = dns.ecscache.ECSResolver(upstream=fake_upstream)

    print("First pass: one query per subnet (both miss the cache).")
    a1 = show(resolver, "203.0.113.7", "subnet A query 1")
    b1 = show(resolver, "198.51.100.9", "subnet B query 1")
    assert a1[0].address != b1[0].address, "subnets must get different answers"

    print("\nSecond pass: different hosts in the same masked /24 networks.")
    a2 = show(resolver, "203.0.113.200", "subnet A query 2")
    b2 = show(resolver, "198.51.100.250", "subnet B query 2")
    assert a2 is a1 and b2 is b1, "same-subnet queries must hit the cache"

    stats = resolver.cache.get_statistics_snapshot()
    print(f"\nCache statistics: hits={stats.hits} misses={stats.misses}")
    assert stats.hits == 2 and stats.misses == 2

    print("\nStored scope networks (full client addresses are never kept):")
    for (name, _, _), entries in resolver.cache.data.items():
        for family, prefixlen, packed in entries:
            import ipaddress

            net = ipaddress.ip_network((ipaddress.ip_address(packed), prefixlen))
            print(f"  {name} reusable for {net}")

    print("\nIsolation check: subnet A never receives subnet B's record.")
    probe = resolver.resolve(QNAME, "A", client_address="203.0.113.50")
    print(f"  subnet A still resolves to {probe[0].address} (not {b1[0].address})")
    assert probe[0].address == a1[0].address

    print("\nOK: answers are scoped, masked, and isolated per client subnet.")


if __name__ == "__main__":
    main()
