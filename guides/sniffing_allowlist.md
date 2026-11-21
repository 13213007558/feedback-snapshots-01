- [Restricting Node Discovery to Approved Networks](#restricting-node-discovery-to-approved-networks)
  - [Configuring the Policy](#configuring-the-policy)
  - [How Discovery Interacts with the Pool](#how-discovery-interacts-with-the-pool)
  - [Async Clients](#async-clients)

# Restricting Node Discovery to Approved Networks

Node discovery (sniffing) fetches the node list from `/_nodes/_all/http` and adds
the returned hosts to the connection pool. In a network-restricted deployment,
the cluster response must not be able to widen the set of networks the
application connects to.

Pass `allowed_hosts` to apply the same policy to the synchronous and
asynchronous clients. Discovery results outside the policy never enter the
connection pool.

## Configuring the Policy

```python
from opensearchpy import OpenSearch

client = OpenSearch(
    hosts=[{"host": "opensearch.internal", "port": 9200}],
    sniff_on_start=True,
    sniffer_timeout=60,
    allowed_hosts=[
        "10.20.0.0/16",          # an IPv4 network
        "fd00:1234::/48",        # an IPv6 network
        "opensearch.internal",   # an exact hostname
        "*.search.internal",     # any subdomain of search.internal
    ],
)
```

Entries are matched against the `host` of a discovered node:

- IP addresses must be written in canonical form, e.g. `10.1.2.3` or `fd00::1`.
- Networks use CIDR notation. A bare IP is also accepted as one exact address.
- Wildcards only match subdomains, so `*.search.internal` matches
  `node-1.search.internal` but not `search.internal`.
- Hostnames are compared lexically and are never resolved through DNS, so the
  policy itself cannot trigger a lookup outside the approved network area.
- Ports and URL schemes are not considered part of the policy.

`allowed_hosts` accepts anything that can be iterated over as strings, or an
already constructed `HostAllowlist`. The same object can be shared by several
clients.

## How Discovery Interacts with the Pool

Hosts passed explicitly in `hosts` are the application's approved entry points
and are not filtered, even if they do not appear in `allowed_hosts`. The policy
only governs hosts obtained from discovery.

When discovery returns a mix of approved and unapproved nodes, only approved
nodes are added to the pool. When discovery returns no approved nodes - because
the response is empty or the policy rejects every node - the existing pool is
kept. Requests, retries and forced resurrection continue to use the
connections that were already serving, so a discovery result never expands the
reachable network area. Errors that prevent the discovery request from
completing still surface as before.

```python
# Discovery returns 10.20.1.5 and 203.0.113.9.
# Only 10.20.1.5 joins the pool; retries stay on approved nodes.
client = OpenSearch(
    hosts=["10.20.0.1"],
    sniff_on_connection_fail=True,
    allowed_hosts=["10.20.0.0/16"],
)
```

Removing `allowed_hosts` restores the default behavior, in which every node
returned by discovery is eligible.

## Async Clients

`AsyncOpenSearch` accepts the same option and applies the same filtering during
its initial sniff, periodic refreshes, and sniffs triggered by connection
failures:

```python
from opensearchpy import AsyncOpenSearch

client = AsyncOpenSearch(
    hosts=["opensearch.internal:9200"],
    sniff_on_start=True,
    allowed_hosts=["10.20.0.0/16", "*.search.internal"],
)
```
