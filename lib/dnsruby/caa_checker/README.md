# Dnsruby::CaaChecker — offline, reviewable CAA authorization

A Certification Authority Authorization (CAA) decision engine built on
Dnsruby. It performs the authorization judgment a CA makes *before*
issuing a certificate, but without contacting any real CA or the live
DNS: every DNS answer is supplied by an injected, offline answer
provider, and every query is recorded so the decision can be reviewed
after the fact.

The processing follows [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659)
(the DNS CAA RR), with alias chasing per RFC 1034 §4.3.2 as updated by
RFC 6672 (DNAME).

## Inputs

`Dnsruby::CaaChecker.authorize` takes four keyword arguments:

| Argument | Meaning |
| --- | --- |
| `domain` | FQDN to be certified. A leading `*.` implies a wildcard request. |
| `wildcard` | `true` when the request is for a Wildcard Domain Name `*.domain`. |
| `issuer` | The issuer-domain-name being tested, e.g. `ca.example.net`. |
| `provider` | An offline answer provider answering CAA queries. |

```ruby
require 'dnsruby'

provider = Dnsruby::CaaChecker::StaticProvider.new(
  {
    "example.com" => {
      answer: ['example.com. 300 IN CAA 0 issue "ca.example.net"']
    }
  },
  missing: :empty # unlisted names are completed empty NOERROR answers
)

result = Dnsruby::CaaChecker.authorize(
  domain: "www.example.com",
  wildcard: false,
  issuer: "ca.example.net",
  provider: provider
)

result.decision      # :allow
result.reason        # :authorized
result.relevant_name # "example.com"
```

## Decisions

`Result#decision` is one of four values. "No policy" and "the query
could not be completed" are never conflated.

| Decision | Meaning |
| --- | --- |
| `:allow` | A Relevant RRset exists and authorizes the issuer, or no restricting Property exists. |
| `:deny` | A Relevant RRset exists but does not authorize the issuer. |
| `:no_policy` | All queries completed and no CAA RRset exists anywhere on the path; CAA imposes no restriction. |
| `:lookup_incomplete` | A query could not be completed, so authorization is undetermined. Do not treat this as "no policy". |

`Result#reason` carries a stable code (`:authorized`, `:issuer_not_listed`,
`:empty_issuer`, `:unsupported_parameters`, `:unknown_critical_property`,
`:no_restricting_properties`, `:no_policy`, `:lookup_failed`), and
`Result#to_h` serializes the whole judgment for archival.

## How the Relevant RRset is found

1. Starting at the requested label, issue a CAA query and chase any
   CNAME/DNAME aliases at that label.
2. If the terminal answer contains CAA records, that RRset is the
   Relevant RRset and the search stops — records at other names are
   never merged into it.
3. Otherwise strip the leftmost label and repeat, up to but not
   including the DNS root.
4. If every label yields an empty answer, there is no policy.

A name that is a CNAME/DNAME alias is evaluated solely against the
policy reached through the alias. Tree climbing happens on the original
FQDN only; after following an alias the checker does not climb back into
the original zone, so an alias cannot inherit a more permissive parent
policy.

## Properties and rules implemented

- `issue` — restricts/authorizes issuance for the FQDN.
- `issuewild` — applies only to wildcard requests; when present for a
  wildcard request, all `issue` Properties are ignored. It is ignored
  entirely for non-wildcard requests.
- `iodef` and other non-restricting tags — do not block issuance.
- Empty issuer (`issue ";"`) and values that violate the RFC 8659 ABNF
  (e.g. `issue "%%%%%"`) request no issuance. Empty and named issuers in
  the same RRset are additive.
- Issuer Critical Flag (`flag & 0x80`) on an unknown/unsupported tag
  forbids issuance. A non-critical unknown tag is ignored.
- Issuer parameters (e.g. `ca.example.net; account=...`) are
  issuer-defined. This checker has no account/validation context, so a
  Property carrying any parameter is never treated as an authorization
  (`:unsupported_parameters`); supply a custom provider-side extension if
  you need to satisfy specific parameters.

## Incomplete lookups

The following produce `:lookup_incomplete` (with details in
`Result#failure`): SERVFAIL/REFUSED/NOTIMP and any rcode other than
NOERROR/NXDOMAIN, a truncated (`TC`) response, an alias loop or a chain
over 16 hops, a provider that raises, and — by default — a name missing
from the offline fixture table. NOERROR with an empty answer and
NXDOMAIN are completed answers and feed the normal tree climb.

`StaticProvider.new(fixtures, missing: :raise|:empty|:nxdomain)`
controls the unlisted-name policy; the default `:raise` keeps a missing
fixture visible instead of silently assuming "no records".

## Review trail

`Result#trace` is an ordered list of `TraceEntry` objects, one per query,
each recording:

- `queried_name` — the name the CAA query was sent for,
- `rcode` and `outcome` (`:empty`, `:nxdomain`, `:failed`, `:alias`,
  `:rrset`),
- `alias_target` when an alias was followed,
- `records` — the CAA RRs at the terminal name for that query.

`Result#relevant_name` and `Result#relevant_records` name the exact
owner and RRset the decision used, and `Result#evaluations` gives the
per-`issue`/`issuewild` match result.

## Custom providers

Any object implementing `query(name) -> Dnsruby::Message` works as a
provider; raise `Dnsruby::CaaChecker::LookupIncomplete` (or let another
error propagate — it is classified the same way) for queries that cannot
be completed. This makes the checker usable against captured DNS
messages, a zone dump, or a test double without any network access.
