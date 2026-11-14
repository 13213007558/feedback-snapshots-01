# Risk scoring with a bounded execution budget

Some protection rules need an external risk scorer (fraud API, ML model,
reputation service). When that scorer stalls, naive `Timeout.timeout` or
thread-per-call wrappers either leak a background thread per timed-out
request or corrupt shared state. Rack::Attack instead runs scorer calls
under a **bounded rule execution budget** with three layers of defense:

1. **A shared, bounded worker pool** (`Rack::Attack.risk_pool`). At most
   `risk_pool_size` threads ever execute scorer code, and at most
   `risk_queue_capacity` calls wait in line. Submissions beyond that are
   rejected immediately. Timed-out requests never leave a thread behind —
   the pool threads are long-lived and reused.
2. **A per-request budget** (`Rack::Attack.risk_budget`, seconds). All risk
   rules evaluated during one request share a single monotonic deadline.
   Once it is spent, further evaluations return `unknown` immediately
   without touching the pool.
3. **Per-request memoization**. Rules that ask the same query share one
   scorer call and one verdict. A confirmed verdict (`allow`/`deny`) is
   final for the request — a later timeout can never overturn a confirmed
   ban, and an unknown result is never treated as low risk.

## Declaring rules

```ruby
scorer = Rack::Attack::Risk::Scorer.new(->(query) { MyRiskClient.score(query) }, deny_at: 0.8)

Rack::Attack.risk_blocklist "login-risk",
  scorer: scorer,
  query: ->(req) { req.ip if req.path == "/login" },
  on_timeout: :deny # or :local, or :ignore
```

`on_timeout` declares what happens when the verdict is **unknown**
(timeout, full queue, exhausted budget, or scorer error):

| Policy   | Behavior                                             |
|----------|------------------------------------------------------|
| `:deny`  | Fail closed: treat the request as matched (blocked). |
| `:local` | Degrade to the local rule block passed to the DSL.   |
| `:ignore`| Fail open: treat this rule as not matched.           |

With `on_timeout: :local`, pass a block as the local fallback rule:

```ruby
Rack::Attack.risk_blocklist "login-risk",
  scorer: scorer,
  query: ->(req) { req.ip },
  on_timeout: :local do |req|
    req.post? && req.path == "/login" # local heuristic while scorer is down
  end
```

The scorer callable may return a Numeric score (denied when `>= deny_at`,
default 0.5), `:deny`/`true`, or `:allow`/`false`/`nil`.

## Tuning

```ruby
Rack::Attack.risk_budget = 0.25          # total scorer wait per request
Rack::Attack.risk_pool_size = 2          # max concurrent scorer calls
Rack::Attack.risk_queue_capacity = 64    # max queued calls
Rack::Attack.reset_risk_pool!            # apply pool settings changed at runtime
```

Size the pool as `p99 scorer latency (s) × peak request rate`, and the
queue as the backlog you are willing to hold before shedding load.

## Observability

Every evaluation appends to `env["rack.attack.risk.decisions"]`:

```ruby
{ rule: "login-risk", outcome: :unknown, reason: :timeout,
  policy: :deny_on_unknown, query_digest: "b94d27..." }
```

- `outcome` is `:deny`, `:allow` or `:unknown`; `reason` is `:scored`,
  `:timeout`, `:queue_full`, `:budget_exhausted` or `:error`.
- `policy` records the strategy actually adopted: `:scored_deny`,
  `:scored_allow`, `:deny_on_unknown`, `:local_on_unknown` or
  `:ignore_on_unknown`.
- Only a SHA-256 digest of the query is recorded. Raw scoring inputs
  (IPs, tokens, account ids) never enter the env, notifications or logs —
  keep it that way by not logging queries inside your scorer either.

Blocked responses carry the adopted policy in the
`x-rack-attack-risk-policy` header, and the standard
`risk_blocklist.rack_attack` ActiveSupport::Notifications event exposes
`env["rack.attack.risk"]` on the payload request.

## What cannot be safely interrupted (and how we limit it instead)

Ruby offers **no safe way to interrupt arbitrary synchronous code**:

- `Thread#kill` / `Thread#raise` can fire inside an `ensure` block, a
  memory allocation, or a C extension, leaving mutexes, connections and
  native state corrupted. `Timeout.timeout` has the same flaw.
- Blocking calls that never return to the Ruby scheduler — unbounded
  socket reads, `getaddrinfo` DNS resolution, C extensions that hold the
  GVL — cannot even be *observed* as timed out from the same thread; they
  also starve other threads.

Therefore the pool **never interrupts workers**. A scorer call that hangs
forever occupies its worker forever; the damage is bounded by
`risk_pool_size`, and requests waiting on it shed load via the budget and
queue limits instead of spawning replacements. To keep workers healthy:

- The scorer callable must enforce its own client-level timeouts
  (connect/read) well below `risk_budget`. This is a hard requirement for
  integrating a synchronous client.
- Never share mutable state (connections, buffers) between scorer calls
  without synchronization — calls run concurrently on pool workers.
- Do not wrap scorer code in `Timeout.timeout` inside the callable; rely
  on client timeouts and the pool's abandon-on-timeout semantics.
- If your client cannot be made interrupt-safe, isolate it behind a local
  sidecar process and talk to it over a socket with read timeouts.
