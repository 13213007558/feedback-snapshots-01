# Bounded-State Throttling

## The risk in the current key path

For a normal throttle, the discriminator returned by the block is interpolated
directly into the cache key:

```ruby
Rack::Attack.throttle("logins/email", limit: 5, period: 60) { |req| req.params["email"] }
```

The path is:

1. `Throttle#matched_by?` calls the block and normalizes the result
   (`strip.downcase` by default).
2. `cache.count("#{name}:#{discriminator}", period)` is called **before** the
   limit is evaluated.
3. `Cache#key_and_expiry` builds
   `rack::attack:<period-generation>:<name>:<discriminator>` and passes an
   expiry of at most `period + 1` seconds.
4. `Cache#do_count` calls `store.increment(key, 1, expires_in: ...)`. Stores
   create the key on first increment.

There is no admission check before step 4. An unauthenticated attacker who
controls an email/username field can therefore create `O(unique accounts)`
keys per period, all with a full-period TTL. The cache will not hold them
indefinitely, but peak state and the number of writes are attacker-controlled.
A cache with `maxmemory` will evict other keys (possibly other throttles or
application keys); an unbounded Redis will grow until memory pressure.

The attacker can steer:

- The **discriminator suffix** of `<name>:<discriminator>` entirely.
- The **number of distinct discriminator-key values** per period.
- The **timing** of key creation within a period, including at a boundary where
  two generations coexist.

The attacker cannot choose the throttle name, prefix, period generation, or
the server's secret (when `hash_key` is configured). Those remain fixed per
deployment.

`request.ip` is not a safe unique dimension by default in Rack 3: it trusts
private/loopback peers and can honor `Forwarded` / `X-Forwarded-For`. Verify
`Rack::Request.ip_filter` before treating IP as a trusted dimension. A
spoofable IP is just another attacker-controlled discriminator.

## What not to do

Do not add a "does this account exist?" lookup before the counter. That turns
rate limiting into an account-enumeration oracle unless the negative and
positive paths are indistinguishable, and it makes the lookup part of the
request budget. It also does not solve the state problem for real unknown
accounts, which still need a counter.

Do not return different status codes, bodies, or latency for known vs unknown
accounts. The throttle decision should be applied uniformly after
authentication, or keyed on a value that does not reveal account existence.

## Bounded strategies

`Rack::Attack.bounded_throttle` supports four strategies. All of them use the
store's atomic `increment`; none uses a read-modify-write cycle. Every counter
has a TTL of at most `period + 1` seconds.

### `strategy: :gate` (recommended when rotation is the threat)

Exact budgets on trusted dimensions are evaluated first. Only requests that
pass every budget touch the exact per-account counter.

```ruby
Rack::Attack.bounded_throttle(
  "login/account",
  strategy: :gate,
  limit: 5,
  period: 60,
  budgets: {
    global: { limit: 2_000, buckets: 1 },
    tenant: { limit: 500, buckets: 256, discriminator: ->(req) { req.get_header("HTTP_X_TENANT_ID") } },
    ip: { limit: 20, buckets: 1024, prefix: 24, discriminator: ->(req) { req.ip } }
  }
) { |req| req.params["email"] }
```

Properties:

- The number of per-account keys per period is bounded by the tightest budget's
  admission count (for the example, at most 500 per tenant slot).
- Budget state is fixed: `buckets` keys per budget.
- Per-account decisions are exact, so repeated attempts on one account are
  counted correctly.
- All budgets must use the same literal period as the throttle. That is what
  makes the admission bound meaningful. The constructor enforces it.
- Requests rejected by a budget do not touch later budgets or the account
  counter.

Tradeoff: a shared budget is a denial-of-service lever. An attacker who can
consume a tenant's or IP slot's budget blocks legitimate users in that scope
for the rest of the period. Use the widest trusted scope available, and size the
budget for peak legitimate traffic, not average traffic.

### `strategy: :budget`

Only the exact budgets are evaluated. There is no per-account counter. This is
the smallest state and the most predictable failure mode, but it cannot
distinguish one account hammering from many accounts rotating.

### `strategy: :sketch`

The discriminator is hashed into `buckets` slots in each of `depth` rows. The
minimum row estimates the account's count. The account is never a cache key.

Properties:

- State is exactly `buckets * depth` keys per period (times `scope_buckets`).
- Collisions cause **overestimation**, so this errs toward false blocks, never
  toward allowing an over-limit account.
- It is a poor defense against one-request-per-account rotation: a fresh account
  has an estimate near 1 and is allowed. It helps with repeated attempts from
  the same account, not with enumeration.
- A large unique-account flood raises every bucket, so it false-blocks normal
  accounts. Keep `buckets` well above `limit * expected concurrent accounts`.
- `hash_key` should be set to a deployment secret so an attacker cannot
  deliberately collide chosen accounts.

### `strategy: :hybrid`

Budgets first, then a sketch for admitted traffic. This bounds sketch pollution
from a flood that already tripped a budget, while keeping per-account
granularity for admitted requests. It is more accurate than `:sketch` under
attack, and more state than `:gate`.

## State bounds

For one throttle and one period:

| strategy | keys |
| --- | --- |
| `:budget` | `sum(budget.buckets)` |
| `:sketch` | `scope_buckets * depth * buckets` |
| `:hybrid` | `sum(budget.buckets) + scope_buckets * depth * buckets` |
| `:gate` | `sum(budget.buckets) + min(budget.limit * budget.buckets)` |

At a period boundary two generations can coexist, so double the bound for a
transient worst case. `matched_by?` exposes `state_key_bound` in
`rack.attack.throttle_data`, and `BoundedThrottle#max_state_keys` returns the
same number.

The `:gate` bound assumes every budget is evaluated for a request that reaches
the account counter. Short-circuiting keeps the actual count at or below this
bound.

## Recovery

All counters expire by TTL; there is no separate reset step and no state that
survives a period. A process restart loses in-memory counters but external
stores keep them until TTL. Recovery is automatic: the next period starts with
empty counters. Budgets recover on their own periods. If a budget is much
longer than the account period, legitimate users can stay blocked across
several account windows, so keep budget periods close to the throttle period
unless that is intentional.

## Comparative model

`examples/bounded_state/stress_model.rb` replays one identical workload through
each policy and reports key cardinality, evictions, legitimate false blocks, and
attack admissions. Defaults: 600 legitimate requests over 120 accounts, 12,000
attack requests over fresh accounts and 250 IPs, account limit 5, tenant budget
3,000, sketch 4096 x 3.

```text
strategy                           keys     peak  evictions   legit blocked  attack allowed
-------------------------------------------------------------------------------------------
exact per-account                 12120    12120          0      0 / 600     12000 / 12000
exact + known-account skip        12000    12000          0      0 / 600     12000 / 12000
exact + tenant budget              2941     2941          0    448 / 600      2848 / 12000
layered gate (IP+tenant, exact)     3348     3348          0    446 / 600      2846 / 12000
count-min sketch                  11677    11677          0    115 / 600     11989 / 12000
sketch + tenant budget             6301     6301          0    448 / 600      2848 / 12000
```

Read this as:

- Exact per-account counting admits every one-shot account. It is the right
  defense only for repeated attempts on the same account.
- A tenant budget stops rotation (2,848 of 12,000 admitted) but blocks 448 of
  600 legitimate requests because the attacker consumes the shared budget.
- A sketch at 4096 x 3 barely stops one-shot rotation (11 of 12,000 blocked) and
  causes 115 legitimate false blocks from collisions.
- Gate has the same budget tradeoff as the tenant budget, but keeps exact
  per-account counts for admitted traffic and bounds account keys to the
  budget's admission count.

The eviction case is important for capacity-limited caches. With
`--attack 12000 --attack-repeats 8 --capacity 512`, per-account counters are
evicted between passes and all six strategies admit about 12,000 of 12,000
attack requests. A capacity smaller than the working set defeats any bounded
design; size the cache above `keys + headroom`, or use a store that evicts
predictably.

For repeated attempts with ample capacity
(`--attack 12000 --attack-repeats 8 --capacity 50000`), exact, gate, and sketch
all admit about 750 of 1,200 (5 of 8 per account), while exact still holds 270
keys and the sketch holds 782. That is the accuracy/state tradeoff in one
comparison.

## Choosing a strategy

- Account rotation is the threat, and you have a trustworthy tenant or
  authenticated scope: `:gate`.
- You only need a hard state cap and accept coarse blocking: `:budget`.
- You need per-account accuracy and can accept collision false blocks:
  `:sketch` or `:hybrid`.
- You do not have a trusted low-cardinality dimension and the discriminator is
  fully attacker-controlled: a bounded sketch is the only option that keeps
  state fixed, but do not expect it to stop one-shot rotation. Combine it with
  authentication or a pre-auth proof-of-work/CAPTCHA gate.

## Where this does not fit

- You need exact per-account counts for millions of accounts with no trusted
  dimension. Exact counting is not bounded; use an external identity service
  or accept a probabilistic bound.
- `request.ip` is spoofable or shared by many users behind one NAT. Do not use
  it as a security boundary; use it only as a coarse, hashed budget.
- Your cache store does not implement atomic `increment`. The bounded code
  relies on it for budget counters; a non-atomic store can undercount.
- You need cross-process consistency with an in-memory store. Each process has
  its own counters, multiplying effective budgets by process count.
- You need to distinguish account existence in the response. This design
  deliberately does not.
