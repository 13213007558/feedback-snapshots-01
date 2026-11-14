# Offline ruleset replay

Replay sanitized request events against the old and the new Rack::Attack
rules and see exactly which decisions change — before deploying a rule
change.

```console
$ exe/rack-attack-replay \
    --old examples/replay/rules_old.rb \
    --new examples/replay/rules_new.rb \
    --events examples/replay/events.jsonl
```

The JSON report contains:

- `events`: every replayed event in replay order (sorted by virtual
  timestamp; equal timestamps keep input order), with a stable
  `fingerprint` so a decision can be traced back to the event. Account
  identifiers appear only as `account_sha256` and can never be reversed
  from the report.
- `runs.old` / `runs.new`: the decision each ruleset produced per event
  (`allow`, `block`, `throttle`, or `undecidable`), including the matched
  rule name. A decision is `undecidable` when a rule read a field the
  sanitized event did not provide — replay never defaults to allow.
- `diffs`: events where the two rulesets disagree, classified as
  `tightened` (newly restricted), `loosened` (newly allowed), `changed`,
  or `undecidable`.

Replay guarantees:

- **Isolation**: rules run against a private in-memory cache driven by a
  virtual clock. The production cache is never touched, responders are
  never invoked, and no notifications are emitted.
- **Determinism**: identical input produces a byte-identical report.
  Reordering two causally related events (e.g. a login success that
  resets an allow2ban counter and a later failed attempt) changes the
  outcome, exactly as it would in production.

This sample demonstrates, in one run:

- a **tightened** decision (event 10: `/search` throttle limit 3 -> 2),
- a **loosened** decision (event 11: `/admin` blocklist removed),
- an **undecidable** decision (event 12: the new `api/agent` throttle
  needs `user_agent`, which the event does not provide),
- allow2ban ban, unban-after-success (event 2 carries an
  `allow2ban_reset` effect), ban expiry under virtual time (event 7),
  and stable ordering of events 3 and 4 sharing a timestamp.
