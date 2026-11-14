# Versioned rule sets

Rack::Attack can switch a whole group of protection rules online. Rules are
built, validated and published as one immutable, versioned `RuleSet`, and
every request is pinned to exactly one version from the moment it enters the
middleware until its hit event is recorded — a request is never safelisted
under one version and then throttle-counted under another.

## Building and validating

```ruby
v2 = Rack::Attack.build_rule_set(version: "v2") do |config|
  config.safelist("office") { |req| req.ip == "10.0.0.1" }
  config.blocklist("allow2ban scanners") do |req|
    Rack::Attack::Allow2Ban.filter(req.ip, maxretry: 3, findtime: 60, bantime: 300) do
      req.path == "/admin"
    end
  end
  config.throttle("req/ip", limit: 5, period: 60) { |req| req.ip }
  config.throttled_responder = ->(req) { [429, {}, ["throttled by v2\n"]] }
end
```

Everything the rules need belongs to the version:

- **Rule callbacks** — the safelist/blocklist/throttle/track blocks above.
- **Responders** — `throttled_responder` / `blocklisted_responder` set on the
  builder's configuration are used only by this version.
- **Counter namespace** — throttle counters are stored under a per-version
  namespace (defaulting to the version string, overridable with
  `namespace:`), so two versions never share a counter. Legacy
  (unversioned) keys keep their historical format.

`build_rule_set` validates the configuration and raises
`Rack::Attack::InvalidRuleSetError` (with all errors in `#errors`) when the
version is missing, a responder is not callable, a rule has no block, or a
throttle limit/period is not positive.

## Publishing

```ruby
Rack::Attack.publish(v2)
```

Publishing validates again, freezes the rule set, and swaps one reference.
The request path never takes the publish mutex, so in-flight requests are
never blocked by a publish; a request that entered under the old version
finishes entirely under the old version. If validation fails, the error is
raised and the current version stays active.

Published rule sets are immutable: adding rules to their configuration
raises `FrozenError`.

## Hit events

Requests served by a published rule set carry
`env["rack.attack.rule_set_version"]`, and the instrumentation payload
includes `rule_set_version` alongside `request`, so an event, the response
and the versioned counter can always be correlated. Legacy requests emit
the exact same payload as before.

## Rollback

```ruby
report = Rack::Attack.rollback
puts report.summary
# => "Rolled back from v2 to v1; bans still in effect: allow2ban:5.6.7.8"
```

`rollback` restores the previously published rule set (publishing always
keeps the previous version, including the implicit legacy one, as a
rollback target) and returns a `Rack::Attack::RollbackReport` with
`from_version`, `to_version` and `active_bans`.

fail2ban/allow2ban ban state lives in the shared cache under unversioned
keys on purpose: a ban is a fact about a client, not about a rule version,
so it survives switches and rollbacks and is enforced again as soon as the
restored version consults the same ban filter. `active_bans` is read from
the store when it can enumerate keys, and otherwise falls back to bans
observed by the current process; when neither is possible it is `nil` and
`report.bans_enumerable?` is false.

## Compatibility with the global configuration

Existing usage is unchanged. `Rack::Attack.safelist`, `.throttle`,
`.blocklisted_responder=`, etc. still configure the global
`Rack::Attack.configuration`, which backs an implicit "legacy" rule set
with no version and no counter namespace. Apps that never call `publish`
see identical behavior, cache keys and event payloads.
`Rack::Attack.clear_configuration` resets the global configuration and
returns to the legacy rule set, discarding publish history.

## Reclaiming old versions

A superseded rule set can be reclaimed when all of the following hold:

1. **No in-flight request references it.** The middleware holds the rule
   set only for the duration of a request, so once requests that entered
   before the switch have drained, the object is garbage-collected — no
   reference counting or request locking is needed.
2. **It is no longer a rollback target.** Every published version stays
   reachable through `Rack::Attack.rule_set_history` until it is popped by
   `rollback` or discarded by `clear_configuration`.
3. **Its counters have expired.** Versioned counter keys are written with a
   TTL of the remainder of their period (plus one second), so the store
   evicts them on its own. Ban keys (`fail2ban`/`allow2ban`) are shared
   across versions and expire with their `bantime`; they must not be
   deleted as part of reclaiming a version.

A runnable experiment showing two requests crossing a switch point lives in
`spec/acceptance/rule_set_switching_spec.rb`.
