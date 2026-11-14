# Migrating CSP directive-injection handling to strict rejection

Caller-controlled source expressions can contain CR, LF or `;` bytes that let
a value break out of its CSP directive and inject sibling directives.
Historically secure_headers replaced those bytes with spaces and emitted a
`Kernel.warn` deprecation. This guide describes the staged move to strict
rejection.

## The two modes

| Mode | Invalid value | Header output | How you find out |
| --- | --- | --- | --- |
| `:observe` (default) | kept for now, bytes replaced with spaces | unchanged from today | structured, redacted violations + the legacy warning |
| `:strict` | rejected before it is applied | never rendered | raises `SecureHeaders::CspValidation::CspValidationError` |

The default is `:observe`, so upgrading the gem changes nothing until you opt
in.

```ruby
SecureHeaders::Configuration.csp_validation_mode = :strict
# valid values: :observe, :strict (anything else raises ArgumentError)
```

The mode is global. A single request may also override it, which is handy for
canarying a strict rollout per traffic bucket:

```ruby
SecureHeaders.append_content_security_policy_directives(
  request, additions, nil, validation_mode: :strict
)
SecureHeaders.override_content_security_policy_directives(
  request, additions, nil, validation_mode: :strict
)
SecureHeaders.use_content_security_policy_named_append(
  request, :widget, validation_mode: :strict
)
```

## Where validation runs

The same rules apply at every place a policy can be introduced or changed:

1. **Default registration** - `SecureHeaders::Configuration.default` (and any
   later `validate_config!`). In strict mode an invalid default is rejected at
   boot and never stored.
2. **Named overrides** - `use_secure_headers_override`. Strict mode builds the
   candidate on a copy first; a failing override raises without replacing the
   request's existing policy.
3. **Named appends / single-request appends and overrides** -
   `use_content_security_policy_named_append`,
   `append_content_security_policy_directives`,
   `override_content_security_policy_directives`. The incoming change is
   validated *before* any mutation, so a rejected change leaves the previous
   policy completely intact - there is no half-written new policy.
4. **Header generation** - the renderer is the final gate. In strict mode it
   raises instead of building header text, so the observe-mode scrubber is
   never reached.

## Reading violations

In observe mode, violations for a request are available after
`header_hash_for` runs:

```ruby
SecureHeaders.header_hash_for(request)
SecureHeaders.content_security_policy_violations(request)
# => [
#   {
#     policy: :enforced,          # or :report_only
#     source: :request_append,    # where it was detected
#     directive: :script_src,
#     token_index: 1,             # nil for scalar directives such as report-to
#     char_offsets: [43],         # 0-based character offsets of every offending byte
#     offending_bytes: [";"],     # \n, \r and/or ;
#     redacted_value: "https://[REDACTED]/assets/app.js; script-src *"
#   }
# ]
```

For a one-off audit outside request handling, build the configuration object
and call `csp_violations`:

```ruby
configuration = SecureHeaders::Configuration.new { |c| c.csp = my_policy_hash }
configuration.csp_violations
```

### Redaction

Violation payloads never carry the two pieces of data callers most often leak:

* Nonce source expressions are reported as `'nonce-[REDACTED]'` - the nonce
  material itself is omitted.
* Absolute URLs have their scheme kept but the host and port (the tenant
  identity) replaced: `https://tenant.example.com:8443/x.js` becomes
  `https://[REDACTED]/x.js`. The path is retained because it does not identify
  the tenant.

The raw `char_offsets` point into the original, unredacted value (character indices, so they stay correct for multibyte content), so the
offending location is unambiguous without shipping the secret in telemetry.

### Stable, separately-locatable results

* Violations are sorted by policy, source, directive, token index and offset,
  so the same policy always produces the identical list, even when several
  directives fail in one request.
* The enforced policy (`policy: :enforced`) and the report-only policy
  (`policy: :report_only`) are reported independently, and a strict error
  carries violations from both. Appending to `:report_only` can be rejected
  without touching the enforced policy, and vice versa.
* Only injection bytes are violations. A policy that is legal but loose -
  `default-src * 'unsafe-inline' 'unsafe-eval' data: blob:` - returns no
  violations and renders normally in both modes. Lax posture is never
  mislabeled as a syntax error.

## Rollout runbook

A complete, runnable version of this flow lives at
[`examples/csp_validation_migration.rb`](../examples/csp_validation_migration.rb)
(`bundle exec ruby examples/csp_validation_migration.rb`).

### 1. Observe

Leave the mode at the default and ship the gem. Existing headers are
byte-identical. Collect `content_security_policy_violations` from real
traffic (or call `csp_violations` against each registered configuration) to
build the list of affected callers.

### 2. Remediate

Fix each offending value at its source. For a value such as
`"https://cdn.example.com/app.js; script-src 'unsafe-inline' *"`, keep the
intended source (`https://cdn.example.com/app.js`) and drop the smuggled
fragment. Re-check in observe mode until `content_security_policy_violations`
is empty for that path.

### 3. Enable strict

Flip the global switch (or start with the per-request `validation_mode:`
override on a canary bucket):

```ruby
SecureHeaders::Configuration.csp_validation_mode = :strict
```

Clean policies render exactly as before. Any remaining invalid change raises
`CspValidation::CspValidationError`, whose `#violations` gives the same
structured, redacted locations. Because validation precedes the mutation, the
previously configured policy stays in force for that request.

### 4. Roll back a failed enablement

The switch is a single reversible assignment. If strict mode blocks an
unanticipated caller, set the mode back to `:observe`; the legacy
scrub-and-warn behavior and original headers resume immediately, while the
violations remain available for follow-up:

```ruby
SecureHeaders::Configuration.csp_validation_mode = :observe
```

## Header parity guarantee

When a configuration contains no injection bytes, the rendered header is
identical in both modes. The strict path only short-circuits invalid policies;
it never rewrites valid ones. This is covered by the parity checks in
`spec/lib/secure_headers/headers/csp_validation_modes_spec.rb` and the
`PARITY` section of the example script.
