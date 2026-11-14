# Configuration ownership and isolation

secure_headers distinguishes three configuration lifetimes. Each has explicit
ownership rules so nested objects can never be modified through an alias held
by another layer.

## The three layers

1. **Registered configurations** — the global default
   (`SecureHeaders::Configuration.default`) and named overrides
   (`Configuration.override`). They are snapshots: every nested hash, array and
   CSP config is deep-frozen when registration completes. Mutating them raises
   `FrozenError`.
2. **Per-request configurations** — a writable deep copy created lazily the
   first time a request legitimately modifies its policy. Each request owns its
   copy; two interleaved requests never share mutable state.
3. **`OPT_OUT`** — a global singleton. It is never copied and never frozen, so
   `config.csp.equal?(SecureHeaders::OPT_OUT)` stays true through registration
   and `dup`.

## Copy-on-write boundaries

Values supplied by the caller are copied the moment they cross into
secure_headers, so changing the original argument after registration has no
effect:

- CSP source lists (`default_src`, `script_src`, ...) are duplicated inside
  `ContentSecurityPolicyConfig`; passing an existing config object stores a
  `dup`, never the caller's object.
- Cookie `only`/`except` condition arrays and the nested `samesite` hashes are
  deep copied by `cookies=`.
- Reporting endpoint hashes are deep copied by `reporting_endpoints=`.

Scalar values (strings, booleans, `nil`) and `OPT_OUT` are shared because they
are immutable or identity-based; copying them would add work without adding
isolation.

A request copy is only created when a request actually changes something. An
unmodified request reads the frozen registered config directly and allocates
no per-request configuration.

## Memoized headers

`Configuration#generate_headers` memoizes the rendered header hash on the
per-request configuration. Every legitimate mutation path invalidates the memo:

- attribute writers (`csp=`, `cookies=`, `reporting_endpoints=`,
  `x_frame_options=`, ...) and `update_x_frame_options`
- in-place CSP mutation (`merge!`, `append`, `update_directive`, `[]=`) via a
  mutation listener registered when the config is assigned
- named overrides applied to a request

Frozen registered configs cannot hold a memo, so they render directly; the
cache lives exclusively on writable request copies. Header generation itself
never duplicates the configuration tree — the single deep copy happens when a
request first modifies the config.

## Middleware cookie handling

On plain HTTP requests the `Secure` flag is suppressed with a request-local
`merge(secure: OPT_OUT)` instead of writing into the configuration's cookie
hash, so interleaved HTTP/HTTPS requests cannot leak state into each other or
into the registered default.

## Demo

`examples/ownership_isolation_demo.rb` walks through two interleaved requests
that reuse the same nested CSP arrays, cookie conditions and reporting
endpoints, prints which objects are frozen versus writable, and reports the
copy scope relative to the previous shallow-copy implementation.
