# CSP nonces behind conditional caches

A CSP nonce only protects a page when the nonce in the
`Content-Security-Policy` response header matches the nonce embedded in the
HTML body the client actually renders. Conditional caching (ETag /
`If-None-Match` / 304, shared HTTP caches) breaks this pairing in two ways:

* a 304 (or cache hit) pairs a **fresh random header nonce** with a **cached
  body** that embeds an older nonce — the browser blocks every inline script;
* a shared cache can serve body A together with the headers of request B.

`SecureHeaders::NonceCacheMiddleware` makes the cache policy for nonce'd
responses explicit instead of accidental. The library never reads the
response body (streaming bodies are safe) and never assumes a page uses a
nonce — pages without a nonce pass through untouched. Every combination it
cannot guarantee is rejected with `SecureHeaders::NonceCacheError`.

## Stack order

Place the middleware **outside** `SecureHeaders::Middleware` and outside any
conditional-get middleware, so it sees the final status and validators:

```ruby
use SecureHeaders::NonceCacheMiddleware, mode: :no_store # the default
use SecureHeaders::Middleware
use Rack::ConditionalGet
use Rack::ETag
run MyApp
```

## Mode `:no_store` (default)

Any response that used a CSP nonce is rewritten to be non-reusable:

* `Cache-Control` is forced to `private, no-store` (even if upstream set a
  cacheable value);
* `ETag` and `Last-Modified` are stripped, so clients never send
  `If-None-Match` / `If-Modified-Since` for nonce'd pages;
* a `304` that still carries a nonce raises `NonceCacheError` — this means a
  validator leaked from somewhere and the pairing would be broken.

**Cost:** nonce'd pages lose conditional caching and shared-cache reuse
entirely. Every request is a full 200 with a freshly rendered body. This is
the only safe option when nonces are random per request.

## Mode `:pinned`

For pages you *do* want to conditionally cache, the nonce becomes a pure
function of the body:

```
nonce = Base64.urlsafe(HMAC-SHA256(secret, token))
```

where `token` identifies the exact body bytes — typically the content digest
the app also uses as its ETag. Because 200, HEAD and 304 responses for the
same body derive the same nonce, the header nonce always matches the cached
body.

```ruby
use SecureHeaders::NonceCacheMiddleware,
  mode: :pinned,
  secret: Rails.application.key_generator.generate_key("csp-nonce", 32),
  # either a callback...
  token: ->(request) { Page.version_for(request.path) },
  # ...and/or set env[SecureHeaders::NonceCacheMiddleware::TOKEN_KEY]
  # in the app BEFORE the first call to
  # SecureHeaders.content_security_policy_*_nonce
  enforce_token_etag_match: true # optional: require token == response ETag
```

Requirements, verified on every response (violations raise
`NonceCacheError`):

* `secret:` must be configured;
* the token must be set before the first nonce is used (otherwise the error
  is raised at render time);
* the response must carry a **strong** ETag (weak `W/` validators do not
  guarantee byte-identical bodies);
* `Cache-Control: no-store` contradicts `:pinned` and is rejected;
* with `enforce_token_etag_match: true`, the token must equal the response
  ETag, proving the token tracks the body.

**Costs and limits:**

* the app must compute a token that changes exactly when the body changes —
  the library cannot verify this without reading the body
  (`enforce_token_etag_match` covers the common case where token == ETag);
* rotating `secret` changes every nonce for unchanged bodies, so it must be
  deployed together with a cache-key/ETag bump, otherwise clients holding
  cached bodies would receive mismatched 304 headers;
* CSP *directive* changes are safe: the nonce does not depend on the
  directives, so a redeploy that only changes the policy still pairs
  correctly with cached bodies (the client picks up the new policy on the
  next 304/200).

## Detectable error combinations (both modes)

* the CSP header contains a nonce secure_headers did not generate for this
  request (e.g. an upstream CSP survived an opt-out) → `NonceCacheError`;
* the CSP header nonce differs from this request's nonce → `NonceCacheError`;
* `:no_store` + a 304 carrying a nonce → `NonceCacheError`;
* `:pinned` without secret/token/strong-ETag, or with `no-store` →
  `NonceCacheError` (or `ArgumentError` at boot for a missing secret).

See `spec/lib/secure_headers/nonce_cache_middleware_spec.rb` for a full
request round trip against an in-memory Rack app: first read, conditional
hit (304), HEAD, and a re-read after a CSP config change.
