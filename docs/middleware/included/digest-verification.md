# Digest Verification

The `Faraday::Request::DigestVerification` middleware provides an optional
**pre-send check** that confirms the body actually transmitted corresponds to a
version you have already reviewed and approved.

Upload approvals usually work against a digest of the outgoing file, but request
middleware such as [`Json`](json.md) and
[`UrlEncoded`](url-encoding.md) can encode or replace the body after that digest
was recorded. Because of this, the digest must be checked against the *final*
body, immediately before the adapter sends it. Add `:digest_verification`
**last among the request middleware**, directly before the adapter:

```ruby
approved = Digest::SHA256.hexdigest('{"name":"YK"}')

conn = Faraday.new do |builder|
  builder.request :json
  builder.request :digest_verification, approved_digest: approved
  builder.adapter :net_http
end
```

If the final body's digest does not match the approved digest, the request is
aborted before reaching the adapter, so unapproved data is never sent.

### What can be verified

- **Small byte strings** — bodies responding to `#to_str` are digested in
  memory.
- **Ordinary streaming uploads** — bodies responding to `#read` are read in
  chunks and digested. When the body also responds to `#rewind`, it is rewound
  afterwards so the adapter can still send the same bytes.

### When verification is not possible

Some bodies cannot be digested without breaking the upload. In that case the
middleware fails closed and raises `Faraday::UnverifiableBodyError` rather than
sending unverified data:

- a streaming body that responds to `#read` but **cannot be rewound** (reading
  it for verification would consume the bytes the adapter needs),
- a body that is neither a string nor a readable stream,
- a `nil` body when an approved digest was provided.

### Options

| Option | Default | Description |
| --- | --- | --- |
| `approved_digest` | `nil` | The digest the final body must match. May be a `String`, or any object responding to `#call(env)` that returns a digest (or `nil` to skip verification for that request). |
| `algorithm` | `Digest::SHA256` | A Digest class/instance responding to `#new` and `#digest`, used to hash the final body. |

### Errors

- `Faraday::DigestMismatchError` — raised when the final body's digest differs
  from the approved digest.
- `Faraday::UnverifiableBodyError` — raised when an approved digest exists but
  the body cannot be digested reliably.

Both inherit from `Faraday::DigestVerificationError`, so a single `rescue` can
handle every verification failure.

### Dynamic approvals

Pass a callable to resolve the approved digest per request, for example from a
header or a lookup table. Returning `nil` skips verification for that request.

```ruby
conn = Faraday.new do |builder|
  builder.request :digest_verification,
                  approved_digest: ->(env) { env.request_headers.delete('X-Approved-Digest') }
  builder.adapter :test do |stub|
    stub.post('/uploads') { [200, {}, ''] }
  end
end
```
