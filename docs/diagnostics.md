# Signature Explanation Reports (diagnostic use only)

`OAuth::Diagnostic` exists for one situation: a partner reports
`signature_invalid`, and both sides need to compare their OAuth 1.0
normalization pipelines **without exchanging consumer secrets, token secrets,
or full business parameters**.

It produces a *signature explanation report*: a JSON-serializable Hash
breaking the request down by

* HTTP `method`,
* `normalized_uri` (scheme/host/port normalization per spec section 9.1.2),
* `parameters` — one entry per parameter occurrence, with its inferred
  `source` (`authorization_header`, `query`, `option`, or `body_or_other`),
  its escaped name, and its value / escaped value,
* `query_string_pairs` — the raw, still-percent-encoded query pairs, so
  encoding differences are visible before parsing,
* `normalized_parameters` — the normalized parameter string with sensitive
  values replaced by correlation tags,
* HMAC tags of the real normalized parameter string and signature base
  string, so equality can be checked without revealing them.

```ruby
report = OAuth::Diagnostic.explain(
  request, # a request proxy, or a Hash snapshot (safest: no live streams)
  diagnostic_key: session_key,           # see "Diagnostic key scope" below
  sensitive_parameters: %w[account_ref], # business fields you may not disclose
  consumer_secret: consumer_secret,      # optional: reported as tags only
  token_secret: token_secret
)

other = receive_report_from_partner
divergence = OAuth::Diagnostic.first_divergence(report, other)
# => {"path" => "$.query_string_pairs[0].raw_value", "a" => "%7Euser", "b" => "~user"}
```

`OAuth::Diagnostic.diff` returns all divergences in deterministic order, so
the first one is the earliest point at which the two pipelines disagree —
e.g. one side percent-encoding `~` as `%7E`, or collapsing a duplicated
query parameter.

## What is protected, and how

* `oauth_signature`, `oauth_token`, `oauth_token_secret`,
  `oauth_consumer_secret`, `oauth_verifier`, `code`, plus anything in
  `:sensitive_parameters`, are **never** emitted. They appear only as
  *correlation tags*: `HMAC-SHA256(diagnostic_key, context || name || value)`.
* Because tags are **keyed**, a low-entropy value (a boolean, a short ID)
  cannot be recovered by guessing — an unkeyed short hash would allow that,
  which is why this library does not use one.
* Both parties compute tags independently with the same diagnostic key;
  equal tags mean equal inputs, without either side revealing the input.

## Guarantees and limitations

* The diagnostic never signs the request, never generates a nonce or
  timestamp, and never mutates the request or its parameters.
* It never reads request body streams. If your request proxy lazily parses
  a body (e.g. a Rack POST), pass a pre-parsed `Hash` snapshot
  (`{"method" => ..., "uri" => ..., "parameters" => ...}`) instead of the
  live request to be certain no input stream is consumed.
* The report summarizes **unverified** request parameters. A report is not
  a verification result; never treat its contents as trusted input or base
  authorization decisions on it.

## Diagnostic key scope

The diagnostic key is the only thing the two parties must share, and it is
**not** a credential:

* **Generate fresh, per incident.** At least 16 bytes of randomness
  (e.g. `OAuth::Helper.generate_key`). The key is enforced to be at least
  16 bytes; treat 32 bytes as the norm.
* **Share out-of-band.** Use an existing authenticated channel with the
  partner (the same channel you would use to discuss the incident), never
  inside the OAuth-signed request itself.
* **Scope: one debugging session.** The key exists only to make correlation
  tags comparable between the two reports of one incident. Do not reuse it
  across incidents, do not derive other keys from it, and do not use it as
  (or derive it from) the consumer secret, token secret, or any production
  credential.
* **Discard after use.** Once the incident is resolved, both parties delete
  the key. Reports exchanged under a discarded key cannot be re-correlated
  later, which limits their usefulness to anyone who obtains them.
* **Reports are still sensitive.** Tags confirm equality but a report
  reveals parameter names, non-sensitive values, and request shape. Share
  reports only with the partner you are debugging with, over a
  confidential channel, and redact them from tickets and logs when the
  incident closes.
