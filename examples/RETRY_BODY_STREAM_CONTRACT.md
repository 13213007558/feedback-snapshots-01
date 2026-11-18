# Retry boundary for `body_stream` requests

Verified on Ruby 4.0.7 / `net-http` 0.9.1 / `net-http-persistent` 4.0.8.
Reproduce with:

```
ruby -Ilib examples/retry_body_stream_contract.rb
ruby -Ilib -Itest test/test_retry_body_stream_contract.rb
```

## Where the retry actually lives

`Net::HTTP::Persistent` has **no retry loop of its own**. It only forwards the
setting to the standard library on every checkout
(`lib/net/http/persistent.rb:657`):

```ruby
http.max_retries = @max_retries if http.respond_to?(:max_retries=)
```

The default is `@max_retries = 1` (`lib/net/http/persistent.rb:523`). The real
decision is in `Net::HTTP#transport_request` (stdlib `net/http.rb:2435`,
method-name test at `net/http.rb:2471`, idempotent list at `net/http.rb:2433`):

```ruby
rescue Net::ReadTimeout, IOError, EOFError,
       Errno::ECONNRESET, Errno::ECONNABORTED, Errno::EPIPE, Errno::ETIMEDOUT,
       OpenSSL::SSL::SSLError, Timeout::Error => exception
  if count < max_retries && IDEMPOTENT_METHODS_.include?(req.method)
    count += 1
    @socket.close if @socket
    retry
  end
  raise
```

Two independent gates must both pass:

1. **Method name gate** — the verb must be in
   `IDEMPOTENT_METHODS_ = %w[GET HEAD PUT DELETE OPTIONS TRACE]`. This is a
   name check only. It says nothing about whether *your* handler is idempotent,
   and nothing about whether the body can be produced a second time.
2. **Exception gate** — the failure must be one of the exceptions listed above.
   `Net::OpenTimeout` is explicitly re-raised, and a connection-level
   `Errno::ECONNREFUSED`/`Errno::EHOSTDOWN` is raised from `connect`, which is
   **outside** this rescue. `Net::HTTP::Persistent` additionally converts those
   two into `Net::HTTP::Persistent::Error` in `connection_for`
   (`lib/net/http/persistent.rb:663`), so they never reach the retry branch.

There is **no third gate** that checks whether the request body can be replayed.

## The body is never rewound

A `body_stream` request is sent with
`IO.copy_stream(f, sock)` (or a `Chunker` wrapper for chunked transfer) in
`Net::HTTPGenericRequest#send_request_with_body_stream`
(stdlib `net/http/generic_request.rb:292`, `copy_stream` at lines 301/304).
Nothing in the retry path calls `rewind` on `f`. On retry the same stream
object is handed to `copy_stream` again from its current offset.

- If the stream was fully read on attempt one, attempt two reads **EOF at once**
  and sends an empty body (Content-Length) or just the `0\r\n\r\n` terminator
  (chunked).
- If it was partially read, attempt two sends only the **remaining suffix**, so
  each TCP connection carries a different, individually incomplete payload.

The 200 response from the second attempt only means "the server answered the
second request"; it is not proof that the original body was delivered.

## Measured outcomes (10-byte body `ABCDEFGHIJ`)

| Scenario | Verb | Stream | Failure point | Retries | Bytes on attempt 1 | Bytes on attempt 2 | Result |
|---|---|---|---|---|---|---|---|
| A | PUT | rewindable | mid-body, after 4 B | 1 | `ABCD` | `` (empty) | 200, body lost |
| B | PUT | forward-only | mid-body, after 4 B | 1 | `ABCD` | `` (empty) | 200, body lost |
| C | PUT | forward-only | mid-body | 0 | `ABCD` | — | `Errno::ECONNRESET` |
| D | POST | forward-only | mid-body | 1 | `ABCD` | — | `Errno::ECONNRESET` (name gate fails) |
| E | PUT | forward-only | connect refused | 1 | none | — | `Net::HTTP::Persistent::Error` |
| F | PUT | forward-only | full body sent, no response | 1 | full 10 B | `` (empty) | 200, body re-sent empty |
| H | PUT | rewindable, chunked | mid-body | 1 | `a\r\nABCDE` | `0\r\n\r\n` | 200, empty chunk |
| M | PUT | metered | two resets | 2 | `ABCD` | `EFGH` then `IJ` | 200, body split across 3 connections |

Key observations:

- **Rewindable vs forward-only behave identically at the wire level.** The
  library does not rewind even when it could. A `StringIO` and a pipe-backed
  stream both yield an empty/suffix replay.
- **The method name is not a safety promise.** A PUT whose server handler
  appends to a log or charges a card is not idempotent in practice, yet it is
  auto-retried. A POST that is idempotent in your API is never auto-retried.
- **"Sent but no response" is the dangerous case.** By the time you get
  `EOFError`/`ECONNRESET` while reading the response, the server may already
  have executed the handler; a retry can execute it again. The client cannot
  tell from the exception alone.

## Three independent questions to answer yourself

Do not collapse these into "it's a GET/PUT so retry is fine":

1. **Is the operation idempotent at the server?** Only your API knows. Map each
   route/verb to an explicit idempotency decision; do not rely on the verb.
2. **Can the request body be replayed byte-for-byte?** A `StringIO`/`File` can
   be rewound by *you*; a pipe, socket, one-shot generator, or already-consumed
   upload stream cannot. `copy_stream` consuming the stream once makes it
   unreadable for the automatic retry.
3. **Might the remote already have executed it?** If any request bytes reached
   the server (mid-body reset, or full body sent before the response was lost),
   execution is possible even though you have no response.

A retry is only safe when all three hold: idempotent handler **and** replayable
body **and** acceptable duplicate execution. The built-in auto-retry checks
none of these.

## Caller patterns

### Explicitly forbid automatic retry

Use this whenever the body is not safely replayable or the handler is not
idempotent. Set it before the request; `0` disables the stdlib retry branch
entirely.

```ruby
persistent = Net::HTTP::Persistent.new(name: 'billing')
persistent.max_retries = 0

req = Net::HTTP::Post.new('/charges')
req['Content-Length'] = payload.bytesize.to_s
req.body_stream = socket_backed_stream   # cannot be rewound

begin
  persistent.request(uri, req)
rescue Errno::ECONNRESET, EOFError, Net::ReadTimeout => e
  # No silent re-send happened. Decide out-of-band whether the charge landed,
  # e.g. query the charge by idempotency key before doing anything else.
end
```

### Explicitly approve and control replay yourself

Turn the automatic retry off and own the loop so every attempt starts from a
fresh, fully readable body. This is the pattern asserted by
`test_caller_driven_rewind_replays_the_full_body`, where attempt two then
carries the complete `ABCDEFGHIJ` instead of an empty body.

```ruby
persistent.max_retries = 0                 # we own retries
stream = StringIO.new(payload)            # genuinely rewindable source
attempts = 0

begin
  attempts += 1
  stream.rewind if attempts > 1           # replay from byte zero every time
  req = Net::HTTP::Put.new('/resource')
  req['Content-Length'] = payload.bytesize.to_s
  req.body_stream = stream
  persistent.request(uri, req)
rescue Errno::ECONNRESET, EOFError => e
  raise unless idempotent_endpoint?       # question 1
  raise if attempts >= 2
  raise unless stream.respond_to?(:rewind) # question 2
  retry
end
```

For a non-rewindable source, buffer it to a `StringIO`/`Tempfile` first, or use
an application-level idempotency key and reconcile by that key rather than
re-sending. Never treat a 200 on the retried connection as confirmation that an
empty/suffix body was accepted — assert the server actually stored the intended
content.
