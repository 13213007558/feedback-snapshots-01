# Read-only IMAP evidence collection prototype

`sample/forensic_collector.rb` is a minimal, self-contained prototype built on
`net-imap`.  It demonstrates collecting the **raw** RFC5322/MIME bytes for one
message by UID, without parsing and re-serializing the message.  Run it with:

```sh
ruby -Ilib sample/forensic_collector.rb
```

The demo starts an in-memory IMAP server on two connected `MemoryDuplex`
objects.  No TCP socket or local port is opened.  The server holds one short
message that contains UTF-8 text, a mix of CRLF and bare LF line endings, a
base64 attachment, and a raw `application/octet-stream` part.  The real
`Net::IMAP` encoder, response parser, and command state machine are used
unchanged.

## What gets recorded

A complete result contains:

- mailbox name, `UIDVALIDITY`, and UID;
- the requested section (`BODY.PEEK[]`) and each standard partial range
  (`BODY.PEEK[]<origin>`);
- `RFC822.SIZE`, total received bytes, and the whole-message SHA-256;
- one entry per chunk: exact request, echoed origin, actual received size,
  response attribute, and chunk SHA-256;
- initial and final flags/MODSEQ.

`run_demo` also returns an audit hash with both the client-sent command log and
the server-received command log, so the two sides can be compared.

`Result#manifest` returns these fields for handing to a signature verifier.
`Result#write_raw(path)` writes the bytes, re-reads the file, checks length and
SHA-256, and returns the manifest with the path.  Neither method works for an
incomplete result.

## How the raw bytes are obtained

1. `EXAMINE <mailbox>` selects the mailbox **read-only**.
2. The client reads `UIDVALIDITY` from the select response.
3. Baseline metadata is fetched with
   `UID FETCH <uid> (UID RFC822.SIZE FLAGS MODSEQ)`.
4. The body is requested as `UID FETCH <uid> BODY.PEEK[]<origin>`.

`BODY.PEEK[]` is the critical part.  A plain `BODY[]` fetch may implicitly set
`\Seen`; `BODY.PEEK[]` must not.  `EXAMINE` is a second, server-enforced
safeguard, but `PEEK` alone is the guarantee at the request level.

Standard IMAP has no byte-count form such as `<origin.count>`.  A partial fetch
returns the suffix from `origin`, and the server may truncate that suffix.  The
prototype therefore:

- checks that the response contains exactly `BODY[]<origin>` for the origin it
  asked for (not merely some `BODY[...]`);
- treats an empty chunk as a stall;
- rejects a chunk larger than the remaining `RFC822.SIZE`;
- requires every chunk to advance the origin by its actual length;
- hashes each chunk immediately; and
- re-reads each origin after the initial pass and compares the prefix SHA-256.

The demo's in-memory server truncates every response to 64 bytes to force
several chunks; a real server may return the whole suffix at once.

## Failure handling

These conditions return `status != :complete` with `source = nil`:

- absent section or `NIL` section;
- a different echoed origin;
- empty/stalled response or overrun;
- wire-level short literal / connection error;
- assembled size mismatch;
- changed UID, size, flags, or MODSEQ;
- missing or short verification response;
- changed chunk digest between reads.

Verified chunks already received stay in `chunks` with their digests, so an
investigator can see where collection stopped.  They are never joined into a
message presented as intact evidence.  `manifest` and `write_raw` raise for
incomplete results.

## What read-only proves, and what it does not

The command log is negative evidence about **this client session**.  The audit
helper flags `STORE`, `EXPUNGE`, `CLOSE`, `APPEND`, `COPY`, `MOVE`, and similar
mutations.  It also flags a body fetch without `.PEEK` (`BODY[]`, `BINARY[]`),
and legacy `RFC822`/`RFC822.TEXT`/`RFC822.HEADER` body fetches, any of which
may set `\Seen`.  `RFC822.SIZE` is metadata and is allowed.

It does **not** prove that the remote mailbox was unchanged during collection.
Another client, a server-side rule, or an administrator can change it
concurrently, and a broken or non-cooperative server may fail to report its own
changes.  `UIDVALIDITY` identifies the mailbox generation; it does not change
when a message is modified.  Compare initial and final `MODSEQ` and re-read
chunks to detect reported changes, and treat "complete" as a statement about
the bytes this session received and verified — not about remote state or chain
of custody.

## Adapting to a real mailbox

Replace the demo construction with a normally connected client:

```ruby
imap = Net::IMAP.new(host, ssl: true)
imap.authenticate("PLAIN", user, password)
result = ForensicIMAP::Collector.new(imap, mailbox: "INBOX", uid: 12345).collect
manifest = result.write_raw("evidence/message.eml") if result.complete?
```

Keep in mind that the in-memory server here is deliberately simple.  Real
servers, TLS policy, authentication, response-size limits, and CONDSTORE
support vary; verify them before treating a result as evidence.
