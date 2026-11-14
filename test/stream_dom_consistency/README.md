# Streaming-filter vs DOM text-consistency harness

This directory holds a seeded differential generator for the class of bug
where a streaming security filter and the business DOM reader disagree about
what characters an XML document contains.  The motivating sequence is a
banned token written with character references, CDATA, line endings, or a
different encoding: the stream sees one string, `REXML::Document` sees
another.

The harness lives in `test/test_stream_dom_consistency.rb` and is run by the
normal test suite.  Nothing here is wired into the library; it only exercises
the public APIs.

## What is compared

Two independent readers, both taken from REXML's real public paths:

- **Stream**: `REXML::Parsers::StreamParser` with a `StreamListener`.  This is
  what a SAX-style filter consumes: `text` and `cdata` callbacks.
- **DOM**: `REXML::Document` (TreeParser), read the way business code reads
  it: `Element#text`, child `Text`/`CData` values, and attribute values.
  `XPath.string(.)` returns the same character sequence.

Comparison is on the **joined character sequence per logical channel**
(text, CDATA, attributes).  Event counts are normalized away first: adjacent
text is merged exactly as the DOM merges it (`NodeNormalizer`), while a CDATA
section stays its own node.  A test that fails because one parser emitted
`text("ab")` and the other `text("a"), text("b")` is a bug in the harness, not
in the product; `test_event_chunking_is_never_treated_as_an_error` guards that.

## What the oracle is

`Expected.compute` is a specification oracle.  It computes the character
sequence from the generated token tree using XML 1.0 rules and **never runs
REXML**:

- literal CR and CRLF normalize to LF before anything else;
- character references denote code points, are exempt from line-end
  normalization, and are checked against the XML `Char` production
  (including rejecting surrogate and non-character values);
- literal `&` and literal `<` in text are not character data;
- a `]]>` inside one CDATA section is malformed;
- attribute values use the XML attribute-value normalization (literal
  tab/LF/CR become a space, references are exempt);
- declared encodings are strict: a non-UTF-8 byte stream requires a
  matching declaration, a UTF-16 document requires a BOM, and a BOM that
  contradicts the declaration is an error.

## Why two implementations cannot certify each other

Checks run in three layers:

1. **Per-side conformance.**  Each reader is compared with the oracle
   independently.  Accepting a document the oracle rejects, or rejecting a
   document it accepts, is an error on that side alone.
2. **Reader-vs-reader.**  The filter and business strings are compared with
   each other.  Divergence is an error.
3. **Consent rule.**  Agreement is not evidence:
   - If the oracle says a **well-formed** document must be rejected but both
     readers allow it, that is `policy_shared_bypass`.  Both were fooled in
     the same direction, which is precisely the dangerous case.
   - If both readers reject but at least one consumed a byte-for-byte
     spec-correct string, the rejection is accepted.  If neither did, it is
     `policy_shared_false_positive`: two wrong readings agreeing is not
     validation.
   - When both readers agree with each other but disagree with XML
     (`shared_spec_deviation`), the finding is a **warning**, not a pass.
     It stays visible so the deviation is documented rather than silently
     blessed.

Additional rule: if an input never contained U+FFFD,
any U+FFFD in either reader's output is an error (`silent_replacement_character`).
Invalid bytes must be rejected; replacement characters must not turn a failed
decode into a different, possibly authorized, string.

## Seeds, shrinking, replay

- `DEFAULT_SEED` is fixed; `Generator.new(seed:)` reproduces identical bytes.
  The suite asserts both that the same seed reproduces and that different
  seeds do not.
- Every generated case is a token tree (`Case`), not a string.  The shrinker
  removes parts, attributes, entities, and trailing characters, but only
  accepts a reduction if both the oracle status and the finding fingerprints
  are unchanged.  That prevents the minimizer from turning a CDATA-boundary
  bug into an unrelated bare-ampersand case.
- A failing case can be serialized with `Runner.dump_replay(case, path)`.  The
  JSON stores the exact XML **bytes** (base64) *and* the token tree, so replay
  does not depend on the generator, the seed, or the REXML version that
  produced it.  Replay is offline:

      ruby -Ilib test/stream_dom_consistency/bin/replay.rb failure.json

  To eyeball one generated case for a category:

      ruby -Ilib test/stream_dom_consistency/bin/replay.rb --seed 20261114 --category newline

  No sockets, subprocesses, clock, or environment are read.

## Currently known defects (pinned, not suppressed)

`KNOWN_ERROR_FINGERPRINTS` in the test file documents real divergences found
against REXML at the baseline commit, keyed by
`finding-kind|category|channel`.  A companion test fails if an allowlist entry
is no longer reproduced, so entries cannot rot silently:

- `StreamParser` emits CDATA verbatim, without the XML 1.0 line-end
  normalization the DOM applies, so CR inside CDATA diverges.
- `StreamParser` does not expand entity references in attribute values, while
  `Attribute#value` does; a filter inspecting attributes sees `&payload;` and
  business code sees the payload.
- A bare `&` in element text is accepted by the stream path.
- `]]>` inside a CDATA literal is accepted by both (the base parser splits
  at the first `]]>`).

These are pinned as errors because they are exactly the contract this harness
exists to detect.  If a fix lands, delete the entry and its cases; a new
divergence class will not match the list and will fail the suite.

## Limits

- `Document.new` and the streaming consumers share `BaseParser`, so some
  defects (e.g. CDATA splitting at `]]>`) are common-mode.  The shared-deviation
  warning records that instead of pretending agreement is proof.
- Undeclared general entity references are modelled as literal
  (REXML's documented behavior); strict DTD/entity validation is covered by
  the existing entity tests rather than duplicated here.
- The generator intentionally only emits well-formed documents for the
  bug-hunting categories.  Malformed constructs are a separate category whose
  purpose is to prove the oracle does not bless whatever REXML accepts.
