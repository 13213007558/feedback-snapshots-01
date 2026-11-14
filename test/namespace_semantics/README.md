# Namespace semantics differential harness

This directory compares how REXML's DOM, Pull and SAX APIs expose
namespace-expanded names and attribute values under nested rebinding.
The unit of comparison is **what an authorizing consumer should see**,
never the three APIs' serialized output.

## Why a projection layer

Each API reports names in its own way:

- DOM exposes resolved URIs through `Element#namespace` and
  `Attribute#namespace`, but `#expanded_name` is just the source qname.
- Pull emits lexical events.  An agent that trusts Pull has to maintain
  the in-scope bindings itself.
- SAX calls back with `(uri, local, qname, attributes)`.

Comparing `to_s`, `expanded_name`, or callback hashes directly would
compare representations.  `projections.rb` therefore turns each API into
a sequence of `Record(kind, path, uri, local, value)` values:

- `uri` is the resolved namespace URI, with `nil`/`""` canonicalized to
  "no namespace";
- `local` is the local name with any prefix removed;
- `value` is the attribute value after character-reference expansion;
- `path` is a document-order child index path, so a missing or reordered
  node is visible.

`oracle.rb` computes the same records independently, straight from the
XML Namespaces rules. It never calls a REXML namespace method, so a bug
shared by DOM and Pull cannot mask a bug in SAX, or vice versa.

## Coverage families

`generator.rb` cycles through four hazards:

- `default_undeclare` — withdraw `xmlns` with `xmlns=""` and rebind a
  prefix in the same element; check the descendants and the restored
  siblings.
- `prefix_alias` — bind two prefixes to the same URI, then split them.
- `same_local_attributes` — the same local atom in the trusted, foreign
  and no namespace on one element.
- `sibling_restore` — rebind default and prefix in an inner scope, then
  return to the outer scope.

Documents are legal by construction: a template never emits the same
expanded attribute name twice, because REXML (and XML Namespaces
itself) rejects that as a duplicate.

## Running

```sh
# Generated differential run with a fixed seed
ruby -Ilib:test test/namespace_semantics/replay.rb --seed 7 --cases 16

# Check one document, no generation
ruby -Ilib:test test/namespace_semantics/replay.rb --file failing.xml

# Scope the check to one API
ruby -Ilib:test test/namespace_semantics/replay.rb --seed 7 --api sax
```

A failing generated case is minimized by `runner.rb`'s `Shrinker`:
attributes and subtrees are deleted, then names and values are
simplified, and every candidate must still diverge on its own. The
minimized document is written to disk as plain XML; replay it with
`--file`, which does not touch the generator. That independence is the
point — a reduced sample is the artifact, not the seed.

The command exits non-zero if any case diverges.

## Divergence classes

`RecordDiff.kinds` distinguishes:

- `:name` — the API and the oracle disagree about the namespace URI or
  local name. This is the authorization boundary.
- `:value` — the expanded names agree but the character data does not.
- `:exception` — the API raised where the oracle produced a view.

The split matters: a value-handling bug must not hide a namespace bug.
`Checker.namespace_divergences` and `Checker.value_divergences` expose
them separately.

## Known defect exposed by this harness

`SAX2Parser` calls `BaseParser#normalize` over every attribute value
when namespace listeners are present:

```ruby
event[2].each {|n, v| event[2][n] = @parser.normalize(v)}
```

`normalize` escapes the five predefined entities and every character
reference rather than expanding them. A numeric reference such as
`&#38;` becomes the four-character text `&amp;#38;`. The same rewrite
applies to `xmlns` declaration values, so a namespace URI written with
`&#101;` no longer resolves to the same expanded name as its literal
spelling. DOM and Pull expand the same source correctly.

The two `pend` tests in `harness_test.rb` pin this. They will start
failing (which surfaces the pending) when the SAX behavior changes; at
that point the `pend` wrapper should be removed, not the assertion.

## Mutation demonstration

`BrokenScopeRestore` is a copy of the SAX projection with exactly one
bug: it never pops the binding scope at `end_element`. The test
`test_MUTATION_scope_restore_omitted_is_caught` feeds it a document whose
second sibling must see the outer binding and asserts the harness
reports a name-level divergence there. If a future refactor stopped
checking restoration, that test would fail even though the real parser
still behaved correctly.
