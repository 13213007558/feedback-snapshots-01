# Parser parity fixtures

Small, security-focused Ruby snippets used to verify that migrating Brakeman's
Ruby parsing entry point from `ruby_parser` to Prism
(`Prism::Translation::RubyParser`) does not silently drop vulnerability
warnings.

## Layout

- `both_parsers/` - syntax both parsers accept. Each file carries
  `# SOURCE:` (params input) and `# SINK:` (dangerous call) annotations.
  Tests compare the full Sexp, the node type/line/file skeleton, the alias
  resolved source-to-sink links and the sink locations under both modes.
- `coverage/` - syntax only one parser accepts. The current cases are
  ruby_parser-only (`it` mixed with numbered parameters, which Prism rejects
  natively). These are asserted as an explicit coverage gap: the Prism
  translation raises, `FileParser` falls back to ruby_parser, and the result
  must never be interpreted as "no vulnerability".
- `mutants/` - variants where the dangerous params source node is deliberately
  replaced by a static literal while every sink stays. A mutation test asserts
  the harness detects that the source-to-sink link disappeared, proving it can
  catch a false negative from a broken AST conversion.
- `invalid/` - intentionally unparseable Ruby. Both parser paths must raise
  (fail closed); a parse error or Prism->ruby_parser fallback is recorded as an
  error, never returned as a clean scan.

## What is compared

Not just "does it parse". For shared syntax the tests assert:

1. full Sexp equality, including nested `dstr`/`evstr`, `safe_call`,
   `forward_args` and nested call structure;
2. node type, line and file metadata on every node (warning locations);
3. dangerous sinks (`eval`, `constantize`, `query`, `where`, `find`,
   `public_send`, `relay`, `render`) are present in both conversions;
4. after `Brakeman::AliasProcessor`, each direct sink still contains a params
   source (the annotated source-to-sink relationship);
5. end-to-end warning fingerprints (type, code, source, line, file) match
   across full scans of the rails3.2 through rails8 test apps.

## Rerunning

```sh
# Minitest suite (also runs under TEST_PRISM=1)
bundle exec ruby -Itest test/tests/prism_parser_parity.rb

# Rerunnable diff list with non-zero exit on any divergence
bundle exec ruby test/scripts/prism_parity_diff.rb
```

## Migration switch and compatibility path

`Brakeman::FileParser` keeps the `use_prism` switch (wired to `--[no-]prism`,
default on). When Prism translation raises, it rescues and falls back to
`ruby_parser`; when both fail the exception propagates. Inline ERB
(`TemplateParser.parse_inline_erb`) honors the same switch, so the legacy
parser stays available as the compatibility path while the conversion is
validated.
