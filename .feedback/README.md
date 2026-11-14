# Local preparation

Upstream: https://github.com/ruby/psych
Upstream commit: 8aafb2f6ff103a28d05c2649cd559058f9bc7caa

Runtime: Ruby 4.0.7 (tested on macOS arm64). The project source is unchanged.

Prepare independent dependencies:

```sh
ruby .feedback/prepare.rb
```

Run the fast baseline:

```sh
bundle exec ruby -Ilib:test -e '%w[test_safe_load test_alias_and_anchor test_coder test_document].each { |f| require_relative '"'"'test/psych/'"'"'+f }'
```

The baseline passed in 1.428 seconds on the preparation machine. This is an existing-test subset, not a solution or task acceptance test. Detailed output is retained in the batch preparation log.

Each execution workspace has its own Bundler directory. The optional argument to prepare.rb is a matching local source-cache path; dependencies are copied, never linked. No external service is needed for this baseline.

The native extension is built from this checkout with the local C compiler and libyaml at /opt/homebrew/opt/libyaml. Build output is private and ignored by Git.

Offline public standards are available under `.feedback/specs/`; `index.json` records their official source URLs and hashes. These are reference documents, not task solutions. Original notices are retained.
