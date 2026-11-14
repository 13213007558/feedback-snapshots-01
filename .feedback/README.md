# Local preparation

Upstream: https://github.com/ruby/net-smtp
Upstream commit: 565716a1fe4671889b7baaa9210951b62534651c

Runtime: Ruby 4.0.7 (tested on macOS arm64). The project source is unchanged.

Prepare independent dependencies:

```sh
ruby .feedback/prepare.rb
```

Run the fast baseline:

```sh
bundle exec ruby -Ilib:test -e '%w[test_response test_sslcontext].each { |f| require_relative '"'"'test/net/smtp/'"'"'+f }'
```

The baseline passed in 0.346 seconds on the preparation machine. This is an existing-test subset, not a solution or task acceptance test. Detailed output is retained in the batch preparation log.

Each execution workspace has its own Bundler directory. The optional argument to prepare.rb is a matching local source-cache path; dependencies are copied, never linked. No external service is needed for this baseline.

Offline public standards are available under `.feedback/specs/`; `index.json` records their official source URLs and hashes. These are reference documents, not task solutions. Original notices are retained.
