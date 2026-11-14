# Local preparation

Upstream: https://github.com/alexdalitz/dnsruby
Upstream commit: 862befbbd0a2639ec890ade64c9333e7f9d8aabf

Runtime: Ruby 4.0.7 (tested on macOS arm64). The project source is unchanged.

Prepare independent dependencies:

```sh
ruby .feedback/prepare.rb
```

Run the fast baseline:

```sh
bundle exec ruby -Ilib:test -e '%w[tc_message tc_nsec tc_nsec3 tc_rrsig tc_ds tc_tsig_rfc8945 tc_dnssec_trust_anchors].each { |f| require_relative '"'"'test/'"'"'+f }'
```

The baseline passed in 0.573 seconds on the preparation machine. This is an existing-test subset, not a solution or task acceptance test. Detailed output is retained in the batch preparation log.

Each execution workspace has its own Bundler directory. The optional argument to prepare.rb is a matching local source-cache path; dependencies are copied, never linked. No external service is needed for this baseline.

Offline public standards are available under `.feedback/specs/`; `index.json` records their official source URLs and hashes. These are reference documents, not task solutions. Original notices are retained.
