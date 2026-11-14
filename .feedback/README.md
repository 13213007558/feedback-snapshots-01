# Local preparation

Upstream: https://github.com/ruby-ldap/ruby-net-ldap
Upstream commit: d2a7de3bfac7aed484c9ee1bd616099c277e3cbd

Runtime: Ruby 4.0.7 (tested on macOS arm64). The project source is unchanged.

Prepare independent dependencies:

```sh
ruby .feedback/prepare.rb
```

Run the fast baseline:

```sh
bundle exec ruby -Ilib:test -e 'Dir['"'"'test/test_*.rb'"'"'].sort.each { |f| require_relative f unless f.end_with?('"'"'test_ssl_ber.rb'"'"') }'
```

The baseline passed in 0.29 seconds on the preparation machine. This is an existing-test subset, not a solution or task acceptance test. Detailed output is retained in the batch preparation log.

Each execution workspace has its own Bundler directory. The optional argument to prepare.rb is a matching local source-cache path; dependencies are copied, never linked. No external service is needed for this baseline.

Offline public standards are available under `.feedback/specs/`; `index.json` records their official source URLs and hashes. These are reference documents, not task solutions. Original notices are retained.
