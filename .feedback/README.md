# Local preparation

Upstream: https://github.com/rack/rack
Upstream commit: da90464e3fa93e3cb49dc2d4ede798e6c6b70b4f

Runtime: Ruby 4.0.7 (tested on macOS arm64). The project source is unchanged.

Prepare independent dependencies:

```sh
ruby .feedback/prepare.rb
```

Run the fast baseline:

```sh
bundle exec ruby -Ilib:test -e '%w[spec_multipart spec_query_parser spec_lint spec_files spec_auth_basic spec_method_override spec_sendfile].each { |f| require_relative '"'"'test/'"'"'+f }'
```

The baseline passed in 0.513 seconds on the preparation machine. This is an existing-test subset, not a solution or task acceptance test. Detailed output is retained in the batch preparation log.

Each execution workspace has its own Bundler directory. The optional argument to prepare.rb is a matching local source-cache path; dependencies are copied, never linked. No external service is needed for this baseline.

Offline public standards are available under `.feedback/specs/`; `index.json` records their official source URLs and hashes. These are reference documents, not task solutions. Original notices are retained.
