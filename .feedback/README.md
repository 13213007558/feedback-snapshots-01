# Local preparation

Upstream: https://github.com/ruby/rexml
Upstream commit: 0fee9c5bfab3ae311ed5958ec760db19a2c95eeb

Runtime: Ruby 4.0.7 (tested on macOS arm64). The project source is unchanged.

Prepare independent dependencies:

```sh
ruby .feedback/prepare.rb
```

Run the fast baseline:

```sh
bundle exec ruby -Ilib:test -e 'require_relative '"'"'test/helper'"'"'; %w[test/test_document.rb test/test_entity.rb test/test_xpath_parser.rb test/test_namespace.rb test/test_pullparser.rb test/test_sax.rb].each { |f| require_relative f }'
```

The baseline passed in 0.406 seconds on the preparation machine. This is an existing-test subset, not a solution or task acceptance test. Detailed output is retained in the batch preparation log.

Each execution workspace has its own Bundler directory. The optional argument to prepare.rb is a matching local source-cache path; dependencies are copied, never linked. No external service is needed for this baseline.

Offline public standards are available under `.feedback/specs/`; `index.json` records their official source URLs and hashes. These are reference documents, not task solutions. Original notices are retained.
