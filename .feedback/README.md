# Local preparation

Upstream: https://github.com/rgrove/sanitize
Upstream commit: 22196ef9786845036948960f1cc481ce23db3ca6

Runtime: Ruby 4.0.7 (tested on macOS arm64). The project source is unchanged.

Prepare independent dependencies:

```sh
ruby .feedback/prepare.rb
```

Run the fast baseline:

```sh
bundle exec ruby -Ilib:test -e 'Dir['"'"'test/test_*.rb'"'"'].sort.each { |f| require_relative f }'
```

The baseline passed in 0.994 seconds on the preparation machine. This is an existing-test subset, not a solution or task acceptance test. Detailed output is retained in the batch preparation log.

Each execution workspace has its own Bundler directory. The optional argument to prepare.rb is a matching local source-cache path; dependencies are copied, never linked. No external service is needed for this baseline.
