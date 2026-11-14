# Local preparation

Upstream: https://github.com/flavorjones/loofah
Upstream commit: f236a1144d6edffc3bf5af5555eb568c7b0d30c2

Runtime: Ruby 4.0.7 (tested on macOS arm64). The project source is unchanged.

Prepare independent dependencies:

```sh
ruby .feedback/prepare.rb
```

Run the fast baseline:

```sh
bundle exec ruby -Ilib:test -e 'Dir['"'"'test/unit/**/*test*.rb'"'"'].sort.each { |f| require_relative f }'
```

The baseline passed in 1.1 seconds on the preparation machine. This is an existing-test subset, not a solution or task acceptance test. Detailed output is retained in the batch preparation log.

Each execution workspace has its own Bundler directory. The optional argument to prepare.rb is a matching local source-cache path; dependencies are copied, never linked. No external service is needed for this baseline.
