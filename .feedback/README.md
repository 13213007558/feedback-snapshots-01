# Environment preparation

Upstream: https://github.com/rubyzip/rubyzip

Upstream commit: `3b9c628063068a6a80007f7a4caef477c8bdecf8`

Runtime used for validation: Ruby 4.0.7. Install Bundler for this Ruby version.

From the repository root:

```sh
ruby .feedback/prepare.rb
bundle exec ruby -Ilib:test -e 'Dir['"'"'test/*_test.rb'"'"'].sort.each { |f| require_relative f }'
```

Dependencies are pinned in `.feedback/Gemfile.lock` and installed into this checkout. The baseline uses existing upstream tests; their pending/skipped cases are reported by the test runner. No task implementation is included in this preparation commit.
