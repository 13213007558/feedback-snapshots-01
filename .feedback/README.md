# Environment preparation

Upstream: https://github.com/presidentbeef/brakeman

Upstream commit: `4bfdad0c35f3bcedb7c5d97baba98c537e689bf2`

Runtime used for validation: Ruby 4.0.7. Install Bundler for this Ruby version.

From the repository root:

```sh
ruby .feedback/prepare.rb
bundle exec ruby -Itest -e '%w[alias_processor call_index find_return_value rails7].each { |f| require_relative '"'"'test/tests/'"'"' + f }'
```

Dependencies are pinned in `.feedback/Gemfile.lock` and installed into this checkout. The baseline uses existing upstream tests; their pending/skipped cases are reported by the test runner. No task implementation is included in this preparation commit.
