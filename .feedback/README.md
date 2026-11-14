# Environment preparation

Upstream: https://github.com/Shopify/liquid

Upstream commit: `4e39ae4cc3da73921923c0669e0fc84a66b2f696`

Runtime used for validation: Ruby 4.0.7. Install Bundler for this Ruby version.

From the repository root:

```sh
ruby .feedback/prepare.rb
bundle exec ruby -Itest -e 'Dir['"'"'test/unit/**/*test.rb'"'"','"'"'test/integration/**/*test.rb'"'"'].sort.each { |f| require_relative f }'
```

Dependencies are pinned in `.feedback/Gemfile.lock` and installed into this checkout. The baseline uses existing upstream tests; their pending/skipped cases are reported by the test runner. No task implementation is included in this preparation commit.
