# Environment preparation

Upstream: https://github.com/omniauth/omniauth

Upstream commit: `a8fa253d844dc161be38c0526362f39f9c03dc4c`

Runtime used for validation: Ruby 4.0.7. Install Bundler for this Ruby version.

From the repository root:

```sh
ruby .feedback/prepare.rb
bundle exec rspec spec
```

Dependencies are pinned in `.feedback/Gemfile.lock` and installed into this checkout. The baseline uses existing upstream tests; their pending/skipped cases are reported by the test runner. No task implementation is included in this preparation commit.
