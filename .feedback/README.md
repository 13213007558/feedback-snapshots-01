# Environment preparation

Upstream: https://github.com/rubysec/bundler-audit

Upstream commit: `1ef637d7a333bdd99cf1d0cbb625d5227364fdc0`

Runtime used for validation: Ruby 4.0.7. Install Bundler for this Ruby version.

From the repository root:

```sh
ruby .feedback/prepare.rb
bundle exec rspec spec/advisory_spec.rb spec/configuration_spec.rb spec/scanner_spec.rb spec/report_spec.rb
```

Dependencies are pinned in `.feedback/Gemfile.lock` and installed into this checkout. The baseline uses existing upstream tests; their pending/skipped cases are reported by the test runner. No task implementation is included in this preparation commit.
