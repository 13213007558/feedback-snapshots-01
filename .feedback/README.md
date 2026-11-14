# Environment preparation

Upstream: https://github.com/github/secure_headers

Upstream commit: `ba4e43b830b3e7935e09a7b93300f9fdad7c91f1`

Runtime used for validation: Ruby 4.0.7. Install Bundler for this Ruby version.

From the repository root:

```sh
ruby .feedback/prepare.rb
env -u CI -u COVERALLS_RUN_LOCALLY bundle exec rspec spec
```

Dependencies are pinned in `.feedback/Gemfile.lock` and installed into this checkout. The baseline uses existing upstream tests; their pending/skipped cases are reported by the test runner. No task implementation is included in this preparation commit.
