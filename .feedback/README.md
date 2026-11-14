# Environment preparation

Upstream: https://github.com/sinatra/sinatra

Upstream commit: `cb22afd7902b566b6eaba6c4ea89739494a65d12`

Runtime used for validation: Ruby 4.0.7. Install Bundler for this Ruby version.

From the repository root:

```sh
ruby .feedback/prepare.rb
bundle exec rspec --options /dev/null --require ./rack-protection/spec/spec_helper.rb rack-protection/spec
```

Dependencies are pinned in `.feedback/Gemfile.lock` and installed into this checkout. The baseline uses existing upstream tests; their pending/skipped cases are reported by the test runner. No task implementation is included in this preparation commit.
