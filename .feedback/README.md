# Environment preparation

Upstream: https://github.com/ruby-oauth/oauth

Upstream commit: `3e2bd0709e1851d34916d165ab0b240e4b6845cd`

Runtime used for validation: Ruby 4.0.7. Install Bundler for this Ruby version.

From the repository root:

```sh
ruby .feedback/prepare.rb
env CI=1 bundle exec ruby -rcgi -Itest -e '%w[test/units/signature_test.rb test/units/signature_base_test.rb test/units/signature_hmac_sha1_test.rb test/units/signature_hmac_sha256_test.rb test/units/rack_request_proxy_test.rb test/units/consumer_test.rb test/units/request_token_test.rb test/units/access_token_test.rb].each { |f| require_relative f }'
```

Dependencies are pinned in `.feedback/Gemfile.lock` and installed into this checkout. The baseline uses existing upstream tests; their pending/skipped cases are reported by the test runner. No task implementation is included in this preparation commit.
