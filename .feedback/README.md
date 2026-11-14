# Environment preparation

Upstream: https://github.com/ruby/net-imap

Upstream commit: `1fac7f2166528622adb98ceadf020628e23e4956`

Runtime used for validation: Ruby 4.0.7. Install Bundler for this Ruby version.

From the repository root:

```sh
ruby .feedback/prepare.rb
env SIMPLECOV_DISABLE=1 bundle exec ruby -Ilib:test -r./test/lib/helper -e '%w[test_authenticators test_saslprep test_response_reader test_command_data].each { |f| require_relative '"'"'test/net/imap/'"'"' + f }'
```

Dependencies are pinned in `.feedback/Gemfile.lock` and installed into this checkout. The baseline uses existing upstream tests; their pending/skipped cases are reported by the test runner. No task implementation is included in this preparation commit.
