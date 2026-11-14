# Environment preparation

Upstream: https://github.com/net-ssh/net-ssh

Upstream commit: `009799bb8cb27580cb6f58f4ec1a7fc9b53a7e2f`

Runtime used for validation: Ruby 4.0.7. Install Bundler for this Ruby version.

From the repository root:

```sh
ruby .feedback/prepare.rb
bundle exec ruby -Itest -e '%w[test/test_buffer.rb test/test_known_hosts.rb test/test_config.rb test/transport/test_packet_stream.rb].each { |f| require_relative f }'
```

Dependencies are pinned in `.feedback/Gemfile.lock` and installed into this checkout. The baseline uses existing upstream tests; their pending/skipped cases are reported by the test runner. No task implementation is included in this preparation commit.
