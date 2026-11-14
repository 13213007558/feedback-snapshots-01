# Environment preparation

Upstream: https://github.com/rack/rack-attack

Upstream commit: `6e417ab3cacda0d3a604b625bb13dd0918816a82`

Runtime used for validation: Ruby 4.0.7. Install Bundler for this Ruby version.

From the repository root:

```sh
ruby .feedback/prepare.rb
bundle exec ruby -Ilib:spec -e '%w[spec/rack_attack_spec.rb spec/rack_attack_throttle_spec.rb spec/fail2ban_spec.rb spec/allow2ban_spec.rb spec/rack_attack_request_spec.rb spec/configuration_spec.rb].each { |f| require_relative f }'
```

Dependencies are pinned in `.feedback/Gemfile.lock` and installed into this checkout. The baseline uses existing upstream tests; their pending/skipped cases are reported by the test runner. No task implementation is included in this preparation commit.
