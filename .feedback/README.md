# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -Ilib -e 'ARGV.each { |p| require_relative p }; ARGV.clear' spec/plugin/sessions_spec.rb spec/plugin/route_csrf_spec.rb spec/plugin/host_authorization_spec.rb spec/plugin/content_security_policy_spec.rb
```
