# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -Ilib -e 'ARGV.each { |p| require_relative p }; ARGV.clear' spec/active_sessions_spec.rb spec/session_expiration_spec.rb spec/remember_spec.rb spec/login_spec.rb
```
