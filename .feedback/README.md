# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh rspec -Ilib spec/faraday/connection_spec.rb spec/faraday/request/authorization_spec.rb spec/faraday/options/proxy_options_spec.rb
```
