# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -Itest -e 'ARGV.each { |test| require_relative test }' test/net/http/test_http_request.rb test/net/http/test_httpresponse.rb
```
