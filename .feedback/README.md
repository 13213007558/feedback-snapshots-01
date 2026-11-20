# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -Itest -e 'ARGV.each { |test| require_relative test }' test/http/redirector_test.rb test/http/connection_test.rb test/http/request/writer_test.rb test/http/features/digest_auth_test.rb test/http/response/body_test.rb
```
