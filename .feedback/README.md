# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -Ilib -e 'ARGV.each { |p| require_relative p }; ARGV.clear' spec/extensions/column_encryption_spec.rb spec/extensions/run_transaction_hooks_spec.rb spec/extensions/transaction_connection_validator_spec.rb spec/core/connection_pool_spec.rb
```
