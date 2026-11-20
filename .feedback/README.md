# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh rspec -r active_record -Ispec spec/cancan/ability_spec.rb spec/cancan/controller_resource_spec.rb spec/cancan/model_adapters/active_record_adapter_spec.rb
```
