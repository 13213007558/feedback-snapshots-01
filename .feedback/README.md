# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'sidekiq'"'"'; require '"'"'sidekiq/client'"'"'; c=Class.new { include Sidekiq::Job }; raise unless Sidekiq::VERSION && c.respond_to?(:perform_async) && Sidekiq::Client.instance_methods.include?(:push_bulk); x=Object.new.extend(Sidekiq::JobUtil).normalize_item({'"'"'class'"'"'=>'"'"'FixtureJob'"'"','"'"'args'"'"'=>['"'"'ok'"'"']}); raise unless x['"'"'queue'"'"']=='"'"'default'"'"' && x.fetch('"'"'jid'"'"').size==24; puts '"'"'Sidekiq local job normalization passed'"'"''
```
