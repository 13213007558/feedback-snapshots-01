# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'dry/configurable'"'"'; raise '"'"'fixture assertion failed'"'"' unless (Dry::Configurable && Dry::Configurable::Config); puts '"'"'dry-configurable in-process baseline passed'"'"''
```
