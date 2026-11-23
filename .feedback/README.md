# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'dry/validation'"'"'; raise '"'"'fixture assertion failed'"'"' unless (Dry::Validation::Contract && Dry::Validation::Result); puts '"'"'dry-validation in-process baseline passed'"'"''
```
