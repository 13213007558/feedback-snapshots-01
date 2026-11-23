# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'rack/unreloader'"'"'; raise '"'"'fixture assertion failed'"'"' unless (Rack::Unreloader.instance_methods.include?(:require)); puts '"'"'rack-unreloader in-process baseline passed'"'"''
```
