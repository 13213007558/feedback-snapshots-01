# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'rack/cors'"'"'; raise '"'"'fixture assertion failed'"'"' unless (Rack::Cors && Rack::Cors::Resource); puts '"'"'rack-cors in-process baseline passed'"'"''
```
