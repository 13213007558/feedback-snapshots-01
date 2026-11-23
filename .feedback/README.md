# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'rack/attack'"'"'; raise '"'"'fixture assertion failed'"'"' unless (Rack::Attack.throttles.is_a?(Hash)); puts '"'"'rack-attack in-process baseline passed'"'"''
```
