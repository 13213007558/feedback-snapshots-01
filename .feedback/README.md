# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'rack/test'"'"'; raise '"'"'fixture assertion failed'"'"' unless (Rack::Test::Session && Rack::Test::CookieJar); puts '"'"'rack-test in-process baseline passed'"'"''
```
