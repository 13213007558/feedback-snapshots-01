# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'rack/contrib'"'"'; raise '"'"'fixture assertion failed'"'"' unless (Rack::ETag && Rack::Sendfile); puts '"'"'rack-contrib in-process baseline passed'"'"''
```
