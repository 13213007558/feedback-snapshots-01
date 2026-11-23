# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'webrick'"'"'; raise '"'"'fixture assertion failed'"'"' unless (WEBrick::HTTPUtils.escape('"'"'a b'"'"').include?('"'"'%20'"'"') && WEBrick::HTTPServer); puts '"'"'webrick in-process baseline passed'"'"''
```
