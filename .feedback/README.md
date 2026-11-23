# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'connection_pool'"'"'; raise '"'"'fixture assertion failed'"'"' unless (ConnectionPool.new(size: 1){'"'"'local'"'"'}.with{|x|x}=='"'"'local'"'"'); puts '"'"'connection_pool in-process baseline passed'"'"''
```
