# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'async'"'"'; raise '"'"'fixture assertion failed'"'"' unless (Async { |task| task.async { '"'"'local'"'"' }.wait }.wait == '"'"'local'"'"'); puts '"'"'async in-process baseline passed'"'"''
```
