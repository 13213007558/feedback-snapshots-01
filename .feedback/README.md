# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'hanami/router'"'"'; raise '"'"'fixture assertion failed'"'"' unless (Hanami::Router); puts '"'"'hanami-router in-process baseline passed'"'"''
```
