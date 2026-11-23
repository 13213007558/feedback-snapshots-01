# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'database_cleaner/core'"'"'; raise '"'"'fixture assertion failed'"'"' unless (DatabaseCleaner[:example]); puts '"'"'database_cleaner-core in-process baseline passed'"'"''
```
