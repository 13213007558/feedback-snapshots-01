# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'excon'"'"'; raise '"'"'fixture assertion failed'"'"' unless (Excon.new('"'"'http://example.invalid'"'"').is_a?(Excon::Connection)); puts '"'"'excon in-process baseline passed'"'"''
```
