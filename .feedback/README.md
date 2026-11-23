# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'protocol/http'"'"'; raise '"'"'fixture assertion failed'"'"' unless (Protocol::HTTP::Headers.new && Protocol::HTTP::Request); puts '"'"'protocol-http in-process baseline passed'"'"''
```
