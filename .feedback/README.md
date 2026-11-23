# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'rexml/document'"'"'; raise '"'"'fixture assertion failed'"'"' unless (REXML::Document.new('"'"'<policy><entry/></policy>'"'"').root.elements['"'"'entry'"'"'].name == '"'"'entry'"'"'); puts '"'"'rexml in-process baseline passed'"'"''
```
