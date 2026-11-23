# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'psych'"'"'; raise '"'"'fixture assertion failed'"'"' unless (Psych.safe_load(Psych.dump({'"'"'team'"'"'=>['"'"'a'"'"','"'"'b'"'"']}))=={'"'"'team'"'"'=>['"'"'a'"'"','"'"'b'"'"']}); puts '"'"'psych in-process baseline passed'"'"''
```
