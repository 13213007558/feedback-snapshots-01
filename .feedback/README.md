# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'httparty'"'"'; raise '"'"'fixture assertion failed'"'"' unless (HTTParty::Request && HTTParty::CookieHash); puts '"'"'httparty in-process baseline passed'"'"''
```
