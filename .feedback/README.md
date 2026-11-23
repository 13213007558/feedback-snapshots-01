# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'oauth2'"'"'; raise '"'"'fixture assertion failed'"'"' unless (OAuth2::Client && OAuth2::AccessToken); puts '"'"'oauth2 in-process baseline passed'"'"''
```
