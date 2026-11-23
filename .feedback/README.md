# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'omniauth-oauth2'"'"'; raise '"'"'fixture assertion failed'"'"' unless (OmniAuth::Strategies::OAuth2); puts '"'"'omniauth-oauth2 in-process baseline passed'"'"''
```
