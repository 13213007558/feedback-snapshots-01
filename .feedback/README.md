# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'rails'"'"'; require '"'"'doorkeeper'"'"'; require '"'"'doorkeeper/openid_connect'"'"'; oidc=Doorkeeper::OpenidConnect; built=oidc::ClaimsBuilder.new { normal_claim(:account, scope: :profile) { '"'"'sample'"'"' } }.build; raise unless oidc::IdToken && built.to_h.keys.map(&:to_s).include?('"'"'account'"'"'); puts '"'"'OIDC token and scoped claim builder loaded'"'"''
```
