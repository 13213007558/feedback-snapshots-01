# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'graphql'"'"'; raise '"'"'fixture assertion failed'"'"' unless (GraphQL::Schema && GraphQL.parse('"'"'{ sample }'"'"').definitions.size==1); puts '"'"'graphql in-process baseline passed'"'"''
```
