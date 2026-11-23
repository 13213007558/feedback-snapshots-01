# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'secure_headers'"'"'; raise '"'"'fixture assertion failed'"'"' unless (SecureHeaders::Configuration && SecureHeaders::Middleware); puts '"'"'secure_headers in-process baseline passed'"'"''
```
