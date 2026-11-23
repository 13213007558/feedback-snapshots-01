# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -Ilib -rsanitize -e 'require '"'"'pathname'"'"'; check=Sanitize.fragment('"'"'<p>ordinary</p>'"'"', Sanitize::Config::BASIC); raise '"'"'fixture'"'"' unless check == '"'"'<p>ordinary</p>'"'"' && Sanitize.fragment(check).strip == '"'"'ordinary'"'"'; puts '"'"'Scoped markup policy fixture passed'"'"''
```
