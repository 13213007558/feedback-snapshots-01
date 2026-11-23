# Local development setup

Ruby 3.3

Run from the repository root:

```sh
sh .feedback/ruby-env.sh install
sh .feedback/ruby-env.sh ruby -e 'require '"'"'loofah'"'"'; raise '"'"'fixture assertion failed'"'"' unless (Loofah.fragment('"'"'<p>ordinary</p>'"'"').text=='"'"'ordinary'"'"'); puts '"'"'loofah in-process baseline passed'"'"''
```
