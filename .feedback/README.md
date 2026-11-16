# Local preparation: persistent

Ruby 4.0.7. Run `ruby .feedback/install.rb`, then `ruby .feedback/baseline.rb`. Dependencies are installed into this workspace only, in `.gems/`; exact versions are in `.feedback/gems.json`. The baseline runs the original upstream unit tests. No remote services are used.

Upstream: https://github.com/drbrain/net-http-persistent, commit 66bf49c4cb990b7a5b2a38006bac05da7582796d.
