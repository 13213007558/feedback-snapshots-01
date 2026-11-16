# Local preparation: cookie

Ruby 4.0.7. Run `ruby .feedback/install.rb`, then `ruby .feedback/baseline.rb`. Dependencies are installed into this workspace only, in `.gems/`; exact versions are in `.feedback/gems.json`. The baseline runs the original upstream unit tests. No remote services are used.

Upstream: https://github.com/sparklemotion/http-cookie, commit c9815408798151e2484cce2548b8fa9f1bc943fc.

The baseline exercises the existing portable HashStore tests. The optional sqlite3 store is not installed or asserted by this preparation.

The baseline exercises the existing portable HashStore tests. The optional sqlite3 store is not installed or asserted by this preparation.
