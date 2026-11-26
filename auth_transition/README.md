# Authentication-method transition constraints

This package demonstrates an optional policy layer for an Authlib client that
keeps one registration while migrating from `legacy-record` authentication to
HMAC-signed `signature-record` authentication.

## Guarantees

- Both recording validators return the same `fictional-client-7558` registration.
- Authlib's actual `request.auth_method` is checked, not the client ID alone.
- Privileged issuance (`scope=admin`) requires `signature-record`.
- Legacy authentication can revoke only maintenance operations registered with
  `legacy_allowed=True` while `TransitionWindow.is_open()` is true.
- Closing the window gives an internal `legacy_transition_window_closed`
  decision. The public OAuth body contains only the `invalid_client` category.
- Token records and the append-only ledger retain the actual method and
  assurance tier. A denied legacy privileged request is never recorded as an
  issued privileged approval.

## Run

```sh
.venv/bin/python -m auth_transition
.venv/bin/python -m pytest -q tests/core/test_oauth2/test_auth_method_transition.py
```

`AuthTransitionHarness` wires the policy into a real
`AuthorizationServer`, a `client_credentials` grant, and Authlib's
`RevocationEndpoint`.
