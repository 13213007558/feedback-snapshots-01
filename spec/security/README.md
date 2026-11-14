# Phase-order security tests

`spec/omniauth/strategy/phase_order_spec.rb` records the events each request
actually produces, using a minimal strategy that logs its phases, plus the
hooks and downstream app the tests install. The same run writes
`phase_order_trace.md`, the current phase timeline, so the ordering can be
reviewed without reading the implementation.

The tests cover the request, callback, OPTIONS, non-auth, `other_phase`, and
test-mode paths, and the security relationships between request validation,
setup, callback state restoration, auth-hash writing, and failure handling.

`phase_order_mutations.rb` proves the ordering tests have teeth. It copies
`lib/` and the ordering spec into a temporary directory, applies one
order-changing mutation at a time, and fails if either mutation survives:

```sh
bundle exec rspec spec/omniauth/strategy/phase_order_spec.rb
bundle exec ruby spec/security/phase_order_mutations.rb
```

The two mutations move only existing lines:

1. Write `omniauth.params` before running `request_validation_phase`, so a
   rejected request stores attacker-controlled params.
2. Write the mocked auth hash before `before_callback_phase` in test mode, so
   a failing callback hook leaves a successful auth hash behind.
