# SEC7558 scenario: scoped CurrentAttributes persistence

These scripts are **not** part of the Sidekiq test suite. They verify the
CurrentAttributes field-allowlist behavior end to end inside the locked local
environment, which does not include Redis, Active Job or Railties.

- `current_attributes_policy_scenario.rb` — full lifecycle scenario:
  1. enqueue a job with a broad request context and inspect the persisted
     message,
  2. fail the first execution and capture the message Sidekiq stores in the
     retry set (via the real `Sidekiq::JobRetry` against an in-memory fake),
  3. narrow the persistence policy before the retry,
  4. retry the same job and assert only still-approved fields are visible,
  5. process an unrelated job in a recycled worker thread and assert no
     context leaks across jobs or remains on the thread afterward,
  6. confirm the monitoring observer can still correlate the approved
     `request_id` while the disallowed secret is never observed.
- `run_current_attributes_tests.rb` — runs the real
  `test/current_attributes_test.rb` unchanged using the minimal shims below.
- `shim/active_job/arguments.rb` — local stand-in for `ActiveJob::Arguments`
  (only the serialize/deserialize contract used by the middleware).
- `shim/test/helper.rb` — minimal replacement for `test/helper.rb` providing
  `reset!` and a Rails reloader that resets CurrentAttributes around work.

Run from the repository root:

```sh
sh .feedback/ruby-env.sh ruby .feedback/scenario/current_attributes_policy_scenario.rb
sh .feedback/ruby-env.sh ruby .feedback/scenario/run_current_attributes_tests.rb
```
