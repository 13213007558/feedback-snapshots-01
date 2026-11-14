# Differential fuzz: `JWT.decode` (legacy) vs `JWT::EncodedToken` (new)

Differential fuzzing of the two ruby-jwt verification entry points, focused on
compact serialization and verification-failure interpretation. Everything runs
in-process against the local gem; all keys are generated locally (no network, no
external key material).

## Files
- `harness.rb` — both APIs behind **explicitly aligned** security policies; the
  three-dimensional outcome oracle (`accept/reject/crash`, trusted-payload
  readable?, key-finder called?).
- `corpus.rb` — deterministic structural edge cases + a seeded `Random` mutator.
- `run_diff.rb` — divergence detection and classification.
- `main.rb` — campaign entry point (baseline sanity checks + report).
- `replay.rb` — replay a structural id (`seg-2`) or a seeded case (`3:29`).
- `selftest.rb` / `selftest_relaxed.rb` — mutation tests proving oracle
  sensitivity to the segment-count check (strict and relaxed directions).
- `probe_*.rb` — focused demonstrations (defaults, duplicates, detached payload,
  finder arity).

## Run
```
bundle exec ruby -Ilib fuzz/main.rb                 # default seeds 1,2,3
SEEDS=1,2,3,4 PER_SEED=300 bundle exec ruby -Ilib fuzz/main.rb
bundle exec ruby -Ilib fuzz/replay.rb seg-2 dup-alg-reverse
bundle exec ruby -Ilib fuzz/replay.rb --finder seg-2
bundle exec ruby -Ilib fuzz/replay.rb 3:29          # seeded random case
bundle exec ruby -Ilib fuzz/selftest.rb
bundle exec ruby -Ilib fuzz/selftest_relaxed.rb
```

## Mutation surface (all required generators)
segment count (0..5, leading/trailing/consecutive dots), base64url boundaries
(padding, `+`/`/`, space, NUL, unicode, truncation, empty segments), duplicate
JSON members (`alg`, payload keys, `b64`), non-object headers (`[]`, `null`,
numbers, strings, `true`, `{}`, malformed/empty JSON), and detached payload
(empty payload segment, `b64:false`/`crit`, out-of-band re-attachment).

## Policy alignment (done BEFORE comparison)
The two APIs ship different defaults. Legacy `JWT.decode` verifies **both**
`exp` and `nbf` out of the box (`DecodeConfiguration`); `EncodedToken` verifies
**only `exp`** by default (`DEFAULT_CLAIMS`). We therefore pin both to the same
policy: algorithm `HS256`, verify `exp` + `nbf`, every other claim check off,
same HMAC secret. `probe_defaults.rb` shows the raw default disagreement (a
future-`nbf` token is rejected by legacy but accepted by the new default) and
that explicit alignment makes them agree.

Intentional feature differences are not treated as vulnerabilities:
- the new API's detached-payload setter (`encoded_payload=`) has no legacy
  equivalent;
- key-finder arity/argument shape differs (legacy yields `header[, payload]`,
  new yields the `EncodedToken`);
- `verify?` predicates return booleans vs the legacy raise-only entry point.

## Oracle / judgment
For every token we record, per API: verdict (`accept` / `reject` / `crash`),
whether a **trusted** payload is afterwards readable, and whether the
**key-finder callback** fired. A non-`JWT::Error` exception is recorded as a
**crash (robustness bug) and explicitly not counted as a safe rejection**.
Divergence = any mismatch of verdict, trusted-readability, finder invocation, or
(on clean rejections) the concrete exception class.

## Mutation-test evidence that the harness works
- `selftest.rb`: tighten the new API's segment check to the legacy strict
  three-segment rule -> the short-token divergences disappear (2/2 -> 0/2).
- `selftest_relaxed.rb`: deliberately relax the legacy segment gate to the new
  "too many only" rule on a two-segment token -> finder timing aligns and the
  divergence disappears (divergent -> identical).

## Findings summary
Across 3,642 generated cases (12 seeds x 300 + full structural corpus):
**0 crashes, 0 acceptance bypasses, 0 trusted-payload exposures.** Every
divergence is a reject-vs-reject interpretation gap. See `FINDINGS.md`.
