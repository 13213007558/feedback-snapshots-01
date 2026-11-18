# Signature acceptance verification

Executable evidence for `docs/security/signature-acceptance-review.md`.

| File | Purpose |
|---|---|
| `run_review.py` | Builds DigestSha256, HMAC and Ed25519 packets, tampers name/content, scores 20 cases under three policies, and asserts the security claims. |
| `signature_policy.py` | Reference verifier: namespace -> allowed signature types -> algorithm. No fallback to a weaker verifier. |
| `policy.lvs` | Light VerSec publication-authority model with author-to-key binding. |
| `test_review.py` | 16 pytest regressions over the same primitives. |

```bash
.venv/bin/python verification/run_review.py
.venv/bin/python verification/run_review.py --json
.venv/bin/python -m pytest verification -q
```

The baseline upstream suite (`.feedback/baseline.py`) is unaffected: these
artifacts add files and change no library code.
