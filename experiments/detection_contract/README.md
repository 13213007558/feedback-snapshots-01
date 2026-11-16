# Detection contract experiment

Two runnable entry points:

```bash
# Compare the legacy is_*_volume smell tests against the evidence contract over 44 cases.
python experiments/detection_contract/run.py --json experiments/detection_contract/results/report.json

# Inspect a single file (add --passphrase / --recovery-password / --bek to verify a key).
python experiments/detection_contract/inspect_volume.py volume.img
```

`run.py` exits non-zero if any contract assertion fails. The cases cover:

- high entropy ordinary files: random bytes (sector aligned and not), gzip, zeros, ASCII
- empty input and truncated headers for all three formats
- valid BitLocker (including decrypted and suspended states), LUKS1, LUKS2 (pbkdf2 and argon2),
  and VeraCrypt (SHA-512 and SHA-256) test volumes
- spoofed headers: LUKS magic with zeros/garbage, corrupted LUKS2 checksum, a `VERA` prefix,
  a BitLocker OEM string with no information block
- conflicting candidates where the legacy VeraCrypt detector fires purely from entropy

Assertions are safety properties, not exact strings: a case lists acceptable conclusions and
forbidden format claims. That is what guarantees "random bytes" can never become a VeraCrypt
finding, regardless of where the entropy threshold moves.

The report records, per case, the output of every legacy detector, whether each detector restored
the stream position, the contract result, and the evidence trail. `results/` is generated output and
is not tracked.

Expected environment note: without a native Argon2 build or `argon2-cffi`, LUKS2 volumes that use
Argon2 are still `header_recognized` but with `supported=false` and `limitation=environment`. The
harness treats that as acceptable; the contract does not downgrade it to `not_encrypted`.
