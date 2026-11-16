# Encrypted volume detection contract

This document defines what `dissect.fve.detect` is allowed to claim, what evidence backs each
claim, and where each claim stops being justified. It exists so an upstream evidence-ingestion
service can store detection output without turning a guess into a confirmed investigative fact.

## Why the contract exists

The legacy entry points answer a boolean question with a smell test:

| Function | Signal it actually uses |
| --- | --- |
| `is_bde_volume` | boot sector parses (`c_bde.BOOT_SECTOR`) |
| `is_luks_volume` | `LUKS\xba\xbe` at offset 0 or a secondary magic at a known offset |
| `is_veracrypt_volume` | stream size is a multiple of 512 **and** Shannon entropy of the first 4 KiB > 7.9 |

These are cheap, but they conflate very different strengths of evidence. In particular
`is_veracrypt_volume` returns `True` for any 4 KiB of random bytes, and `is_luks_volume` returns
`True` for a bare magic string with no valid header behind it. A boolean cannot express
"unsupported", so a build that cannot handle a variant either crashes or (worse) reports the volume
as unencrypted.

The experiment in `experiments/detection_contract/run.py` demonstrates both failure modes on a
44-case corpus; the pre-change behavior is summarized below.

## Vocabulary

Three positive conclusions, ordered by strength:

1. `POSSIBLY_ENCRYPTED` — a statistical observation only. The bytes are consistent with ciphertext
   (high entropy, sector-aligned size). **No format is named.** This is a lead, never a finding.
2. `HEADER_RECOGNIZED` — a specific format's header was parsed and its own integrity check (if the
   format has one) passed. Strong evidence of *format identity*, still no proof that any supplied
   key belongs to the volume.
3. `KEY_VERIFIED` — an authorized key cryptographically proved membership: BitLocker VMK/FVEK
   authentication, a LUKS keyslot digest match, or a VeraCrypt header that decrypted to `VERA` with
   both CRC32 fields matching.

Three non-claims, so that absence of a result is not recorded as a negative finding:

- `UNSUPPORTED_FORMAT` — the container was recognized but this build cannot process the variant
  (unknown FVEK type, unsupported cipher, missing Argon2 backend, ...). Never downgrade to
  "not encrypted".
- `NOT_ENCRYPTED` — positive evidence of a plaintext structure (NTFS/FAT/exFAT/ReFS boot sector,
  MBR partition table, GPT header) and no format claim. This is an observation about *this* volume,
  not proof that the medium contains no encrypted data elsewhere.
- `INCONCLUSIVE` — too few bytes or no recognizable signal. The default when nothing can be said.

Support status is orthogonal: a `HEADER_RECOGNIZED` result whose `supported` is `false` means the
format was identified but the variant is beyond this build. This is what prevents "we recognized it
but cannot open it" from being flattened into either "encrypted" or "plaintext".

## Evidence matrix

Each conclusion requires the evidence in its row. Missing evidence demotes the conclusion; it never
silently upgrades it.

| Conclusion | Format | Required evidence | Explicitly insufficient |
| --- | --- | --- | --- |
| `POSSIBLY_ENCRYPTED` | none | `ENTROPY` over a full sample; optionally sector-aligned size | entropy of a short/truncated sample names no format |
| `HEADER_RECOGNIZED` | BitLocker | `-FVE-FS-` OEM or information GUID **and** a parseable `FVE_INFORMATION` block whose CRC32 matches | OEM string alone; GUID alone; boot sector that parses but references an unreadable block |
| `HEADER_RECOGNIZED` | LUKS1 | magic + version 1 + plausible cipher/mode/hash/key size/uuid in the 1024-byte header | magic + version only |
| `HEADER_RECOGNIZED` | LUKS2 | magic + version 2 + plausible `hdr_size`/`hdr_offset` + checksum over binary header and JSON area + parseable JSON | magic only; checksum mismatch; truncated JSON |
| `KEY_VERIFIED` | BitLocker | `BDE.unlock*` authenticated the VMK/FVEK (AES-CCM `decrypt_and_verify`) | a wrong passphrase; merely having a recovery password datum |
| `KEY_VERIFIED` | LUKS | derived volume key matched a keyslot digest | successful parse; a keyslot that merely exists |
| `KEY_VERIFIED` | VeraCrypt | decrypted header contains `VERA` **and** CRC32(192:448) matches **and** CRC32(0:188) matches | entropy; the ASCII string `VERA` in plaintext; header decrypted but CRCs wrong |
| `UNSUPPORTED_FORMAT` | any | A `HEADER_RECOGNIZED` level of structural evidence **plus** a named limitation | absence of a parser for a format nobody looked for |
| `NOT_ENCRYPTED` | none | a `PLAINTEXT_STRUCTURE` marker and no format claim | low entropy alone (could be an encrypted header region) |

## Misclassification boundaries

- **Entropy is not identification.** `POSSIBLY_ENCRYPTED` never carries a format. A VeraCrypt
  candidate exists in the result, but with `format=None` and `conclusion=POSSIBLY_ENCRYPTED`; the
  candidate-level `format` field stays `null`. Only `detect(..., key_material=...)` or the
  `detect_veracrypt` helper can produce a VeraCrypt claim.
- **A magic string is not a header.** LUKS requires a plausible version and, for LUKS2, a verified
  checksum over the JSON area. A `LUKS\xba\xbe` prefix followed by garbage or zeros is
  `INCONCLUSIVE`, even though the legacy detector says `True`.
- **Truncation never promotes.** If the integrity region is incomplete (BitLocker information block
  past EOF, LUKS1 header shorter than 1024 bytes, LUKS2 JSON area incomplete), the result stays
  `INCONCLUSIVE` with a `TRUNCATED` evidence entry. A forensic partial image is not a header claim.
- **Unsupported is not plaintext.** `UNSUPPORTED_FORMAT` is only emitted after structural evidence
  reached header strength. The `supported` flag and a `limitation` detail (`implementation` vs
  `environment`) record why. Callers must not map it to `NOT_ENCRYPTED`.
- **Conflicts are surfaced, not resolved.** Two formats at equal strength produce
  `ambiguous=True`, `format=None` and a `confirmed_format` of `None`. Two verified formats produce
  `HEADER_RECOGNIZED` with a warning rather than picking one. Downstream must treat this as
  "needs manual review".
- **Plaintext markers are format-scoped.** `LUKS\xba\xbe` is deliberately *not* a plaintext marker;
  it is a container signature handled by the LUKS probe.
- **BitLocker DECRYPTED state** is still a recognized BitLocker container (state 1, FVEK type NONE),
  not an unsupported format. This matters for volumes that were decrypted in place.

## API shape

```python
from dissect.fve.detect import detect

result = detect(
    fh,
    offset=0,             # volume start inside the stream
    size=None,            # volume length; defaults to remaining bytes
    formats=None,         # subset of Format members or their string values, e.g. ["luks"]
    key_material=None,    # optional; see below
    veracrypt_is_system=False,
)

result.conclusion          # Conclusion
result.format              # Format | None, only when exactly one format is implicated
result.confirmed_format    # None when ambiguous
result.key_verified        # bool
result.ambiguous           # bool
result.candidates          # per-format evidence trails
result.verifications       # per-format authorized-key attempts
result.plaintext_markers   # e.g. ["NTFS"]
result.to_dict() / to_json()
```

A runnable inspection CLI lives at `experiments/detection_contract/inspect_volume.py`:

```bash
python experiments/detection_contract/inspect_volume.py volume.img --passphrase hunter2
```

It exits `0` on success, `1` if a file cannot be read, and `2` when a supplied key was rejected.

`key_material` is a mapping. Recognized keys:

| Key | Used for |
| --- | --- |
| `passphrase` | BitLocker, LUKS, VeraCrypt |
| `pim` | VeraCrypt |
| `recovery_password` | BitLocker |
| `bek`, `external_key`, `fvek` | BitLocker |
| `key_file` | LUKS |
| `volume_key` + `keyslot` | LUKS |

Verification only runs against formats that already have a plausible claim, except VeraCrypt, which
has no plaintext header: a supplied passphrase/header key is itself the trigger when no other format
claimed the stream. Failed verification never lowers a `HEADER_RECOGNIZED` result and never raises.

Verification statuses are distinct so a caller cannot confuse them:

| Status | Meaning |
| --- | --- |
| `verified` | the key authenticated against the volume; the only state that may become `KEY_VERIFIED` |
| `rejected` | the key was consumed and failed authentication |
| `unsupported` | the variant or backend needed to check the key is unavailable (e.g. no Argon2) |
| `not_applicable` | there is nothing to verify (a BitLocker volume already in the DECRYPTED state) |
| `error` | an unexpected exception was caught; it is not a rejection |

Format-specific key material that does not match any credible candidate produces a warning rather
than a verification attempt, so a LUKS recovery password does not show up as a BitLocker rejection.

## Position and failure handling

Every probe decorates itself with `_position_safe` and restores the stream position in a `finally`
block, so calling a probe directly is safe as well. `detect` additionally restores the outer
position and reports `position_preserved=False` instead of raising if restoration fails. An
unseekable stream yields `INCONCLUSIVE` with a warning and `position_preserved=False`; it does not
throw. Probe exceptions are captured per format in `probe_errors` and do not abort the other probes.

The experiment asserts position preservation for every legacy detector and for the contract on every
case, including empty input and all truncations.

## Observed legacy behavior (from the experiment)

| Input | `is_bde_volume` | `is_luks_volume` | `is_veracrypt_volume` | Contract |
| --- | --- | --- | --- | --- |
| empty / truncated boot sector | `EOFError` | `False` | `False` | `INCONCLUSIVE` |
| 4 KiB random bytes | `False` | `False` | **`True`** | `POSSIBLY_ENCRYPTED`, no format |
| `LUKS\xba\xbe` + zeros | `False` | **`True`** | `False` | `INCONCLUSIVE` |
| LUKS2 with corrupted checksum | `False` | **`True`** | `False` | `INCONCLUSIVE` |
| valid VeraCrypt without a key | `False` | `False` | `True` | `POSSIBLY_ENCRYPTED`, no format |
| valid VeraCrypt with the key | — | — | — | `KEY_VERIFIED` |

The legacy VeraCrypt detector has four false positives in the corpus; the legacy LUKS detector has
four single-signal positives. The legacy BitLocker detector raises `EOFError` on 12 truncated or
empty inputs. The contract has zero assertion violations and zero position failures.

## What is intentionally not implemented

- No key derivation in probes; detection stays cheap and secret-free.
- No new decryption backends. Unsupported ciphers/KDFs are reported as `UNSUPPORTED_FORMAT` with a
  `limitation` reason instead of being implemented.
- No claim about hidden VeraCrypt volumes, LUKS2 integrity segments, or AES-XTS key sizes beyond
  what `dissect.fve` already supports.
