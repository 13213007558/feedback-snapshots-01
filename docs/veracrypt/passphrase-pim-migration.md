# VeraCrypt passphrase and PIM contract

This document defines the passphrase byte semantics and the Personal Iterations
Multiplier (PIM) contract used by `dissect.fve.veracrypt`, and shows how to
migrate calls to the legacy `VeraCrypt.unlock_with_passphrase` interface without
relying on encoding guessing.

## Passphrase byte semantics

VeraCrypt turns a typed passphrase into bytes with UTF-8 before running PBKDF2.
Key derivation therefore operates on a specific, reproducible byte sequence.
Trying several encodings in sequence would hide real differences: for example
`"pässwörd"` is 8 bytes in `latin-1` but 10 bytes in UTF-8, and a Japanese
passphrase cannot be encoded with `latin-1` at all. The library never guesses an
encoding; the caller states the semantics explicitly.

Three entry points are provided:

| Entry point | Input | Bytes fed to the KDF |
| --- | --- | --- |
| `unlock_with_text_passphrase(passphrase, pim=None, *, encoding="utf-8")` | `str` | `passphrase.encode(encoding)`, UTF-8 by default |
| `unlock_with_raw_passphrase(passphrase, pim=None)` | `bytes` | the exact byte sequence, untouched |
| `unlock_with_passphrase(passphrase, pim=None)` | legacy | `str` -> `latin-1` (with a `DeprecationWarning`); `bytes` passed through |

The legacy interface stays available so existing investigations remain
reproducible. Its `str` behavior is frozen at the historical `latin-1` encoding;
it does not silently switch to UTF-8.

After a successful unlock the object records what was actually used, without
storing the passphrase or any derived key material:

- `VeraCrypt.passphrase_encoding`: the stated encoding (`"utf-8"`, another codec
  name, `"raw bytes"` or the legacy labels).
- `VeraCrypt.kdf`: the KDF class that decrypted the header.
- `VeraCrypt.kdf_iterations`: the PBKDF2 iteration count derived from the PIM.

## KDF candidates per volume type

Only the KDF candidates applicable to the target volume type are attempted. The
cipher used to decrypt the header still identifies the correct combination, so
no cross-family attempts are made.

| Volume type | Candidates (`dissect.fve.veracrypt.key`) | Default iterations (no PIM) |
| --- | --- | --- |
| File container / non-system partition | `Pkcs5HmacSha512`, `Pkcs5HmacSha256` | 500000 for both |
| System (boot) volume | `Pkcs5HmacSha512_Boot`, `Pkcs5HmacSha256_Boot` | 500000 (SHA-512), 200000 (SHA-256) |

With an explicit, valid PIM the iteration counts are:

- Non-system: `15000 + PIM * 1000`
- System: `PIM * 2048`

## PIM validation contract

Validation runs before any KDF object is used or any PBKDF2 round is computed,
so invalid input never triggers an expensive derivation.

| Input | Non-system volume | System volume | Result |
| --- | --- | --- | --- |
| omitted / `None` | default 500000 | default 500000 / 200000 | accepted, default iterations |
| `0` | rejected | rejected | `ValueError`; use `None` for the default |
| negative | rejected | rejected | `ValueError` |
| below minimum (`< 1` / `< 98`) | rejected when `PIM < 1` | rejected when `PIM < 98` | `ValueError` |
| above the maximum (`> 2**31 - 1`) | rejected | rejected | `ValueError` |
| non-integer (`float`, `str`, `bool`, ...) | rejected | rejected | `TypeError` |

The minimum PIM of 98 for system volumes keeps the resulting iteration count at
or above the default; `0` is reserved internally by VeraCrypt for "use the
default" and is therefore not an accepted explicit value.

## Migrating legacy calls

Legacy call, text passphrase (historical `latin-1` bytes):

```python
vc = VeraCrypt(fh)
vc.unlock_with_passphrase(passphrase_text)
```

Unambiguous replacements:

```python
# VeraCrypt-native text passphrase (new default; matches volumes created with
# a normal keyboard passphrase).
vc = VeraCrypt(fh)
vc.unlock_with_text_passphrase(passphrase_text)

# If the exact historical latin-1 byte sequence must be reproduced, state it.
vc = VeraCrypt(fh)
vc.unlock_with_raw_passphrase(passphrase_text.encode("latin-1"))

# Binary passphrase: pass the bytes directly, no encoding involved.
vc = VeraCrypt(fh)
vc.unlock_with_raw_passphrase(passphrase_bytes)

# A PIM is either omitted (None) for the volume default or a validated integer.
vc = VeraCrypt(fh, is_system=True)
vc.unlock_with_text_passphrase(passphrase_text, pim=120)
```

For a system volume pass `is_system=True` so the boot KDF candidates and the
system PIM minimum (98) are applied.

## Evidence from the repository samples

Unlocking the checked-in VeraCrypt 1.26.24 samples (passphrases and keys are
not reproduced here) records the following parameters:

| Sample | Entry point | Encoding | Winning KDF | Iterations |
| --- | --- | --- | --- | --- |
| `aes256-sha512.hc` | `unlock_with_text_passphrase` | UTF-8 | `Pkcs5HmacSha512` | 500000 |
| `aes256-sha256.hc` | `unlock_with_text_passphrase` | UTF-8 | `Pkcs5HmacSha256` | 500000 |
| `aes256-sha512.system` | `unlock_with_text_passphrase` | UTF-8 | `Pkcs5HmacSha512_Boot` | 500000 |

The same passphrase supplied through `unlock_with_raw_passphrase` using the
matching bytes reaches the same KDF and iteration count, and the legacy
`unlock_with_passphrase` path still unlocks the samples while emitting a
`DeprecationWarning` for `str` input. Short-vector tests in
`tests/veracrypt/test_key.py` cover the PIM boundary cases and prove that
PBKDF2 is never invoked for invalid PIM input.
