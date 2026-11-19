# 5G NAS security negotiation transcripts

Synthetic, offline transcripts for `pycrate_mobile.NASSecAudit`. All keys and
identities below are lab values; nothing here contacts a network. Each PDU is
a real pycrate-encoded 5GMM message (TS 24.501) wrapped in the security header
layout from `TS24501_FGMM.FGMMSecProtNASMessage`.

Run:

```
./tools/pycrate_nas_secaudit.py test/res/nas-secaudit/normal.json
./tools/pycrate_nas_secaudit.py test/res/nas-secaudit/capability-replaced.json -j
```

## normal.json — expected `consistent`

| record | direction | message | security header | UE security capability |
|--------|-----------|---------|-----------------|------------------------|
| 1 | UL | Registration Request | 0, cleartext | EA0-EA3, IA0-IA3 (cleartext declaration) |
| 2 | DL | Security Mode Command | 3, MAC verified (5G-IA2) | echo = declaration |
| 3 | UL | Security Mode Complete | 3, MAC verified | — |

Selection is 5G-EA2 / 5G-IA2, inside both the declaration and the echo. The
declaration is still cleartext, so the report says so and lists the
authenticated re-declaration as the missing evidence, without calling the
result a downgrade.

## capability-replaced.json — expected `inconsistent`, replacement confirmed

| record | direction | message | security header | UE security capability |
|--------|-----------|---------|-----------------|------------------------|
| 1 | UL | Registration Request (mobility update) | 1, MAC verified | EA1-EA3, IA1-IA3 (authenticated) |
| 2 | DL | Security Mode Command | 3, MAC verified | echo narrowed to EA0 + IA2 |
| 3 | UL | Security Mode Complete | 3, MAC verified | — |

Two authenticated statements disagree: the UE declared EA1-EA3/IA1-IA3, while
the SMC echo drops all of them except the null ciphering algorithm, and the SMC
selects EA0/IA2. The report confirms a capability replacement *inside this
capture*; it does not confirm a downgrade, because the AMF may legitimately
narrow the offered set, and NAS alone cannot show which side wrote the echo.

## capture-gap.json — expected `insufficient_evidence`

| record | direction | message | status |
|--------|-----------|---------|--------|
| 1 | UL | Registration Request | cleartext, UESecCap EA1-EA3/IA1-IA3 |
| 2 | DL | *(gap)* | Security Mode Command not captured |
| 3 | UL | Security Mode Complete | header 3, no K_NASint, no 32-bit COUNT |

No algorithm selection is observed, so nothing can be called consistent or
inconsistent. The missing SMC is reported as missing evidence; the later
protected message stays `unverified`, never `verified`.

## Evidence model

* `cleartext` — observed under security header type 0. A claim on the wire.
  The UESecCap of an initial Registration Request is always in this class
  (TS 24.501, 4.4.6).
* `authenticated` — observed inside an integrity protected message whose MAC
  was recomputed and matched, using the supplied `K_NASint` and the full
  32-bit NAS COUNT.
* `unverified` — observed inside an integrity protected envelope, but the MAC
  could not be checked (no key, no 32-bit COUNT, null or unsupported
  integrity algorithm). Never treated as verified.

The audit never asserts a downgrade. It reports agreement, evidence level, and
the exact missing item that would be needed to conclude one. `5G-IA0` has no
MAC at all, so a record protected with it cannot become `authenticated` even if
its MAC field is zero.
