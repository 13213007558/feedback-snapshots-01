Fixed-width hash-input regression (pysrp pure Python)
====================================================

Symptom
-------
An upgraded SRP peer fails authentication only for some short public keys
(A and/or B with a leading zero byte).  Equality of the integer A/B is not
enough to prove the transcript bytes agree: the hash input width decides the
digest.

Where the width is decided
--------------------------
`srp/_pysrp.py` had the width rule applied in three places out of four:

  stage                       RFC5054 mode                 legacy mode
  --------------------------  ----------------------------  -----------------
  k = H(N, g)                 H(PAD(N), PAD(g))             H(N, g) minimal
  u = H(A, B)                 H(PAD(A), PAD(B))             H(A, B) minimal
  HNxorg (M prefix)           H(N) xor H(PAD(g))            H(N) xor H(g) minimal
  M = H(..., A, B, K)         (missing: used minimal A/B)   minimal
  H_AMK = H(A, M, K)          (missing: used minimal A)     minimal

So with RFC5054 mode enabled, k and u were padded but the evidence messages
M and H_AMK still hashed the minimal encoding of A (and B for M).  Two pysrp
peers agree with each other because both compute the same wrong bytes, which
is exactly why "mutual success" cannot detect this.  A peer that is really
RFC5054-conformant disagrees as soon as A or B is shorter than N.

Reproduce
---------
    .venv/bin/python srp/fixed_width_probe.py
    .venv/bin/python srp/fixed_width_probe.py NG_1024 rfc
    .venv/bin/python -m unittest srp.test_fixed_width

`srp/test_fixed_width.py` fixes a/b per group and mode.  They were searched
deterministically so that both A and B have a leading zero byte (one byte
short) in NG_1024, NG_2048, NG_4096, NG_8192 and a 1536-bit custom group.
Expected k/x/v/u/S/K/M/H_AMK digests come from a small reference
implementation written inside the test that applies only the RFC 5054 PAD()
rule and plain modular arithmetic; no library helper produces an expectation.
The published RFC 5054 Appendix B 1024-bit vector (k = 7556AA04...,
x = 94B7555A..., M = 62C71B28..., H_AMK = B475D7F2...) anchors both the
reference and the library.

Stage-by-stage result (NG_1024, RFC5054 mode, 1 leading zero in A and B)
-----------------------------------------------------------------------
    a          8000...0002
    b          8000...014F
    A (127 B)  809974AE020799E2...
    B (127 B)  C7FB08078D9B43EC...
    k  lib/ref 7556AA045AEF2CDD / 7556AA045AEF2CDD  OK
    u  lib/ref F703DB8F23A06D14 / F703DB8F23A06D14  OK
    M  lib/ref 81d6f3585489c3d5 / 81d6f3585489c3d5  OK  (after fix)
    HA lib/ref a8835683a36cfe70 / a8835683a36cfe70  OK  (after fix)

Before the fix M was 3be507afa8f85012... and H_AMK 18b5b5139ca75f7c...,
i.e. the minimal-encoding transcript.  The probe prints the full table for
all groups and both modes.

Independent corroboration for the RFC5054 width rule
----------------------------------------------------
* RFC 5054 Appendix B fixed 1024-bit digests (above) match the reference.
* The system OpenSSL 3.6 `SRP_Calc_u` disassembles to `BN_bn2binpad` for both
  A and B at exactly the width of N; with 1-byte A/B it returns the padded
  digest, not the minimal one.  That is the same rule the pure-Python path now
  applies to u, M and H_AMK.

Change made
-----------
`srp/_pysrp.py` only:
* new `hash_input_bytes(value, width)` is the single width policy used by
  H(), `calculate_M()` and `calculate_H_AMK()`;
* `calculate_M()` passes the width of N for A and B;
* `calculate_H_AMK()` takes an optional N and pads A when given (the old
  5-argument call keeps the minimal encoding).

Legacy (default) mode is byte-for-byte unchanged.  The historical NG_2048
SHA1 transcript with a = b = 8000...0000 was captured before the change and is
replayed in `LegacyTranscriptTests`; it still verifies with the same M and
H_AMK.  Note K = H(S) still uses the minimal encoding of S in both modes, so
a short S is unaffected; that behaviour is unchanged and is not part of this
regression.

Compatibility advice
--------------------
* If you interoperate with RFC 5054 peers, call `srp.rfc5054_enable()` on every
  process and regenerate stored salts/verifiers with that mode.  The fix makes
  the pure-Python path agree with the ctypes path and with OpenSSL.
* Do not enable RFC5054 mode on one side only: k, u, M and H_AMK all change,
  not just the leading-zero cases.
* The failure mode is "only some short keys": a peer that never produces a
  leading zero will pass even with the old code, so a green handshake is not
  evidence that the encoding matches.
* The stored verifier v derives from x and is unchanged by this fix; only the
  transcript digests change.  Sessions established before the upgrade keep
  working under legacy mode; they cannot be continued under RFC5054 mode.
* If you must keep the old RFC5054 transcript for existing peers, stay on the
  previous release and pin that behaviour; there is no runtime switch that
  reproduces the old M/H_AMK while claiming RFC5054 conformance.
