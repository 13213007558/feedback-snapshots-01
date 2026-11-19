#!/usr/bin/env python3
"""Print the real hash input / digest at each SRP-6a stage.

This is a diagnostic companion to ``srp/test_fixed_width.py``.  It uses a
self-contained reference (no library helper computes the expectations) so the
output can be compared stage by stage with the pure-Python backend.

    python srp/fixed_width_probe.py            # all groups, both modes
    python srp/fixed_width_probe.py NG_1024 rfc
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from srp import _pysrp as srp
from srp.test_fixed_width import (
    FIXED_KEYS, GROUP_PARAMS, PASSWORD, SALT, USERNAME, Rfc5054Reference, minimal)


def show(group, mode):
    ng_type, n_hex, g_hex = GROUP_PARAMS[group]
    if ng_type == srp.NG_CUSTOM:
        n_hex, g_hex = n_hex.encode("ascii"), g_hex.encode("ascii")
    else:
        n_hex = g_hex = None
    n, g = srp.get_ng(ng_type, n_hex, g_hex)
    ref = Rfc5054Reference(n, g, mode)
    keys = FIXED_KEYS[group][mode]
    width = FIXED_KEYS[group]["width"]

    A = int(keys["A"], 16)
    B = int(keys["B"], 16)

    srp.rfc5054_enable(mode == "rfc")
    try:
        user = srp.User(USERNAME, PASSWORD, hash_alg=srp.SHA1, ng_type=ng_type,
                        n_hex=n_hex, g_hex=g_hex,
                        bytes_a=int(keys["a"], 16).to_bytes(256, "big"))
        _, A_out = user.start_authentication()
        server = srp.Verifier(USERNAME, SALT, minimal(ref.v()), A_out,
                              hash_alg=srp.SHA1, ng_type=ng_type,
                              n_hex=n_hex, g_hex=g_hex,
                              bytes_b=int(keys["b"], 16).to_bytes(256, "big"))
        s, B_out = server.get_challenge()
        M = user.process_challenge(s, B_out)
        HAMK = server.verify_session(M)
        user.verify_session(HAMK)
    finally:
        srp.rfc5054_enable(False)

    K = bytes.fromhex(keys["K"])
    print("=== %s  mode=%s  width=%d  g=%d" % (group, mode, width, g))
    print("  a            %s" % keys["a"])
    print("  b            %s" % keys["b"])
    print("  A  (%3d B)   %s%s" % ((A.bit_length() + 7) // 8, keys["A"][:24], "..."))
    print("  B  (%3d B)   %s%s" % ((B.bit_length() + 7) // 8, keys["B"][:24], "..."))
    print("  k  lib/ref   %s / %s  %s" % (
        format(user.k, "X")[:16], format(ref.k(), "X")[:16],
        "OK" if user.k == ref.k() else "MISMATCH"))
    print("  u  lib/ref   %s / %s  %s" % (
        format(user.u, "X")[:16], format(ref.u(A, B), "X")[:16],
        "OK" if user.u == ref.u(A, B) else "MISMATCH"))
    print("  M  lib/ref   %s / %s  %s" % (
        user.M.hex()[:16], ref.M(SALT, A, B, K).hex()[:16],
        "OK" if user.M == ref.M(SALT, A, B, K) else "MISMATCH"))
    print("  HA lib/ref   %s / %s  %s" % (
        user.H_AMK.hex()[:16], ref.H_AMK(A, M, K).hex()[:16],
        "OK" if user.H_AMK == ref.H_AMK(A, M, K) else "MISMATCH"))
    print("  authenticated user=%s server=%s" % (
        user.authenticated(), server.authenticated()))


def main(argv):
    if len(argv) == 3:
        show(argv[1], argv[2])
        return 0
    for group in FIXED_KEYS:
        for mode in ("legacy", "rfc"):
            show(group, mode)
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
