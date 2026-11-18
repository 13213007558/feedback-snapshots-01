#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""Demo: how a traffic-review backend must present 5G NAS protection state.

The *same* inner clear-text NAS message is placed into three envelopes:

1. a plain, unprotected message;
2. an integrity-protected envelope with a valid MAC;
3. an integrity-protected, "ciphered" envelope whose MAC is wrong, but whose
   inner bytes still happen to be a perfectly valid NAS message.

Integrity is decided by an injected verifier (a self-contained lab HMAC here),
so no base station, SIM card or production key is involved.  Notice that case 3
decodes just as well as case 2 at the byte level, yet must be shown as
untrusted: format conformance never upgrades a message to authenticated.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pycrate_mobile.TS24501_FGMM import FGMMSecProtNASMessage, FGMMStatus

from nas_review import (
    review_nas5g,
    format_review,
    make_lab_hmac_verifier,
    apply_lab_hmac,
)


LAB_SECRET = b"demo-secret-not-a-network-key"


def build_envelopes():
    inner = FGMMStatus(val={"5GMMCause": b"\x18"})
    inner_bytes = inner.to_bytes()

    plain = inner_bytes

    valid = FGMMSecProtNASMessage()
    valid["5GMMHeaderSec"].set_val({"EPD": 126, "spare": 0, "SecHdr": 1})
    valid["Seqn"].set_val(5)
    valid["NASMessage"].set_val(inner_bytes)
    apply_lab_hmac(valid, LAB_SECRET)

    bogus = FGMMSecProtNASMessage()
    bogus["5GMMHeaderSec"].set_val({"EPD": 126, "spare": 0, "SecHdr": 2})
    bogus["MAC"].set_val(b"\xde\xad\xbe\xef")
    bogus["Seqn"].set_val(5)
    bogus["NASMessage"].set_val(inner_bytes)

    return inner_bytes, [
        ("1. plain, no security header", plain),
        ("2. integrity-protected, MAC valid", valid.to_bytes()),
        ("3. ciphered header, MAC wrong, inner still valid NAS", bogus.to_bytes()),
    ]


def main():
    inner_bytes, envelopes = build_envelopes()
    verifier = make_lab_hmac_verifier(LAB_SECRET)

    print("Shared inner message (hex): {0}\n".format(inner_bytes.hex()))
    for title, pdu in envelopes:
        print("=" * 72)
        print(title)
        print("on-wire PDU (hex): {0}".format(pdu.hex()))
        print("-" * 72)
        result = review_nas5g(pdu, verifier=verifier)
        print(format_review(result))
        print()

    print("=" * 72)
    print("same bytes without any verifier injected (e.g. key unavailable):")
    print("-" * 72)
    _, envelopes = build_envelopes()
    result = review_nas5g(envelopes[1][1])
    print(format_review(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
