#!/usr/bin/env python3
#
# Show what a TSIG BADTIME response proves, using only locally constructed
# messages.  This does not change the system clock and does not use the
# network.
#
# usage: tsig_badtime.py

import time

import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.rdtypes.ANY.TSIG
import dns.tsig
import dns.tsigkeyring

KEYRING = dns.tsigkeyring.from_text({"keyname.": "NjHwPsMKjdN++dOfE5iAiQ=="})
KEYNAME = dns.name.from_text("keyname.")
KEY = dns.tsig.Key(KEYNAME, KEYRING[KEYNAME], dns.tsig.HMAC_SHA256)


def make_query():
    q = dns.message.make_query("example.", "A")
    q.use_tsig(KEY, KEYNAME)
    q.to_wire()  # set q.mac
    return q


def signed_badtime(q, server_time):
    r = dns.message.make_response(q, tsig_error=dns.rcode.BADTIME)
    r.use_tsig(
        KEY,
        KEYNAME,
        tsig_error=dns.rcode.BADTIME,
        other_data=int(server_time).to_bytes(6, "big"),
    )
    r.request_mac = q.mac
    return r.to_wire()


def forged_badtime(q):
    r = dns.message.make_response(q, tsig_error=dns.rcode.BADTIME)
    r.use_tsig(
        KEY,
        KEYNAME,
        tsig_error=dns.rcode.BADTIME,
        other_data=int(time.time() + 3600).to_bytes(6, "big"),
    )
    r.request_mac = q.mac
    wire = bytearray(r.to_wire())
    offset = wire.find(r.tsig[0].mac)
    assert offset >= 0
    wire[offset] ^= 0xFF  # corrupt the MAC
    return bytes(wire)


def show(label, q, wire):
    print(f"\n{label}")
    try:
        dns.message.from_wire(wire, keyring=KEY, request_mac=q.mac)
        print("  accepted")
    except Exception as error:
        print(f"  exception: {type(error).__name__}")
        print(f"  authenticated: {getattr(error, 'authenticated', False)}")
        assessment = dns.tsig.assess_tsig_error(q, error)
        print(f"  status: {assessment.status.value}")
        print(f"  server_time: {assessment.server_time}")
        decision = dns.tsig.decide_tsig_retry(
            assessment,
            policy=dns.tsig.TSIGRetryPolicy(max_retries=1, max_offset=7200),
        )
        print(f"  retry: {decision.action.value} ({decision.reason})")
        if decision.signing_time_offset is not None:
            print(
                f"  signing-time offset for the retry: {decision.signing_time_offset}s"
            )
            print("  system clock and fudge are unchanged")


def show_normal():
    q = make_query()
    r = dns.message.make_response(q)
    r.use_tsig(KEY, KEYNAME)
    r.request_mac = q.mac
    parsed = dns.message.from_wire(r.to_wire(), keyring=KEY, request_mac=q.mac)
    assessment = dns.tsig.assess_tsig_response(q, parsed)
    print("normal signed response")
    print(f"  status: {assessment.status.value}")
    print(f"  authenticated: {assessment.authenticated}")


def show_empty_mac_badtime():
    q = make_query()
    r = dns.message.make_response(q)
    r.request_mac = q.mac
    tsig = dns.rdtypes.ANY.TSIG.TSIG(
        dns.rdataclass.ANY,
        dns.rdatatype.TSIG,
        dns.tsig.HMAC_SHA256,
        int(time.time()),
        300,
        b"",
        q.id,
        dns.rcode.BADTIME,
        int(time.time() + 3600).to_bytes(6, "big"),
    )
    r.tsig = dns.rrset.from_rdata(KEYNAME, 0, tsig)
    r.want_tsig_sign = False
    show("BADTIME with an empty MAC (unsigned claim)", q, r.to_wire())


if __name__ == "__main__":
    show_normal()
    q = make_query()
    show("authenticated BADTIME", q, signed_badtime(q, time.time() + 3600))
    show("forged BADTIME (MAC corrupted)", q, forged_badtime(q))
    show_empty_mac_badtime()
