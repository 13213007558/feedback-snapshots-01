#!/usr/bin/env python3
"""Build a synthetic GTPv2-C transcript for the offline correlator.

Everything here is generated locally with pycrate encoders. No socket is
opened and no real mobile network is touched; the output is a plain JSON
file that mimics what an offline pcap extraction would produce (one record
per observed UDP/2123 datagram, in capture order).

Transcript scenario (S11-style, UDP/2123):
  * pair A (10.10.0.1 <-> 10.10.0.2) and pair B (10.20.0.1 <-> 10.20.0.2)
    both use sequence number 700 for Create Session -> identical sequence
    numbers on different endpoint pairs must not be mixed;
  * pair A retransmits its Create Session Request once (identical bytes);
  * pair A gets a confirming Create Session Response;
  * pair B's Create Session Request is never answered (request only);
  * pair A later reuses seq=700 with a fresh F-TEID and a bumped restart
    counter -> a NEW transaction, not a continuation of the old one;
  * a late duplicate Create Session Response for the OLD pair-A context
    arrives after the new transaction started -> kept as evidence, must
    not be glued onto the new transaction;
  * a Delete Session exchange on pair A is captured out of order
    (response record appears before the request record).
"""
import json
import os

from pycrate_mobile.TS29274_GTPC import GTPCMsg

GTP_C_PORT = 2123

# GTPv2-C message types
ECHO_REQ, ECHO_RESP = 1, 2
CS_REQ, CS_RESP = 32, 33
DS_REQ, DS_RESP = 36, 37

# F-TEID interface types (29.274 8.22)
IF_S11_MME_GTPC = 10
IF_S11_SGW_GTPC = 11

CAUSE_REQUEST_ACCEPTED = 16

MME_A, SGW_A = "10.10.0.1", "10.10.0.2"
MME_B, SGW_B = "10.20.0.1", "10.20.0.2"


def ie_imsi(digits):
    return {"Hdr": {"Type": 1}, "Data": digits}


def ie_recovery(counter):
    return {"Hdr": {"Type": 3}, "Data": counter}


def ie_fteid(if_type, teid, ipv4, inst=0):
    return {"Hdr": {"Type": 87, "Inst": inst},
            "Data": {"V4": 1, "IF": if_type, "TEID_GREKey": teid, "IPv4Addr": ipv4}}


def ie_cause(value):
    return {"Hdr": {"Type": 2}, "Data": {"Val": value}}


def gtpc(msg_type, seq, teid=0, ies=()):
    msg = GTPCMsg()
    msg.set_val({
        "GTPCHdr": {"Version": 2, "P": 0, "T": 1, "MP": 0,
                    "Type": msg_type, "TEID": teid, "SeqNum": seq},
        "GTPCIEs": list(ies),
    })
    return msg.to_bytes()


def frame(ts, src, dst, payload, note=""):
    return {
        "ts": ts,
        "src": src, "sport": GTP_C_PORT,
        "dst": dst, "dport": GTP_C_PORT,
        "gtpc_hex": payload.hex(),
        "note": note,
    }


def build():
    # pair A, transaction A1: Create Session, seq=700, sender F-TEID 0x0a0a0001
    a1_req = gtpc(CS_REQ, seq=700, teid=0, ies=[
        ie_imsi("001010123456789"),
        ie_fteid(IF_S11_MME_GTPC, 0x0A0A0001, MME_A),
        ie_recovery(7),
    ])
    # pair B, transaction B1: same seq=700, different endpoints/context
    b1_req = gtpc(CS_REQ, seq=700, teid=0, ies=[
        ie_imsi("001020987654321"),
        ie_fteid(IF_S11_MME_GTPC, 0x0B0B0001, MME_B),
        ie_recovery(3),
    ])
    # pair A, transaction A1: confirming response (hdr TEID = MME's F-TEID)
    a1_resp = gtpc(CS_RESP, seq=700, teid=0x0A0A0001, ies=[
        ie_cause(CAUSE_REQUEST_ACCEPTED),
        ie_fteid(IF_S11_SGW_GTPC, 0x0A0A00F1, SGW_A),
        ie_recovery(7),
    ])
    # pair A, transaction A2: seq=700 REUSED after restart (recovery 7 -> 8),
    # new sender F-TEID 0x0a0a0002 -> must be a new transaction
    a2_req = gtpc(CS_REQ, seq=700, teid=0, ies=[
        ie_imsi("001010555000111"),
        ie_fteid(IF_S11_MME_GTPC, 0x0A0A0002, MME_A),
        ie_recovery(8),
    ])
    # late duplicate of the A1 response (old F-TEID 0x0a0a0001), arrives
    # after A2 has already started
    a1_resp_late = gtpc(CS_RESP, seq=700, teid=0x0A0A0001, ies=[
        ie_cause(CAUSE_REQUEST_ACCEPTED),
        ie_fteid(IF_S11_SGW_GTPC, 0x0A0A00F1, SGW_A),
        ie_recovery(7),
    ])
    # pair A: Delete Session for the A1 tunnel, captured OUT OF ORDER
    # (response record shows up before the request record)
    a_ds_req = gtpc(DS_REQ, seq=702, teid=0x0A0A00F1, ies=[])
    a_ds_resp = gtpc(DS_RESP, seq=702, teid=0x0A0A0001, ies=[
        ie_cause(CAUSE_REQUEST_ACCEPTED),
    ])

    return [
        frame(1000.000, MME_A, SGW_A, a1_req,  "A1 Create Session Request"),
        frame(1000.012, MME_B, SGW_B, b1_req,  "B1 Create Session Request (same seq 700)"),
        frame(1000.400, MME_A, SGW_A, a1_req,  "A1 retransmission (identical bytes)"),
        frame(1000.650, SGW_A, MME_A, a1_resp, "A1 Create Session Response (accepted)"),
        frame(1002.000, MME_A, SGW_A, a2_req,  "A2 Create Session Request (seq 700 reused, recovery 8)"),
        frame(1002.900, SGW_A, MME_A, a1_resp_late, "late duplicate of A1 response"),
        frame(1003.100, SGW_A, MME_A, a_ds_resp, "A3 Delete Session Response (captured first)"),
        frame(1003.050, MME_A, SGW_A, a_ds_req,  "A3 Delete Session Request (captured late)"),
    ]


def main():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "transcript.json")
    records = build()
    with open(path, "w") as fd:
        json.dump(records, fd, indent=2)
    print("wrote %d records to %s" % (len(records), path))


if __name__ == "__main__":
    main()
