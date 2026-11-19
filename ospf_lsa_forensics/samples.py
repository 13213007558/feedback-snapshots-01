"""Build the offline review sample set: raw LS Update frames.

Frames are assembled with Scapy and kept as bytes plus synthetic
capture timestamps; nothing is sent.  The set exercises one LSA
identity (router LSA of 10.0.0.1 in area 0.0.0.0) through updates,
a same-sequence/different-checksum collision, a MaxAge flush,
sequence space exhaustion and restart, plus invalid captures, and a
second identity (10.0.0.2) for the MaxAgeDiff rule.
"""

import struct

from scapy.contrib.ospf import OSPF_Hdr, OSPF_Link, OSPF_LSUpd, \
    OSPF_Router_LSA

from .lsa_forensics import INITIAL_SEQ, MAX_AGE, MAX_SEQ, RESERVED_SEQ

AREA = "0.0.0.0"
SRC = "10.0.0.9"  # emitting neighbor; not part of LSA identity
T0 = 1700000000.0


def _link(lsid, data, ltype, metric):
    return OSPF_Link(id=lsid, data=data, type=ltype, toscount=0,
                     metric=metric)


def _router_lsa(rid, seq, links, age=1):
    return OSPF_Router_LSA(age=age, options=0x02, type=1, id=rid,
                           adrouter=rid, seq=seq, flags=0, reserved=0,
                           linkcount=len(links), linklist=links)


def _update(lsas, area=AREA, src=SRC, authtype=0):
    pkt = (OSPF_Hdr(version=2, type=4, src=src, area=area,
                    authtype=authtype)
           / OSPF_LSUpd(lsacount=len(lsas), lsalist=lsas))
    return bytes(pkt)


def _aged(raw_update, age):
    """Return the update with the first LSA's age field set (age is
    excluded from the LSA checksum, so the checksum stays valid)."""
    raw = bytearray(raw_update)
    struct.pack_into("!H", raw, 24 + 4, age)  # OSPF hdr + lsacount
    return bytes(raw)


def _flip_body_byte(raw_update):
    """Corrupt one LSA body byte (a link metric) to break the
    Fletcher-16 checksum without touching length fields."""
    raw = bytearray(raw_update)
    raw[24 + 4 + 30] ^= 0xFF
    return bytes(raw)


LINKS_A = [_link("10.0.12.2", "10.0.12.1", 3, 10)]
LINKS_AB = LINKS_A + [_link("10.0.13.3", "10.0.13.1", 3, 10)]
LINKS_AC = LINKS_A + [_link("10.0.14.4", "10.0.14.1", 3, 20)]

RID1 = "10.0.0.1"
RID2 = "10.0.0.2"

# --- identity 1: router LSA of 10.0.0.1 ---
U1 = _update([_router_lsa(RID1, 0x80000005, LINKS_A)])
U2 = _update([_router_lsa(RID1, 0x80000007, LINKS_AB)])
U3 = _update([_router_lsa(RID1, 0x80000006, LINKS_A)])
U4 = _update([_router_lsa(RID1, 0x80000007, LINKS_AC)])  # same seq as U2
U6 = _update([_router_lsa(RID1, MAX_SEQ, LINKS_AB)])
U8 = _update([_router_lsa(RID1, INITIAL_SEQ, LINKS_A)])
U5 = _aged(U4, MAX_AGE)   # flush of the U4 instance (seq 0x80000007)
U7 = _aged(U6, MAX_AGE)   # flush of the MaxSequenceNumber instance
U9 = _flip_body_byte(U2)              # checksum mismatch
_full = _update([_router_lsa(RID1, 0x80000009, LINKS_AB)])
U10 = _full[:-8]                       # truncated: LSA body incomplete
U11 = U2                               # exact replay of U2, arrives late
U12 = _update([_router_lsa(RID1, RESERVED_SEQ, LINKS_A)])

# --- identity 2: router LSA of 10.0.0.2, for the MaxAgeDiff rule ---
V1 = _update([_router_lsa(RID2, 0x80000010, LINKS_A, age=1500)])
V2 = _update([_router_lsa(RID2, 0x80000010, LINKS_A, age=400)])
V3 = _update([_router_lsa(RID2, 0x80000010, LINKS_A, age=500)])

# (name, frame, capture_time); capture time is evidence metadata,
# kept apart from the raw bytes.
FRAMES = [
    ("U1",  U1,  T0 + 1000),
    ("U2",  U2,  T0 + 1010),
    ("U3",  U3,  T0 + 1020),
    ("U4",  U4,  T0 + 1030),
    ("U5",  U5,  T0 + 1040),
    ("U6",  U6,  T0 + 1050),
    ("U7",  U7,  T0 + 1060),
    ("U8",  U8,  T0 + 1070),
    ("U9",  U9,  T0 + 1080),
    ("U10", U10, T0 + 1090),
    ("U11", U11, T0 + 1100),
    ("U12", U12, T0 + 1110),
    ("V1",  V1,  T0 + 2000),
    ("V2",  V2,  T0 + 2010),
    ("V3",  V3,  T0 + 2020),
]

# Two arrival orders of the same raw evidence.
ORDER_A = ["U1", "U2", "U3", "U4", "U5", "U6", "U7", "U8",
           "U9", "U10", "U11", "U12", "V1", "V2", "V3"]
ORDER_B = ["U8", "U11", "U6", "U2", "U4", "U7", "U3", "U1",
           "U5", "U12", "U10", "U9", "V3", "V1", "V2"]
