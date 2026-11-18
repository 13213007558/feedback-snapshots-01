#!/usr/bin/env python3
"""Offline GTP-C request/response correlator (security-alert prototype).

Reads a JSON transcript of observed GTPv2-C datagrams (see
build_transcript.py), parses every frame with pycrate and correlates
requests with responses.

Correlation identity (never the sequence number alone):
  * endpoint pair (src/dst ip:port, direction-aware);
  * message pairing from 29.274 (GTPCReqResp: request type -> response types);
  * TEID context: header TEID, or - for initial requests with header
    TEID == 0 - the sender F-TEID IE, which is where the response's
    header TEID must point back to;
  * sequence number, only meaningful inside the three items above.

Rules:
  * a request re-sent with identical TEID context and identical IE
    content is a retransmission of the same transaction, kept as evidence;
  * a sequence number reused with a different TEID context starts a NEW
    transaction; it is never auto-joined to the old one;
  * a response matching only an already-confirmed transaction is a late
    duplicate: retained, but it changes nothing and is never attributed
    to a newer transaction that happens to reuse the sequence number;
  * a response with no matching request is kept as an orphan (out-of-order
    captures are reconciled at the end);
  * a request that never gets a matching response stays REQUEST-ONLY:
    no tunnel establishment is fabricated from one-sided evidence.
"""
import hashlib
import json
import os
import sys

from pycrate_mobile.TS29274_GTPC import (
    GTPCMsg, GTPCReqResp, GTPCMsgType_dict, Cause_dict,
)

RESP_TO_REQ = {resp: req for req, resps in GTPCReqResp.items() for resp in resps}
REQUEST_TYPES = set(GTPCReqResp)


def msg_name(msg_type):
    return GTPCMsgType_dict.get(msg_type, "type-%d" % msg_type)


def cause_name(value):
    return Cause_dict.get(value, "cause-%d" % value)


class Frame(object):
    """One parsed GTP-C datagram with the raw fields we correlate on."""

    def __init__(self, idx, record):
        self.idx = idx
        self.ts = record["ts"]
        self.src = record["src"]
        self.sport = record["sport"]
        self.dst = record["dst"]
        self.dport = record["dport"]
        self.note = record.get("note", "")
        self.raw = bytes.fromhex(record["gtpc_hex"])

        msg = GTPCMsg()
        msg.from_bytes(self.raw)
        hdr = msg["GTPCHdr"]
        self.version = hdr["Version"].get_val()
        self.msg_type = hdr["Type"].get_val()
        self.hdr_teid = hdr["TEID"].get_val()
        self.seq = hdr["SeqNum"].get_val()

        self.imsi = None
        self.recovery = None
        self.cause = None
        self.sender_fteid = None  # F-TEID IE, instance 0
        for ie in msg["GTPCIEs"]:
            data = ie["Data"]
            kind = type(data).__name__
            if kind == "IMSI":
                self.imsi = data.decode()
            elif kind == "Recovery":
                self.recovery = data.get_val()
            elif kind == "Cause":
                self.cause = data["Val"].get_val()
            elif kind == "FTEID" and ie["Hdr"]["Inst"].get_val() == 0 \
                    and self.sender_fteid is None:
                self.sender_fteid = data["TEID_GREKey"].get_val()

        self.is_request = self.msg_type in REQUEST_TYPES
        self.is_response = self.msg_type in RESP_TO_REQ
        # hash of the IE blob: identical retransmissions hash equal
        self.ie_hash = hashlib.sha1(msg["GTPCIEs"].to_bytes()).hexdigest()[:12]

    @property
    def teid_ctx(self):
        """TEID identity of the transaction this frame belongs to."""
        return self.hdr_teid if self.hdr_teid else (self.sender_fteid or 0)

    @property
    def expected_resp_teid(self):
        """Header TEID a response must carry, if derivable from the request.

        Only defined for initial requests (header TEID == 0): the response
        must point back to the requester's sender F-TEID. For requests that
        already run inside a tunnel, the expected TEID comes from the
        observed session context (see Correlator.resolve_tunnel_teid).
        """
        if self.hdr_teid:
            return None
        return self.sender_fteid or 0

    def ep(self):
        return "%s:%d" % (self.src, self.sport), "%s:%d" % (self.dst, self.dport)

    def describe(self):
        src, dst = self.ep()
        fields = [
            "frame#%d" % self.idx,
            "t=%.3f" % self.ts,
            "%s -> %s" % (src, dst),
            "type=%d(%s)" % (self.msg_type, msg_name(self.msg_type)),
            "hdr_teid=0x%08x" % self.hdr_teid,
            "seq=%d" % self.seq,
        ]
        if self.sender_fteid is not None:
            fields.append("sender_fteid=0x%08x" % self.sender_fteid)
        if self.imsi:
            fields.append("imsi=%s" % self.imsi)
        if self.recovery is not None:
            fields.append("recovery=%d" % self.recovery)
        if self.cause is not None:
            fields.append("cause=%d(%s)" % (self.cause, cause_name(self.cause)))
        fields.append("ie_hash=%s" % self.ie_hash)
        return " ".join(fields)


class Transaction(object):
    _count = 0

    def __init__(self, request):
        Transaction._count += 1
        self.tid = Transaction._count
        self.initiator, self.responder = request.ep()
        self.req_type = request.msg_type
        self.seq = request.seq
        self.teid_ctx = request.teid_ctx
        self.expected_resp_teid = request.expected_resp_teid
        self.ie_hash = request.ie_hash
        self.requests = [request]        # first copy + retransmissions
        self.responses = []              # confirming responses
        self.late_responses = []         # duplicates arriving after confirm
        self.status = "OPEN"
        self.notes = []

    @property
    def req_name(self):
        return msg_name(self.req_type)

    def matches_retransmission(self, frame):
        return (frame.src + ":%d" % frame.sport == self.initiator
                and frame.msg_type == self.req_type
                and frame.seq == self.seq
                and frame.teid_ctx == self.teid_ctx
                and frame.ie_hash == self.ie_hash)

    def same_seq_reuse(self, frame):
        return (frame.src + ":%d" % frame.sport == self.initiator
                and frame.msg_type == self.req_type
                and frame.seq == self.seq)

    def accepts_response(self, frame):
        return (frame.dst + ":%d" % frame.dport == self.initiator
                and frame.src + ":%d" % frame.sport == self.responder
                and RESP_TO_REQ.get(frame.msg_type) == self.req_type
                and frame.seq == self.seq
                and (self.expected_resp_teid is None
                     or frame.hdr_teid == self.expected_resp_teid))


class Correlator(object):
    def __init__(self):
        self.txns = []
        self.orphan_responses = []   # kept as evidence, never fabricated
        self.pending_responses = []  # may be out-of-order captures
        self.restarts = {}           # endpoint -> highest recovery seen
        self.log = []

    # -- requests ------------------------------------------------------

    def handle_request(self, frame):
        for txn in self.txns:
            if txn.matches_retransmission(frame):
                txn.requests.append(frame)
                txn.notes.append(
                    "frame#%d: retransmission (same endpoints/type/seq=%d, "
                    "same teid_ctx=0x%08x, same ie_hash=%s) - same transaction"
                    % (frame.idx, frame.seq, frame.teid_ctx, frame.ie_hash))
                return
        reused = [t for t in self.txns if t.same_seq_reuse(frame)]
        txn = Transaction(frame)
        self.txns.append(txn)
        if frame.hdr_teid and txn.expected_resp_teid is None:
            resolved = self.resolve_tunnel_teid(frame)
            txn.expected_resp_teid = resolved
            if resolved is not None:
                txn.notes.append(
                    "tunnel context: req hdr_teid=0x%08x belongs to responder "
                    "of an observed session; responses must carry "
                    "hdr_teid=0x%08x" % (frame.hdr_teid, resolved))
            else:
                txn.notes.append(
                    "no session context observed for hdr_teid=0x%08x; "
                    "response TEID left unverified" % frame.hdr_teid)
        prev_recovery = self.restarts.get(frame.src)
        if prev_recovery is not None and frame.recovery is not None \
                and frame.recovery > prev_recovery:
            txn.notes.append(
                "restart suspected: recovery %d -> %d from %s"
                % (prev_recovery, frame.recovery, frame.src))
        if frame.recovery is not None:
            self.restarts[frame.src] = max(frame.recovery,
                                           prev_recovery or 0)
        for old in reused:
            txn.notes.append(
                "seq=%d reused: NOT joined to txn#%d "
                "(old teid_ctx=0x%08x ie_hash=%s, new teid_ctx=0x%08x "
                "ie_hash=%s) - separate transaction"
                % (frame.seq, old.tid, old.teid_ctx, old.ie_hash,
                   frame.teid_ctx, frame.ie_hash))

    def resolve_tunnel_teid(self, frame):
        """Expected response TEID for a request inside an existing tunnel.

        The request's header TEID identifies the responder's tunnel end;
        find a confirmed transaction on the same endpoint pair whose
        response announced that TEID in its F-TEID IE, and map it back to
        the initiator-side TEID. Returns None when no session context was
        observed - in that case the TEID check is skipped, not invented.
        """
        src_ep = frame.src + ":%d" % frame.sport
        dst_ep = frame.dst + ":%d" % frame.dport
        for txn in self.txns:
            if txn.status != "CONFIRMED" or txn.initiator != src_ep \
                    or txn.responder != dst_ep:
                continue
            for resp in txn.responses:
                if resp.sender_fteid == frame.hdr_teid:
                    return txn.teid_ctx
        return None

    # -- responses -----------------------------------------------------

    def handle_response(self, frame):
        open_match = [t for t in self.txns
                      if t.status == "OPEN" and t.accepts_response(frame)]
        if open_match:
            self._confirm(open_match[0], frame)
            return
        closed_match = [t for t in self.txns
                        if t.status != "OPEN" and t.accepts_response(frame)]
        if closed_match:
            txn = closed_match[0]
            txn.late_responses.append(frame)
            hijack = [t for t in self.txns if t.status == "OPEN"
                      and t.seq == frame.seq
                      and RESP_TO_REQ.get(frame.msg_type) == t.req_type
                      and t.initiator == frame.dst + ":%d" % frame.dport]
            txn.notes.append(
                "frame#%d: LATE duplicate response for closed transaction "
                "(hdr_teid=0x%08x matches this txn) - retained as evidence"
                % (frame.idx, frame.hdr_teid))
            for other in hijack:
                txn.notes.append(
                    "frame#%d: NOT attributed to open txn#%d reusing seq=%d "
                    "(it expects resp hdr_teid=0x%08x, frame carries 0x%08x)"
                    % (frame.idx, other.tid, frame.seq,
                       other.expected_resp_teid, frame.hdr_teid))
            return
        # no transaction yet: could be an out-of-order capture
        self.pending_responses.append(frame)

    def _confirm(self, txn, frame):
        txn.responses.append(frame)
        txn.status = "CONFIRMED"
        rtt = frame.ts - txn.requests[-1].ts
        txn.notes.append(
            "frame#%d: confirmed by %s, matched on endpoints + msg pair "
            "(%d->%d) + seq=%d + resp hdr_teid=0x%08x == expected 0x%08x "
            "(rtt=%.3fs)"
            % (frame.idx, msg_name(frame.msg_type), txn.req_type,
               frame.msg_type, frame.seq, frame.hdr_teid,
               txn.expected_resp_teid, rtt))

    # -- out-of-order reconciliation ------------------------------------

    def reconcile(self):
        for frame in self.pending_responses:
            match = [t for t in self.txns if t.accepts_response(frame)]
            if match:
                txn = match[0]
                first_req_ts = txn.requests[0].ts
                txn.responses.append(frame)
                if txn.status == "OPEN":
                    txn.status = "CONFIRMED"
                txn.notes.append(
                    "frame#%d: OUT-OF-ORDER capture - response recorded "
                    "before request frame#%d (resp t=%.3f, req t=%.3f); "
                    "matched retroactively on endpoints + msg pair + seq=%d "
                    "+ hdr_teid=0x%08x"
                    % (frame.idx, txn.requests[0].idx, frame.ts,
                       first_req_ts, frame.seq, frame.hdr_teid))
            else:
                self.orphan_responses.append(frame)

    # -- driver ----------------------------------------------------------

    def run(self, records):
        frames = [Frame(i + 1, rec) for i, rec in enumerate(records)]
        for frame in frames:
            if frame.is_request:
                self.handle_request(frame)
            elif frame.is_response:
                self.handle_response(frame)
            else:
                self.log.append("frame#%d: %s - not a req/resp pair message, "
                                "ignored" % (frame.idx, msg_name(frame.msg_type)))
        self.reconcile()
        return frames


def print_report(correlator, frames):
    print("=" * 78)
    print("GTP-C OFFLINE CORRELATION REPORT (synthetic transcript, no live network)")
    print("=" * 78)

    print("\n-- parsed frames (raw fields extracted with pycrate) " + "-" * 26)
    for frame in frames:
        kind = "REQ " if frame.is_request else ("RESP" if frame.is_response else "----")
        print("[%s] %s" % (kind, frame.describe()))
        if frame.note:
            print("       capture note: %s" % frame.note)

    print("\n-- transactions " + "-" * 63)
    for txn in correlator.txns:
        print("\nTXN#%d  %s  %s -> %s" % (txn.tid, txn.req_name,
                                             txn.initiator, txn.responder))
        expected = ("0x%08x" % txn.expected_resp_teid
                    if txn.expected_resp_teid is not None else "unresolved")
        print("  identity: req_type=%d seq=%d teid_ctx=0x%08x "
              "expected_resp_teid=%s ie_hash=%s"
              % (txn.req_type, txn.seq, txn.teid_ctx,
                 expected, txn.ie_hash))
        print("  status: %s" % txn.status)
        for req in txn.requests:
            tag = "request" if req is txn.requests[0] else "retransmission"
            print("  [%s] %s" % (tag, req.describe()))
        for resp in txn.responses:
            print("  [response] %s" % resp.describe())
        for resp in txn.late_responses:
            print("  [late-response] %s" % resp.describe())
        for note in txn.notes:
            print("  note: %s" % note)

    if correlator.orphan_responses:
        print("\n-- orphan responses (no matching request; kept, not fabricated) ")
        for frame in correlator.orphan_responses:
            print("  %s" % frame.describe())

    print("\n-- session-establishment verdicts " + "-" * 44)
    for txn in correlator.txns:
        if txn.req_name != "Create Session Request":
            continue
        if txn.status == "CONFIRMED":
            verdict = ("CONFIRMED tunnel establishment "
                       "(request + accepted response observed)")
        else:
            verdict = ("REQUEST ONLY - no accepted response observed; "
                       "no tunnel is assumed to exist")
        print("  TXN#%d %s seq=%d teid_ctx=0x%08x: %s"
              % (txn.tid, txn.initiator, txn.seq, txn.teid_ctx, verdict))
    print()


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "transcript.json")
    with open(path) as fd:
        records = json.load(fd)
    correlator = Correlator()
    frames = correlator.run(records)
    print_report(correlator, frames)


if __name__ == "__main__":
    main()
