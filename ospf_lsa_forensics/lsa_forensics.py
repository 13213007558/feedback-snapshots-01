"""Offline forensic criteria for OSPFv2 LSA version comparison.

Implements the LSA instance freshness rules of RFC 2328 (sections
12.1.6 "LS sequence number", 12.1.7 "LS age", 13.1 "Determining which
LSA is newer" and annex C "Checksum") as *evidence evaluation*
criteria.  Given raw captured LS Update frames, the functions here
decide which LSA instance supersedes which, and which captures must
remain undetermined.  Nothing here originates, floods or sends
packets; Scapy is used for decoding only.

Three kinds of data are kept strictly separate:

* raw fields   -- bytes and header values exactly as captured;
* capture time -- the observation timestamp of each frame;
* conclusions  -- derived verdicts, always emitted with the rule
  that produced them.

Authentication data from the OSPF header is recorded but never
verified (no keys are available offline), so it is never treated as a
trust source.
"""

import struct
from dataclasses import dataclass, field
from enum import Enum

from scapy.contrib.ospf import (
    OSPF_External_LSA,
    OSPF_Hdr,
    OSPF_LSA_Hdr,
    OSPF_NSSA_External_LSA,
    OSPF_Network_LSA,
    OSPF_Router_LSA,
    OSPF_SummaryASBR_LSA,
    OSPF_SummaryIP_LSA,
    ospf_lsa_checksum,
)

LSA_HEADER_LEN = 20
OSPF_HDR_LEN = 24

# RFC 2328 constants
MAX_AGE = 3600            # section 12.1.7 / appendix B
MAX_AGE_DIFF = 900        # section 13.1: 15 minutes
INITIAL_SEQ = 0x80000001  # InitialSequenceNumber, section 12.1.6
MAX_SEQ = 0x7FFFFFFF      # MaxSequenceNumber, section 12.1.6
RESERVED_SEQ = 0x80000000  # "reserved and should never be used"

LSA_CLASSES = {
    1: OSPF_Router_LSA,
    2: OSPF_Network_LSA,
    3: OSPF_SummaryIP_LSA,
    4: OSPF_SummaryASBR_LSA,
    5: OSPF_External_LSA,
    7: OSPF_NSSA_External_LSA,
}

AUTH_NOTE = ("authentication data present in capture but NOT verified "
             "offline; never used as a trust source")


def seq_to_signed(seq):
    """Interpret an LS sequence number in its signed 32-bit space.

    RFC 2328 section 12.1.6: the sequence space is linear and signed,
    from InitialSequenceNumber (-2**31 + 1) to MaxSequenceNumber
    (2**31 - 1).  A plain unsigned integer sort inverts the two ends
    of the space and must not be used.
    """
    return seq - 2 ** 32 if seq >= 2 ** 31 else seq


@dataclass
class CapturedLsa:
    """One LSA instance: raw bytes, capture time, decoded fields."""

    raw: bytes               # exact captured LSA bytes (may be short)
    capture_time: float      # observation time of the enclosing frame
    area: str                # area from the enclosing OSPF header
    age: int = 0
    lstype: int = 0
    lsid: str = ""
    adrouter: str = ""
    seq: int = 0
    chksum: int = 0
    declared_len: int = 0    # len field as captured
    captured_len: int = 0    # bytes actually available for this LSA
    errors: list = field(default_factory=list)

    @property
    def identity(self):
        """LSA identity per RFC 2328 section 12.1: type, LS ID,
        advertising router -- scoped by the area it was seen in."""
        return (self.area, self.lstype, self.lsid, self.adrouter)

    @property
    def is_flush(self):
        return self.age == MAX_AGE

    def short(self):
        return ("type=%d id=%s adv=%s seq=0x%08X cksum=0x%04X age=%d"
                % (self.lstype, self.lsid, self.adrouter, self.seq,
                   self.chksum, self.age))


@dataclass
class CapturedUpdate:
    """One decoded LS Update frame."""

    raw: bytes
    capture_time: float
    src: str = ""
    area: str = ""
    authtype: int = 0
    auth_note: str = AUTH_NOTE
    declared_len: int = 0
    captured_len: int = 0
    trailing_bytes: int = 0  # e.g. crypto auth digest we cannot verify
    lsas: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def _verify_checksum(raw, declared_len):
    """RFC 2328 annex C: Fletcher-16 over the LSA excluding the age
    field, with the checksum field itself treated as zero."""
    body = raw[:declared_len]
    zeroed = body[:16] + b"\x00\x00" + body[18:]
    return ospf_lsa_checksum(zeroed) == body[16:18]


def decode_lsa(raw, capture_time, area, available):
    """Decode and validate one raw LSA slice.

    Validation runs before any comparison: a declared length that is
    implausible or exceeds the captured bytes, or a checksum mismatch,
    marks the instance unusable as evidence.
    """
    clsa = CapturedLsa(raw=raw, capture_time=capture_time, area=area,
                       captured_len=available)
    if len(raw) < LSA_HEADER_LEN:
        clsa.errors.append("truncated LSA header: %d of %d bytes captured"
                           % (len(raw), LSA_HEADER_LEN))
        return clsa
    (clsa.age, _options, clsa.lstype, lsid, adrouter, clsa.seq,
     clsa.chksum, clsa.declared_len) = struct.unpack("!HBB4s4sIHH",
                                                     raw[:LSA_HEADER_LEN])
    clsa.lsid = ".".join(str(b) for b in lsid)
    clsa.adrouter = ".".join(str(b) for b in adrouter)
    if clsa.declared_len < LSA_HEADER_LEN:
        clsa.errors.append("declared len %d < LSA header size %d"
                           % (clsa.declared_len, LSA_HEADER_LEN))
    if clsa.declared_len % 4 != 0:
        clsa.errors.append("declared len %d not a multiple of 4"
                           % clsa.declared_len)
    if clsa.declared_len > available:
        clsa.errors.append("incomplete capture: declared len %d but only "
                           "%d bytes available"
                           % (clsa.declared_len, available))
    if clsa.seq == RESERVED_SEQ:
        clsa.errors.append("sequence number 0x80000000 is reserved "
                           "(RFC 2328 section 12.1.6)")
    if not clsa.errors:
        # full declared length is present; decode with Scapy and verify
        cls = LSA_CLASSES.get(clsa.lstype, OSPF_LSA_Hdr)
        cls(raw[:clsa.declared_len])  # dissection sanity check
        if not _verify_checksum(raw, clsa.declared_len):
            clsa.errors.append("LSA checksum mismatch (RFC 2328 annex C)")
    return clsa


def decode_ls_update(frame, capture_time):
    """Decode one raw OSPF LS Update frame (starting at the OSPF
    header) into a CapturedUpdate with validated CapturedLsa items."""
    upd = CapturedUpdate(raw=frame, capture_time=capture_time,
                         captured_len=len(frame))
    try:
        hdr = OSPF_Hdr(frame)
    except Exception as exc:
        upd.errors.append("OSPF header dissection failed: %s" % exc)
        return upd
    upd.src = hdr.src
    upd.area = hdr.area
    upd.authtype = hdr.authtype
    upd.declared_len = hdr.len or 0
    if hdr.type != 4:
        upd.errors.append("not an LS Update (OSPF type %r)" % hdr.type)
        return upd
    if upd.declared_len > len(frame):
        upd.errors.append("incomplete frame: OSPF len %d but %d bytes "
                          "captured" % (upd.declared_len, len(frame)))
    elif upd.declared_len < len(frame):
        upd.trailing_bytes = len(frame) - upd.declared_len
    body_end = min(upd.declared_len, len(frame))
    body = frame[OSPF_HDR_LEN:body_end]
    if len(body) < 4:
        upd.errors.append("missing LSA count field")
        return upd
    (count,) = struct.unpack("!I", body[:4])
    offset = 4
    for _ in range(count):
        if offset + LSA_HEADER_LEN > len(body):
            upd.errors.append("LSA list truncated at offset %d" % offset)
            break
        (declared,) = struct.unpack("!H", body[offset + 18:offset + 20])
        available = len(body) - offset
        slice_len = min(declared, available) if declared >= LSA_HEADER_LEN \
            else LSA_HEADER_LEN
        raw_lsa = body[offset:offset + slice_len]
        upd.lsas.append(decode_lsa(raw_lsa, capture_time, hdr.area,
                                   available))
        if declared < LSA_HEADER_LEN:
            break  # cannot trust further offsets
        offset += declared
    return upd


class Verdict(Enum):
    A_MORE_RECENT = "A more recent"
    B_MORE_RECENT = "B more recent"
    EQUIVALENT = "equivalent"
    UNDECIDABLE = "undecidable"


@dataclass
class Comparison:
    verdict: Verdict
    reason: str


def compare_instances(a, b):
    """RFC 2328 section 13.1: determine which of two instances of the
    same LSA identity is more recent.

    The rules are applied in the RFC's order: (1) signed sequence
    number, (2) checksum, (3) MaxAge, (4) MaxAgeDiff.  Both instances
    must already have passed length and checksum validation.
    """
    if a.identity != b.identity:
        return Comparison(Verdict.UNDECIDABLE,
                          "different LSA identity; not comparable")
    if a.errors or b.errors:
        return Comparison(Verdict.UNDECIDABLE,
                          "at least one instance failed validation")
    sa, sb = seq_to_signed(a.seq), seq_to_signed(b.seq)
    if sa != sb:
        newer, seq = (Verdict.B_MORE_RECENT, b) if sb > sa \
            else (Verdict.A_MORE_RECENT, a)
        return Comparison(newer,
                          "RFC 2328 13.1(1): signed sequence number "
                          "0x%08X > 0x%08X"
                          % (max(sa, sb) & 0xFFFFFFFF,
                             min(sa, sb) & 0xFFFFFFFF))
    if a.chksum != b.chksum:
        verdict = Verdict.B_MORE_RECENT if b.chksum > a.chksum \
            else Verdict.A_MORE_RECENT
        return Comparison(verdict,
                          "RFC 2328 13.1(2): same sequence, larger "
                          "checksum 0x%04X wins"
                          % max(a.chksum, b.chksum))
    if a.is_flush != b.is_flush:
        verdict = Verdict.B_MORE_RECENT if b.is_flush \
            else Verdict.A_MORE_RECENT
        return Comparison(verdict,
                          "RFC 2328 13.1(3): same sequence and checksum, "
                          "the instance aged to MaxAge is more recent")
    diff = abs(a.age - b.age)
    if diff > MAX_AGE_DIFF:
        verdict = Verdict.B_MORE_RECENT if b.age < a.age \
            else Verdict.A_MORE_RECENT
        return Comparison(verdict,
                          "RFC 2328 13.1(4): age difference %ds exceeds "
                          "MaxAgeDiff (%ds); younger instance wins"
                          % (diff, MAX_AGE_DIFF))
    return Comparison(Verdict.EQUIVALENT,
                      "RFC 2328 13.1: same sequence and checksum, age "
                      "difference %ds within MaxAgeDiff; instances are "
                      "equivalent, no topology change" % diff)


def naive_unsigned_newer(a, b):
    """The backend anti-pattern under review: 'larger sequence number
    wins' on the raw unsigned 32-bit value.  Kept only to demonstrate
    where it diverges from RFC 2328 section 12.1.6."""
    return b.seq > a.seq


class Action(Enum):
    INSTALL = "INSTALL"            # first valid instance for an identity
    OVERRIDE = "OVERRIDE"          # newer instance replaces the retained one
    FLUSH = "FLUSH"                # newer instance is MaxAge: identity flushed
    WRAP_RESTART = "WRAP_RESTART"  # legitimate restart after seq exhaustion
    RETAIN = "RETAIN"              # incoming is older: kept as history only
    DUPLICATE = "DUPLICATE"        # equivalent per 13.1: no topology change
    REJECT_INVALID = "REJECT_INVALID"  # failed length/checksum/reserved seq
    UNCERTAIN = "UNCERTAIN"        # evidence insufficient; no conclusion


@dataclass
class Decision:
    action: Action
    reason: str
    lsa: CapturedLsa
    incumbent: object = None


class ForensicStore:
    """Replay engine: applies captured instances in arrival order and
    records an auditable decision for each.

    Wrap handling (RFC 2328 section 12.1.6): after MaxSequenceNumber a
    router must flush its LSA (premature aging to MaxAge) before
    reoriginating at InitialSequenceNumber.  A restart at
    InitialSequenceNumber is therefore accepted only when the flush of
    the MaxSequenceNumber instance was observed for the same identity;
    the pair is tracked explicitly so that neither plain unsigned nor
    plain signed integer ordering can silently swallow it.  Instances
    whose sequence numbers belong to the pre-wrap generation and that
    arrive after a confirmed wrap are flagged UNCERTAIN instead of
    being ranked by integer order.
    """

    def __init__(self):
        self.current = {}        # identity -> retained CapturedLsa
        self.history = {}        # identity -> [CapturedLsa]
        self.wrap_pending = {}   # identity -> CapturedLsa (MaxSeq flush)
        self.wraps = {}          # identity -> (flush_time, confirm_time)
        self.pre_wrap_seqs = {}  # identity -> set of pre-wrap seq numbers

    def _confirm_wrap(self, key, restart, flush_time, confirm_time):
        self.wraps[key] = (flush_time, confirm_time)
        self.pre_wrap_seqs[key] = {
            c.seq for c in self.history.get(key, [])
            if c.capture_time <= confirm_time and c is not restart
        }
        self.wrap_pending.pop(key, None)
        self.current[key] = restart

    def apply(self, clsa):
        key = clsa.identity
        self.history.setdefault(key, []).append(clsa)
        if clsa.errors:
            return Decision(Action.REJECT_INVALID,
                            "; ".join(clsa.errors), clsa,
                            self.current.get(key))
        incumbent = self.current.get(key)
        if incumbent is None:
            if clsa.is_flush:
                return Decision(
                    Action.UNCERTAIN,
                    "MaxAge flush with no prior instance observed; "
                    "nothing to remove and origin cannot be verified",
                    clsa, None)
            self.current[key] = clsa
            return Decision(Action.INSTALL,
                            "first valid instance observed for this "
                            "identity", clsa, None)
        if key in self.wraps:
            flush_time, confirm_time = self.wraps[key]
            if clsa.capture_time < flush_time:
                return Decision(
                    Action.UNCERTAIN,
                    "captured at t=%.0f, before the wrap flush (t=%.0f): "
                    "pre-wrap generation evidence arriving late; integer "
                    "ordering would wrongly resurrect it"
                    % (clsa.capture_time, flush_time), clsa, incumbent)
            if (clsa.capture_time > confirm_time
                    and clsa.seq in self.pre_wrap_seqs.get(key, set())):
                return Decision(
                    Action.UNCERTAIN,
                    "sequence number 0x%08X belongs to the pre-wrap "
                    "generation (wrap confirmed at t=%.0f); integer "
                    "ordering would wrongly resurrect this stale instance"
                    % (clsa.seq, confirm_time), clsa, incumbent)
        if (key in self.wrap_pending and clsa.seq == INITIAL_SEQ
                and not clsa.is_flush):
            flushed = self.wrap_pending[key]
            self._confirm_wrap(key, clsa, flushed.capture_time,
                               clsa.capture_time)
            return Decision(
                Action.WRAP_RESTART,
                "RFC 2328 12.1.6: MaxSequenceNumber instance was flushed "
                "at t=%.0f; restart at InitialSequenceNumber accepted "
                "as a new generation, not ranked by integer order"
                % flushed.capture_time, clsa, incumbent)
        comp = compare_instances(incumbent, clsa)
        if comp.verdict is Verdict.B_MORE_RECENT:
            if clsa.is_flush:
                self.current[key] = clsa
                if clsa.seq == MAX_SEQ:
                    self.wrap_pending[key] = clsa
                    restart = self._find_restart(key, clsa)
                    if restart is not None:
                        self._confirm_wrap(key, restart,
                                           clsa.capture_time,
                                           clsa.capture_time)
                        return Decision(
                            Action.WRAP_RESTART,
                            "RFC 2328 12.1.6: flush of MaxSequenceNumber "
                            "confirms the already-captured restart at "
                            "InitialSequenceNumber (t=%.0f); new "
                            "generation restored retroactively"
                            % restart.capture_time, clsa, incumbent)
                return Decision(Action.FLUSH,
                                comp.reason + "; identity flushed "
                                "(premature aging)", clsa, incumbent)
            self.current[key] = clsa
            return Decision(Action.OVERRIDE, comp.reason, clsa, incumbent)
        if comp.verdict is Verdict.A_MORE_RECENT:
            return Decision(Action.RETAIN,
                            comp.reason + "; incoming instance is older "
                            "than the retained one: historical evidence "
                            "only, not a topology change", clsa, incumbent)
        if comp.verdict is Verdict.EQUIVALENT:
            return Decision(Action.DUPLICATE, comp.reason, clsa, incumbent)
        return Decision(Action.UNCERTAIN, comp.reason, clsa, incumbent)

    def _find_restart(self, key, flush):
        for c in self.history.get(key, []):
            if (c.seq == INITIAL_SEQ and not c.is_flush and not c.errors
                    and c.capture_time > flush.capture_time - 1e-9
                    and c is not flush):
                return c
        return None
