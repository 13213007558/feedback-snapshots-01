"""DNSSEC-aware caching example.

A successful ``dns.dnssec.validate()`` call (or a received AD bit) only
answers "is this RRset authentic *right now*?".  It says nothing about how
long the answer may be cached.  This example shows how an integrator
computes an evidence-backed cache lifetime from:

* the RRset's own TTL,
* the RRSIG's original TTL (RFC 4034 section 3.1.3), and
* the remaining validity of the signature that actually verified
  (RRSIG expiration minus the fixed validation time).

The effective TTL is the minimum of the three, computed once at a fixed
validation instant and stored as an absolute expiry.  A complete answer
(e.g. CNAME chain plus final address RRset) keeps the per-RRset evidence
for every link and expires with its weakest link.  Failed revalidation,
policy-denied or unrelated signatures, and backwards clock jumps can never
extend an entry.

Run ``python examples/dnssec_cache.py`` for a demo that uses short-lived
signatures over long TTLs and advances a fake clock to show cache hits and
expiry, printing a report of which field actually limits each entry.
"""

import time
from dataclasses import dataclass
from typing import Callable

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rrset
from dns.rdtypes.ANY.RRSIG import RRSIG


class NoValidSignature(Exception):
    """No RRSIG in the supplied set validated the RRset."""


@dataclass(frozen=True)
class ValidatedRRset:
    """An RRset plus the single RRSIG that actually validated it.

    The evidence is bound to the fixed validation instant ``validated_at``.
    The absolute expiry is derived once from that instant, so a backwards
    clock jump can never renew the entry.
    """

    rrset: dns.rrset.RRset
    rrsig: RRSIG
    validated_at: int

    @property
    def signature_remaining(self) -> int:
        """Seconds of signature validity left at the validation instant."""
        return max(0, self.rrsig.expiration - self.validated_at)

    @property
    def effective_ttl(self) -> int:
        """The evidence-backed TTL: the minimum of the RRset TTL, the
        RRSIG original TTL, and the remaining signature validity."""
        return min(self.rrset.ttl, self.rrsig.original_ttl, self.signature_remaining)

    @property
    def expires_at(self) -> int:
        """Absolute expiry instant, fixed at validation time."""
        return self.validated_at + self.effective_ttl

    @property
    def limiting_factor(self) -> str:
        """Which field actually bounds the cache lifetime."""
        ttl = self.effective_ttl
        if ttl == self.signature_remaining:
            return "rrsig-remaining-validity"
        if ttl == self.rrset.ttl:
            return "rrset-ttl"
        return "rrsig-original-ttl"

    def is_valid_at(self, now: float) -> bool:
        """Absolute check, immune to clock rollback."""
        return now < self.expires_at

    def remaining_ttl(self, now: float) -> int:
        """TTL to serve at *now*, clamped so a backwards clock can never
        produce a TTL larger than the evidence justified."""
        return max(0, min(self.effective_ttl, int(self.expires_at - now)))

    def explain(self) -> dict:
        """The evidence behind this entry's cache deadline."""
        return {
            "name": str(self.rrset.name),
            "rdtype": dns.rdatatype.to_text(self.rrset.rdtype),
            "validated_at": self.validated_at,
            "rrset_ttl": self.rrset.ttl,
            "rrsig_original_ttl": self.rrsig.original_ttl,
            "rrsig_remaining_validity": self.signature_remaining,
            "effective_ttl": self.effective_ttl,
            "expires_at": self.expires_at,
            "limiting_factor": self.limiting_factor,
            "signer": str(self.rrsig.signer),
            "key_tag": self.rrsig.key_tag,
        }


def validate_rrset(
    rrset: dns.rrset.RRset,
    rrsigset: dns.rrset.RRset,
    keys: dict,
    *,
    now: int,
    policy: dns.dnssec.Policy | None = None,
    origin: dns.name.Name | None = None,
) -> ValidatedRRset:
    """Validate *rrset* at the fixed instant *now* and return the evidence.

    Every RRSIG is tried on its own.  Only a signature that actually
    verifies -- covering this RRset's type and class, made by a known key,
    inside its validity window, and allowed by *policy* -- may anchor a
    cache entry.  Expired, not-yet-valid, policy-denied, or unrelated
    signatures are ignored and can never extend the cache.  When several
    signatures validate, the one yielding the latest expiry wins.

    :raises NoValidSignature: if no RRSIG validates the RRset.
    """
    best: ValidatedRRset | None = None
    for rrsig in rrsigset:
        singleton = dns.rdataset.from_rdata(rrsigset.ttl, rrsig)
        try:
            dns.dnssec.validate(
                rrset, (rrsigset.name, singleton), keys, origin, now, policy
            )
        except dns.dnssec.ValidationFailure:
            continue
        candidate = ValidatedRRset(rrset=rrset, rrsig=rrsig, validated_at=now)
        if best is None or candidate.expires_at > best.expires_at:
            best = candidate
    if best is None:
        raise NoValidSignature(
            f"no usable RRSIG for {rrset.name} "
            f"{dns.rdatatype.to_text(rrset.rdtype)}"
        )
    return best


@dataclass(frozen=True)
class CachedAnswer:
    """A complete answer: every RRset in the CNAME chain plus the final
    address RRset, each carrying its own validation evidence."""

    qname: dns.name.Name
    qtype: dns.rdatatype.RdataType
    chain: tuple[ValidatedRRset, ...]

    @property
    def expires_at(self) -> int:
        """The whole answer dies with its weakest link -- never take only
        the last RRset's expiry."""
        return min(link.expires_at for link in self.chain)

    @property
    def limiting_link(self) -> ValidatedRRset:
        return min(self.chain, key=lambda link: link.expires_at)

    def is_valid_at(self, now: float) -> bool:
        return now < self.expires_at

    def remaining_ttl(self, now: float) -> int:
        """TTL to serve for the whole answer: the minimum over all links,
        each already clamped against clock rollback."""
        return min(link.remaining_ttl(now) for link in self.chain)


class DNSSECCache:
    """A minimal evidence-backed cache with an injectable clock."""

    def __init__(self, clock: Callable[[], float] = time.time):
        self._clock = clock
        self._rrsets: dict[tuple, ValidatedRRset] = {}
        self._answers: dict[tuple, CachedAnswer] = {}

    def store_rrset(self, evidence: ValidatedRRset) -> None:
        key = (evidence.rrset.name, evidence.rrset.rdclass, evidence.rrset.rdtype)
        self._rrsets[key] = evidence

    def lookup_rrset(
        self, name: dns.name.Name, rdtype, rdclass=dns.rdataclass.IN
    ) -> ValidatedRRset | None:
        entry = self._rrsets.get((name, rdclass, rdtype))
        if entry is None:
            return None
        if not entry.is_valid_at(self._clock()):
            del self._rrsets[(name, rdclass, rdtype)]
            return None
        return entry

    def store_answer(self, answer: CachedAnswer) -> None:
        self._answers[(answer.qname, answer.qtype)] = answer

    def lookup_answer(self, qname: dns.name.Name, qtype) -> CachedAnswer | None:
        answer = self._answers.get((qname, qtype))
        if answer is None:
            return None
        if not answer.is_valid_at(self._clock()):
            del self._answers[(qname, qtype)]
            return None
        return answer

    def refresh_rrset(
        self,
        rrset: dns.rrset.RRset,
        rrsigset: dns.rrset.RRset,
        keys: dict,
        *,
        policy: dns.dnssec.Policy | None = None,
    ) -> ValidatedRRset | None:
        """Revalidate and replace the entry for *rrset*.

        Only a freshly validated signature creates new evidence.  If
        revalidation fails, the old entry is kept untouched until its own
        absolute expiry -- a failed revalidation, or a signature unrelated
        to this RRset, can never extend the cache.
        """
        try:
            evidence = validate_rrset(
                rrset, rrsigset, keys, now=int(self._clock()), policy=policy
            )
        except NoValidSignature:
            key = (rrset.name, rrset.rdclass, rrset.rdtype)
            return self._rrsets.get(key)
        self.store_rrset(evidence)
        return evidence


def render_answer_report(answer: CachedAnswer, now: float) -> str:
    """Render the evidence report for a cached answer."""
    lines = [
        f"answer {answer.qname} {dns.rdatatype.to_text(answer.qtype)}: "
        f"expires at {answer.expires_at} "
        f"(in {answer.remaining_ttl(now)}s), "
        f"limited by {answer.limiting_link.rrset.name} "
        f"[{answer.limiting_link.limiting_factor}]",
        "  {:<28} {:>9} {:>9} {:>9} {:>9}  {}".format(
            "rrset", "ttl", "orig-ttl", "sig-left", "eff-ttl", "limiting"
        ),
    ]
    for link in answer.chain:
        lines.append(
            "  {:<28} {:>9} {:>9} {:>9} {:>9}  {}".format(
                f"{link.rrset.name} {dns.rdatatype.to_text(link.rrset.rdtype)}",
                link.rrset.ttl,
                link.rrsig.original_ttl,
                link.signature_remaining,
                link.effective_ttl,
                link.limiting_factor,
            )
        )
    lines.append(
        "  note: validation success and the AD bit only say 'authentic "
        "now'; the deadline above comes from the fields shown."
    )
    return "\n".join(lines)


class FakeClock:
    """A manually advanced clock for demos and tests."""

    def __init__(self, now: float):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def rewind(self, seconds: float) -> None:
        self.now -= seconds


def make_zone_key(algorithm="ECDSAP256SHA256"):
    """Make a (private key, DNSKEY rdata) pair for a zone.  Useful for
    integrator test setups; requires the ``dnssec`` extra."""
    from cryptography.hazmat.primitives.asymmetric import ec

    private_key = ec.generate_private_key(ec.SECP256R1())
    dnskey = dns.dnssec.make_dnskey(private_key.public_key(), algorithm)
    return private_key, dnskey


def _demo() -> None:
    t0 = 1_000_000
    clock = FakeClock(t0)
    signer = dns.name.from_text("example.com.")
    private_key, dnskey = make_zone_key()
    keys = {signer: dns.rdataset.from_rdata(0, dnskey)}

    def signed(name, ttl, rdtype, rdata_text, lifetime, sign_ttl=None):
        rrset = dns.rrset.from_text(name, ttl, "IN", rdtype, rdata_text)
        sign_rrset = rrset
        if sign_ttl is not None:
            # Sign when the zone had a different (shorter) TTL.
            sign_rrset = dns.rrset.from_rdata(rrset.name, sign_ttl, *rrset)
        rrsig = dns.dnssec.sign(
            sign_rrset,
            private_key,
            signer,
            dnskey,
            inception=t0,
            expiration=t0 + lifetime,
        )
        rrsigset = dns.rrset.from_rdata(rrset.name, rrset.ttl, rrsig)
        return validate_rrset(rrset, rrsigset, keys, now=t0)

    # Short-lived signatures covering longer TTLs.
    cname = signed("www.example.com.", 300, "CNAME", "lb.example.com.", 900)
    addr = signed("lb.example.com.", 3600, "A", "192.0.2.1", 120)
    api = signed("api.example.com.", 500, "A", "192.0.2.9", 800, sign_ttl=200)

    answer = CachedAnswer(
        qname=dns.name.from_text("www.example.com."),
        qtype=dns.rdatatype.A,
        chain=(cname, addr),
    )
    print(render_answer_report(answer, clock()))
    print()
    print(
        f"api.example.com. A alone: effective TTL {api.effective_ttl}s "
        f"limited by {api.limiting_factor} "
        f"(served TTL 500, RRSIG original TTL 200)"
    )
    print()

    cache = DNSSECCache(clock)
    cache.store_answer(answer)
    cache.store_rrset(cname)
    cache.store_rrset(addr)

    clock.advance(100)
    hit = cache.lookup_answer(answer.qname, dns.rdatatype.A)
    print(f"t={int(clock())}: answer hit, serve TTL {hit.remaining_ttl(clock())}s")

    clock.advance(21)
    print(
        f"t={int(clock())}: answer hit? {cache.lookup_answer(answer.qname, dns.rdatatype.A) is not None}"
    )

    # Clock rollback cannot renew stored entries.
    clock.rewind(521)  # t = 999600, before validation time
    entry = cache.lookup_rrset(addr.rrset.name, dns.rdatatype.A)
    print(
        f"t={int(clock())} (rolled back): A entry still expires at "
        f"{entry.expires_at}, served TTL clamped to "
        f"{entry.remaining_ttl(clock())}s (not {entry.expires_at - int(clock())}s)"
    )

    # Failed revalidation cannot extend the entry.
    clock.now = t0 + 100
    expired_rrsig = dns.dnssec.sign(
        addr.rrset,
        private_key,
        signer,
        dnskey,
        inception=t0 - 1000,
        expiration=t0 - 500,
    )
    stale_sigs = dns.rrset.from_rdata(addr.rrset.name, 3600, expired_rrsig)
    kept = cache.refresh_rrset(addr.rrset, stale_sigs, keys)
    print(
        f"t={int(clock())}: refresh with only an expired signature -> "
        f"entry unchanged, still expires at {kept.expires_at}"
    )


if __name__ == "__main__":
    _demo()
