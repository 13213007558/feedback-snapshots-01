"""Tests for the DNSSEC-aware caching example (examples/dnssec_cache.py)."""

import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "examples"))

import dns.dnssec
import dns.name
import dns.rdataset
import dns.rdatatype
import dns.rrset

import dnssec_cache

T0 = 1_000_000
SIGNER = dns.name.from_text("example.com.")


@pytest.fixture
def keypair():
    return dnssec_cache.make_zone_key()


@pytest.fixture
def keys(keypair):
    _, dnskey = keypair
    return {SIGNER: dns.rdataset.from_rdata(0, dnskey)}


def make_rrset(name, ttl, rdtype, rdata):
    return dns.rrset.from_text(name, ttl, "IN", rdtype, rdata)


def sign(keypair, rrset, inception=T0, expiration=T0 + 600, sign_ttl=None):
    private_key, dnskey = keypair
    sign_rrset = rrset
    if sign_ttl is not None:
        sign_rrset = dns.rrset.from_rdata(rrset.name, sign_ttl, *rrset)
    rrsig = dns.dnssec.sign(
        sign_rrset,
        private_key,
        SIGNER,
        dnskey,
        inception=inception,
        expiration=expiration,
    )
    return dns.rrset.from_rdata(rrset.name, rrset.ttl, rrsig)


def test_effective_ttl_limited_by_rrset_ttl(keypair, keys):
    rrset = make_rrset("www.example.com.", 300, "A", "192.0.2.1")
    rrsigset = sign(keypair, rrset, expiration=T0 + 900)
    ev = dnssec_cache.validate_rrset(rrset, rrsigset, keys, now=T0)
    assert ev.effective_ttl == 300
    assert ev.limiting_factor == "rrset-ttl"
    assert ev.expires_at == T0 + 300


def test_short_lived_signature_caps_long_ttl(keypair, keys):
    rrset = make_rrset("lb.example.com.", 3600, "A", "192.0.2.1")
    rrsigset = sign(keypair, rrset, expiration=T0 + 120)
    ev = dnssec_cache.validate_rrset(rrset, rrsigset, keys, now=T0)
    assert ev.effective_ttl == 120
    assert ev.limiting_factor == "rrsig-remaining-validity"
    assert ev.expires_at == T0 + 120


def test_rrsig_original_ttl_caps_served_ttl(keypair, keys):
    # Signed when the zone TTL was 200, now served with TTL 500.
    rrset = make_rrset("api.example.com.", 500, "A", "192.0.2.9")
    rrsigset = sign(keypair, rrset, expiration=T0 + 800, sign_ttl=200)
    ev = dnssec_cache.validate_rrset(rrset, rrsigset, keys, now=T0)
    assert ev.effective_ttl == 200
    assert ev.limiting_factor == "rrsig-original-ttl"


def test_best_of_multiple_valid_signatures_wins(keypair, keys):
    rrset = make_rrset("www.example.com.", 300, "A", "192.0.2.1")
    short = sign(keypair, rrset, expiration=T0 + 100)
    long = sign(keypair, rrset, expiration=T0 + 900)
    combined = dns.rrset.from_rdata(
        rrset.name, 300, *[r for r in short] + [r for r in long]
    )
    ev = dnssec_cache.validate_rrset(rrset, combined, keys, now=T0)
    assert ev.effective_ttl == 300
    assert ev.rrsig.expiration == T0 + 900


def test_expired_signature_cannot_extend(keypair, keys):
    rrset = make_rrset("www.example.com.", 300, "A", "192.0.2.1")
    expired = sign(keypair, rrset, inception=T0 - 1000, expiration=T0 - 500)
    with pytest.raises(dnssec_cache.NoValidSignature):
        dnssec_cache.validate_rrset(rrset, expired, keys, now=T0)


def test_unrelated_signature_cannot_validate(keypair, keys):
    rrset = make_rrset("www.example.com.", 300, "A", "192.0.2.1")
    txt = make_rrset("www.example.com.", 300, "TXT", '"hello"')
    txt_sigs = sign(keypair, txt, expiration=T0 + 900)
    with pytest.raises(dnssec_cache.NoValidSignature):
        dnssec_cache.validate_rrset(rrset, txt_sigs, keys, now=T0)


def test_policy_denied_signature_cannot_extend(keypair, keys):
    rrset = make_rrset("www.example.com.", 300, "A", "192.0.2.1")
    rrsigset = sign(keypair, rrset, expiration=T0 + 900)
    deny_all = dns.dnssec.SimpleDeny(
        set(), {dns.dnssec.Algorithm.ECDSAP256SHA256}, set(), set()
    )
    with pytest.raises(dnssec_cache.NoValidSignature):
        dnssec_cache.validate_rrset(rrset, rrsigset, keys, now=T0, policy=deny_all)


def test_answer_expires_with_weakest_link(keypair, keys):
    cname = make_rrset("www.example.com.", 300, "CNAME", "lb.example.com.")
    addr = make_rrset("lb.example.com.", 3600, "A", "192.0.2.1")
    cname_ev = dnssec_cache.validate_rrset(
        cname, sign(keypair, cname, expiration=T0 + 900), keys, now=T0
    )
    addr_ev = dnssec_cache.validate_rrset(
        addr, sign(keypair, addr, expiration=T0 + 120), keys, now=T0
    )
    answer = dnssec_cache.CachedAnswer(
        qname=dns.name.from_text("www.example.com."),
        qtype=dns.rdatatype.A,
        chain=(cname_ev, addr_ev),
    )
    # Not the last RRset's expiry (1000120 is the address link), and not
    # the CNAME's 300s: the whole answer dies with the weakest link.
    assert answer.expires_at == T0 + 120
    assert answer.limiting_link is addr_ev


def test_cache_hit_and_expiry_with_fake_clock(keypair, keys):
    clock = dnssec_cache.FakeClock(T0)
    cache = dnssec_cache.DNSSECCache(clock)
    rrset = make_rrset("lb.example.com.", 3600, "A", "192.0.2.1")
    ev = dnssec_cache.validate_rrset(
        rrset, sign(keypair, rrset, expiration=T0 + 120), keys, now=T0
    )
    cache.store_rrset(ev)
    clock.advance(119)
    hit = cache.lookup_rrset(rrset.name, dns.rdatatype.A)
    assert hit is not None
    assert hit.remaining_ttl(clock()) == 1
    clock.advance(2)
    assert cache.lookup_rrset(rrset.name, dns.rdatatype.A) is None


def test_failed_revalidation_does_not_extend(keypair, keys):
    clock = dnssec_cache.FakeClock(T0)
    cache = dnssec_cache.DNSSECCache(clock)
    rrset = make_rrset("lb.example.com.", 3600, "A", "192.0.2.1")
    ev = dnssec_cache.validate_rrset(
        rrset, sign(keypair, rrset, expiration=T0 + 120), keys, now=T0
    )
    cache.store_rrset(ev)
    clock.advance(100)
    # Only an expired signature is offered: no new evidence, no extension.
    stale = sign(keypair, rrset, inception=T0 - 1000, expiration=T0 - 500)
    kept = cache.refresh_rrset(rrset, stale, keys)
    assert kept is ev
    assert kept.expires_at == T0 + 120
    clock.advance(21)
    assert cache.lookup_rrset(rrset.name, dns.rdatatype.A) is None


def test_clock_rollback_does_not_renew(keypair, keys):
    clock = dnssec_cache.FakeClock(T0)
    cache = dnssec_cache.DNSSECCache(clock)
    rrset = make_rrset("lb.example.com.", 3600, "A", "192.0.2.1")
    ev = dnssec_cache.validate_rrset(
        rrset, sign(keypair, rrset, expiration=T0 + 120), keys, now=T0
    )
    cache.store_rrset(ev)
    clock.rewind(600)  # clock jumps backwards past validation time
    hit = cache.lookup_rrset(rrset.name, dns.rdatatype.A)
    assert hit is not None
    # Absolute expiry unchanged, and the served TTL is clamped to the
    # evidence-backed TTL rather than growing to 720s.
    assert hit.expires_at == T0 + 120
    assert hit.remaining_ttl(clock()) == 120
    clock.now = T0 + 120
    assert cache.lookup_rrset(rrset.name, dns.rdatatype.A) is None


def test_report_identifies_limiting_field(keypair, keys):
    rrset = make_rrset("lb.example.com.", 3600, "A", "192.0.2.1")
    ev = dnssec_cache.validate_rrset(
        rrset, sign(keypair, rrset, expiration=T0 + 120), keys, now=T0
    )
    info = ev.explain()
    assert info["limiting_factor"] == "rrsig-remaining-validity"
    assert info["rrset_ttl"] == 3600
    assert info["rrsig_original_ttl"] == 3600
    assert info["rrsig_remaining_validity"] == 120
    assert info["effective_ttl"] == 120
    assert info["expires_at"] == T0 + 120
