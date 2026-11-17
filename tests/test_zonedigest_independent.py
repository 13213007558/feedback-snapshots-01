# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Independent regression tests for ZONEMD (RFC 8976) zone digest
# verification.  Unlike test_zonedigest.py, which checks dnspython against
# the RFC's example zones, these tests build the canonical RR stream of
# RFC 8976 section 3.3.1 by hand and hash it with hashlib directly, so the
# expected digest does not depend on dnspython's digest code producing the
# same bytes as itself.

import calendar
import hashlib
import struct

import pytest

import dns.name
import dns.rdata
import dns.rdataset
import dns.zone

IN = 1
SERIAL = 2024010100

A = 1
NS = 2
SOA = 6
TXT = 16
RRSIG = 46
ZONEMD = 63

SCHEME_SIMPLE = 1
HASH_SHA384 = 1
HASH_SHA512 = 2

EXPIRATION = calendar.timegm((2025, 1, 1, 0, 0, 0, 0, 0, 0))
INCEPTION = calendar.timegm((2024, 1, 1, 0, 0, 0, 0, 0, 0))

# Canonical (lowercase, uncompressed) wire-form names, written out by hand.
EXAMPLE = b"\x07example\x00"
NS1 = b"\x03ns1" + EXAMPLE
NS2 = b"\x03ns2" + EXAMPLE
HOSTMASTER = b"\x0ahostmaster" + EXAMPLE
WWW = b"\x03www" + EXAMPLE


def rr(owner, rdtype, ttl, rdata):
    # One canonical RR: owner | type | class | TTL | RDLENGTH | RDATA.
    return owner + struct.pack("!HHIH", rdtype, IN, ttl, len(rdata)) + rdata


SOA_RDATA = NS1 + HOSTMASTER + struct.pack("!IIIII", SERIAL, 7200, 3600, 1209600, 3600)
RRSIG_SOA_RDATA = (
    struct.pack("!HBBIIIH", SOA, 8, 2, 3600, EXPIRATION, INCEPTION, 12345)
    + EXAMPLE
    + b"\x01\x02\x03\x04"
)
RRSIG_ZONEMD_RDATA = (
    struct.pack("!HBBIIIH", ZONEMD, 8, 2, 3600, EXPIRATION, INCEPTION, 12345)
    + EXAMPLE
    + b"\x05\x06\x07\x08"
)
ZONEMD_PLACEHOLDER_RDATA = struct.pack("!IBB", SERIAL, 1, 1) + b"\x00" * 48

# The canonical RR stream of RFC 8976 section 3.3.1 for ZONE below, listed
# by hand in canonical order: owner names in DNSSEC canonical order, then
# rdatasets by (type, covers), then rdatas sorted by canonical wire form.
# The apex ZONEMD RRset and the apex RRSIG covering ZONEMD are deliberately
# absent; the apex RRSIG covering SOA is present.
CANONICAL_STREAM = b"".join(
    [
        rr(EXAMPLE, A, 300, b"\xc0\x00\x02\x01"),
        rr(EXAMPLE, A, 300, b"\xc0\x00\x02\x02"),
        rr(EXAMPLE, NS, 7200, NS1),
        rr(EXAMPLE, NS, 7200, NS2),
        rr(EXAMPLE, SOA, 3600, SOA_RDATA),
        rr(EXAMPLE, RRSIG, 3600, RRSIG_SOA_RDATA),
        rr(WWW, A, 60, b"\xc0\x00\x02\x03"),
        rr(WWW, TXT, 600, b"\x05hello"),
    ]
)

EXPECTED_DIGESTS = {
    HASH_SHA384: hashlib.sha384(CANONICAL_STREAM).digest(),
    HASH_SHA512: hashlib.sha512(CANONICAL_STREAM).digest(),
}

# The same stream with the records at www in the wrong relative order.
WRONG_ORDER_STREAM = b"".join(
    [
        rr(EXAMPLE, A, 300, b"\xc0\x00\x02\x01"),
        rr(EXAMPLE, A, 300, b"\xc0\x00\x02\x02"),
        rr(EXAMPLE, NS, 7200, NS1),
        rr(EXAMPLE, NS, 7200, NS2),
        rr(EXAMPLE, SOA, 3600, SOA_RDATA),
        rr(EXAMPLE, RRSIG, 3600, RRSIG_SOA_RDATA),
        rr(WWW, TXT, 600, b"\x05hello"),
        rr(WWW, A, 60, b"\xc0\x00\x02\x03"),
    ]
)

# The stream an implementation would produce if it forgot to exclude the
# apex ZONEMD RRset and the RRSIG covering it.
STREAM_INCLUDING_EXCLUDED_RECORDS = b"".join(
    [
        rr(EXAMPLE, A, 300, b"\xc0\x00\x02\x01"),
        rr(EXAMPLE, A, 300, b"\xc0\x00\x02\x02"),
        rr(EXAMPLE, NS, 7200, NS1),
        rr(EXAMPLE, NS, 7200, NS2),
        rr(EXAMPLE, SOA, 3600, SOA_RDATA),
        rr(EXAMPLE, RRSIG, 3600, RRSIG_SOA_RDATA),
        rr(EXAMPLE, RRSIG, 3600, RRSIG_ZONEMD_RDATA),
        rr(EXAMPLE, ZONEMD, 300, ZONEMD_PLACEHOLDER_RDATA),
        rr(WWW, A, 60, b"\xc0\x00\x02\x03"),
        rr(WWW, TXT, 600, b"\x05hello"),
    ]
)

# The zone matching CANONICAL_STREAM.  It exercises mixed-case and relative
# owner names (WWW), mixed-case rdata names (NS1.EXAMPLE.), multiple rdatas
# per rrset, per-rrset TTLs, an apex ZONEMD placeholder with a wrong digest,
# and apex RRSIGs covering both SOA (digested) and ZONEMD (excluded).
ZONE = """
$ORIGIN example.
@           3600  IN  SOA   ns1 hostmaster 2024010100 7200 3600 1209600 3600
@           7200  IN  NS    NS1.EXAMPLE.
@           7200  IN  NS    ns2
@           300   IN  A     192.0.2.1
@           300   IN  A     192.0.2.2
@           3600  IN  RRSIG SOA 8 2 3600 20250101000000 20240101000000 12345 example. AQIDBA==
@           3600  IN  RRSIG ZONEMD 8 2 3600 20250101000000 20240101000000 12345 example. BQYHCA==
@           300   IN  ZONEMD 2024010100 1 1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
WWW         60    IN  A     192.0.2.3
www         600   IN  TXT   "hello"
"""

# The same zone with the records and the rdatas within each rrset in a
# different order, and all owner names written absolute.  Canonicalization
# must map it to the same stream.
PERMUTED_ZONE = """
$ORIGIN example.
www.example.  600   IN  TXT   "hello"
WWW.EXAMPLE.  60    IN  A     192.0.2.3
example.      300   IN  ZONEMD 2024010100 1 1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
example.      3600  IN  RRSIG ZONEMD 8 2 3600 20250101000000 20240101000000 12345 example. BQYHCA==
example.      300   IN  A     192.0.2.2
example.      300   IN  A     192.0.2.1
example.      7200  IN  NS    ns2.example.
example.      3600  IN  RRSIG SOA 8 2 3600 20250101000000 20240101000000 12345 example. AQIDBA==
example.      7200  IN  NS    NS1.EXAMPLE.
example.      3600  IN  SOA   ns1 hostmaster 2024010100 7200 3600 1209600 3600
"""


def make_zone(text=ZONE, relativize=True):
    return dns.zone.from_text(text, "example.", relativize=relativize)


def zonemd_rr(serial, scheme, hash_algorithm, digest):
    return dns.rdata.from_text(
        "IN", "ZONEMD", f"{serial} {scheme} {hash_algorithm} {digest.hex()}"
    )


def install_zonemd(zone, *rrs, ttl=300):
    zone.replace_rdataset(dns.name.empty, dns.rdataset.from_rdata(ttl, *rrs))


def test_hand_built_stream_matches_compute_digest():
    for relativize in (True, False):
        zone = make_zone(relativize=relativize)
        for hash_algorithm, expected in EXPECTED_DIGESTS.items():
            zonemd = zone.compute_digest(hash_algorithm)
            assert zonemd.digest == expected
            assert zonemd.serial == SERIAL
            assert zonemd.scheme == SCHEME_SIMPLE
            assert zonemd.hash_algorithm == hash_algorithm


def test_verify_accepts_hand_built_digest():
    zone = make_zone()
    good = zonemd_rr(SERIAL, SCHEME_SIMPLE, HASH_SHA384, EXPECTED_DIGESTS[HASH_SHA384])
    zone.verify_digest(good)
    install_zonemd(zone, good)
    zone.verify_digest()


def test_rr_permutation_and_absolute_names_give_same_digest():
    zone = make_zone(PERMUTED_ZONE)
    assert zone.compute_digest(HASH_SHA384).digest == EXPECTED_DIGESTS[HASH_SHA384]
    assert zone.compute_digest(HASH_SHA512).digest == EXPECTED_DIGESTS[HASH_SHA512]


def test_noncanonical_order_stream_is_rejected():
    # Verification must pin the exact canonical stream, not accept a digest
    # of some other ordering of the same records.
    wrong = hashlib.sha384(WRONG_ORDER_STREAM).digest()
    assert wrong != EXPECTED_DIGESTS[HASH_SHA384]
    zone = make_zone()
    with pytest.raises(dns.zone.DigestVerificationFailure):
        zone.verify_digest(zonemd_rr(SERIAL, SCHEME_SIMPLE, HASH_SHA384, wrong))


def test_stream_including_excluded_records_is_rejected():
    # A digest computed over a stream that wrongly includes the apex ZONEMD
    # RRset and the RRSIG covering it must not verify.
    wrong = hashlib.sha384(STREAM_INCLUDING_EXCLUDED_RECORDS).digest()
    assert wrong != EXPECTED_DIGESTS[HASH_SHA384]
    zone = make_zone()
    with pytest.raises(dns.zone.DigestVerificationFailure):
        zone.verify_digest(zonemd_rr(SERIAL, SCHEME_SIMPLE, HASH_SHA384, wrong))


def test_participating_record_changes_are_rejected():
    mutations = []

    def change_www_address(zone):
        zone.replace_rdataset(
            dns.name.from_text("www.example."),
            dns.rdataset.from_text("IN", "A", 60, "192.0.2.4"),
        )

    mutations.append(change_www_address)

    def change_ns_ttl(zone):
        zone.replace_rdataset(
            dns.name.empty,
            dns.rdataset.from_text("IN", "NS", 7201, "ns1.example.", "ns2.example."),
        )

    mutations.append(change_ns_ttl)

    def change_txt_content(zone):
        zone.replace_rdataset(
            dns.name.from_text("www.example."),
            dns.rdataset.from_text("IN", "TXT", 600, "hello", "bye"),
        )

    mutations.append(change_txt_content)

    for mutate in mutations:
        zone = make_zone()
        install_zonemd(
            zone, zonemd_rr(SERIAL, SCHEME_SIMPLE, HASH_SHA384, EXPECTED_DIGESTS[1])
        )
        mutate(zone)
        with pytest.raises(dns.zone.DigestVerificationFailure):
            zone.verify_digest()


def test_excluded_record_changes_are_accepted():
    # The apex ZONEMD RRset (TTL and rdata) and the apex RRSIG covering
    # ZONEMD are not part of the digested stream, so changing them must not
    # break verification.
    zone = make_zone()
    good384 = zonemd_rr(SERIAL, SCHEME_SIMPLE, HASH_SHA384, EXPECTED_DIGESTS[1])
    good512 = zonemd_rr(SERIAL, SCHEME_SIMPLE, HASH_SHA512, EXPECTED_DIGESTS[2])
    install_zonemd(zone, good384, good512, ttl=999)
    garbage512 = zonemd_rr(SERIAL, SCHEME_SIMPLE, HASH_SHA512, b"\xab" * 64)
    install_zonemd(zone, good384, garbage512, ttl=999)
    mutated_rrsig = dns.rdata.from_text(
        "IN",
        "RRSIG",
        "ZONEMD 8 2 3600 20250101000000 20240101000000 12345 example. BQYHCQ==",
    )
    zone.replace_rdataset(dns.name.empty, dns.rdataset.from_rdata(3600, mutated_rrsig))
    zone.verify_digest()


def test_included_rrsig_change_is_rejected():
    # The apex RRSIG covering SOA *is* digested; only the one covering
    # ZONEMD is excluded.
    zone = make_zone()
    install_zonemd(
        zone, zonemd_rr(SERIAL, SCHEME_SIMPLE, HASH_SHA384, EXPECTED_DIGESTS[1])
    )
    mutated_rrsig = dns.rdata.from_text(
        "IN",
        "RRSIG",
        "SOA 8 2 3600 20250101000000 20240101000000 12345 example. AQIDBQ==",
    )
    zone.replace_rdataset(dns.name.empty, dns.rdataset.from_rdata(3600, mutated_rrsig))
    with pytest.raises(dns.zone.DigestVerificationFailure):
        zone.verify_digest()


def test_serial_mismatch_is_rejected():
    zone = make_zone()
    install_zonemd(
        zone, zonemd_rr(SERIAL + 1, SCHEME_SIMPLE, HASH_SHA384, EXPECTED_DIGESTS[1])
    )
    with pytest.raises(dns.zone.DigestVerificationFailure):
        zone.verify_digest()


def test_duplicate_scheme_and_algorithm_is_a_conflict_not_a_choice():
    zone = make_zone()
    good = zonemd_rr(SERIAL, SCHEME_SIMPLE, HASH_SHA384, EXPECTED_DIGESTS[1])
    conflicting = zonemd_rr(SERIAL, SCHEME_SIMPLE, HASH_SHA384, b"\xab" * 48)
    install_zonemd(zone, good, conflicting)
    # The correct digest is present, but its (scheme, algorithm) tuple
    # occurs twice, so RFC 8976 section 4 step 4 disqualifies both RRs.
    # Verification must fail rather than pick one and ignore the conflict.
    with pytest.raises(dns.zone.DigestVerificationFailure):
        zone.verify_digest()
    # On its own the good record verifies, proving the failure above is the
    # duplicate-tuple rule and not a digest mismatch.
    zone.verify_digest(good)


def test_unsupported_scheme_and_hash_algorithm_are_rejected():
    zone = make_zone()
    # Even with digest bytes that would be correct for the hash, an
    # unsupported scheme must not verify.
    install_zonemd(zone, zonemd_rr(SERIAL, 241, HASH_SHA384, EXPECTED_DIGESTS[1]))
    with pytest.raises(dns.zone.DigestVerificationFailure):
        zone.verify_digest()
    install_zonemd(zone, zonemd_rr(SERIAL, SCHEME_SIMPLE, 240, b"\xab" * 48))
    with pytest.raises(dns.zone.DigestVerificationFailure):
        zone.verify_digest()


def adjudicate(zone):
    """Independently decide which apex ZONEMD RRs verification must use.

    Returns a list of (zonemd RR, usable, reason) verdicts derived from the
    hand-built expected digests and the RFC 8976 section 4 rules, without
    calling dnspython's verification.
    """
    rds = zone.get_rdataset(zone.origin, "ZONEMD")
    assert rds is not None
    keys = [(rr.scheme, rr.hash_algorithm) for rr in rds]
    verdicts = []
    for rr in rds:
        key = (rr.scheme, rr.hash_algorithm)
        if keys.count(key) > 1:
            verdicts.append((rr, False, "duplicate (scheme, hash algorithm)"))
        elif rr.serial != SERIAL:
            verdicts.append((rr, False, "serial does not match the SOA serial"))
        elif rr.scheme != SCHEME_SIMPLE:
            verdicts.append((rr, False, "unsupported scheme"))
        elif rr.hash_algorithm not in EXPECTED_DIGESTS:
            verdicts.append((rr, False, "unsupported hash algorithm"))
        elif rr.digest != EXPECTED_DIGESTS[rr.hash_algorithm]:
            verdicts.append((rr, False, "digest mismatch"))
        else:
            verdicts.append((rr, True, "usable"))
    return verdicts


def test_verify_reports_accept_reject_per_digest_record():
    zone = make_zone()
    good384 = zonemd_rr(SERIAL, SCHEME_SIMPLE, HASH_SHA384, EXPECTED_DIGESTS[1])
    good512 = zonemd_rr(SERIAL, SCHEME_SIMPLE, HASH_SHA512, EXPECTED_DIGESTS[2])
    wrong_serial = zonemd_rr(SERIAL + 1, SCHEME_SIMPLE, 240, b"\xab" * 48)
    unsupported_scheme = zonemd_rr(SERIAL, 241, HASH_SHA384, EXPECTED_DIGESTS[1])
    unsupported_hash = zonemd_rr(SERIAL, SCHEME_SIMPLE, 239, b"\xab" * 48)
    install_zonemd(
        zone, good384, good512, wrong_serial, unsupported_scheme, unsupported_hash
    )
    verdicts = adjudicate(zone)
    # The report says exactly the SHA-384 and SHA-512 records are usable.
    assert [rr for rr, usable, _ in verdicts if usable] == [good384, good512]
    for rr, usable, reason in verdicts:
        try:
            zone.verify_digest(rr)
            verified = True
        except dns.zone.DigestVerificationFailure:
            verified = False
        assert verified == usable, f"{rr.to_text()}: {reason}"
    # At least one usable record exists, so whole-zone verification succeeds.
    zone.verify_digest()


def test_all_records_unusable_means_zone_rejected():
    zone = make_zone()
    wrong_serial = zonemd_rr(
        SERIAL + 1, SCHEME_SIMPLE, HASH_SHA384, EXPECTED_DIGESTS[1]
    )
    bad_digest = zonemd_rr(SERIAL, SCHEME_SIMPLE, HASH_SHA512, b"\xab" * 64)
    install_zonemd(zone, wrong_serial, bad_digest)
    verdicts = adjudicate(zone)
    assert not any(usable for _, usable, _ in verdicts)
    with pytest.raises(dns.zone.DigestVerificationFailure):
        zone.verify_digest()


def test_correct_digest_proves_integrity_not_authenticity():
    # ZONEMD is an integrity check over the canonical RR stream, not an
    # authentication of the zone's source: anyone who can alter the zone
    # can also recompute the digest over the altered stream.  A successful
    # verify_digest() therefore must not be treated as proof of provenance;
    # only DNSSEC validation of the ZONEMD RRSIG provides that.
    zone = make_zone()
    zone.replace_rdataset(
        dns.name.from_text("www.example."),
        dns.rdataset.from_text("IN", "A", 60, "192.0.2.4"),
    )
    attacker_supplied = zone.compute_digest(dns.zone.DigestHashAlgorithm.SHA384)
    assert attacker_supplied.digest != EXPECTED_DIGESTS[HASH_SHA384]
    install_zonemd(zone, attacker_supplied)
    zone.verify_digest()
