"""
Targeted structural-mutation tests for the boundary between the Name
Resolution Block (NRB) record list and the block options, and between
the Enhanced Packet Block (EPB) packet data and its options.

Rationale: a malicious capture can declare inner lengths (record length,
terminator length, option length) or alignment bytes such that a parser
mistakes the *next* layer's legitimate data for the *previous* layer's
padding or terminator -- e.g. bytes following a malformed
``nrb_record_end`` being interpreted as options, yielding forged DNS
names.

All mutations keep the *outer* block lengths legal (both length fields
match the actual content), so the only thing a parser can trip on is the
inner structure.  Every case is driven through the real
:class:`pcapng.FileScanner` and through lazy field/option decoding --
no test calls a bare integer reader.

Layout of this file:

* ``generate_cases()`` -- a fixed-seed (``GENERATOR_SEED``) generator
  combining the mutation dimensions: terminator record length, option
  length, alignment/padding bytes, and unknown record/option types.
* ``BOUNDARY CRITERIA`` -- encoded in ``_run_case()``: valid unknown
  records/options must be preserved; illegal terminator structures must
  fail loudly and must never emit forged subsequent names.
* Minimal failing samples -- hand-written byte strings anchoring each
  structural check in ``pcapng/structs.py``.  Removing the guarded
  check makes the corresponding test fail deterministically.
"""

import io
import random
import struct

import pytest

from pcapng import blocks
from pcapng.exceptions import CorruptedFile, TruncatedFile
from pcapng.scanner import FileScanner

# Fixed seed for the mutation generator.  Do not change without a good
# reason: the generated mutation stream (and hence the boundary
# coverage) is meant to be reproducible.
GENERATOR_SEED = 20261115
GENERATED_CASE_COUNT = 40

# ---------------------------------------------------------------------
# Baseline content
# ---------------------------------------------------------------------

IPV4_ADDR = b"\x0a\x00\x00\x01"  # 10.0.0.1
IPV4_NAMES = (b"host-one.example", b"host-one")
IPV6_ADDR = bytes.fromhex("20010db8000000000000000000000001")  # 2001:db8::1
IPV6_NAMES = (b"v6-host.example",)
UNKNOWN_REC_TYPE = 0x7777
UNKNOWN_REC_PAYLOAD = b"\xde\xad\xbe\xef\xca\xfe"
NS_DNSNAME = b"dns.example"
EPB_PACKET = bytes(range(13))  # 13 bytes -> 3 padding bytes
EPB_DROPCOUNT = 7
EPB_UNKNOWN_OPT_CODE = 0x7778
EPB_UNKNOWN_OPT_PAYLOAD = b"\x01\x02\x03"

BASELINE_RECORDS = [
    {"type": 1, "address": "10.0.0.1", "names": ["host-one.example", "host-one"]},
    {"type": 2, "address": "2001:db8::1", "names": ["v6-host.example"]},
    {"type": UNKNOWN_REC_TYPE, "raw": UNKNOWN_REC_PAYLOAD},
]
BASELINE_NRB_OPTIONS = {"ns_dnsname": [NS_DNSNAME.decode()]}
BASELINE_EPB_OPTIONS = {
    "epb_dropcount": [EPB_DROPCOUNT],
    EPB_UNKNOWN_OPT_CODE: [EPB_UNKNOWN_OPT_PAYLOAD],
}

# ---------------------------------------------------------------------
# Framing helpers -- every produced block has legal outer lengths
# ---------------------------------------------------------------------


def _pad(data, fill=0):
    return data + bytes([fill]) * (-len(data) % 4)


def frame_block(block_type, payload, endianness="<"):
    payload = _pad(payload)
    total = 12 + len(payload)
    return (
        struct.pack(endianness + "II", block_type, total)
        + payload
        + struct.pack(endianness + "I", total)
    )


def section_header(endianness="<"):
    payload = struct.pack(endianness + "IHHq", 0x1A2B3C4D, 1, 0, -1)
    return frame_block(0x0A0D0D0A, payload, endianness)


def interface_description(endianness="<"):
    payload = struct.pack(endianness + "HHI", 1, 0, 0xFFFF)
    payload += struct.pack(endianness + "HH", 0, 0)  # opt_endofopt
    return frame_block(0x00000001, payload, endianness)


def nrb_record(record_type, payload, endianness="<", declared_length=None, pad_fill=0):
    length = len(payload) if declared_length is None else declared_length
    return struct.pack(endianness + "HH", record_type, length) + _pad(
        payload, pad_fill
    )


def nrb_terminator(length=0, endianness="<"):
    return struct.pack(endianness + "HH", 0, length)


def option(code, payload, endianness="<", declared_length=None, pad_fill=0):
    length = len(payload) if declared_length is None else declared_length
    return struct.pack(endianness + "HH", code, length) + _pad(payload, pad_fill)


def endofopt(endianness="<", length=0, pad_fill=0):
    return struct.pack(endianness + "HH", 0, length) + bytes([pad_fill]) * length


def name_resolution_block(records_blob, options_blob, endianness="<"):
    return frame_block(0x00000004, records_blob + options_blob, endianness)


def enhanced_packet_block(packet_data, options_blob, endianness="<", pad_fill=0):
    captured = len(packet_data)
    fixed = struct.pack(
        endianness + "IIIII", 0, 0x0004F81E, 0x3C3ED5A9, captured, captured
    )
    return frame_block(
        0x00000006, fixed + _pad(packet_data, pad_fill) + options_blob, endianness
    )


def _ipv4_payload():
    return IPV4_ADDR + b"".join(name + b"\x00" for name in IPV4_NAMES)


def _ipv6_payload():
    return IPV6_ADDR + b"".join(name + b"\x00" for name in IPV6_NAMES)


def baseline_records_blob(endianness="<", pad_fill=0):
    return (
        nrb_record(1, _ipv4_payload(), endianness, pad_fill=pad_fill)
        + nrb_record(2, _ipv6_payload(), endianness, pad_fill=pad_fill)
        + nrb_record(UNKNOWN_REC_TYPE, UNKNOWN_REC_PAYLOAD, endianness,
                     pad_fill=pad_fill)
        + nrb_terminator(0, endianness)
    )


def baseline_nrb_options_blob(endianness="<", pad_fill=0):
    return option(2, NS_DNSNAME, endianness, pad_fill=pad_fill) + endofopt(endianness)


def baseline_epb_options_blob(endianness="<", pad_fill=0):
    return (
        option(4, struct.pack(endianness + "Q", EPB_DROPCOUNT), endianness,
               pad_fill=pad_fill)
        + option(EPB_UNKNOWN_OPT_CODE, EPB_UNKNOWN_OPT_PAYLOAD, endianness,
                 pad_fill=pad_fill)
        + endofopt(endianness)
    )


def build_capture(
    records_blob,
    nrb_options_blob,
    epb_options_blob=None,
    endianness="<",
    epb_pad_fill=0,
):
    if epb_options_blob is None:
        epb_options_blob = baseline_epb_options_blob(endianness)
    return (
        section_header(endianness)
        + interface_description(endianness)
        + name_resolution_block(records_blob, nrb_options_blob, endianness)
        + enhanced_packet_block(EPB_PACKET, epb_options_blob, endianness,
                                pad_fill=epb_pad_fill)
    )


# ---------------------------------------------------------------------
# Scanner driver -- everything goes through the real FileScanner and
# forces lazy field/option decoding on every parsed block.
# ---------------------------------------------------------------------


def scan_capture(data):
    found = {}
    scanner = FileScanner(io.BytesIO(data))
    for block in scanner:
        if isinstance(block, blocks.NameResolution):
            # Lazy reads: record list + decoded option values
            found["nrb_records"] = block.records
            found["nrb_options"] = dict(block.options.iter_all_items())
        elif isinstance(block, blocks.EnhancedPacket):
            found["epb_packet"] = block.packet_data
            found["epb_options"] = dict(block.options.iter_all_items())
    return found


# ---------------------------------------------------------------------
# Fixed-seed mutation generator
# ---------------------------------------------------------------------

# Mutation kinds.  Error cases assert an explicit failure; ok cases
# assert the next layer is parsed exactly as generated (no forged or
# swallowed content across the boundary).
_KINDS = (
    "terminator_length",  # nrb_record_end with length != 0 -> CorruptedFile
    "record_overrun",  # record length past block end -> TruncatedFile
    "short_address_record",  # v4/v6 record shorter than its address -> CorruptedFile
    "option_overrun",  # option length past block end -> TruncatedFile
    "padding_fill",  # nonzero / header-like alignment bytes -> ok, intact
    "unknown_record",  # unknown record types -> ok, preserved raw
    "unknown_option",  # unknown option codes -> ok, preserved raw
    "endofopt_nonzero",  # content after endofopt -> ok, never parsed
)


def _case_terminator_length(rng, endianness, index):
    # The key structural check: a terminator declaring a nonzero length
    # must not cause the following bytes to be re-interpreted as options.
    forged = b"evil-%d.example" % index
    length = rng.choice([1, 4, 8, 0xFFFF])
    records = (
        nrb_record(1, _ipv4_payload(), endianness)
        + nrb_terminator(length, endianness)
        + option(2, forged, endianness)  # would surface as forged ns_dnsname
        + endofopt(endianness)
    )
    return {
        "id": "terminator_length-%d" % index,
        "data": build_capture(records, b"", endianness=endianness),
        "error": CorruptedFile,
    }


def _case_record_overrun(rng, endianness, index):
    declared = len(_ipv4_payload()) + rng.choice([8, 64, 1024])
    records = (
        nrb_record(1, _ipv4_payload(), endianness, declared_length=declared)
        + nrb_terminator(0, endianness)
    )
    return {
        "id": "record_overrun-%d" % index,
        "data": build_capture(
            records, baseline_nrb_options_blob(endianness), endianness=endianness
        ),
        "error": TruncatedFile,
    }


def _case_short_address_record(rng, endianness, index):
    record_type = rng.choice([1, 2])
    addr = IPV4_ADDR if record_type == 1 else IPV6_ADDR
    length = rng.randrange(0, len(addr))
    records = (
        nrb_record(record_type, addr[:length], endianness)
        + nrb_terminator(0, endianness)
    )
    return {
        "id": "short_address_record-%d" % index,
        "data": build_capture(
            records, baseline_nrb_options_blob(endianness), endianness=endianness
        ),
        "error": CorruptedFile,
    }


def _case_option_overrun(rng, endianness, index):
    declared_extra = rng.choice([8, 64, 1024])
    if rng.random() < 0.5:
        # NRB option claims more bytes than the block holds
        dns_opt = option(
            2, NS_DNSNAME, endianness,
            declared_length=len(NS_DNSNAME) + declared_extra,
        )
        return {
            "id": "option_overrun-nrb-%d" % index,
            "data": build_capture(
                baseline_records_blob(endianness),
                dns_opt + endofopt(endianness),
                endianness=endianness,
            ),
            "error": TruncatedFile,
        }
    # Same idea on the EPB options layer
    dropcount = struct.pack(endianness + "Q", EPB_DROPCOUNT)
    epb_opts = option(
        4, dropcount, endianness, declared_length=len(dropcount) + declared_extra
    ) + endofopt(endianness)
    return {
        "id": "option_overrun-epb-%d" % index,
        "data": build_capture(
            baseline_records_blob(endianness),
            baseline_nrb_options_blob(endianness),
            epb_opts,
            endianness,
        ),
        "error": TruncatedFile,
    }


def _case_padding_fill(rng, endianness, index):
    # Alignment bytes that look like record/option headers must be
    # skipped as padding, never parsed as the next layer's content.
    fill = rng.choice([0xAA, 0x02, 0xFF])
    return {
        "id": "padding_fill-%d" % index,
        "data": build_capture(
            baseline_records_blob(endianness, pad_fill=fill),
            baseline_nrb_options_blob(endianness, pad_fill=fill),
            baseline_epb_options_blob(endianness, pad_fill=fill),
            endianness,
            epb_pad_fill=fill,
        ),
        "error": None,
        "records": BASELINE_RECORDS,
        "nrb_options": BASELINE_NRB_OPTIONS,
        "epb_options": BASELINE_EPB_OPTIONS,
    }


def _case_unknown_record(rng, endianness, index):
    record_type = rng.choice([0x0003, 0x7777, 0xFFFE])
    payload = bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 5, 17])))
    records = (
        nrb_record(1, _ipv4_payload(), endianness)
        + nrb_record(record_type, payload, endianness)
        + nrb_terminator(0, endianness)
    )
    expected = BASELINE_RECORDS[:1] + [{"type": record_type, "raw": payload}]
    return {
        "id": "unknown_record-%d" % index,
        "data": build_capture(
            records, baseline_nrb_options_blob(endianness), endianness=endianness
        ),
        "error": None,
        "records": expected,
        "nrb_options": BASELINE_NRB_OPTIONS,
        "epb_options": BASELINE_EPB_OPTIONS,
    }


def _case_unknown_option(rng, endianness, index):
    # Must avoid codes known to either block schema (1..7, customs)
    code = rng.choice([0x0042, 0x7779, 0xFFFE])
    payload = bytes(rng.randrange(256) for _ in range(rng.choice([1, 3, 9])))
    if rng.random() < 0.5:
        nrb_opts = (
            option(2, NS_DNSNAME, endianness)
            + option(code, payload, endianness)
            + endofopt(endianness)
        )
        expected_nrb = dict(BASELINE_NRB_OPTIONS)
        expected_nrb[code] = [payload]
        return {
            "id": "unknown_option-nrb-%d" % index,
            "data": build_capture(
                baseline_records_blob(endianness), nrb_opts, endianness=endianness
            ),
            "error": None,
            "records": BASELINE_RECORDS,
            "nrb_options": expected_nrb,
            "epb_options": BASELINE_EPB_OPTIONS,
        }
    epb_opts = (
        option(code, payload, endianness)
        + option(4, struct.pack(endianness + "Q", EPB_DROPCOUNT), endianness)
        + endofopt(endianness)
    )
    return {
        "id": "unknown_option-epb-%d" % index,
        "data": build_capture(
            baseline_records_blob(endianness),
            baseline_nrb_options_blob(endianness),
            epb_opts,
            endianness,
        ),
        "error": None,
        "records": BASELINE_RECORDS,
        "nrb_options": BASELINE_NRB_OPTIONS,
        "epb_options": {"epb_dropcount": [EPB_DROPCOUNT], code: [payload]},
    }


def _case_endofopt_nonzero(rng, endianness, index):
    # An endofopt with a nonzero length ends the options layer; anything
    # after it (including option-shaped forgeries) must be ignored.
    forged = b"evil-%d.example" % index
    nrb_opts = (
        option(2, NS_DNSNAME, endianness)
        + endofopt(endianness, length=4, pad_fill=0x02)
        + option(2, forged, endianness)
    )
    return {
        "id": "endofopt_nonzero-%d" % index,
        "data": build_capture(
            baseline_records_blob(endianness), nrb_opts, endianness=endianness
        ),
        "error": None,
        "records": BASELINE_RECORDS,
        "nrb_options": BASELINE_NRB_OPTIONS,  # no forged name may appear
        "epb_options": BASELINE_EPB_OPTIONS,
    }


_CASE_BUILDERS = {
    "terminator_length": _case_terminator_length,
    "record_overrun": _case_record_overrun,
    "short_address_record": _case_short_address_record,
    "option_overrun": _case_option_overrun,
    "padding_fill": _case_padding_fill,
    "unknown_record": _case_unknown_record,
    "unknown_option": _case_unknown_option,
    "endofopt_nonzero": _case_endofopt_nonzero,
}


def generate_cases(seed=GENERATOR_SEED, count=GENERATED_CASE_COUNT):
    rng = random.Random(seed)
    cases = []
    for index in range(count):
        kind = _KINDS[index % len(_KINDS)]
        endianness = rng.choice("<>")
        case = _CASE_BUILDERS[kind](rng, endianness, index)
        case["kind"] = kind
        case["id"] += "-le" if endianness == "<" else "-be"
        cases.append(case)
    return cases


GENERATED_CASES = generate_cases()

# ---------------------------------------------------------------------
# Boundary criteria
# ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "case", GENERATED_CASES, ids=[c["id"] for c in GENERATED_CASES]
)
def test_nrb_epb_boundary_mutation(case):
    if case["error"] is not None:
        # Illegal structures must fail loudly, with a precise pcapng
        # exception -- never silently accept, never leak a bare
        # StreamEmpty/OSError, never emit forged subsequent names.
        with pytest.raises(case["error"]):
            scan_capture(case["data"])
        return

    parsed = scan_capture(case["data"])
    assert parsed["nrb_records"] == case["records"]
    assert parsed["nrb_options"] == case["nrb_options"]
    assert parsed["epb_options"] == case["epb_options"]
    assert parsed["epb_packet"] == EPB_PACKET
    # No mutation may smuggle forged names into the parsed output.
    assert b"evil" not in repr(parsed).encode()


def test_generated_cases_cover_all_mutation_kinds():
    kinds = {case["kind"] for case in GENERATED_CASES}
    assert kinds == set(_KINDS)
    # Both endiannesses must be exercised
    assert any(c["id"].endswith("-be") for c in GENERATED_CASES)
    assert any(c["id"].endswith("-le") for c in GENERATED_CASES)


# ---------------------------------------------------------------------
# Minimal failing samples (hand-written, little-endian).
# Each sample is the smallest capture exhibiting one illegal boundary
# structure; the comment names the check in pcapng/structs.py it guards.
# Removing the guarded check makes the sample test fail.
# ---------------------------------------------------------------------

MINIMAL_SHB = (
    b"\x0a\x0d\x0d\x0a"  # Section Header Block magic
    b"\x1c\x00\x00\x00"  # block length (28)
    b"\x4d\x3c\x2b\x1a"  # byte-order magic (little endian)
    b"\x01\x00\x00\x00"  # version 1.0
    b"\xff\xff\xff\xff\xff\xff\xff\xff"  # section length: unspecified
    b"\x1c\x00\x00\x00"  # block length (28)
)

# Guards: NameResolutionRecordField.load terminator zero-length check.
MINIMAL_TERMINATOR_FORGERY = MINIMAL_SHB + (
    b"\x04\x00\x00\x00"  # Name Resolution Block
    b"\x24\x00\x00\x00"  # block length (36)
    b"\x00\x00\x04\x00"  # nrb_record_end claiming length 4 (illegal)
    b"\x02\x00\x0c\x00"
    b"evil.example"  # forged ns_dnsname option
    b"\x00\x00\x00\x00"  # opt_endofopt
    b"\x24\x00\x00\x00"  # block length (36)
)

# Guards: NameResolutionRecordField.load IPv4 address-length check.
MINIMAL_SHORT_IPV4_RECORD = MINIMAL_SHB + (
    b"\x04\x00\x00\x00"  # Name Resolution Block
    b"\x18\x00\x00\x00"  # block length (24)
    b"\x01\x00\x02\x00"  # IPv4 record, length 2 (too short for an address)
    b"\x0a\x00\x00\x00"  # 2 payload bytes + padding
    b"\x00\x00\x00\x00"  # nrb_record_end
    b"\x18\x00\x00\x00"  # block length (24)
)

# Guards: NameResolutionRecordField.load truncated-payload check.
MINIMAL_TRUNCATED_RECORD = MINIMAL_SHB + (
    b"\x04\x00\x00\x00"  # Name Resolution Block
    b"\x10\x00\x00\x00"  # block length (16)
    b"\x01\x00\x40\x00"  # IPv4 record declaring 64 bytes, block ends here
    b"\x10\x00\x00\x00"  # block length (16)
)

# Guards: read_options truncated-payload check (NRB options layer).
MINIMAL_TRUNCATED_OPTION = MINIMAL_SHB + (
    b"\x04\x00\x00\x00"  # Name Resolution Block
    b"\x14\x00\x00\x00"  # block length (20)
    b"\x00\x00\x00\x00"  # nrb_record_end
    b"\x02\x00\x40\x00"  # ns_dnsname declaring 64 bytes, block ends here
    b"\x14\x00\x00\x00"  # block length (20)
)

# Guards: read_options truncated-payload check (EPB options layer).
MINIMAL_TRUNCATED_EPB_OPTION = MINIMAL_SHB + (
    b"\x06\x00\x00\x00"  # Enhanced Packet Block
    b"\x24\x00\x00\x00"  # block length (36)
    b"\x00\x00\x00\x00"  # interface id
    b"\x00\x00\x00\x00\x00\x00\x00\x00"  # timestamp
    b"\x00\x00\x00\x00"  # captured length (0)
    b"\x00\x00\x00\x00"  # original length (0)
    b"\x04\x00\x40\x00"  # epb_dropcount declaring 64 bytes, block ends here
    b"\x24\x00\x00\x00"  # block length (36)
)

# Guards: unknown record types remain preserved (control sample).
MINIMAL_UNKNOWN_RECORD = MINIMAL_SHB + (
    b"\x04\x00\x00\x00"  # Name Resolution Block
    b"\x18\x00\x00\x00"  # block length (24)
    b"\x77\x77\x04\x00"  # unknown record type 0x7777, length 4
    b"\xde\xad\xbe\xef"
    b"\x00\x00\x00\x00"  # nrb_record_end
    b"\x18\x00\x00\x00"  # block length (24)
)


def test_minimal_terminator_forgery_fails():
    with pytest.raises(CorruptedFile):
        scan_capture(MINIMAL_TERMINATOR_FORGERY)


def test_minimal_short_ipv4_record_fails():
    with pytest.raises(CorruptedFile):
        scan_capture(MINIMAL_SHORT_IPV4_RECORD)


def test_minimal_truncated_record_fails():
    with pytest.raises(TruncatedFile):
        scan_capture(MINIMAL_TRUNCATED_RECORD)


def test_minimal_truncated_option_fails():
    with pytest.raises(TruncatedFile):
        scan_capture(MINIMAL_TRUNCATED_OPTION)


def test_minimal_truncated_epb_option_fails():
    with pytest.raises(TruncatedFile):
        scan_capture(MINIMAL_TRUNCATED_EPB_OPTION)


def test_minimal_unknown_record_preserved():
    parsed = scan_capture(MINIMAL_UNKNOWN_RECORD)
    assert parsed["nrb_records"] == [
        {"type": 0x7777, "raw": b"\xde\xad\xbe\xef"}
    ]
    assert parsed["nrb_options"] == {}
