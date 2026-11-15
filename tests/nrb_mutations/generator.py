"""
Fixed-seed structural deformation corpus for NRB record / option boundaries.

The generator is deliberately small and deterministic. It builds two legal
baselines (a Name Resolution Block with records and options, and an Enhanced
Packet Block with packet padding and options), then emits variants that keep
the *outer* block length and trailer valid while deforming the inner boundary:

    records ... [end-of-records] options ... [opt_endofopt]

Why this matters: the NRB record list and the NRB option list share one block
body. If the end-of-records marker is not validated, bytes belonging to the
next layer (or to the block trailer) can be consumed as record payload or as
the terminator. The same is true of the EPB packet padding vs. its options.

Every case carries its own ``expect`` data:

- ``ok``    -> the file must scan, and the listed records/options must be
               present with exactly these values (unknown items preserved).
- ``error`` -> scanning must raise the named pcapng exception whose message
               contains the listed fragment; no block may be yielded for the
               malformed block, so no fake names can leak out.

The committed ``corpus.json`` and ``samples/`` are the canonical artifacts;
``tests/test_nrb_epb_boundaries.py`` reads them rather than regenerating on
the fly. Run ``python -m tests.nrb_mutations.generator`` from the repository
root after intentionally changing the generator.
"""

import base64
import json
import os
import random
import struct
import sys

SEED = 0x5EED2026

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS_PATH = os.path.join(HERE, "corpus.json")


def _ensure_tests_dir_on_path():
    """Allow ``python -m tests.nrb_mutations.generator`` from the repo root."""
    tests_dir = os.path.dirname(HERE)
    if tests_dir not in sys.path:
        sys.path.insert(0, tests_dir)


_ensure_tests_dir_on_path()
SAMPLES_DIR = os.path.join(HERE, "samples")
SAMPLES_MANIFEST_PATH = os.path.join(SAMPLES_DIR, "manifest.json")

BYTE_ORDERS = ("<", ">")


# ---------------------------------------------------------------------------
# Framing helpers: every block gets a correct outer length and trailer.
# ---------------------------------------------------------------------------


def _u16(value, endianness):
    return struct.pack(endianness + "H", value)


def _u32(value, endianness):
    return struct.pack(endianness + "I", value)


def _pad(payload):
    return payload + b"\x00" * ((-len(payload)) % 4)


def _block(block_type, body, endianness):
    body = _pad(body)
    total = len(body) + 12
    return (
        _u32(block_type, endianness)
        + _u32(total, endianness)
        + body
        + _u32(total, endianness)
    )


def _shb(endianness):
    bom = b"\x1a\x2b\x3c\x4d" if endianness == ">" else b"\x4d\x3c\x2b\x1a"
    body = bom + struct.pack(endianness + "HHq", 1, 0, -1)
    total = len(body) + 12
    return (
        _u32(0x0A0D0D0A, endianness) + _u32(total, endianness) + body
        + _u32(total, endianness)
    )


def _idb(endianness):
    body = struct.pack(endianness + "HHI", 1, 0, 65535) + _u32(0, endianness)
    return _block(0x00000001, body, endianness)


def _record(record_type, value, endianness, declared_length=None):
    if declared_length is None:
        declared_length = len(value)
    return (
        _u16(record_type, endianness)
        + _u16(declared_length, endianness)
        + _pad(value)
    )


def _option(code, value, endianness, declared_length=None):
    if declared_length is None:
        declared_length = len(value)
    return (
        _u16(code, endianness) + _u16(declared_length, endianness) + _pad(value)
    )


def _end_of_records(endianness):
    return _u16(0, endianness) + _u16(0, endianness)


def _end_of_options(endianness):
    return _u32(0, endianness)


def _nrb(endianness, records, options=b"", include_record_terminator=True):
    body = b"".join(records)
    if include_record_terminator:
        body += _end_of_records(endianness)
    body += options
    return _block(0x00000004, body, endianness)


def _epb(endianness, packet_data, options=b""):
    body = (
        struct.pack(
            endianness + "IIIII",
            0,
            0x00000001,
            0x00000002,
            len(packet_data),
            len(packet_data),
        )
        + _pad(packet_data)
        + options
    )
    return _block(0x00000006, body, endianness)


# ---------------------------------------------------------------------------
# Fixed-seed content.
# ---------------------------------------------------------------------------

EPB_PACKET = b"packet-data-013"  # 15 bytes -> one alignment byte


def _content(rng):
    return {
        "unknown_record_code": 0x2A00 + rng.randrange(0x100),
        "unknown_record_payload": bytes(rng.randrange(0x20, 0x7F) for _ in range(11)),
        "unknown_option_code": 0x3B00 + rng.randrange(0x100),
        "unknown_option_payload": bytes(rng.randrange(0x20, 0x7F) for _ in range(9)),
        "ipv4_name": "host-{0}.example".format(rng.randrange(1000)),
        "ipv6_name": "v6-{0}.example".format(rng.randrange(1000)),
        "comment": "nrb comment {0}".format(rng.randrange(1000)),
        "dns_name": "dns-{0}.example".format(rng.randrange(1000)),
    }


def _baseline_records(endianness, content):
    return [
        _record(
            1,
            b"\x7f\x00\x00\x01" + content["ipv4_name"].encode() + b"\x00",
            endianness,
        ),
        _record(
            2,
            b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
            + content["ipv6_name"].encode()
            + b"\x00",
            endianness,
        ),
        _record(
            content["unknown_record_code"],
            content["unknown_record_payload"],
            endianness,
        ),
    ]


def _baseline_options(endianness, content):
    return (
        _option(1, content["comment"].encode(), endianness)
        + _option(2, content["dns_name"].encode(), endianness)
        + _option(
            content["unknown_option_code"],
            content["unknown_option_payload"],
            endianness,
        )
        + _end_of_options(endianness)
    )


# ---------------------------------------------------------------------------
# Case construction.
# ---------------------------------------------------------------------------


def _case(group, name, data, endianness, content, expect, criterion):
    return {
        "id": "{0}-{1}".format("le" if endianness == "<" else "be", name),
        "group": group,
        "name": name,
        "endianness": endianness,
        "expect": expect,
        "criterion": criterion,
        "contribution": {
            "unknown_record_code": content["unknown_record_code"],
            "unknown_record_payload": content["unknown_record_payload"].decode(
                "ascii", "replace"
            ),
            "unknown_option_code": content["unknown_option_code"],
            "unknown_option_payload": content["unknown_option_payload"].decode(
                "ascii", "replace"
            ),
        },
        "bytes": base64.b64encode(data).decode("ascii"),
    }


def _ok_common(content):
    return {
        "records": [
            {"type": 1, "address": "127.0.0.1", "names": [content["ipv4_name"]]},
            {"type": 2, "address": "2001:db8::1", "names": [content["ipv6_name"]]},
            {
                "type": content["unknown_record_code"],
                "raw": content["unknown_record_payload"],
            },
        ],
        # Options are exposed decoded: strings, integers, or raw bytes.
        "options": {
            1: content["comment"],
            2: content["dns_name"],
            content["unknown_option_code"]: content["unknown_option_payload"],
        },
    }


def _cases_for(endianness):
    rng = random.Random(SEED)
    content = _content(rng)
    shb = _shb(endianness)
    idb = _idb(endianness)
    records = _baseline_records(endianness, content)
    options = _baseline_options(endianness, content)
    end_rec = _end_of_records(endianness)
    end_opts = _end_of_options(endianness)

    valid_nrb = _nrb(endianness, records, options)
    valid_epb = _epb(
        endianness,
        EPB_PACKET,
        _option(2, _u32(0, endianness), endianness)
        + _option(3, b"\x02" + b"A" * 16, endianness)
        + _option(
            content["unknown_option_code"],
            content["unknown_option_payload"],
            endianness,
        )
        + end_opts,
    )
    ok = _ok_common(content)
    cases = []

    def add(group, name, data, expect, criterion):
        cases.append(_case(group, name, data, endianness, content, expect, criterion))

    # ---------------- legal baselines ----------------
    add(
        "baseline",
        "nrb-records-and-options",
        shb + valid_nrb,
        {"kind": "ok", "block_index": 1, **ok},
        "valid NRB parses records, terminator, then options",
    )
    add(
        "baseline",
        "epb-padding-then-options",
        shb + idb + valid_epb,
        {
            "kind": "ok",
            "block_index": 2,
            "packet_data": EPB_PACKET,
            "options": {
                2: {"__epbflags__": 0},
                3: (2, b"A" * 16),
                content["unknown_option_code"]: content["unknown_option_payload"],
            },
        },
        "EPB packet padding is not part of packet data nor options",
    )
    add(
        "baseline",
        "nrb-then-epb",
        shb + idb + valid_nrb + valid_epb,
        {
            "kind": "ok",
            "block_types": [
                "SectionHeader",
                "InterfaceDescription",
                "NameResolution",
                "EnhancedPacket",
            ],
        },
        "a valid NRB does not consume the next block",
    )

    # ---------------- record terminator length ----------------
    add(
        "record-terminator",
        "end-record-length-4",
        shb
        + _nrb(
            endianness,
            records
            + [
                _u16(0, endianness)
                + _u16(4, endianness)
                + b"JUNK"
                + end_rec,
            ],
            options,
        ),
        {
            "kind": "error",
            "exception": "CorruptedFile",
            "message": "Name resolution end record must have length 0",
        },
        "end-of-records marker length must be zero; its value must not be consumed",
    )
    add(
        "record-terminator",
        "end-record-length-2-aligned-payload",
        shb
        + _nrb(
            endianness,
            records
            + [
                _u16(0, endianness)
                + _u16(2, endianness)
                + b"AB"
                + b"\x00\x00"
            ],
            options,
        ),
        {
            "kind": "error",
            "exception": "CorruptedFile",
            "message": "Name resolution end record must have length 0",
        },
        "aligned 2-byte payload after a non-zero end record must not be skipped",
    )

    # ---------------- missing record terminator ----------------
    add(
        "record-terminator",
        "missing-end-record-at-body-end",
        shb + _nrb(endianness, records, b"", include_record_terminator=False),
        {
            "kind": "error",
            "exception": "CorruptedFile",
            "message": "Missing explicit end-of-list marker",
        },
        "record list must end with an explicit marker, not stream exhaustion",
    )
    add(
        "record-terminator",
        "missing-end-record-options-as-records",
        shb + _nrb(endianness, records, options, include_record_terminator=False),
        {
            "kind": "error",
            "exception": "CorruptedFile",
            "message": "Name resolution record names must be NUL-terminated",
        },
        "option bytes have no record header shape and must not be decoded "
        "as name records",
    )
    add(
        "record-terminator",
        "missing-end-record-partial-header",
        shb + _nrb(endianness, records + [b"\x77\x77\x00"], b"",
                   include_record_terminator=False),
        {
            "kind": "error",
            "exception": "CorruptedFile",
            "message": "Missing explicit end-of-list marker",
        },
        "a partial 3-byte record header is padded as an unknown record, "
        "then the still-unterminated list must fail",
    )

    # ---------------- record length / alignment ----------------
    add(
        "record-length",
        "record-length-swallows-terminator",
        shb
        + _nrb(
            endianness,
            [
                _record(
                    1,
                    b"\x7f\x00\x00\x01localhost\x00" + bytes(4),
                    endianness,
                    declared_length=18,
                )
            ],
            options,
        ),
        {
            "kind": "error",
            "exception": "CorruptedFile",
            "message": "record contains empty or extra trailing name",
        },
        "record length that absorbs the terminator NULs must not fabricate names",
    )
    add(
        "record-length",
        "record-length-ends-in-alignment",
        shb
        + _nrb(
            endianness,
            [
                _record(
                    1,
                    b"\x7f\x00\x00\x01localhost\x00",
                    endianness,
                    declared_length=15,
                )
            ],
            options,
        ),
        {
            "kind": "error",
            "exception": "CorruptedFile",
            "message": "record contains empty or extra trailing name",
        },
        "record length ending inside alignment padding leaves a stray NUL in the name",
    )

    # ---------------- record payload validity ----------------
    add(
        "record-payload",
        "ipv4-record-too-short",
        shb + _nrb(endianness, [_record(1, b"\x7f", endianness)], end_opts),
        {
            "kind": "error",
            "exception": "CorruptedFile",
            "message": "IPv4 name resolution record is too short",
        },
        "IPv4 record must contain at least the address; no negative slicing",
    )
    add(
        "record-payload",
        "ipv6-record-too-short",
        shb + _nrb(endianness, [_record(2, b"\x20\x01\x00", endianness)], end_opts),
        {
            "kind": "error",
            "exception": "CorruptedFile",
            "message": "IPv6 name resolution record is too short",
        },
        "IPv6 record must contain at least the address; no negative slicing",
    )
    add(
        "record-payload",
        "ipv4-name-not-utf8",
        shb
        + _nrb(
            endianness,
            [_record(1, b"\x7f\x00\x00\x01\xff\xfebad\x00", endianness)],
            end_opts,
        ),
        {
            "kind": "error",
            "exception": "CorruptedFile",
            "message": "Invalid UTF-8 name",
        },
        "undecodable record names fail instead of becoming fake names",
    )

    # ---------------- option terminator / length ----------------
    add(
        "option-terminator",
        "missing-opt-endofopt",
        shb
        + _nrb(
            endianness,
            records,
            _option(1, b"comment", endianness),
            include_record_terminator=True,
        ),
        {
            "kind": "error",
            "exception": "CorruptedFile",
            "message": "Unterminated options list",
        },
        "options must end with opt_endofopt, not stream exhaustion",
    )
    add(
        "option-terminator",
        "opt-endofopt-length-4",
        shb
        + _nrb(
            endianness,
            records,
            options[:-4]
            + _option(1, b"comment", endianness)
            + _u16(0, endianness)
            + _u16(4, endianness)
            + b"JUNK",
        ),
        {
            "kind": "error",
            "exception": "CorruptedFile",
            "message": "opt_endofopt must have length 0",
        },
        "opt_endofopt length must be zero; its value must not be consumed",
    )
    add(
        "option-terminator",
        "bytes-after-opt-endofopt",
        shb
        + _nrb(
            endianness,
            records,
            options + _option(content["unknown_option_code"], b"late", endianness),
        ),
        {
            "kind": "error",
            "exception": "CorruptedFile",
            "message": "Trailing bytes after the last block field",
        },
        "everything after opt_endofopt is residual, not another option",
    )
    add(
        "option-length",
        "option-length-overruns-body",
        shb
        + _nrb(
            endianness,
            records,
            _option(
                2,
                b"dns.example",
                endianness,
                declared_length=64,
            ),
        ),
        {
            "kind": "error",
            "exception": "TruncatedFile",
            "message": "only got",
        },
        "an option length cannot claim bytes outside the block body",
    )
    add(
        "option-length",
        "unknown-option-length-misaligned",
        shb
        + _nrb(
            endianness,
            records,
            _option(
                content["unknown_option_code"],
                b"abc",
                endianness,
                declared_length=3,
            )
            + _option(1, b"next", endianness)
            + end_opts,
        ),
        {
            "kind": "ok",
            "block_index": 1,
            "records": ok["records"],
            "options": {
                content["unknown_option_code"]: b"abc",
                1: "next",
            },
        },
        "alignment padding belongs to the declared length, not to the next option",
    )

    # ---------------- unknown record / option retention ----------------
    add(
        "unknown-items",
        "unknown-record-and-option-retained",
        shb + valid_nrb,
        {"kind": "ok", "block_index": 1, **ok},
        "unknown record and option codes survive with their raw values",
    )
    add(
        "unknown-items",
        "repeated-unknown-option-retained",
        shb
        + _nrb(
            endianness,
            records,
            _option(content["unknown_option_code"], b"one", endianness)
            + _option(content["unknown_option_code"], b"two", endianness)
            + end_opts,
        ),
        {
            "kind": "ok",
            "block_index": 1,
            "records": ok["records"],
            "options_all": {content["unknown_option_code"]: [b"one", b"two"]},
        },
        "unknown options are not schema entries; repetition must not KeyError",
    )

    # ---------------- EPB boundary ----------------
    add(
        "epb-options",
        "epb-unknown-option-retained",
        shb + idb + valid_epb,
        {
            "kind": "ok",
            "block_index": 2,
            "packet_data": EPB_PACKET,
            "options": {
                content["unknown_option_code"]: content["unknown_option_payload"],
            },
        },
        "EPB options after the padded packet preserve unknown codes",
    )
    add(
        "epb-options",
        "epb-missing-opt-endofopt",
        shb
        + idb
        + _epb(
            endianness,
            EPB_PACKET,
            _option(1, b"comment", endianness),
        ),
        {
            "kind": "error",
            "exception": "CorruptedFile",
            "message": "Unterminated options list",
        },
        "EPB options also require an explicit terminator",
    )
    add(
        "epb-options",
        "epb-bytes-after-opt-endofopt",
        shb
        + idb
        + _epb(
            endianness,
            EPB_PACKET,
            _option(1, b"comment", endianness)
            + end_opts
            + _option(content["unknown_option_code"], b"late", endianness),
        ),
        {
            "kind": "error",
            "exception": "CorruptedFile",
            "message": "Trailing bytes after the last block field",
        },
        "EPB alignment padding does not license bytes after opt_endofopt",
    )

    # ---------------- next block framing ----------------
    add(
        "next-block",
        "valid-nrb-then-valid-epb",
        shb + idb + valid_nrb + valid_epb,
        {
            "kind": "ok",
            "block_types": [
                "SectionHeader",
                "InterfaceDescription",
                "NameResolution",
                "EnhancedPacket",
            ],
        },
        "valid NRB leaves the next block framed correctly",
    )
    add(
        "next-block",
        "bad-nrb-then-valid-epb",
        shb
        + idb
        + _nrb(
            endianness,
            records,
            _option(1, b"comment", endianness),
        )
        + valid_epb,
        {
            "kind": "error",
            "exception": "CorruptedFile",
            "message": "Unterminated options list",
        },
        "malformed NRB fails instead of yielding the following EPB as NRB data",
    )

    return cases


def _jsonable(obj):
    """Recursively encode bytes so expectations round-trip through JSON."""
    if isinstance(obj, bytes):
        return {"__bytes__": base64.b64encode(obj).decode("ascii")}
    if isinstance(obj, tuple):
        return {"__pair__": [_jsonable(v) for v in obj]}
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_jsonable(v) for v in obj]
    return obj


def _unjsonable(obj):
    if isinstance(obj, dict):
        if set(obj) == {"__bytes__"}:
            return base64.b64decode(obj["__bytes__"])
        if set(obj) == {"__int__"}:
            return int(obj["__int__"])
        if set(obj) == {"__pair__"}:
            first, second = obj["__pair__"]
            return (first, _unjsonable(second))
        return {k: _unjsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_unjsonable(v) for v in obj]
    return obj


def load_corpus(path=CORPUS_PATH):
    with open(path) as fp:
        raw = json.load(fp)
    for case in raw["cases"]:
        case["data"] = base64.b64decode(case.pop("bytes"))
    return raw


def load_samples(path=SAMPLES_MANIFEST_PATH):
    with open(path) as fp:
        return json.load(fp)


def generate():
    cases = []
    for endianness in BYTE_ORDERS:
        cases.extend(_cases_for(endianness))
    return {
        "seed": SEED,
        "description": (
            "NRB record/option and EPB padding/option boundary cases; every "
            "outer block length and trailer is valid"
        ),
        "cases": [_jsonable(case) for case in cases],
    }


# Key minimal samples. Each one is a full, self-contained capture file and is
# tied to one structural guard so removing that guard makes the sample parse
# differently (usually successfully, with fake data).
MINIMAL_SAMPLE_NAMES = [
    ("record-terminator", "end-record-length-4"),
    ("record-terminator", "missing-end-record-at-body-end"),
    ("record-terminator", "missing-end-record-options-as-records"),
    ("record-payload", "ipv4-record-too-short"),
    ("option-terminator", "missing-opt-endofopt"),
    ("option-terminator", "opt-endofopt-length-4"),
    ("option-terminator", "bytes-after-opt-endofopt"),
    ("unknown-items", "unknown-record-and-option-retained"),
    ("epb-options", "epb-missing-opt-endofopt"),
]


# Each entry names one structural guard and the corpus case names that must
# change classification when that guard is removed. ``tests`` monkeypatches the
# guard and asserts this list, so deleting a key check produces a stable
# failure instead of silently accepting the malformed input.
GUARD_CASES = [
    (
        "on_missing_record_terminator",
        ["missing-end-record-at-body-end", "missing-end-record-partial-header"],
    ),
    (
        "on_unterminated_options",
        ["missing-opt-endofopt", "epb-missing-opt-endofopt"],
    ),
    (
        "check_zero_length",
        ["end-record-length-4", "opt-endofopt-length-4"],
    ),
    (
        "check_min_record_length",
        ["ipv4-record-too-short", "ipv6-record-too-short"],
    ),
    (
        "check_no_trailing_bytes",
        ["bytes-after-opt-endofopt", "epb-bytes-after-opt-endofopt"],
    ),
    (
        "check_nrb_names_shape",
        [
            "missing-end-record-options-as-records",
            "record-length-swallows-terminator",
        ],
    ),
]


def minimal_samples():
    """Return every (case, filename) pair for the minimal sample set."""
    docs = generate()
    selected = [
        c
        for c in docs["cases"]
        if (c["group"], c["name"]) in MINIMAL_SAMPLE_NAMES
    ]
    assert len(selected) == 2 * len(MINIMAL_SAMPLE_NAMES), (
        "expected both endian variants of every minimal sample"
    )
    return selected


def write_artifacts():
    corpus = generate()
    with open(CORPUS_PATH, "w") as fp:
        json.dump(corpus, fp, indent=2, sort_keys=True)
        fp.write("\n")

    os.makedirs(SAMPLES_DIR, exist_ok=True)
    manifest = []
    for case in minimal_samples():
        group, name = case["group"], case["name"]
        filename = case["id"] + ".pcapng.bin"
        with open(os.path.join(SAMPLES_DIR, filename), "wb") as fp:
            fp.write(base64.b64decode(case["bytes"]))
        manifest.append(
            {
                "file": filename,
                "group": group,
                "name": name,
                "expect": case["expect"],
                "criterion": case["criterion"],
            }
        )
    with open(SAMPLES_MANIFEST_PATH, "w") as fp:
        json.dump(
            {"seed": SEED, "samples": manifest}, fp, indent=2, sort_keys=True
        )
        fp.write("\n")

    return corpus, manifest


def main():
    corpus, manifest = write_artifacts()
    print(
        "wrote {0} cases to {1} and {2} samples to {3}".format(
            len(corpus["cases"]), CORPUS_PATH, len(manifest), SAMPLES_DIR
        )
    )


if __name__ == "__main__":
    main()
