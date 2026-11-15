"""
Directed structural-deformation tests for Name Resolution Block (NRB) record /
option boundaries and the equivalent EPB packet-padding / option boundary.

These tests intentionally go through :class:`pcapng.scanner.FileScanner` and the
lazily-decoded block fields, not through a single integer reader. Every case in
the corpus has a valid outer block length and trailer; only the inner boundary
is malformed, so any misparse comes from the parser treating bytes of the next
layer as filler/terminator for this layer.

The corpus is generated deterministically by
``tests/nrb_mutations/generator.py`` (fixed seed, committed bytes) and mirrored
by minimal sample files under ``tests/nrb_mutations/samples``.
"""

import base64
import io
import os
import sys

import pytest

import pcapng.structs as structs
from pcapng import FileScanner
from pcapng.blocks import EnhancedPacket, NameResolution, SectionHeader
from pcapng.exceptions import (
    CorruptedFile,
    PcapngException,
    TruncatedFile,
)

# The generator is a test-support module, not part of the installed package.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nrb_mutations.generator import (  # noqa: E402
    GUARD_CASES,
    SAMPLES_DIR,
    _unjsonable,
    load_corpus,
    load_samples,
)

CORPUS = load_corpus()


def _with_decoded_expect(case):
    case = dict(case)
    case["expect"] = _unjsonable(case["expect"])
    return case


CASES = [_with_decoded_expect(case) for case in CORPUS["cases"]]
CASE_IDS = [case["id"] for case in CASES]
SAMPLES = [
    dict(sample, expect=_unjsonable(sample["expect"]))
    for sample in load_samples()["samples"]
]

EXCEPTION_TYPES = {
    "CorruptedFile": CorruptedFile,
    "TruncatedFile": TruncatedFile,
}

ERROR_CASES = [case for case in CASES if case["expect"]["kind"] == "error"]


def scan(data):
    return list(FileScanner(io.BytesIO(data)))


def _assert_block(case, block):
    expect = case["expect"]

    if "block_types" in expect:
        assert [type(b).__name__ for b in block] == expect["block_types"]
        return

    target = block[expect["block_index"]]
    assert isinstance(target, (NameResolution, EnhancedPacket))

    if "packet_data" in expect:
        assert target.packet_data == expect["packet_data"]

    for expected_record in expect.get("records", []):
        matches = [r for r in target.records if r["type"] == expected_record["type"]]
        assert matches, "missing record type {0:#x}".format(
            expected_record["type"]
        )
        record = matches[0]
        for key in ("address", "raw", "names"):
            if key in expected_record:
                assert record.get(key) == expected_record[key], (
                    "record {0:#x} field {1!r} mismatch".format(
                        expected_record["type"], key
                    )
                )

    for code, expected_value in expect.get("options", {}).items():
        actual = target.options[int(code)]
        if isinstance(expected_value, dict) and "__epbflags__" in expected_value:
            assert int(actual) == expected_value["__epbflags__"]
        else:
            assert actual == expected_value

    for code, expected_values in expect.get("options_all", {}).items():
        assert target.options.get_all(int(code)) == expected_values


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_corpus_case(case):
    expect = case["expect"]

    if expect["kind"] == "ok":
        blocks = scan(case["data"])
        _assert_block(case, blocks)
        return

    exc_type = EXCEPTION_TYPES[expect["exception"]]
    with pytest.raises(exc_type) as ctx:
        scan(case["data"])

    assert expect["message"] in str(ctx.value), (
        "expected {0!r} in {1!r}".format(expect["message"], str(ctx.value))
    )


@pytest.mark.parametrize("sample", SAMPLES, ids=[s["file"] for s in SAMPLES])
def test_minimal_samples(sample):
    """The handful of committed minimal files must reproduce corpus results."""
    with open(os.path.join(SAMPLES_DIR, sample["file"]), "rb") as fp:
        data = fp.read()

    expect = sample["expect"]
    if expect["kind"] == "ok":
        blocks = scan(data)
        assert blocks
        return

    exc_type = EXCEPTION_TYPES[expect["exception"]]
    with pytest.raises(exc_type) as ctx:
        scan(data)
    assert expect["message"] in str(ctx.value)


def test_corpus_is_deterministic_and_seeded():
    """Regenerating must yield byte-identical cases and a stable fixed seed."""
    from nrb_mutations import generator

    regenerated = generator.generate()
    assert regenerated["seed"] == 0x5EED2026

    original = {c["id"]: c["data"] for c in load_corpus()["cases"]}
    produced = {
        c["id"]: base64.b64decode(c["bytes"]) for c in regenerated["cases"]
    }
    assert produced == original


def test_every_failing_case_names_a_guard():
    """No error case may rely on a generic exception with an opaque message."""
    for case in ERROR_CASES:
        message = case["expect"]["message"]
        assert isinstance(message, str) and message
        # Truncation messages are intentionally generic but still identify the
        # failed read; every other failure must name the violated boundary.
        if case["expect"]["exception"] != "TruncatedFile":
            assert len(message) > 10


def test_errors_do_not_emit_fake_trailing_names():
    """
    Every malformed case must fail before a NameResolution object is yielded.

    The scanner decodes block fields eagerly enough that a malformed NRB raises
    while the block is being constructed; if that ever changes, this catches a
    caller receiving records built from option bytes or the block trailer.
    """
    for case in ERROR_CASES:
        blocks = []
        with pytest.raises(PcapngException):
            for block in FileScanner(io.BytesIO(case["data"])):
                blocks.append(block)
                if isinstance(block, NameResolution):
                    pytest.fail(
                        "malformed case {0} yielded a NameResolution with "
                        "records {1!r}".format(case["id"], block.records)
                    )
        # Nothing beyond the valid prefix (SHB, IDB) may have been produced.
        assert all(
            isinstance(block, SectionHeader)
            or type(block).__name__ == "InterfaceDescription"
            for block in blocks
        )


# ---------------------------------------------------------------------------
# Negative controls: disable one structural check at a time and prove the
# corpus goes red. The authoritative guard-to-case mapping lives next to the
# criteria in ``nrb_mutations.generator.GUARD_CASES``; these tests keep the
# "remove a key check" alarm stable instead of tying it to one code shape.
# ---------------------------------------------------------------------------

CORRUPT_OR_TRUNC = (CorruptedFile, TruncatedFile)

_GUARD_REPLACEMENTS = {
    "on_missing_record_terminator": (
        "_on_missing_record_terminator",
        lambda: True,
    ),
    "on_unterminated_options": (
        "_on_unterminated_options",
        lambda: True,
    ),
    "check_zero_length": (
        "_check_zero_length",
        lambda kind, length: None,
    ),
    "check_min_record_length": (
        "_check_min_record_length",
        lambda kind, length, minimum: None,
    ),
    "check_no_trailing_bytes": (
        "_check_no_trailing_bytes",
        lambda stream: None,
    ),
    "check_nrb_names_shape": (
        "_check_nrb_names_shape",
        lambda data: None,
    ),
}


def _scan_outcome(data):
    try:
        blocks = scan(data)
    except Exception as exc:  # controls may fall through to generic errors
        return ("error", type(exc).__name__, str(exc))
    return ("ok", [type(b).__name__ for b in blocks])


@pytest.mark.parametrize(
    "guard,case_names",
    GUARD_CASES,
    ids=[guard for guard, _ in GUARD_CASES],
)
def test_removing_one_guard_changes_its_cases(monkeypatch, guard, case_names):
    """Every guard in GUARD_CASES must be load-bearing for its named cases."""
    attribute, replacement = _GUARD_REPLACEMENTS[guard]

    affected = [case for case in CASES if case["name"] in case_names]
    assert len(affected) == 2 * len(case_names), (
        "expected both endian variants for guard {0}".format(guard)
    )

    # Sanity: with the guard in place, each case raises its named error.
    for case in affected:
        expect = case["expect"]
        with pytest.raises(EXCEPTION_TYPES[expect["exception"]]) as ctx:
            scan(case["data"])
        assert expect["message"] in str(ctx.value)

    monkeypatch.setattr(structs, attribute, replacement)

    # With the guard removed, the case must no longer produce the same
    # exception *and* the same named diagnostic: it either parses or fails
    # differently (a generic OSError, truncation at another offset, ...).
    for case in affected:
        expect = case["expect"]
        outcome = _scan_outcome(case["data"])
        still_named = (
            outcome[0] == "error"
            and outcome[1] == expect["exception"]
            and expect["message"] in outcome[2]
        )
        assert not still_named, (
            "guard {0} is not load-bearing for {1}".format(guard, case["id"])
        )
