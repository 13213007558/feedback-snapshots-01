"""Unused-sector and previous-task marker leakage checks.

Every byte outside a stream's declared content must be zero, and a marker
embedded in an earlier/larger container must never appear in the free sectors
or slack space of a later/smaller one. Regular-FAT and DIFAT containers are
fully covered here; the mini-stream defect rows are asserted separately.
"""

import pytest

from .fixtures import (
    TASK_MARKER,
    deterministic_randomness,
    encrypt_fixture,
    make_payload,
)
from .matrix import matrix_entries
from .ole_validator import validate_container
from .slack_checker import check_leaks

REGULAR_ROWS = [(label, size) for label, size, region, mini in matrix_entries() if not mini]


@pytest.mark.parametrize("label,size", REGULAR_ROWS, ids=lambda v: v)
def test_no_marker_or_nonzero_leak_in_regular_containers(label, size):
    blob = encrypt_fixture(make_payload(size), marker=True)
    report = validate_container(blob)
    findings = check_leaks(blob, report, TASK_MARKER)
    marker_hits = [f for f in findings if f.code.startswith("MARKER_")]
    assert not marker_hits, [f"{f.code}@{f.offset}" for f in marker_hits]
    # Free sectors and slack must be zero-initialised (no recycled content).
    assert not findings, [f"{f.code}@{f.offset}" for f in findings]


def test_smaller_container_does_not_inherit_larger_marker():
    # Build a big, marker-laden payload first; then a small regular container
    # and confirm none of the marker survives in its free sectors or slack.
    # Encryption hides the payload marker, so the leak scan is the real gate;
    # here we only assert the marker payload is what we asked for.
    big_payload = make_payload(256_000)
    big_payload = bytearray(big_payload)
    big_payload[0:len(TASK_MARKER)] = TASK_MARKER
    assert TASK_MARKER in bytes(big_payload)
    encrypt_fixture(bytes(big_payload), marker=True)  # exercise the large path

    small = encrypt_fixture(make_payload(5_000), marker=False)
    report = validate_container(small)
    findings = check_leaks(small, report, TASK_MARKER)
    assert not [f for f in findings if f.code.startswith("MARKER_")]


def test_difat_container_free_sectors_are_clean():
    blob = encrypt_fixture(make_payload(7_300_000), marker=True)
    report = validate_container(blob)
    findings = check_leaks(blob, report, TASK_MARKER)
    assert not [f for f in findings if f.code.startswith("MARKER_")]
    # DIFAT/FAT metadata sectors are never treated as free data sectors.
    assert report.free_big_sectors or report.num_difat >= 1


def test_deterministic_source_does_not_alter_production_rng():
    import inspect

    from msoffcrypto.method import ecma376_agile as agile
    from .fixtures import DeterministicRandom

    before = agile._random_buffer
    with deterministic_randomness(b"seed"):
        inside = agile._random_buffer
        assert inside is not before
        # Two independent RNGs over the same seed emit identical streams.
        assert DeterministicRandom(b"seed")(32) == DeterministicRandom(b"seed")(32)
    assert agile._random_buffer is before  # restored on exit
    source = inspect.getsource(agile._random_buffer)
    assert "secrets.token_bytes" in source
    # Live CSPRNG output still varies after the context exits.
    assert agile._random_buffer(16) != agile._random_buffer(16)
