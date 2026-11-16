"""Independent OLE structural checks across the boundary matrix.

These tests assert the layout properties that hold for *every* well-formed
container, and separately pin the known mini-stream writer defect so the
failure is explicit and localized rather than silent.
"""

import pytest

from .fixtures import encrypt_fixture, make_payload
from .matrix import DIFAT_ONSET_PLAINTEXT, matrix_entries
from .ole_validator import validate_container

# Rows whose EncryptedPackage is larger than the 4096-byte mini-stream cutoff
# must always be structurally perfect: regular FAT, directory, miniFAT and
# DIFAT (when present) with no overlaps and exact stream lengths.
REGULAR_ROWS = [(label, size) for label, size, region, mini in matrix_entries() if not mini]

# Rows routed through the mini stream exercise the known writer defect.
MINI_ROWS = [(label, size) for label, size, region, mini in matrix_entries() if mini]


@pytest.mark.parametrize("label,size", REGULAR_ROWS, ids=lambda v: v)
def test_regular_and_difat_containers_are_structurally_valid(label, size):
    blob = encrypt_fixture(make_payload(size))
    report = validate_container(blob)
    assert report.ok, _format(report)


@pytest.mark.parametrize("label,size", REGULAR_ROWS, ids=lambda v: v)
def test_no_sector_overlaps_in_regular_containers(label, size):
    report = validate_container(encrypt_fixture(make_payload(size)))
    overlap = [d for d in report.defects if d.code.startswith("OVERLAP")]
    assert not overlap, _format(report)


def test_difat_extension_engages_at_documented_onset():
    below = validate_container(encrypt_fixture(make_payload(DIFAT_ONSET_PLAINTEXT - 1)))
    at = validate_container(encrypt_fixture(make_payload(DIFAT_ONSET_PLAINTEXT)))
    assert below.num_difat == 0 and below.num_fat <= 109
    assert at.num_difat == 1 and at.num_fat == 110
    # The DIFAT sector must self-mark DIFSECT and be reachable from the header.
    assert at.first_difat <= 0xFFFFFFFA
    assert not [d for d in at.defects if d.code in ("FAT_DIF_MARK", "DIFAT_HEADER")]


def test_difat_sector_chain_terminates_cleanly():
    report = validate_container(encrypt_fixture(make_payload(7_300_000)))
    assert report.num_difat >= 1
    assert report.ok, _format(report)


@pytest.mark.parametrize("label,size", MINI_ROWS, ids=lambda v: v)
def test_mini_stream_package_defect_is_localized(label, size):
    """Pin the known writer defect: EncryptedPackage <=4096 is placed in the
    mini stream without a miniFAT chain, colliding with other mini streams.

    If this test starts passing, the writer bug has been fixed and the xfail
    marker (and this documentation) should be removed.
    """
    report = validate_container(encrypt_fixture(make_payload(size)))
    pkg = next(s for s in report.streams if s.name == "EncryptedPackage")
    assert pkg.is_mini
    codes = {d.code for d in report.defects}
    # The defect always manifests as an overlap or a wrong mini-chain length.
    assert codes & {"OVERLAP_MINI", "CHAIN_LENGTH", "STREAM_LENGTH"}, _format(report)


def _format(report):
    return "; ".join(f"[{d.code}] {d.stream}: {d.detail}" for d in report.defects) or "clean"
