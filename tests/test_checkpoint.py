from __future__ import annotations

import logging
from io import BytesIO

import pytest

from dissect.apfs import checkpoint as checkpoint_module
from dissect.apfs.apfs import APFS
from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.exception import CheckpointError
from dissect.apfs.util import fletcher64
from tests.checkpoint_helpers import (
    clone_superblock,
    corrupt_checksum,
    descriptor_window,
    find_descriptor_superblocks,
    load_image,
    parse_header,
    read_block,
    set_descriptor_window,
    write_block,
)


def _container(image: bytearray) -> APFS:
    return APFS(BytesIO(bytes(image)))


def _candidate(container: APFS, xid: int) -> checkpoint_module.CheckpointCandidate:
    matches = [candidate for candidate in container.checkpoint_candidates if candidate.xid == xid]
    assert len(matches) == 1
    return matches[0]


def _candidate_at(container: APFS, address: int, xid: int) -> checkpoint_module.CheckpointCandidate:
    matches = [
        candidate
        for candidate in container.checkpoint_candidates
        if candidate.xid == xid and candidate.address == address
    ]
    assert len(matches) == 1
    return matches[0]


def test_ring_window_wraps_around() -> None:
    """A valid window that wraps the end of the ring still resolves its newest transaction."""
    image = load_image("snapshot.bin.gz")
    base, capacity, _index, _length = descriptor_window(image)

    assert capacity == 8

    # Each checkpoint transaction occupies two descriptor blocks (a checkpoint map and a superblock).
    # Position a four-block window so it straddles the ring boundary and holds two complete transactions.
    wrapping_index = capacity - 2
    set_descriptor_window(image, index=wrapping_index, length=4)

    # Ring offsets in window order wrap from the end of the ring back to the start.
    expected_ring_offsets = [(wrapping_index + offset) % capacity for offset in range(4)]
    assert expected_ring_offsets == [6, 7, 0, 1]
    expected_superblock_addresses = {base + 7, base + 1}

    container = _container(image)

    in_window = [candidate for candidate in container.checkpoint_candidates if candidate.in_window]
    assert {candidate.address for candidate in in_window} == expected_superblock_addresses
    assert all(candidate.accepted for candidate in in_window)

    # The superblock in the wrapped slot (ring offset 1, xid 2573) is selected as the newest transaction.
    assert container.sb.xid == 2573
    assert container.checkpoint_report.selected.xid == 2573
    assert not container.checkpoint_report.fell_back
    assert len(container.volumes) == 1
    assert container.volumes[0].name == "Snapshots"


def test_latest_candidate_omap_corrupt_falls_back(caplog: pytest.LogCaptureFixture) -> None:
    """When the newest in-window transaction has a broken OMAP, selection falls back to the older one."""
    image = load_image("case_sensitive.bin.gz")

    # Widen the window so both the newest (xid 4) and the previous (xid 3) transaction are in scope.
    set_descriptor_window(image, index=4, length=4)

    newest_sb_address = 8
    newest_sb = c_apfs.nx_superblock(bytes(read_block(image, newest_sb_address)))
    omap_address = newest_sb.nx_omap_oid

    # Corrupt the newest transaction's OMAP while leaving the superblock itself intact.
    omap_block = read_block(image, omap_address)
    omap_block[-1] ^= 0xFF
    write_block(image, omap_address, omap_block)

    with caplog.at_level(logging.WARNING, checkpoint_module.log.name):
        container = _container(image)

    newest = _candidate(container, 4)
    older = _candidate(container, 3)

    assert newest.in_window
    assert not newest.accepted
    assert any("OMAP" in reason for reason in newest.rejected_reasons)

    assert older.in_window
    assert older.accepted

    # The selected transaction is the older, still-consistent one and the report explains the fallback.
    assert container.sb.xid == 3
    assert container.checkpoint_report.selected.xid == 3
    assert container.checkpoint_report.fell_back
    assert any(record.levelno >= logging.WARNING for record in caplog.records)
    assert "xid=3" in container.checkpoint_report.describe()

    # The recovered volume list is served by the selected transaction, not the corrupt newest one.
    assert len(container.volumes) == 1
    assert container.volumes[0].name == "Case Sensitive"


def test_out_of_window_decoy_is_never_selected() -> None:
    """A checksum-valid, higher-xid block outside the window must not masquerade as the latest state."""
    image = load_image("case_sensitive.bin.gz")

    # Keep the genuine window on the newest real transaction (ring slots 6 and 7).
    base, capacity, index, length = descriptor_window(image)
    assert (index, length) == (6, 2)

    # Plant a decoy superblock in a stale slot with a higher xid and a valid checksum.
    decoy_address = base + 2
    clone_superblock(image, source_address=8, target_address=decoy_address, xid=9999)
    decoy_header = parse_header(image, decoy_address)
    assert decoy_header.o_xid == 9999

    decoy_block = read_block(image, decoy_address)
    assert fletcher64(bytes(decoy_block[8:])) == int.from_bytes(bytes(decoy_block[:8]), "little")

    container = _container(image)

    decoy = _candidate(container, 9999)
    assert not decoy.in_window
    assert not decoy.accepted
    assert any("outside the valid checkpoint descriptor window" in reason for reason in decoy.rejected_reasons)

    # The decoy has the highest xid in the area but the genuine in-window transaction wins.
    assert container.sb.xid == 4
    assert container.checkpoint_report.selected.xid == 4
    assert not container.checkpoint_report.fell_back
    assert len(container.volumes) == 1


def test_all_candidates_fail_raises_and_keeps_no_half_state() -> None:
    """If every in-window candidate fails, an explicit error is raised instead of using an unproven state."""
    image = load_image("case_sensitive.bin.gz")

    # Widen the window to cover the two most recent transactions (xid 3 and xid 4), then break both of their
    # superblocks. The window is configured first: set_descriptor_window re-checksums its targets and would
    # otherwise repair the corruption applied afterwards.
    set_descriptor_window(image, index=4, length=4)
    in_window_superblocks = [(address, xid) for address, xid in find_descriptor_superblocks(image) if xid in (3, 4)]
    assert sorted(xid for _, xid in in_window_superblocks) == [3, 4]
    for address, _xid in in_window_superblocks:
        corrupt_checksum(image, address)

    with pytest.raises(CheckpointError) as exc_info:
        _container(image)

    error = exc_info.value
    message = str(error)
    assert "No consistent checkpoint superblock" in message
    # The error carries the full audit trail, not a single skip message.
    rejected_xids = {candidate.xid for candidate in error.report.candidates if candidate.rejected_reasons}
    assert {3, 4} <= rejected_xids
    assert any("checksum" in reason for candidate in error.report.candidates for reason in candidate.rejected_reasons)


def test_report_lists_full_candidate_scope_and_reasons() -> None:
    """The report records every candidate, its window membership, rejection reason and the final pick."""
    image = load_image("corrupt.bin.gz")
    container = _container(image)

    report = container.checkpoint_report
    # Every NX superblock in the descriptor area is recorded, including stale out-of-window transactions.
    candidate_keys = {(candidate.address, candidate.xid) for candidate in report.candidates}
    assert {(2, 301), (4, 302), (6, 303), (8, 304)} <= candidate_keys

    # xid 304 has a valid checksum but sits outside the anchor's valid window.
    stale = _candidate_at(container, address=8, xid=304)
    assert not stale.in_window
    assert any("window" in reason for reason in stale.rejected_reasons)

    # xid 303 is inside the ring area but its superblock checksum is broken.
    broken = _candidate(container, 303)
    assert any("checksum" in reason for reason in broken.rejected_reasons)

    assert report.selected.xid == 302
    assert container.sb.xid == 302
    # 303 and 304 are outside the anchor window, so 302 is the newest in-window transaction, not a fallback.
    assert not report.fell_back
    description = report.describe()
    assert "Rejected candidate xid=304" in description
    assert "Selected checkpoint transaction xid=302" in description
    assert len(container.volumes) == 1
