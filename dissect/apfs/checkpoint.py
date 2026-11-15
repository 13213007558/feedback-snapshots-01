from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dissect.apfs.exception import CheckpointError
from dissect.apfs.objects import NxSuperblock
from dissect.apfs.objects.base import Object

if TYPE_CHECKING:
    from dissect.apfs.apfs import APFS

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_APFS", "CRITICAL"))


@dataclass
class CheckpointWindow:
    """The valid window of the checkpoint descriptor ring.

    The checkpoint descriptor area is a ring buffer. Only the blocks covered by the window described by
    ``nx_xp_desc_index`` and ``nx_xp_desc_len`` belong to the currently committed set of checkpoints. Blocks
    outside that window are stale, overwritten slots and must never be treated as candidates, regardless of
    their checksum or transaction ID.

    Args:
        base: The block address the descriptor ring starts at (``nx_xp_desc_base``).
        capacity: The total number of blocks backing the ring (``nx_xp_desc_blocks``, high bit cleared).
        index: The ring index of the first block in the valid window (``nx_xp_desc_index``).
        length: The number of blocks in the valid window (``nx_xp_desc_len``).
        btree: Whether the descriptor area is stored in a B-tree rather than a ring.
    """

    base: int
    capacity: int
    index: int
    length: int
    btree: bool = False

    @property
    def addresses(self) -> list[int]:
        """The block addresses covered by the valid window, in ring order."""
        if self.btree or self.capacity == 0:
            return []

        return [self.base + (self.index + offset) % self.capacity for offset in range(min(self.length, self.capacity))]

    def contains(self, address: int) -> bool:
        """Check whether a block address falls inside the valid window."""
        if self.btree:
            return True

        offset = address - self.base
        if not 0 <= offset < self.capacity:
            return False

        return (offset - self.index) % self.capacity < self.length


@dataclass
class CheckpointCandidate:
    """A checkpoint superblock candidate and the verdict of its validation.

    Args:
        address: The block address the candidate was read from.
        xid: The transaction ID stored in the candidate header.
        in_window: Whether the block address is inside the valid descriptor window.
        rejected_reasons: The reasons the candidate was rejected, in evaluation order. Empty when accepted.
    """

    address: int
    xid: int
    in_window: bool
    rejected_reasons: list[str] = field(default_factory=list)

    @property
    def accepted(self) -> bool:
        """Whether the candidate passed every check and was selected."""
        return self.in_window and not self.rejected_reasons


@dataclass
class CheckpointReport:
    """An audit trail of the checkpoint selection process.

    Records the descriptor window that defined the candidate scope, every superblock that was found in the
    descriptor area with the reason it was rejected (if any), and the transaction that was ultimately
    selected as the container's entry point.

    Args:
        window: The valid descriptor window used to scope candidates.
        anchor_xid: The transaction ID of the block 0 superblock used as the container anchor.
        candidates: Every superblock candidate, including out-of-window decoys, highest xid first.
        selected: The candidate that was selected, or ``None`` when all candidates failed.
    """

    window: CheckpointWindow
    anchor_xid: int
    candidates: list[CheckpointCandidate] = field(default_factory=list)
    selected: CheckpointCandidate | None = None

    @property
    def fell_back(self) -> bool:
        """Whether selection fell back past a newer, but invalid, in-window transaction."""
        if self.selected is None:
            return False

        return any(candidate.in_window and candidate.xid > self.selected.xid for candidate in self.candidates)

    def describe(self) -> str:
        """Render a human-readable explanation of the selection and any fallback that occurred."""
        lines = [
            "Checkpoint descriptor window: "
            f"base={self.window.base} capacity={self.window.capacity} "
            f"index={self.window.index} length={self.window.length}"
        ]

        for candidate in self.candidates:
            location = "in-window" if candidate.in_window else "outside-window"
            if candidate.rejected_reasons:
                lines.append(
                    f"Rejected candidate xid={candidate.xid} address={candidate.address} ({location}): "
                    + "; ".join(candidate.rejected_reasons)
                )
            else:
                lines.append(f"Accepted candidate xid={candidate.xid} address={candidate.address} ({location})")

        if self.selected is None:
            lines.append("No consistent checkpoint superblock could be selected")
        else:
            lines.append(f"Selected checkpoint transaction xid={self.selected.xid} address={self.selected.address}")

        return "\n".join(lines)


def _build_window(anchor: NxSuperblock) -> CheckpointWindow:
    """Derive the valid descriptor window from the block 0 anchor superblock."""
    descriptor = anchor.object.nx_xp_desc_blocks
    return CheckpointWindow(
        base=anchor.object.nx_xp_desc_base,
        capacity=descriptor & 0x7FFFFFFF,
        index=anchor.object.nx_xp_desc_index,
        length=anchor.object.nx_xp_desc_len,
        btree=bool(descriptor & 0x80000000),
    )


def _iter_descriptor_objects(container: APFS, window: CheckpointWindow) -> list[Object]:
    """Read every object stored in the descriptor area.

    The whole area is read so out-of-window decoys can be reported. Each block is parsed defensively: a block
    that does not even hold a decodable object header is skipped rather than aborting the selection.
    """
    if window.btree:
        # A B-tree backed descriptor area has no stale ring slots, so every object it yields is in scope.
        from dissect.apfs.objects.nx_superblock import _read_checkpoint_objects

        anchor = container.anchor
        return list(
            _read_checkpoint_objects(
                container,
                anchor.object.nx_xp_desc_base,
                anchor.object.nx_xp_desc_blocks,
            )
        )

    objects: list[Object] = []
    for offset in range(window.capacity):
        address = window.base + offset
        try:
            objects.append(Object.from_address(container, address))
        except Exception as e:  # noqa: BLE001 - undecodable garbage must not abort the scan
            log.debug("Unable to parse descriptor block address=%d: %s", address, e)

    return objects


def _validate_candidate(candidate_sb: NxSuperblock, anchor: NxSuperblock) -> list[str]:
    """Run the full consistency chain for a candidate superblock and return the rejection reasons."""
    reasons: list[str] = []

    try:
        candidate_sb.check()
    except Exception as e:  # noqa: BLE001 - record the exact reason and continue
        reasons.append(str(e))

    try:
        candidate_sb.compare(anchor)
    except Exception as e:  # noqa: BLE001
        reasons.append(str(e))

    try:
        if not candidate_sb.omap.is_valid():
            reasons.append("invalid OMAP")
    except Exception as e:  # noqa: BLE001 - an unreadable OMAP is just as unusable as an invalid one
        reasons.append(f"invalid OMAP: {e}")

    return reasons


def select_checkpoint(container: APFS) -> tuple[NxSuperblock, CheckpointReport]:
    """Select the newest consistent checkpoint superblock and report exactly how it was chosen.

    Candidates are scoped to the valid window of the checkpoint descriptor ring advertised by the block 0
    anchor superblock. Out-of-window blocks are recorded as rejected decoys even when their checksum is
    valid and their xid is higher, so a stale block can never masquerade as the latest state. Every in-window
    superblock must prove a valid checksum, matching container identity (``compare``) and a consistent object
    map before it is accepted. Candidates are tried newest xid first; if all of them fail,
    :class:`CheckpointError` is raised instead of silently keeping an unproven state.

    Args:
        container: The APFS container to select a checkpoint for.

    Returns:
        A tuple of the selected superblock and the full selection report.
    """
    anchor = container.anchor
    window = _build_window(anchor)
    report = CheckpointReport(window=window, anchor_xid=anchor.xid)

    descriptor_objects = _iter_descriptor_objects(container, window)
    superblocks = [obj for obj in descriptor_objects if isinstance(obj, NxSuperblock)]

    evaluated: list[tuple[CheckpointCandidate, NxSuperblock]] = []

    # Evaluate every superblock in the descriptor area first so the report always records the full candidate
    # scope, even after a consistent transaction has been found lower down the list.
    for candidate_sb in sorted(superblocks, key=lambda obj: obj.xid, reverse=True):
        candidate = CheckpointCandidate(
            address=candidate_sb.address,
            xid=candidate_sb.xid,
            in_window=window.contains(candidate_sb.address),
        )

        if not candidate.in_window:
            # The window verdict is disqualifying on its own, but the remaining checks are still recorded so
            # the report explains exactly why an out-of-window decoy is unusable rather than merely "stale".
            candidate.rejected_reasons.append("block is outside the valid checkpoint descriptor window")
            log.debug(
                "Superblock xid=%d address=%d is outside the valid checkpoint descriptor window",
                candidate.xid,
                candidate.address,
            )

        candidate.rejected_reasons.extend(_validate_candidate(candidate_sb, anchor))
        if candidate.rejected_reasons:
            log.debug(
                "Rejecting superblock xid=%d: %s",
                candidate.xid,
                "; ".join(candidate.rejected_reasons),
            )

        report.candidates.append(candidate)
        evaluated.append((candidate, candidate_sb))

    # Candidates were ordered newest xid first, so the first accepted one is the newest provable state.
    for candidate, candidate_sb in evaluated:
        if not candidate.accepted:
            continue

        report.selected = candidate
        if report.fell_back:
            log.warning(
                "Checkpoint fallback: selected transaction xid=%d, newer in-window transactions were rejected\n%s",
                candidate.xid,
                report.describe(),
            )
        else:
            log.debug("Selected checkpoint superblock xid=%d", candidate.xid)
        return candidate_sb, report

    raise CheckpointError(report)
