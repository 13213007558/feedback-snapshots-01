from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.exception import CheckpointError
from dissect.apfs.objects.base import Object
from dissect.apfs.objects.fs import FS
from dissect.apfs.objects.omap import ObjectMap
from dissect.apfs.util import cmp_omap

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.apfs.apfs import APFS
    from dissect.apfs.objects.nx_superblock import NxSuperblock


_QQ = struct.Struct("<QQ")


@dataclass(frozen=True)
class CheckpointWindow:
    """The active checkpoint descriptor window declared by the container anchor.

    The checkpoint descriptor area is a circular area of ``descriptor_blocks``
    blocks. The most recent committed checkpoint occupies ``length`` consecutive
    slots starting at ``index``. Both the checkpoint map and the NX superblock of
    that transaction must live inside this window. Any other NX block in the
    descriptor area is only usable as an older fallback checkpoint if it is
    linked to this window through the descriptor ring.

    Args:
        descriptor_base: Absolute block address of the descriptor area.
        descriptor_blocks: Number of blocks in the descriptor area.
        index: Offset of the first slot of the active checkpoint.
        length: Number of slots occupied by the active checkpoint.
        next_index: Offset the anchor says the next checkpoint will be written to.
    """

    descriptor_base: int
    descriptor_blocks: int
    index: int
    length: int
    next_index: int

    @property
    def slots(self) -> tuple[int, ...]:
        """The slots occupied by the active checkpoint, in order."""
        return tuple((self.index + i) % self.descriptor_blocks for i in range(self.length))

    @property
    def addresses(self) -> tuple[int, ...]:
        """The absolute block addresses occupied by the active checkpoint."""
        return tuple(self.descriptor_base + slot for slot in self.slots)

    @property
    def start_slot(self) -> int:
        return self.index

    @property
    def end_slot(self) -> int:
        """The first slot after the active checkpoint."""
        return (self.index + self.length) % self.descriptor_blocks

    @property
    def wraps(self) -> bool:
        """Whether the active window wraps around the end of the descriptor area."""
        return self.index + self.length > self.descriptor_blocks

    @property
    def next_matches(self) -> bool:
        """Whether the anchor's ``nx_xp_desc_next`` agrees with the window end."""
        return self.end_slot == self.next_index

    def contains_slot(self, slot: int) -> bool:
        return slot in self.slots


@dataclass
class CheckpointCandidate:
    """An NX superblock found in the checkpoint descriptor area.

    Args:
        address: Absolute block address of the NX superblock.
        slot: Offset relative to the start of the descriptor area.
        superblock: The parsed NX superblock, if the block could be parsed.
        role: ``"active"`` for the window's NX, ``"prior"`` for a linked older
            checkpoint, or ``"outside"`` for a block that cannot be part of the
            committed descriptor chain.
        in_window: Whether the block is inside the anchor's active window.
        reasons: Why this candidate was rejected. Empty when accepted.
        volume_oids: Container volume OIDs declared by this checkpoint.
        volume_names: Names of the volumes that were successfully verified.
    """

    address: int
    slot: int
    superblock: NxSuperblock | None = None
    role: str = "outside"
    in_window: bool = False
    reasons: list[str] = field(default_factory=list)
    volume_oids: list[int] = field(default_factory=list)
    volume_names: list[str] = field(default_factory=list)

    @property
    def xid(self) -> int | None:
        return self.superblock.xid if self.superblock is not None else None

    @property
    def accepted(self) -> bool:
        return not self.reasons

    def describe(self) -> str:
        xid = "unknown" if self.xid is None else str(self.xid)
        return f"xid={xid} block={self.address} slot={self.slot} role={self.role}"


@dataclass
class CheckpointSelection:
    """The result of selecting a consistent APFS checkpoint.

    Args:
        anchor: The bootstrap NX superblock from block 0.
        window: The active checkpoint descriptor window declared by the anchor.
        candidates: All descriptor-area NX candidates, in evaluation order.
        selected: The accepted candidate, or ``None`` when every candidate failed.
    """

    anchor: NxSuperblock
    window: CheckpointWindow
    candidates: list[CheckpointCandidate]
    selected: CheckpointCandidate | None

    @property
    def superblock(self) -> NxSuperblock:
        if self.selected is None or self.selected.superblock is None:
            raise CheckpointError("No consistent checkpoint was selected")
        return self.selected.superblock

    @property
    def active(self) -> CheckpointCandidate | None:
        for candidate in self.candidates:
            if candidate.role == "active":
                return candidate
        return None

    @property
    def fallback(self) -> bool:
        """Whether the selected checkpoint is older than the active window checkpoint."""
        return self.selected is not None and self.selected.role == "prior"

    @property
    def rejected_active(self) -> list[CheckpointCandidate]:
        return [candidate for candidate in self.candidates if candidate.role == "active" and candidate.reasons]

    @property
    def reason(self) -> str:
        """A concise explanation of why the selected checkpoint was used."""
        if self.selected is None:
            return "no candidate formed a consistent NX, container identity, OMAP and volume mapping"

        if self.selected.role == "active":
            return (
                f"active checkpoint xid={self.selected.xid} accepted after verifying NX, "
                "container identity, OMAP and volume mappings"
            )

        active = self.active
        if active is None:
            active_slot = self.window.slots[-1]
            return (
                f"active window checkpoint at slot {active_slot} is unavailable; "
                f"selected linked prior checkpoint xid={self.selected.xid}"
            )

        if active.reasons:
            return (
                f"active checkpoint xid={active.xid} rejected ({'; '.join(active.reasons)}); "
                f"selected linked prior checkpoint xid={self.selected.xid}"
            )

        return f"selected linked prior checkpoint xid={self.selected.xid}"

    def _window_line(self) -> str:
        window = self.window
        addresses = ", ".join(str(address) for address in window.addresses) or "none"
        wrap = " (wraps)" if window.wraps else ""
        scanned = f"{window.descriptor_base}..{window.descriptor_base + window.descriptor_blocks - 1}"
        next_note = (
            f"nx_xp_desc_next={window.next_index} matches window end"
            if window.next_matches
            else f"nx_xp_desc_next={window.next_index} disagrees with window end={window.end_slot}"
        )
        return (
            f"Checkpoint descriptor area: base={window.descriptor_base} blocks={window.descriptor_blocks} "
            f"scanned={scanned}\n"
            f"Active window: index={window.index} length={window.length} slots={window.slots} "
            f"blocks=[{addresses}]{wrap}; {next_note}"
        )

    def report(self) -> str:
        """Render a human-readable report of the selection."""
        lines = [self._window_line(), "Candidates:"]

        for candidate in self.candidates:
            status = "accepted" if candidate.accepted else "rejected"
            detail = "" if candidate.accepted else ": " + "; ".join(candidate.reasons)
            volumes = ""
            if candidate.accepted and candidate.volume_names:
                volumes = f" volumes={candidate.volume_names!r}"
            lines.append(f"  - {candidate.describe()} in_window={candidate.in_window} {status}{detail}{volumes}")

        if self.selected is None:
            lines.append("Selected: none")
            lines.append("Fallback: no usable checkpoint")
            lines.append(f"Reason: {self.reason}")
        else:
            lines.append(f"Selected: {self.selected.describe()} volumes={self.selected.volume_names!r}")
            lines.append(f"Fallback: {'yes' if self.fallback else 'no'}")
            lines.append(f"Reason: {self.reason}")

        return "\n".join(lines)

    def log_messages(self) -> Iterator[str]:
        """Yield structured log messages describing the selection.

        The first messages keep the historical ``Skipping superblock xid=...``
        wording for callers that grepped logs for rejected candidates. They are
        followed by the structured decision trail.
        """
        rejected = sorted(
            (candidate for candidate in self.candidates if candidate.reasons),
            key=lambda candidate: (candidate.xid is None, -(candidate.xid or 0)),
        )
        for candidate in rejected:
            xid = "unknown" if candidate.xid is None else str(candidate.xid)
            yield f"Skipping superblock xid={xid}: {_legacy_reason(candidate.reasons)}"

        for candidate in self.candidates:
            if candidate.accepted:
                yield f"Checkpoint {candidate.describe()}: accepted"
            else:
                yield f"Checkpoint {candidate.describe()}: rejected: {'; '.join(candidate.reasons)}"

        if self.selected is None:
            yield f"No checkpoint selected: {self.reason}"
        else:
            suffix = " (fallback)" if self.fallback else ""
            yield f"Selected checkpoint {self.selected.describe()}{suffix}: {self.reason}"


def _legacy_reason(reasons: list[str]) -> str:
    for reason in reasons:
        if "invalid OMAP object" in reason or "not an OMAP" in reason:
            return "invalid OMAP"
    for reason in reasons:
        if "checksum" in reason:
            return "Invalid nx_superblock checksum"
    return reasons[0] if reasons else "unknown"


def select_checkpoint(container: APFS, anchor: NxSuperblock) -> CheckpointSelection:
    """Select the newest consistent checkpoint from the descriptor area.

    The active window from the anchor is authoritative. Candidates inside that
    window are considered first. Only older checkpoints that are linked to the
    window through the descriptor ring may be used as a fallback. A checksum
    valid NX with a higher xid outside the window is never treated as the
    current state.

    Args:
        container: The APFS container to read blocks from.
        anchor: The bootstrap NX superblock from block 0.

    Raises:
        CheckpointError: If the anchor does not describe a usable window or if
            no candidate forms a consistent NX, identity, OMAP and volume entry.
    """
    window = _read_window(anchor)
    candidates = list(_iter_candidates(container, window))

    active = _select_active(candidates, window)
    if active is not None:
        active.role = "active"
        active.in_window = True

    prior_chain = _build_prior_chain(candidates, window, active)

    active_xid = active.xid if active is not None else None

    for candidate in candidates:
        if candidate.role == "active":
            _validate_candidate(container, anchor, window, candidate, active_xid=active_xid, successor_xid=None)
        elif candidate.role == "prior":
            _validate_candidate(
                container,
                anchor,
                window,
                candidate,
                active_xid=active_xid,
                successor_xid=_successor_xid(candidate, prior_chain, active),
            )
        else:
            _validate_candidate(container, anchor, window, candidate, active_xid=active_xid, successor_xid=None)

    # Evaluation order: active first, then the linked older checkpoints from
    # newest to oldest, then unlinked blocks that are only reported for context.
    order = [candidate for candidate in (active,) if candidate is not None]
    order.extend(prior_chain)
    order.extend(
        sorted(
            (candidate for candidate in candidates if candidate not in order),
            key=lambda candidate: (candidate.xid is None, -(candidate.xid or 0)),
        )
    )

    selection = CheckpointSelection(
        anchor=anchor,
        window=window,
        candidates=order,
        selected=None,
    )

    for candidate in order:
        if candidate.accepted:
            selection.selected = candidate
            break

    if selection.selected is None:
        raise CheckpointError("No consistent APFS checkpoint found\n" + selection.report())

    return selection


def _read_window(anchor: NxSuperblock) -> CheckpointWindow:
    object = anchor.object
    descriptor_blocks = object.nx_xp_desc_blocks
    if descriptor_blocks & 0x80000000:
        raise CheckpointError("Checkpoint descriptor area uses a B-tree, which is not supported")

    if descriptor_blocks < 2:
        raise CheckpointError(f"Invalid checkpoint descriptor area size: {descriptor_blocks} blocks")

    if object.nx_block_size < c_apfs.NX_MINIMUM_BLOCK_SIZE or object.nx_block_size > c_apfs.NX_MAXIMUM_BLOCK_SIZE:
        raise CheckpointError(f"Invalid container block size: {object.nx_block_size}")

    if object.nx_block_size & (object.nx_block_size - 1):
        raise CheckpointError(f"Invalid container block size: {object.nx_block_size}")

    if object.nx_block_count == 0:
        raise CheckpointError("Invalid container block count: 0")

    base = object.nx_xp_desc_base
    if base < 0 or base + descriptor_blocks > object.nx_block_count:
        raise CheckpointError(
            f"Checkpoint descriptor area out of bounds: base={base} blocks={descriptor_blocks} "
            f"container_blocks={object.nx_block_count}"
        )

    index = object.nx_xp_desc_index
    length = object.nx_xp_desc_len
    if index >= descriptor_blocks:
        raise CheckpointError(f"Checkpoint descriptor index out of range: {index} >= {descriptor_blocks}")
    if length < 2 or length > descriptor_blocks:
        raise CheckpointError(f"Invalid checkpoint descriptor window length: {length}")

    return CheckpointWindow(
        descriptor_base=base,
        descriptor_blocks=descriptor_blocks,
        index=index,
        length=length,
        next_index=object.nx_xp_desc_next,
    )


def _iter_candidates(container: APFS, window: CheckpointWindow) -> Iterator[CheckpointCandidate]:
    for slot in range(window.descriptor_blocks):
        address = window.descriptor_base + slot
        block = container._read_block(address)

        try:
            header = c_apfs.obj_phys(block)
        except Exception:
            continue

        if header.o_type & c_apfs.OBJECT_TYPE_MASK != c_apfs.OBJECT_TYPE.NX_SUPERBLOCK:
            continue

        candidate = CheckpointCandidate(
            address=address,
            slot=slot,
            in_window=window.contains_slot(slot),
        )

        try:
            candidate.superblock = Object.from_block(container, address, block)
        except Exception as e:
            candidate.reasons.append(f"could not parse NX superblock: {e}")

        yield candidate


def _select_active(candidates: list[CheckpointCandidate], window: CheckpointWindow) -> CheckpointCandidate | None:
    active_slot = window.slots[-1]
    matches = [candidate for candidate in candidates if candidate.slot == active_slot]

    if not matches:
        return None

    if len(matches) > 1:
        for candidate in matches:
            candidate.reasons.append("multiple NX superblocks occupy the active window slot")
        return matches[0]

    return matches[0]


def _build_prior_chain(
    candidates: list[CheckpointCandidate], window: CheckpointWindow, active: CheckpointCandidate | None
) -> list[CheckpointCandidate]:
    chain: list[CheckpointCandidate] = []
    starts: set[int] = set()
    cursor = window.start_slot
    successor_xid = active.xid if active is not None else None

    for _ in range(window.descriptor_blocks):
        matches = [
            candidate
            for candidate in candidates
            if candidate is not active
            and candidate not in chain
            and _is_group_for(candidate, cursor, window.descriptor_blocks)
        ]

        if not matches:
            break

        # Multiple blocks claiming the same predecessor are ambiguous evidence.
        if len(matches) > 1:
            for candidate in matches:
                candidate.reasons.append(
                    f"ambiguous descriptor link into checkpoint window start slot {cursor}"
                )
            break

        candidate = matches[0]
        if candidate.superblock is None:
            candidate.role = "prior"
            chain.append(candidate)
            break

        # A fallback checkpoint must be strictly older than the checkpoint that
        # follows it. Descriptor ring slots can hold stale writes from an
        # earlier lap around the ring; following them would move forward in
        # time instead of back.
        if candidate.xid is None:
            break
        if successor_xid is not None and candidate.xid >= successor_xid:
            break

        candidate.role = "prior"
        candidate.in_window = False
        chain.append(candidate)
        successor_xid = candidate.xid

        next_start = candidate.superblock.object.nx_xp_desc_index
        if next_start in starts or next_start == window.start_slot:
            break

        starts.add(next_start)
        cursor = next_start

    return chain


def _is_group_for(candidate: CheckpointCandidate, next_start: int, descriptor_blocks: int) -> bool:
    superblock = candidate.superblock
    if superblock is None:
        return False

    object = superblock.object
    index = object.nx_xp_desc_index
    length = object.nx_xp_desc_len

    if index >= descriptor_blocks or length < 2 or length > descriptor_blocks:
        return False

    # A checkpoint's NX superblock is the last slot of its descriptor group.
    if candidate.slot != (index + length - 1) % descriptor_blocks:
        return False

    return (index + length) % descriptor_blocks == next_start


def _successor_xid(
    candidate: CheckpointCandidate, chain: list[CheckpointCandidate], active: CheckpointCandidate | None
) -> int | None:
    index = chain.index(candidate)
    if index > 0:
        return chain[index - 1].xid
    return active.xid if active is not None else None


def _validate_candidate(
    container: APFS,
    anchor: NxSuperblock,
    window: CheckpointWindow,
    candidate: CheckpointCandidate,
    *,
    active_xid: int | None,
    successor_xid: int | None,
) -> None:
    superblock = candidate.superblock

    if superblock is None:
        if not candidate.reasons:
            candidate.reasons.append("could not parse NX superblock")
        return

    object = superblock.object

    try:
        superblock.check()
    except Exception as e:
        candidate.reasons.append(str(e))
        return

    if object.nx_next_xid <= superblock.xid:
        candidate.reasons.append(
            f"nx_next_xid={object.nx_next_xid} is not greater than checkpoint xid={superblock.xid}"
        )

    _validate_container_identity(candidate, anchor)

    _validate_descriptor_position(candidate, window)
    _validate_checkpoint_maps(container, candidate, window)

    if (
        candidate.role == "outside"
        and active_xid is not None
        and candidate.xid is not None
        and candidate.xid > active_xid
    ):
        candidate.reasons.append(
            f"xid={candidate.xid} is newer than the active window checkpoint xid={active_xid} "
            "but the block is not the active checkpoint"
        )

    if candidate.role == "prior" and successor_xid is not None and candidate.xid is not None:
        if candidate.xid >= successor_xid:
            candidate.reasons.append(
                f"xid={candidate.xid} is not older than successor checkpoint xid={successor_xid}"
            )

    _validate_object_map(container, candidate)

    if candidate.role == "outside" and not candidate.reasons:
        candidate.reasons.append(
            "block is not the active checkpoint and is not linked to it through the descriptor ring"
        )


def _validate_container_identity(candidate: CheckpointCandidate, anchor: NxSuperblock) -> None:
    superblock = candidate.superblock
    if superblock is None:
        return

    if superblock.oid != c_apfs.OID_NX_SUPERBLOCK:
        candidate.reasons.append(f"NX superblock has oid={superblock.oid}, expected {c_apfs.OID_NX_SUPERBLOCK}")

    try:
        superblock.compare(anchor, xid=False)
    except Exception as e:
        candidate.reasons.append(f"container identity mismatch: {e}")


def _validate_descriptor_position(candidate: CheckpointCandidate, window: CheckpointWindow) -> None:
    superblock = candidate.superblock
    if superblock is None:
        return

    object = superblock.object
    index = object.nx_xp_desc_index
    length = object.nx_xp_desc_len
    blocks = window.descriptor_blocks

    if index >= blocks or length < 2 or length > blocks:
        candidate.reasons.append(
            f"invalid descriptor window in NX: index={index} length={length} blocks={blocks}"
        )
        return

    expected_slot = (index + length - 1) % blocks
    if candidate.slot != expected_slot:
        candidate.reasons.append(
            f"NX at slot {candidate.slot} does not match its declared window "
            f"index={index} length={length} (expected slot {expected_slot})"
        )

    if candidate.role == "active":
        if index != window.index or length != window.length:
            candidate.reasons.append(
                f"active NX declares index={index} length={length}, "
                f"anchor window is index={window.index} length={window.length}"
            )
    elif candidate.role == "outside":
        if candidate.slot in window.slots:
            candidate.reasons.append(
                f"duplicate NX superblock in active checkpoint window slot {candidate.slot}"
            )
        else:
            candidate.reasons.append(
                f"outside active checkpoint descriptor window "
                f"(slot {candidate.slot}, active slots {window.slots})"
            )


def _validate_checkpoint_maps(container: APFS, candidate: CheckpointCandidate, window: CheckpointWindow) -> None:
    superblock = candidate.superblock
    if superblock is None:
        return

    object = superblock.object
    blocks = window.descriptor_blocks
    index = object.nx_xp_desc_index
    length = object.nx_xp_desc_len

    if index >= blocks or length < 2 or length > blocks:
        return

    group = [(index + i) % blocks for i in range(length)]
    if group[-1] != candidate.slot:
        return

    map_slots = group[:-1]
    last_map = len(map_slots) - 1

    for position, slot in enumerate(map_slots):
        address = window.descriptor_base + slot
        try:
            block = container._read_block(address)
            header = c_apfs.obj_phys(block)
        except Exception as e:
            candidate.reasons.append(f"could not read checkpoint map at block {address}: {e}")
            continue

        if header.o_type & c_apfs.OBJECT_TYPE_MASK != c_apfs.OBJECT_TYPE.CHECKPOINT_MAP:
            candidate.reasons.append(
                f"descriptor group slot {slot} at block {address} is not a checkpoint map"
            )
            continue

        try:
            checkpoint_map = Object.from_block(container, address, block)
        except Exception as e:
            candidate.reasons.append(f"could not parse checkpoint map at block {address}: {e}")
            continue

        if not checkpoint_map.is_valid():
            candidate.reasons.append(f"invalid checkpoint map checksum at block {address}")
            continue

        if checkpoint_map.xid != superblock.xid:
            candidate.reasons.append(
                f"checkpoint map xid={checkpoint_map.xid} at block {address} "
                f"does not match NX xid={superblock.xid}"
            )
            continue

        if checkpoint_map.oid != address:
            candidate.reasons.append(
                f"checkpoint map at block {address} has oid={checkpoint_map.oid}"
            )
            continue

        flags = checkpoint_map.object.cpm_flags
        if position == last_map:
            if not flags & c_apfs.CHECKPOINT_MAP_LAST:
                candidate.reasons.append(
                    f"checkpoint map at block {address} does not mark the end of the descriptor group"
                )
        elif flags & c_apfs.CHECKPOINT_MAP_LAST:
            candidate.reasons.append(
                f"checkpoint map at block {address} marks the end of the group too early"
            )

        if checkpoint_map.object.cpm_count == 0:
            candidate.reasons.append(f"checkpoint map at block {address} contains no mappings")
            continue

        _validate_checkpoint_map_entries(container, candidate, checkpoint_map)


def _validate_checkpoint_map_entries(container: APFS, candidate: CheckpointCandidate, checkpoint_map: Object) -> None:
    superblock = candidate.superblock
    if superblock is None:
        return

    block_count = superblock.object.nx_block_count

    for mapping in checkpoint_map.object.cpm_map:
        paddr = mapping.cpm_paddr
        if paddr < 0 or paddr >= block_count:
            candidate.reasons.append(
                f"checkpoint map entry oid={mapping.cpm_oid} points outside the container: block {paddr}"
            )
            continue

        try:
            mapped = Object.from_block(container, paddr, container._read_block(paddr))
        except Exception as e:
            candidate.reasons.append(
                f"could not read checkpoint map entry oid={mapping.cpm_oid} at block {paddr}: {e}"
            )
            continue

        if not mapped.is_valid():
            candidate.reasons.append(
                f"checkpoint map entry oid={mapping.cpm_oid} at block {paddr} has an invalid checksum"
            )
            continue

        if mapped.oid != mapping.cpm_oid:
            candidate.reasons.append(
                f"checkpoint map entry oid={mapping.cpm_oid} resolves to object oid={mapped.oid} at block {paddr}"
            )
            continue

        if mapped.xid != superblock.xid:
            candidate.reasons.append(
                f"checkpoint map entry oid={mapping.cpm_oid} at block {paddr} has xid={mapped.xid}, "
                f"expected {superblock.xid}"
            )
            continue

        expected_type = mapping.cpm_type & c_apfs.OBJECT_TYPE_MASK
        if mapped.header.o_type & c_apfs.OBJECT_TYPE_MASK != expected_type:
            candidate.reasons.append(
                f"checkpoint map entry oid={mapping.cpm_oid} at block {paddr} has type {mapped.type.name}, "
                f"expected type 0x{expected_type:x}"
            )


def _validate_object_map(container: APFS, candidate: CheckpointCandidate) -> None:
    superblock = candidate.superblock
    if superblock is None:
        return

    object = superblock.object
    block_count = object.nx_block_count

    if object.nx_omap_oid < 0 or object.nx_omap_oid >= block_count:
        candidate.reasons.append(f"nx_omap_oid={object.nx_omap_oid} is outside the container")
        return

    try:
        omap_object = Object.from_block(container, object.nx_omap_oid, container._read_block(object.nx_omap_oid))
    except Exception as e:
        candidate.reasons.append(f"could not read OMAP at block {object.nx_omap_oid}: {e}")
        return

    if not isinstance(omap_object, ObjectMap):
        candidate.reasons.append(
            f"nx_omap_oid={object.nx_omap_oid} references {omap_object.type.name}, not an OMAP"
        )
        return

    if not omap_object.is_valid():
        candidate.reasons.append(f"invalid OMAP object at block {object.nx_omap_oid}")
        return

    if omap_object.xid > superblock.xid:
        candidate.reasons.append(
            f"OMAP xid={omap_object.xid} is newer than checkpoint xid={superblock.xid}"
        )

    tree_oid = omap_object.object.om_tree_oid
    if tree_oid < 0 or tree_oid >= block_count:
        candidate.reasons.append(f"OMAP B-tree oid={tree_oid} is outside the container")
        return

    try:
        tree = omap_object.btree
        root = tree.root
    except Exception as e:
        candidate.reasons.append(f"could not read OMAP B-tree root {tree_oid}: {e}")
        return

    if not root.is_valid():
        candidate.reasons.append(f"invalid OMAP B-tree root checksum at block {tree_oid}")
        return

    if root.type not in (c_apfs.OBJECT_TYPE.BTREE, c_apfs.OBJECT_TYPE.BTREE_NODE):
        candidate.reasons.append(
            f"OMAP B-tree root at block {tree_oid} has type {root.type.name}, not a B-tree"
        )
        return

    if not tree.flags & c_apfs.BTREE.PHYSICAL:
        candidate.reasons.append(f"OMAP B-tree at block {tree_oid} is not physical")
        return

    volume_oids = [oid for oid in object.nx_fs_oid if oid != 0]
    candidate.volume_oids = volume_oids

    for oid in volume_oids:
        try:
            value = _omap_lookup(omap_object, oid, superblock.xid)
        except Exception as e:
            candidate.reasons.append(f"volume oid={oid} not mapped in OMAP at xid={superblock.xid}: {e}")
            continue

        omap_val = c_apfs.omap_val(value)
        if omap_val.ov_flags & c_apfs.OMAP_VAL_DELETED:
            candidate.reasons.append(f"volume oid={oid} is marked deleted in OMAP")
            continue

        paddr = omap_val.ov_paddr
        if paddr < 0 or paddr >= block_count:
            candidate.reasons.append(f"volume oid={oid} maps to out-of-bounds block {paddr}")
            continue

        try:
            fs_object = Object.from_block(container, paddr, container._read_block(paddr))
        except Exception as e:
            candidate.reasons.append(f"could not read volume oid={oid} at block {paddr}: {e}")
            continue

        if not fs_object.is_valid():
            candidate.reasons.append(f"invalid volume object checksum for oid={oid} at block {paddr}")
            continue

        if fs_object.type != c_apfs.OBJECT_TYPE.FS:
            candidate.reasons.append(
                f"volume oid={oid} maps to {fs_object.type.name} at block {paddr}, not an FS object"
            )
            continue

        if fs_object.oid != oid:
            candidate.reasons.append(
                f"volume oid={oid} maps to object oid={fs_object.oid} at block {paddr}"
            )
            continue

        if fs_object.xid > superblock.xid:
            candidate.reasons.append(
                f"volume oid={oid} object xid={fs_object.xid} is newer than checkpoint xid={superblock.xid}"
            )
            continue

        try:
            volume = FS(container, paddr, block=container._read_block(paddr))
            name = volume.name
        except Exception as e:
            candidate.reasons.append(f"volume oid={oid} at block {paddr} is not a valid filesystem: {e}")
            continue

        if name not in candidate.volume_names:
            candidate.volume_names.append(name)


def _omap_lookup(omap: ObjectMap, oid: int, xid: int) -> bytes:
    # Imported here to avoid a circular import at package load time.
    from dissect.apfs.cursor import Cursor

    cursor = Cursor(omap.btree).search((oid, xid), cmp=cmp_omap)
    key_oid, key_xid = _QQ.unpack(cursor.key())

    if key_oid != oid:
        raise KeyError(f"no OMAP entry for oid {oid} (predecessor oid {key_oid})")
    if key_xid > xid:
        raise KeyError(f"OMAP entry xid {key_xid} is newer than requested xid {xid}")

    return cursor.value()
