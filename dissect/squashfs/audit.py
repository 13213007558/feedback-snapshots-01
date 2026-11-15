"""Read-only permission evidence inventory for SquashFS firmware images.

This module inventories objects carrying elevated or special permission bits
(setuid, setgid, sticky and world-writable) and records exactly which numeric
identity owns them.

Evidence rules:

* The ``uid`` and ``guid`` fields of an inode header are *indices* into the
  SquashFS ID table, not numeric UIDs/GIDs. Both values are retained as raw
  evidence and resolved through one code path (:func:`resolve_identity`), so
  basic inodes, extended inodes and hardlinked inodes sharing an index are
  treated identically.
* No local account database (``/etc/passwd``, :mod:`pwd`, :mod:`grp`) is ever
  consulted; only the numeric ID stored inside the image is reported.
* An index outside the ID table, or a truncated/corrupt table entry, is
  reported as an unknown identity with the reason and the original index. It
  is never silently coerced to zero (which would falsely imply root).
* Hard links share a single inode: the underlying object is counted once and
  every directory entry pointing at it is retained as evidence of its paths.

The image is only opened read-only; no object is ever extracted or modified.
"""

from __future__ import annotations

import argparse
import json
import stat
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from dissect.squashfs.squashfs import INode, SquashFS

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

RESOLVED = "resolved"
UNKNOWN = "unknown"

OUT_OF_RANGE = "id_index_out_of_range"
TABLE_TRUNCATED = "id_table_truncated_or_corrupt"

ROOT_SETUID = "definitely-root-setuid"
UNKNOWN_OWNER_SETUID = "unknown-owner-setuid"
OTHER_SETUID = "non-root-setuid"
SPECIAL_PERMISSION = "special-permission"

_SETUID = stat.S_ISUID
_SETGID = stat.S_ISGID
_STICKY = stat.S_ISVTX
_WORLD_WRITE = stat.S_IWOTH
_SPECIAL_MASK = _SETUID | _SETGID | _STICKY | _WORLD_WRITE

_TYPE_NAMES = {
    stat.S_IFDIR: "directory",
    stat.S_IFREG: "file",
    stat.S_IFLNK: "symlink",
    stat.S_IFBLK: "block-device",
    stat.S_IFCHR: "character-device",
    stat.S_IFIFO: "fifo",
    stat.S_IFSOCK: "socket",
}

# Documents which raw on-disk field every judgement is based on.
FIELD_BASIS = {
    "mode": "inode header field 'mode' (raw 16-bit permission bits, type bits excluded)",
    "uid_index": "inode header field 'uid' (index into the SquashFS ID table, not a UID)",
    "gid_index": "inode header field 'guid' (index into the SquashFS ID table, not a GID)",
    "resolved_id": "uint32 read from the ID table at the header index via SquashFS._lookup_id",
}


@dataclass(frozen=True, slots=True)
class IdentityEvidence:
    """Raw identity index plus the numeric ID it resolves to.

    Attributes:
        kind: ``"uid"`` or ``"gid"``.
        index: Raw value of the inode header ``uid``/``guid`` field.
        id: Numeric ID stored in the ID table, or ``None`` when it cannot be
            determined.
        status: :data:`RESOLVED` or :data:`UNKNOWN`.
        reason: Why resolution failed, or ``None`` when resolved.
    """

    kind: str
    index: int
    id: int | None
    status: str
    reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "raw_index": self.index,
            "resolved_id": self.id,
            "status": self.status,
            "reason": self.reason,
            "field_basis": FIELD_BASIS["uid_index" if self.kind == "uid" else "gid_index"],
        }


@dataclass(frozen=True, slots=True)
class PermissionEvidence:
    """One underlying inode with elevated/special permission bits.

    All values are raw evidence: ``mode_raw`` is the unmodified header field
    and the identity objects keep both the header index and the resolved ID.
    """

    inode_number: int
    inode_type_raw: int
    extended_inode: bool
    type_name: str
    paths: tuple[str, ...]
    mode_raw: int
    mode_octal: str
    special_bits: tuple[str, ...]
    uid: IdentityEvidence
    gid: IdentityEvidence
    classification: str

    @property
    def owner_known(self) -> bool:
        return self.uid.status == RESOLVED

    @property
    def root_owned(self) -> bool | None:
        """``True`` for a resolved UID 0, ``False`` for another ID, ``None`` if unknown."""
        if self.uid.status != RESOLVED:
            return None
        return self.uid.id == 0

    def to_dict(self) -> dict[str, object]:
        return {
            "inode_number": self.inode_number,
            "inode_type_raw": self.inode_type_raw,
            "extended_inode": self.extended_inode,
            "type": self.type_name,
            "paths": list(self.paths),
            "mode_raw": self.mode_raw,
            "mode_octal": self.mode_octal,
            "special_bits": list(self.special_bits),
            "uid": self.uid.to_dict(),
            "gid": self.gid.to_dict(),
            "root_owned": self.root_owned,
            "classification": self.classification,
            "field_basis": FIELD_BASIS,
        }


def resolve_identity(fs: SquashFS, index: int, kind: str) -> IdentityEvidence:
    """Resolve an inode header identity index through the SquashFS ID table.

    This is the single parsing path for every identity (UID and GID, basic and
    extended inodes, indices shared by multiple inodes). The raw index is
    always preserved. A missing or corrupt entry yields an unknown identity
    rather than a fabricated zero.

    Args:
        fs: Parsed SquashFS filesystem.
        index: Raw ``uid``/``guid`` field from an inode header.
        kind: ``"uid"`` or ``"gid"``, used only for labelling evidence.
    """
    if not 0 <= index < fs.sb.no_ids:
        return IdentityEvidence(
            kind=kind,
            index=index,
            id=None,
            status=UNKNOWN,
            reason=f"{OUT_OF_RANGE}: index={index}, superblock no_ids={fs.sb.no_ids}",
        )

    try:
        # SquashFS._lookup_id performs the (potentially cross metadata-page)
        # table read and returns the actual uint32 numeric ID.
        numeric_id = fs._lookup_id(index)
    except (IndexError, EOFError, struct.error) as exc:
        return IdentityEvidence(
            kind=kind,
            index=index,
            id=None,
            status=UNKNOWN,
            reason=f"{TABLE_TRUNCATED}: {type(exc).__name__}: {exc}",
        )

    return IdentityEvidence(kind=kind, index=index, id=numeric_id, status=RESOLVED)


def _special_bits(mode: int) -> tuple[str, ...]:
    bits = []
    if mode & _SETUID:
        bits.append("setuid")
    if mode & _SETGID:
        bits.append("setgid")
    if mode & _STICKY:
        bits.append("sticky")
    if mode & _WORLD_WRITE:
        bits.append("world-writable")
    return tuple(bits)


def _classify(mode: int, owner: IdentityEvidence) -> str:
    if not (mode & _SETUID):
        return SPECIAL_PERMISSION
    if owner.status == UNKNOWN:
        return UNKNOWN_OWNER_SETUID
    if owner.id == 0:
        return ROOT_SETUID
    return OTHER_SETUID


def evidence_for_inode(node: INode, paths: Sequence[str]) -> PermissionEvidence:
    """Build permission evidence for one underlying inode and all of its paths."""
    header = node.header
    mode_raw = header.mode
    fs = node.fs

    uid_evidence = resolve_identity(fs, header.uid, "uid")
    gid_evidence = resolve_identity(fs, header.guid, "gid")

    return PermissionEvidence(
        inode_number=node.inode_number,
        inode_type_raw=header.inode_type,
        extended_inode=header.inode_type >= 8,
        type_name=_TYPE_NAMES.get(stat.S_IFMT(node.mode), "unknown"),
        paths=tuple(paths),
        mode_raw=mode_raw,
        mode_octal=f"0o{mode_raw:04o}",
        special_bits=_special_bits(mode_raw),
        uid=uid_evidence,
        gid=gid_evidence,
        classification=_classify(mode_raw, uid_evidence),
    )


def _walk_tree(node: INode, prefix: str) -> Iterator[tuple[INode, str]]:
    for child in node.iterdir():
        path = f"{prefix.rstrip('/')}/{child.name}"
        yield child, path
        if child.is_dir():
            yield from _walk_tree(child, path)


def _collect_inodes(fs: SquashFS) -> dict[int, tuple[INode, list[str]]]:
    # Keyed by inode number so hard links (multiple directory entries for one
    # inode) retain every path while the underlying object is stored once.
    collected: dict[int, tuple[INode, list[str]]] = {}
    for node, path in _walk_tree(fs.root, "/"):
        number = node.inode_number
        if number not in collected:
            collected[number] = (node, [])
        collected[number][1].append(path)
    return collected


def permission_inventory(fs: SquashFS) -> list[PermissionEvidence]:
    """Return evidence for every setuid/setgid/sticky/world-writable object.

    Hard links are counted exactly once per underlying inode; all paths that
    reach the inode are preserved on the evidence record.
    """
    inventory = []
    for node, paths in _collect_inodes(fs).values():
        if node.header.mode & _SPECIAL_MASK:
            inventory.append(evidence_for_inode(node, paths))
    return inventory


def _format_identity(identity: IdentityEvidence) -> str:
    if identity.status == RESOLVED:
        return f"{identity.kind} index={identity.index} -> {identity.kind}={identity.id} [resolved]"
    return f"{identity.kind} index={identity.index} -> UNKNOWN [{identity.reason}]"


def render_text(inventory: Sequence[PermissionEvidence]) -> str:
    """Render the inventory as a human-readable evidence report."""
    lines = [
        "SquashFS permission evidence inventory (read-only)",
        f"Objects with setuid/setgid/sticky/world-writable bits: {len(inventory)}",
        "",
    ]
    for item in inventory:
        lines.append(f"[{item.classification}] inode={item.inode_number} type={item.type_name}")
        for path in item.paths:
            lines.append(f"  path: {path}")
        lines.append(
            f"  mode: {item.mode_octal} (raw header.mode={item.mode_raw}, "
            f"inode_type={item.inode_type_raw}, extended={item.extended_inode}) "
            f"bits={','.join(item.special_bits)}"
        )
        lines.append(f"  owner: {_format_identity(item.uid)}")
        lines.append(f"  group: {_format_identity(item.gid)}")
        lines.append("")
    return "\n".join(lines)


def render_json(inventory: Sequence[PermissionEvidence]) -> str:
    """Render the inventory as machine-readable JSON evidence."""
    return json.dumps([item.to_dict() for item in inventory], indent=2, sort_keys=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only SquashFS setuid/setgid/special-write permission evidence inventory"
    )
    parser.add_argument("image", help="Path to the SquashFS firmware image")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)

    # Explicit read-only binary mode: the image is never modified.
    with open(args.image, "rb") as fh:  # noqa: PTH123 - CLI opens a user supplied path
        fs = SquashFS(fh)
        inventory = permission_inventory(fs)

    if args.format == "json":
        print(render_json(inventory))  # noqa: T201 - CLI output
    else:
        print(render_text(inventory))  # noqa: T201 - CLI output
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
