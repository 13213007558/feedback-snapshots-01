"""Read-only permission evidence inventory for SquashFS images.

The inventory reports objects whose on-disk mode grants setuid, setgid,
sticky, or (optionally) world-writable permissions.  Each finding includes
the raw mode and the raw id-table indexes from the inode header, together
with the numeric uid/gid resolved through the filesystem's id table.

No account names are resolved on the host: only numeric IDs from the image
are reported.  A failed id-table lookup is reported as unknown and is never
interpreted as uid/gid 0 (root).
"""

from __future__ import annotations

import argparse
import json
import stat
import sys
from dataclasses import dataclass, field, replace
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from typing import BinaryIO

    from dissect.squashfs.identity import IdLookup
    from dissect.squashfs.squashfs import INode, SquashFS


MODE_FIELDS = (
    ("setuid", stat.S_ISUID),
    ("setgid", stat.S_ISGID),
    ("sticky", stat.S_ISVTX),
    ("owner_write", stat.S_IWUSR),
    ("group_write", stat.S_IWGRP),
    ("other_write", stat.S_IWOTH),
)

FILE_TYPE_NAMES = {
    stat.S_IFDIR: "directory",
    stat.S_IFREG: "regular",
    stat.S_IFLNK: "symlink",
    stat.S_IFBLK: "block_device",
    stat.S_IFCHR: "character_device",
    stat.S_IFIFO: "fifo",
    stat.S_IFSOCK: "socket",
}


def _type_name(mode: int) -> str:
    return FILE_TYPE_NAMES.get(stat.S_IFMT(mode), "unknown")


def _mode_octal(mode: int) -> str:
    return f"{stat.S_IMODE(mode):04o}"


@dataclass(frozen=True, slots=True)
class PermissionEntry:
    """One distinct underlying inode that matched the inventory criteria."""

    path: str
    paths: tuple[str, ...]
    inode_block: int
    inode_offset: int
    inode_number: int
    header_inode_number: int
    inode_type: int
    raw_mode: int
    full_mode: int
    owner: IdLookup
    group: IdLookup
    nlink: int | None
    reasons: tuple[str, ...]
    include_all: bool = False

    @property
    def setuid(self) -> bool:
        """Whether the inode's raw mode has the setuid bit."""
        return bool(self.raw_mode & stat.S_ISUID)

    @property
    def setgid(self) -> bool:
        """Whether the inode's raw mode has the setgid bit."""
        return bool(self.raw_mode & stat.S_ISGID)

    @property
    def sticky(self) -> bool:
        """Whether the inode's raw mode has the sticky bit."""
        return bool(self.raw_mode & stat.S_ISVTX)

    @property
    def world_writable(self) -> bool:
        """Whether the ``other`` class has a write bit (``S_IWOTH``)."""
        return bool(self.raw_mode & stat.S_IWOTH)

    @property
    def group_writable(self) -> bool:
        """Whether the ``group`` class has a write bit (``S_IWGRP``)."""
        return bool(self.raw_mode & stat.S_IWGRP)

    @property
    def owner_known(self) -> bool:
        """Whether the numeric owner could be resolved from the id table."""
        return self.owner.known

    @property
    def group_known(self) -> bool:
        """Whether the numeric group could be resolved from the id table."""
        return self.group.known

    @property
    def owner_id(self) -> int | None:
        """The resolved numeric uid, or ``None`` when unknown."""
        return self.owner.resolved_id

    @property
    def group_id(self) -> int | None:
        """The resolved numeric gid, or ``None`` when unknown."""
        return self.group.resolved_id

    @property
    def owner_is_root(self) -> bool | None:
        """``True`` only for a known uid 0; ``False`` for known non-root; ``None`` if unknown."""
        return self.owner.is_root

    @property
    def group_is_root(self) -> bool | None:
        """``True`` only for a known gid 0; ``False`` for known non-root; ``None`` if unknown."""
        return self.group.is_root

    @property
    def identity_status(self) -> str:
        """A compact owner/group resolution status for this object."""
        if self.owner_known and self.group_known:
            return "known"
        if not self.owner_known and not self.group_known:
            return "owner_and_group_unknown"
        if not self.owner_known:
            return "owner_unknown"
        return "group_unknown"

    @property
    def definitely_root_owned_setuid(self) -> bool:
        """Whether this is a setuid file whose owner is known to be numeric uid 0."""
        return self.setuid and self.owner_is_root is True

    @property
    def permission_known_owner_unknown(self) -> bool:
        """Whether the permission bits are known but the owner is not."""
        return not self.owner_known

    @property
    def classification(self) -> str:
        """The primary security-relevant classification of this object."""
        if self.setuid:
            if self.owner_is_root is True:
                return "setuid_root"
            if self.owner_is_root is None:
                return "setuid_owner_unknown"
            return "setuid_non_root"
        if self.setgid:
            if self.group_is_root is True:
                return "setgid_root"
            if self.group_is_root is None:
                return "setgid_group_unknown"
            return "setgid_non_root"
        if self.sticky:
            return "sticky"
        if self.world_writable:
            return "world_writable"
        if self.group_writable:
            return "group_writable"
        return "other"

    @property
    def mode_flags(self) -> dict[str, bool]:
        """Boolean view of every mode bit relevant to the inventory."""
        return {name: bool(self.raw_mode & bit) for name, bit in MODE_FIELDS}

    @property
    def raw_fields(self) -> dict[str, object]:
        """Map each judgement back to the raw on-disk field it came from."""
        return {
            "inode_type": {
                "field": "squashfs_base_inode_header.inode_type",
                "value": self.inode_type,
            },
            "mode": {
                "field": "squashfs_base_inode_header.mode",
                "value": self.raw_mode,
                "octal": _mode_octal(self.raw_mode),
                "setuid": bool(self.raw_mode & stat.S_ISUID),
                "setgid": bool(self.raw_mode & stat.S_ISGID),
                "sticky": bool(self.raw_mode & stat.S_ISVTX),
                "world_writable": bool(self.raw_mode & stat.S_IWOTH),
            },
            "owner_index": {
                "field": "squashfs_base_inode_header.uid",
                "value": self.owner.index,
                "resolved_id": self.owner.resolved_id,
                "status": self.owner.status,
                "reason": self.owner.reason,
            },
            "group_index": {
                "field": "squashfs_base_inode_header.guid",
                "value": self.group.index,
                "resolved_id": self.group.resolved_id,
                "status": self.group.status,
                "reason": self.group.reason,
            },
        }

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable evidence record."""
        return {
            "path": self.path,
            "paths": list(self.paths),
            "path_count": len(self.paths),
            "hardlinked": len(self.paths) > 1,
            "inode": {
                "block": self.inode_block,
                "offset": self.inode_offset,
                "number": self.inode_number,
                "header_inode_number": self.header_inode_number,
                "type": self.inode_type,
                "file_type": _type_name(self.full_mode),
                "file_type_bits": stat.S_IFMT(self.full_mode),
                "nlink": self.nlink,
            },
            "permissions": {
                "raw_mode": self.raw_mode,
                "raw_mode_octal": _mode_octal(self.raw_mode),
                "full_mode": self.full_mode,
                "full_mode_octal": f"{self.full_mode:06o}",
                "permission_bits": stat.S_IMODE(self.raw_mode),
                "permission_bits_octal": _mode_octal(self.raw_mode),
                "flags": self.mode_flags,
            },
            "identity": {
                "owner": self.owner.to_dict(),
                "group": self.group.to_dict(),
                "owner_known": self.owner_known,
                "group_known": self.group_known,
                "owner_id": self.owner_id,
                "group_id": self.group_id,
                "owner_is_root": self.owner_is_root,
                "group_is_root": self.group_is_root,
                "status": self.identity_status,
            },
            "judgement": {
                "reasons": list(self.reasons),
                "classification": self.classification,
                "definitely_root_owned_setuid": self.definitely_root_owned_setuid,
                "permission_known_owner_unknown": self.permission_known_owner_unknown,
                "identity_complete": self.identity_status == "known",
            },
            "raw_fields": self.raw_fields,
            "id_table_evidence": {
                "owner": {
                    "pointer_array_index": self.owner.pointer_index,
                    "metadata_block": self.owner.metadata_block,
                    "metadata_offset": self.owner.metadata_offset,
                },
                "group": {
                    "pointer_array_index": self.group.pointer_index,
                    "metadata_block": self.group.metadata_block,
                    "metadata_offset": self.group.metadata_offset,
                },
            },
        }


@dataclass(frozen=True, slots=True)
class HardLinkGroup:
    """All paths that refer to one underlying hard-linked inode."""

    inode_block: int
    inode_offset: int
    inode_number: int
    paths: tuple[str, ...]
    header_nlink: int | None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable hard-link group record."""
        return {
            "inode": {
                "block": self.inode_block,
                "offset": self.inode_offset,
                "number": self.inode_number,
                "header_nlink": self.header_nlink,
            },
            "paths": list(self.paths),
            "path_count": len(self.paths),
        }


@dataclass(frozen=True, slots=True)
class InventoryOptions:
    """Selection criteria for the permission inventory."""

    include_sticky: bool = True
    include_world_writable: bool = True
    include_group_writable: bool = False
    include_symlinks: bool = False
    include_all: bool = False

    def applies_to(self, entry: PermissionEntry) -> bool:
        """Whether ``entry`` matches these criteria."""
        if entry.include_all:
            return True
        if stat.S_IFMT(entry.full_mode) == stat.S_IFLNK and not self.include_symlinks:
            # Linux ignores permission bits on symlink inodes.
            return False
        if entry.setuid or entry.setgid:
            return True
        if self.include_sticky and entry.sticky:
            return True
        if self.include_world_writable and entry.world_writable:
            return True
        return self.include_group_writable and entry.group_writable

    def reasons_for(self, entry: PermissionEntry) -> tuple[str, ...]:
        """Explain why ``entry`` matched these criteria."""
        reasons = []
        if entry.setuid:
            reasons.append("setuid")
        if entry.setgid:
            reasons.append("setgid")
        if self.include_sticky and entry.sticky:
            reasons.append("sticky")
        if self.include_world_writable and entry.world_writable:
            reasons.append("world_writable")
        if self.include_group_writable and entry.group_writable:
            reasons.append("group_writable")
        if entry.include_all and not reasons:
            reasons.append("include_all")
        if entry.setuid and entry.owner_is_root is True:
            reasons.append("owner_is_root")
        elif entry.setuid and entry.owner_is_root is None:
            reasons.append("owner_unknown")
        if entry.setgid and entry.group_is_root is True:
            reasons.append("group_is_root")
        elif entry.setgid and entry.group_is_root is None:
            reasons.append("group_unknown")
        return tuple(reasons)


@dataclass
class PermissionManifest:
    """A complete, read-only inventory of permission-relevant SquashFS objects."""

    entries: list[PermissionEntry] = field(default_factory=list)
    hardlinks: list[HardLinkGroup] = field(default_factory=list)
    diagnostics: list[dict[str, object]] = field(default_factory=list)
    options: InventoryOptions = field(default_factory=InventoryOptions)
    source: str | None = None
    objects_examined: int = 0
    paths_examined: int = 0
    id_table_truncated: bool = False
    id_table_error: str | None = None
    id_table_block_count: int = 0
    _all_objects: dict[tuple[int, int], PermissionEntry] = field(default_factory=dict, repr=False)
    _expanded_dirs: set[tuple[int, int]] = field(default_factory=set, repr=False)
    _seen_paths: set[str] = field(default_factory=set, repr=False)

    @property
    def object_count(self) -> int:
        """Number of distinct matching underlying objects (hard links count once)."""
        return len(self.entries)

    @property
    def path_count(self) -> int:
        """Number of matching path references (hard links count separately)."""
        return sum(len(entry.paths) for entry in self.entries)

    @property
    def unknown_identity_count(self) -> int:
        """Number of matching objects with at least one unresolved numeric identity."""
        return sum(1 for entry in self.entries if entry.identity_status != "known")

    def __iter__(self) -> Iterator[PermissionEntry]:
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable representation of the whole inventory."""
        return {
            "source": self.source,
            "summary": {
                "objects_examined": self.objects_examined,
                "paths_examined": self.paths_examined,
                "matching_objects": self.object_count,
                "matching_paths": self.path_count,
                "unknown_identity_objects": self.unknown_identity_count,
                "hardlink_groups": len(self.hardlinks),
                "diagnostics": len(self.diagnostics),
            },
            "id_table": {
                "block_count": self.id_table_block_count,
                "truncated": self.id_table_truncated,
                "error": self.id_table_error,
            },
            "criteria": {
                "include_sticky": self.options.include_sticky,
                "include_world_writable": self.options.include_world_writable,
                "include_group_writable": self.options.include_group_writable,
                "include_symlinks": self.options.include_symlinks,
                "include_all": self.options.include_all,
            },
            "entries": [entry.to_dict() for entry in self.entries],
            "hardlinks": [group.to_dict() for group in self.hardlinks],
            "diagnostics": self.diagnostics,
        }

    def to_json(self, indent: int | None = 2) -> str:
        """Return the inventory as JSON."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)

    def render_text(self) -> str:
        """Render a compact human-readable report."""
        lines = [
            f"objects examined: {self.objects_examined}, paths examined: {self.paths_examined}",
            (
                f"matching objects: {self.object_count}, matching paths: {self.path_count}, "
                f"unknown identity: {self.unknown_identity_count}"
            ),
        ]
        for entry in self.entries:
            owner = (
                f"uid[{entry.owner.index}]={entry.owner_id}"
                if entry.owner_known
                else f"uid[{entry.owner.index}]=unknown"
            )
            group = (
                f"gid[{entry.group.index}]={entry.group_id}"
                if entry.group_known
                else f"gid[{entry.group.index}]=unknown"
            )
            paths = " | ".join(entry.paths)
            lines.append(
                f"{paths} mode={_mode_octal(entry.raw_mode)} {owner} {group} "
                f"[{entry.classification}] reasons={','.join(entry.reasons)}"
            )
            if not entry.owner_known:
                lines.append(f"  owner evidence: {entry.owner.reason} ({entry.owner.detail})")
            if not entry.group_known:
                lines.append(f"  group evidence: {entry.group.reason} ({entry.group.detail})")
        if self.hardlinks:
            lines.append("hardlink groups:")
            lines.extend(
                f"  inode {group.inode_number} @ {group.inode_block}:{group.inode_offset} -> {list(group.paths)}"
                for group in self.hardlinks
            )
        if self.diagnostics:
            lines.append("diagnostics:")
            lines.extend(f"  {diagnostic}" for diagnostic in self.diagnostics)
        return "\n".join(lines)


def _inode_key(node: INode) -> tuple[int, int]:
    return (node.block, node.offset)


def _nlink(node: INode) -> int | None:
    return getattr(node.header, "nlink", None)


def _make_entry(node: INode, path: str, paths: tuple[str, ...], include_all: bool = False) -> PermissionEntry:
    return PermissionEntry(
        path=path,
        paths=paths,
        inode_block=node.block,
        inode_offset=node.offset,
        inode_number=node.inode_number,
        header_inode_number=node.header.inode_number,
        inode_type=node.header.inode_type,
        raw_mode=node.header.mode,
        full_mode=node.mode,
        owner=node.uid_lookup,
        group=node.gid_lookup,
        nlink=_nlink(node),
        reasons=(),
        include_all=include_all,
    )


def build_permission_manifest(
    source: SquashFS | Path | str | bytes | bytearray | BinaryIO,
    *,
    options: InventoryOptions | None = None,
    include_sticky: bool | None = None,
    include_world_writable: bool | None = None,
    include_group_writable: bool | None = None,
    include_symlinks: bool | None = None,
    include_all: bool | None = None,
) -> PermissionManifest:
    """Walk a SquashFS image read-only and return a permission evidence inventory.

    Args:
        source: A :class:`~dissect.squashfs.squashfs.SquashFS` instance, a path
            to an image, raw image bytes, or an open binary file-like object.
        options: Explicit inventory criteria.
        include_sticky: Include inodes with the sticky bit (default ``True``).
        include_world_writable: Include inodes writable by ``other`` (default ``True``).
        include_group_writable: Include inodes writable by ``group`` (default ``False``).
        include_symlinks: Include symlink inodes whose ignored mode bits match (default ``False``).
        include_all: Include every inode, not only matching permission bits (default ``False``).

    Returns:
        A :class:`PermissionManifest` whose entries retain raw indexes, resolved
        numeric IDs, and source-field evidence.
    """
    from dissect.squashfs.squashfs import SquashFS

    if options is None:
        if any(
            value is not None
            for value in (include_sticky, include_world_writable, include_group_writable, include_symlinks, include_all)
        ):
            options = InventoryOptions(
                include_sticky=True if include_sticky is None else include_sticky,
                include_world_writable=True if include_world_writable is None else include_world_writable,
                include_group_writable=bool(include_group_writable),
                include_symlinks=bool(include_symlinks),
                include_all=bool(include_all),
            )
        else:
            options = InventoryOptions()

    source_name = None
    fh = None
    if isinstance(source, SquashFS):
        fs = source
    elif isinstance(source, (bytes, bytearray)):
        fs = SquashFS(BytesIO(bytes(source)))
    elif hasattr(source, "read") and hasattr(source, "seek"):
        fs = SquashFS(source)  # type: ignore[arg-type]
    else:
        source_name = str(source)
        fh = Path(source).open("rb")  # noqa: SIM115 - closed in the finally block below
        try:
            fs = SquashFS(fh)
        except Exception:
            fh.close()
            raise

    manifest = PermissionManifest(
        options=options,
        source=source_name,
        id_table_truncated=getattr(fs, "id_table_truncated", False),
        id_table_error=getattr(fs, "id_table_error", None),
        id_table_block_count=len(getattr(fs, "id_table", ())),
    )
    if manifest.id_table_truncated:
        manifest.diagnostics.append(
            {
                "scope": "id_table",
                "error": "id_table_truncated",
                "detail": ("one or more id-table block pointers are missing; identities that need them are unknown"),
            }
        )
    if manifest.id_table_error:
        manifest.diagnostics.append(
            {
                "scope": "id_table",
                "error": "id_table_read_error",
                "detail": manifest.id_table_error,
            }
        )

    def record(node: INode, path: str) -> PermissionEntry:
        key = _inode_key(node)
        existing = manifest._all_objects.get(key)
        if existing is not None:
            if path in existing.paths:
                return existing

            replacement = replace(existing, path=existing.paths[0], paths=(*existing.paths, path))
            manifest._all_objects[key] = replacement
            return replacement

        entry = _make_entry(node, path, (path,), include_all=options.include_all)
        manifest._all_objects[key] = entry
        manifest.objects_examined += 1
        return entry

    def walk(node: INode, path: str) -> None:
        key = _inode_key(node)
        record(node, path)
        if path not in manifest._seen_paths:
            manifest._seen_paths.add(path)
            manifest.paths_examined += 1

        if not node.is_dir() or key in manifest._expanded_dirs:
            return
        manifest._expanded_dirs.add(key)

        base = "" if path == "/" else path
        try:
            children = list(node.iterdir())
        except Exception as e:
            manifest.diagnostics.append(
                {
                    "path": path,
                    "inode_block": node.block,
                    "inode_offset": node.offset,
                    "error": f"{type(e).__name__}: {e}",
                }
            )
            return

        for child in children:
            if child.name is None:
                continue
            child_path = f"{base}/{child.name}" if base else f"/{child.name}"
            try:
                walk(child, child_path)
            except Exception as e:
                manifest.diagnostics.append(
                    {
                        "path": child_path,
                        "inode_block": child.block,
                        "inode_offset": child.offset,
                        "error": f"{type(e).__name__}: {e}",
                    }
                )

    try:
        walk(fs.root, "/")
    except Exception as e:
        manifest.diagnostics.append({"path": "/", "error": f"{type(e).__name__}: {e}"})
    finally:
        if fh is not None:
            fh.close()

    for entry in manifest._all_objects.values():
        if not options.applies_to(entry):
            continue

        paths = tuple(sorted(entry.paths))
        manifest.entries.append(
            replace(entry, path=paths[0], paths=paths, reasons=options.reasons_for(entry)),
        )

    manifest.entries.sort(key=lambda item: item.path)

    for entry in manifest._all_objects.values():
        if len(entry.paths) > 1:
            manifest.hardlinks.append(
                HardLinkGroup(
                    inode_block=entry.inode_block,
                    inode_offset=entry.inode_offset,
                    inode_number=entry.inode_number,
                    paths=entry.paths,
                    header_nlink=entry.nlink,
                )
            )
    manifest.hardlinks.sort(key=lambda group: group.paths[0])

    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    """Run the read-only permission inventory from the command line."""
    parser = argparse.ArgumentParser(
        prog="python -m dissect.squashfs.manifest",
        description="List setuid, setgid, sticky and world-writable SquashFS objects with identity evidence.",
    )
    parser.add_argument("image", help="SquashFS image path, or '-' to read from stdin")
    parser.add_argument("--json", action="store_true", help="emit the full machine-readable inventory")
    parser.add_argument("--no-sticky", action="store_true", help="do not match the sticky bit")
    parser.add_argument("--no-world-writable", action="store_true", help="do not match S_IWOTH")
    parser.add_argument("--include-group-writable", action="store_true", help="also match S_IWGRP")
    parser.add_argument("--include-symlinks", action="store_true", help="also inspect symlink mode bits")
    parser.add_argument("--all", action="store_true", help="include every inode")
    args = parser.parse_args(argv)

    options = InventoryOptions(
        include_sticky=not args.no_sticky,
        include_world_writable=not args.no_world_writable,
        include_group_writable=args.include_group_writable,
        include_symlinks=args.include_symlinks,
        include_all=args.all,
    )

    if args.image == "-":
        manifest = build_permission_manifest(sys.stdin.buffer.read(), options=options)
    else:
        manifest = build_permission_manifest(args.image, options=options)
        manifest.source = args.image

    if args.json:
        print(manifest.to_json())
    else:
        print(manifest.render_text())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
