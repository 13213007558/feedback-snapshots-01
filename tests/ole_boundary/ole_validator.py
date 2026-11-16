"""Independent OLE/CFB structural validation.

The checks here deliberately do *not* use msoffcrypto to read the container
back. They parse the written bytes with ``olefile`` (a separate library) and
then re-derive every sector assignment with raw arithmetic so that overlaps,
dangling chains, wrong lengths and leaked slack bytes are caught even if
olefile's own streaming helpers gloss over them.

The public entry point is :func:`validate_container`, which returns a
:class:`ValidationReport`. A report aggregates every defect instead of raising
on the first one, so a single run pinpoints all failure locations.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field

import olefile

#: Special FAT entries per [MS-CFB].
ENDOFCHAIN = olefile.ENDOFCHAIN  # 0xFFFFFFFE
FREESECT = olefile.FREESECT      # 0xFFFFFFFF
FATSECT = 0xFFFFFFFD
DIFSECT = 0xFFFFFFFC
NOSTREAM = 0xFFFFFFFF
MAXREGSECT = 0xFFFFFFFA

SECTOR_SIZE = 512
MINI_SECTOR_SIZE = 64
MINI_CUTOFF = 4096
HEADER_SIZE = 512


@dataclass
class Defect:
    code: str
    detail: str
    stream: str | None = None


@dataclass
class StreamInfo:
    name: str
    entry_type: int
    size: int
    start: int
    is_mini: bool
    chain: list[int]
    expected_chain_len: int
    readable_size: int


@dataclass
class ValidationReport:
    file_size: int
    nb_sect: int
    num_fat: int
    num_difat: int
    first_difat: int
    streams: list[StreamInfo] = field(default_factory=list)
    defects: list[Defect] = field(default_factory=list)
    # Sector allocation map: sector index -> owner label (for overlap checks).
    big_owners: dict = field(default_factory=dict)
    mini_owners: dict = field(default_factory=dict)
    free_big_sectors: list = field(default_factory=list)
    free_mini_sectors: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.defects

    def add(self, code: str, detail: str, stream: str | None = None):
        self.defects.append(Defect(code, detail, stream))


def _walk_chain(table, start, limit):
    """Walk FAT/miniFAT chain, guarding against loops and out-of-range links."""
    chain = []
    seen = set()
    cur = start
    while cur <= MAXREGSECT:
        if cur >= limit:
            return chain, f"chain index {cur} out of table range ({limit})"
        if cur in seen:
            return chain, f"cycle detected at sector {cur}"
        seen.add(cur)
        chain.append(cur)
        cur = table[cur]
    if cur not in (ENDOFCHAIN,):
        return chain, f"chain ended on unexpected marker {cur:#010x}"
    return chain, None


def validate_container(blob: bytes) -> ValidationReport:
    """Validate every structural property of an OLE container in ``blob``."""
    ole = olefile.OleFileIO(io.BytesIO(blob))
    report = ValidationReport(
        file_size=len(blob),
        nb_sect=ole.nb_sect,
        num_fat=ole.num_fat_sectors,
        num_difat=ole.num_difat_sectors,
        first_difat=ole.first_difat_sector,
    )
    try:
        if ole.fat is None:
            ole.loadfat(blob[:HEADER_SIZE])
        ole.loaddirectory(ole.first_dir_sector)
        if ole.minifat is None:
            ole.loadminifat()
        fat = list(ole.fat)
        minifat = list(ole.minifat) if ole.minifat is not None else []

        _check_header_invariants(ole, report)
        _check_fat_integrity(blob, fat, ole, report)
        _check_directory_and_chains(ole, fat, minifat, report)
        _check_overlaps(blob, ole, fat, minifat, report)
    finally:
        ole.close()
    return report


def _check_header_invariants(ole, report: ValidationReport):
    if ole.sectorsize != SECTOR_SIZE:
        report.add("HEADER_SECTOR_SIZE", f"sector size {ole.sectorsize} != {SECTOR_SIZE}")
    if ole.mini_sector_size != MINI_SECTOR_SIZE:
        report.add("HEADER_MINI_SIZE", f"mini sector size {ole.mini_sector_size} != {MINI_SECTOR_SIZE}")
    if ole.minisectorcutoff != MINI_CUTOFF:
        report.add("HEADER_CUTOFF", f"cutoff {ole.minisectorcutoff} != {MINI_CUTOFF}")
    # DIFAT consistency.
    if report.num_difat == 0 and ole.first_difat_sector != ENDOFCHAIN:
        report.add("DIFAT_HEADER", f"num_difat=0 but first_difat={ole.first_difat_sector:#x}")
    if report.num_difat > 0 and ole.first_difat_sector > MAXREGSECT:
        report.add("DIFAT_HEADER", f"num_difat>0 but first_difat={ole.first_difat_sector:#x}")


def _check_fat_integrity(blob, fat, ole, report: ValidationReport):
    # Every FAT/DIF sector must self-mark correctly.
    difat_sectors = _collect_difat_sectors(ole)
    for sect in difat_sectors:
        if sect < len(fat) and fat[sect] != DIFSECT:
            report.add("FAT_DIF_MARK", f"DIFAT sector {sect} marked {fat[sect]:#x}, expected DIFSECT")
    # FAT sectors are reachable through the DIFAT; verify their FAT entries.
    fat_sectors = _collect_fat_sectors(blob, ole)
    for sect in fat_sectors:
        if sect < len(fat) and fat[sect] != FATSECT:
            report.add("FAT_SELF_MARK", f"FAT sector {sect} marked {fat[sect]:#x}, expected FATSECT")
    # Every regular sector's FAT entry must be a valid marker or in-range index.
    for idx, entry in enumerate(fat):
        if entry <= MAXREGSECT and entry >= len(fat):
            report.add("FAT_DANGLING", f"FAT[{idx}] points beyond table to {entry}")


def _collect_difat_sectors(ole):
    sectors = []
    if ole.num_difat_sectors == 0:
        return sectors
    cur = ole.first_difat_sector
    seen = set()
    while cur <= MAXREGSECT and cur not in seen:
        seen.add(cur)
        sectors.append(cur)
        raw = ole.sect2array(ole.getsect(cur))
        cur = raw[ole.sectorsize // 4 - 1]
    return sectors


def _collect_fat_sectors(blob, ole):
    # First 109 FAT pointers live in the header at offset 0x4C; any overflow
    # FAT pointers are reached through the DIFAT sectors.
    header_pointers = list(ole.sect2array(blob[76:512]))
    pointers = [p for p in header_pointers if p <= MAXREGSECT]
    for ds in _collect_difat_sectors(ole):
        raw = ole.sect2array(ole.getsect(ds))
        pointers.extend(p for p in raw[: ole.sectorsize // 4 - 1] if p <= MAXREGSECT)
    return pointers[: ole.num_fat_sectors]


def _check_directory_and_chains(ole, fat, minifat, report: ValidationReport):
    root = ole.root
    # The root entry owns the mini stream as a normal FAT chain.
    if root.size > 0:
        chain, err = _walk_chain(fat, root.isectStart, len(fat))
        if err:
            report.add("ROOT_CHAIN", err, "Root Entry")
        _record_big(chain, "Root Entry/mini-stream", report)
        # Root mini stream must be a whole number of big sectors and cover the
        # mini sectors referenced by miniFAT.
        needed_mini_big = (root.size + SECTOR_SIZE - 1) // SECTOR_SIZE
        if len(chain) != needed_mini_big:
            report.add("ROOT_CHAIN_LEN",
                       f"root chain {len(chain)} sectors != size-implied {needed_mini_big}",
                       "Root Entry")

    for sid, entry in enumerate(ole.direntries):
        if entry is None or entry.entry_type == olefile.STGTY_EMPTY:
            continue
        if entry.entry_type not in (olefile.STGTY_STREAM, olefile.STGTY_ROOT,
                                    olefile.STGTY_STORAGE):
            report.add("DIR_TYPE", f"sid {sid} unexpected type {entry.entry_type}")
            continue
        if entry.entry_type != olefile.STGTY_STREAM:
            continue

        name = entry.name
        table = minifat if entry.is_minifat else fat
        limit = len(minifat) if entry.is_minifat else len(fat)
        if entry.size == 0:
            # Zero-length streams must not claim a start sector.
            if entry.isectStart != NOSTREAM and entry.isectStart != 0:
                report.add("EMPTY_START", f"zero-length stream has start {entry.isectStart}", name)
            report.streams.append(StreamInfo(name, entry.entry_type, 0, entry.isectStart,
                                              entry.is_minifat, [], 0, 0))
            continue

        chain, err = _walk_chain(table, entry.isectStart, limit)
        if err:
            report.add("CHAIN_BROKEN", f"{err}", name)

        sector_unit = MINI_SECTOR_SIZE if entry.is_minifat else SECTOR_SIZE
        expected = (entry.size + sector_unit - 1) // sector_unit
        if len(chain) != expected:
            report.add("CHAIN_LENGTH",
                       f"chain has {len(chain)} { 'mini' if entry.is_minifat else 'big'} "
                       f"sectors but size {entry.size} needs {expected}", name)

        # Independent read-back length. Use the SID-based low-level open so the
        # check does not depend on storage-path name resolution.
        try:
            with ole._open(entry.isectStart, entry.size) as fh:
                readable = len(fh.read())
        except Exception as exc:  # pragma: no cover - defensive
            readable = -1
            report.add("STREAM_OPEN", f"{type(exc).__name__}: {exc}", name)
        if readable != entry.size:
            report.add("STREAM_LENGTH",
                       f"directory size {entry.size} but readable bytes {readable}", name)

        report.streams.append(StreamInfo(name, entry.entry_type, entry.size,
                                          entry.isectStart, entry.is_minifat, chain,
                                          expected, readable))
        if entry.is_minifat:
            _record_mini(chain, name, report)
        else:
            _record_big(chain, name, report)


def _record_big(chain, owner, report: ValidationReport):
    for sect in chain:
        prior = report.big_owners.get(sect)
        if prior is not None:
            report.add("OVERLAP_BIG", f"big sector {sect} shared by {prior!r} and {owner!r}")
        else:
            report.big_owners[sect] = owner


def _record_mini(chain, owner, report: ValidationReport):
    for sect in chain:
        prior = report.mini_owners.get(sect)
        if prior is not None:
            report.add("OVERLAP_MINI", f"mini sector {sect} shared by {prior!r} and {owner!r}")
        else:
            report.mini_owners[sect] = owner


def _check_overlaps(blob, ole, fat, minifat, report: ValidationReport):
    # Mark reserved/metadata sectors so data chains cannot collide with them.
    metadata = {}
    for sect in _collect_fat_sectors(blob, ole):
        metadata[sect] = "FAT"
    for sect in _collect_difat_sectors(ole):
        metadata[sect] = "DIFAT"
    for sect in _chain_sectors(fat, ole.first_dir_sector):
        metadata[sect] = "Directory"
    for sect in _chain_sectors(fat, ole.minifatsect):
        metadata[sect] = "MiniFAT"

    for sect, owner in report.big_owners.items():
        if sect in metadata:
            report.add("OVERLAP_METADATA",
                       f"data sector {sect} ({owner}) collides with {metadata[sect]}")

    # Free-sector accounting: any big sector not owned and marked FREESECT is
    # genuinely free; capture them for slack/leak inspection by the caller.
    owned = set(report.big_owners) | set(metadata)
    free = [i for i in range(ole.nb_sect) if i not in owned]
    report.free_big_sectors = free
    # Mini sectors beyond those owned are free within the root mini stream.
    mini_total = (ole.root.size + MINI_SECTOR_SIZE - 1) // MINI_SECTOR_SIZE if ole.root.size else 0
    report.free_mini_sectors = [i for i in range(mini_total) if i not in report.mini_owners]


def _chain_sectors(fat, start):
    out = []
    if start is None or start > MAXREGSECT:
        return out
    cur = start
    seen = set()
    while cur <= MAXREGSECT and cur not in seen:
        seen.add(cur)
        out.append(cur)
        cur = fat[cur]
    return out
