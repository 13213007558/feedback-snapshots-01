"""Detect leftover bytes in unused sectors and stream slack space.

The writer zero-initialises its whole output buffer before placing streams, so
every byte that is not part of a stream's declared content must be zero:

* the tail of a stream's last big sector beyond its declared size ("slack");
* the tail of a mini stream's last 64-byte mini sector;
* every big sector that no FAT chain owns ("free sector");
* every mini sector inside the root mini stream that no miniFAT chain owns.

A previous-task marker (see :data:`fixtures.TASK_MARKER`) is folded into the
payload of an earlier, larger container. If the writer recycled a buffer
without clearing it, the marker would survive in one of the regions above.
"""

from __future__ import annotations

from dataclasses import dataclass

import olefile

from .ole_validator import (
    HEADER_SIZE,
    MINI_SECTOR_SIZE,
    SECTOR_SIZE,
    MAXREGSECT,
    ValidationReport,
    _chain_sectors,
    _collect_difat_sectors,
    _collect_fat_sectors,
)


@dataclass
class LeakFinding:
    code: str
    detail: str
    offset: int | None = None


def _big_sector_offset(sect: int) -> int:
    return HEADER_SIZE + sect * SECTOR_SIZE


def _walk(table, start):
    """Walk a FAT/miniFAT chain, stopping cleanly on out-of-range links."""
    out = []
    cur = start
    seen = set()
    while cur <= MAXREGSECT:
        if cur >= len(table) or cur in seen:
            break
        seen.add(cur)
        out.append(cur)
        cur = table[cur]
    return out


def check_leaks(blob: bytes, report: ValidationReport, marker: bytes) -> list[LeakFinding]:
    """Inspect slack and free regions for non-zero bytes and the marker."""
    findings: list[LeakFinding] = []
    ole = olefile.OleFileIO(__import__("io").BytesIO(blob))
    try:
        if ole.fat is None:
            ole.loadfat(blob[:SECTOR_SIZE])
        ole.loaddirectory(ole.first_dir_sector)
        if ole.minifat is None:
            ole.loadminifat()
        fat = list(ole.fat)
        minifat = list(ole.minifat) if ole.minifat is not None else []

        findings.extend(_check_big_stream_slack(ole, fat, blob, marker))
        findings.extend(_check_mini_stream_slack(ole, minifat, blob, marker))
        findings.extend(_check_free_big_sectors(ole, fat, blob, marker))
        findings.extend(_check_free_mini_sectors(ole, minifat, blob, marker))
    finally:
        ole.close()
    return findings


def _marker_hits(region: bytes, marker: bytes, base: int):
    hits = []
    start = 0
    while True:
        idx = region.find(marker, start)
        if idx < 0:
            break
        hits.append(base + idx)
        start = idx + 1
    return hits


def _check_big_stream_slack(ole, fat, blob, marker):
    findings = []
    for entry in ole.direntries:
        if entry is None or entry.entry_type != olefile.STGTY_STREAM or entry.is_minifat:
            continue
        if entry.size == 0:
            continue
        chain = _walk(fat, entry.isectStart)
        if not chain:
            continue
        last_sect = chain[-1]
        used_in_last = entry.size % SECTOR_SIZE
        if used_in_last == 0:
            continue  # last sector fully consumed
        slack_off = _big_sector_offset(last_sect) + used_in_last
        slack = blob[slack_off: slack_off + (SECTOR_SIZE - used_in_last)]
        for off in _marker_hits(slack, marker, slack_off):
            findings.append(LeakFinding("MARKER_IN_BIG_SLACK",
                                        f"{entry.name}: previous-task marker in big-sector slack", off))
        if slack.strip(b"\x00"):
            findings.append(LeakFinding("NONZERO_BIG_SLACK",
                                        f"{entry.name}: {len(slack.strip(b'\\x00'))} non-zero slack byte(s)",
                                        slack_off))
    return findings


def _check_mini_stream_slack(ole, minifat, blob, marker):
    findings = []
    # Root mini stream location (big sectors) -> contiguous mini sector space.
    root_chain = _walk(list(ole.fat), ole.root.isectStart) if ole.root.size else []
    mini_base_sect = root_chain[0] if root_chain else None
    for entry in ole.direntries:
        if entry is None or entry.entry_type != olefile.STGTY_STREAM or not entry.is_minifat:
            continue
        if entry.size == 0 or mini_base_sect is None:
            continue
        chain = _walk(minifat, entry.isectStart)
        if not chain:
            continue
        last_mini = chain[-1]
        used = entry.size % MINI_SECTOR_SIZE
        if used == 0:
            continue
        # mini sector 'last_mini' sits inside root mini stream.
        mini_stream_off = HEADER_SIZE + mini_base_sect * SECTOR_SIZE
        off = mini_stream_off + last_mini * MINI_SECTOR_SIZE + used
        slack = blob[off: off + (MINI_SECTOR_SIZE - used)]
        for hit in _marker_hits(slack, marker, off):
            findings.append(LeakFinding("MARKER_IN_MINI_SLACK",
                                        f"{entry.name}: previous-task marker in mini-sector slack", hit))
        if slack.strip(b"\x00"):
            findings.append(LeakFinding("NONZERO_MINI_SLACK",
                                        f"{entry.name}: non-zero mini-sector slack", off))
    return findings


def _check_free_big_sectors(ole, fat, blob, marker):
    findings = []
    metadata = set(_collect_fat_sectors(blob, ole)) | set(_collect_difat_sectors(ole))
    metadata |= set(_chain_sectors(fat, ole.first_dir_sector))
    metadata |= set(_chain_sectors(fat, ole.minifatsect))
    # Root mini stream big sectors are also owned.
    if ole.root.size:
        metadata |= set(_walk(fat, ole.root.isectStart))
    for entry in ole.direntries:
        if entry is None or entry.entry_type != olefile.STGTY_STREAM or entry.is_minifat:
            continue
        if entry.size:
            metadata |= set(_walk(fat, entry.isectStart))

    for sect in range(ole.nb_sect):
        if sect in metadata:
            continue
        off = _big_sector_offset(sect)
        region = blob[off: off + SECTOR_SIZE]
        for hit in _marker_hits(region, marker, off):
            findings.append(LeakFinding("MARKER_IN_FREE_SECTOR",
                                        f"free big sector {sect} contains previous-task marker", hit))
        if region.strip(b"\x00"):
            findings.append(LeakFinding("NONZERO_FREE_SECTOR",
                                        f"free big sector {sect} not zero-initialised", off))
    return findings


def _check_free_mini_sectors(ole, minifat, blob, marker):
    findings = []
    if not ole.root.size:
        return findings
    root_chain = _walk(list(ole.fat), ole.root.isectStart)
    if not root_chain:
        return findings
    mini_stream_off = HEADER_SIZE + root_chain[0] * SECTOR_SIZE
    total_mini = (ole.root.size + MINI_SECTOR_SIZE - 1) // MINI_SECTOR_SIZE
    owned = set()
    for entry in ole.direntries:
        if entry is None or entry.entry_type != olefile.STGTY_STREAM or not entry.is_minifat:
            continue
        if entry.size:
            owned |= set(_walk(minifat, entry.isectStart))
    for ms in range(total_mini):
        if ms in owned:
            continue
        off = mini_stream_off + ms * MINI_SECTOR_SIZE
        region = blob[off: off + MINI_SECTOR_SIZE]
        for hit in _marker_hits(region, marker, off):
            findings.append(LeakFinding("MARKER_IN_FREE_MINI",
                                        f"free mini sector {ms} contains previous-task marker", hit))
        if region.strip(b"\x00"):
            findings.append(LeakFinding("NONZERO_FREE_MINI",
                                        f"free mini sector {ms} not zero-initialised", off))
    return findings
