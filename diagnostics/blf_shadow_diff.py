#!/usr/bin/env python3
"""Offline comparison diagnostic for the two metadata copies inside a CLFS BLF.

A Base Log File (``.blf``) keeps each metadata block twice: a "current" slot
(even block type) and a "shadow" slot (odd block type).  CLFS alternates writes
between these two slots so that a torn write can be recovered at mount time.
The two copies are therefore *two historical metadata states*, not two halves
of one state, and their stream/container lists must never be unioned into a
single "real" state.

This tool uses ``dissect.clfs`` only to *parse* the on-disk structures.  It
keeps the current and shadow views separate, preserves every raw field value
together with its source block, classifies every compared item into three
top-level buckets (consistent / contradictory / undecidable) with an explicit
``divergent`` sub-label for fields (e.g. LSNs, DumpCount) that are expected to
differ between two transaction snapshots and therefore are not integrity
contradictions, and refuses to infer:

  * wall-clock ordering from LSN magnitude (an LSN is a logical position,
    ``ContainerId:RecordIndex`` -- not a timestamp), or
  * that an entry appearing only in the shadow view is a deleted object
    (the shadow is a previous transaction image, not a tombstone list).

Output: a structured report (``--json`` for machine readable, plain text by
default).  Nothing here mutates the input file.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
from typing import Any, BinaryIO

from dissect.clfs.blf import BaseRecord, BLF, ControlRecord
from dissect.clfs.c_clfs import CLFS_CONTROL_RECORD_MAGIC_VALUE, BlockHeader, c_clfs
from dissect.clfs.exceptions import Error as ClfsError

# Each metadata block type paired with its shadow counterpart.
PAIRS: dict[str, tuple[int, int]] = {
    "control": (
        int(c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockControl),
        int(c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockControlShadow),
    ),
    "general": (
        int(c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockGeneral),
        int(c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockGeneralShadow),
    ),
    "scratch": (
        int(c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockScratch),
        int(c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockScratchShadow),
    ),
}

LSN_FIELDS = ("lsn_archive_tail", "lsn_base", "lsn_last", "lsn_flush", "lsn_physical_base")
# archive tail uses CLFS LSN_INVALID (container id 0xFFFFFFFF, record index 0).
LSN_INVALID_PHYS = 0xFFFFFFFF00000000


# --------------------------------------------------------------------------- #
# data model
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class ParseOutcome:
    """Result of attempting to parse one metadata block."""

    slot: str  # "current" | "shadow"
    block_type: int
    descriptor: dict[str, Any] | None
    status: str  # "parsed" | "zero_block" | "unparseable" | "missing"
    detail: str = ""
    header: dict[str, Any] | None = None
    control: dict[str, Any] | None = None
    base_header: dict[str, Any] | None = None
    streams: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    containers: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    truncate: dict[str, Any] | None = None


def lsn_dict(lsn: Any) -> dict[str, Any]:
    """Preserve the raw LSN value plus its decomposed ContainerId/RecordIndex."""
    return {
        "physical_offset": int(lsn.PhysicalOffset),
        "container_id": int(lsn.Offset.ContainerId),
        "record_index": int(lsn.Offset.RecordIndex),
        "is_clfs_invalid": int(lsn.PhysicalOffset) == LSN_INVALID_PHYS,
    }


def stream_dict(stream: Any) -> dict[str, Any]:
    out = {
        "name": stream.name,
        "id": int(stream.id),
        "file_attributes": str(stream.file_attributes),
        "file_attributes_raw": int(stream.file_attributes),
        "source_block_type": int(stream.type),
        "container_start_offset": int(stream.offset),
    }
    for field_name in LSN_FIELDS:
        out[field_name] = lsn_dict(getattr(stream, field_name))
    return out


def container_dict(container: Any) -> dict[str, Any]:
    return {
        "name": container.name,
        "id": int(container.id),
        "size": int(container.size),
        "source_block_type": int(container.type),
    }


def header_dict(bh: BlockHeader) -> dict[str, Any]:
    return {
        "file_offset": int(bh.offset),
        "major_version": int(bh.header.MajorVersion),
        "minor_version": int(bh.header.MinorVersion),
        "fixup": int(bh.header.Fixup),
        "client_id": int(bh.header.ClientId),
        "total_sectors": int(bh.header.TotalSectors),
        "valid_sectors": int(bh.header.ValidSectors),
        "checksum_raw": f"0x{int(bh.header.Checksum):08x}",
        "flags": str(bh.header.Flags),
        "record_offsets": [int(x) for x in bh.header.RecordOffsets],
        "fixup_offset": int(bh.header.FixupOffset),
        # dissect.clfs does not verify this checksum; kept as evidence only.
        "checksum_verified": False,
    }


def descriptor_dict(mb: Any) -> dict[str, Any]:
    return {
        "type": int(mb.Type),
        "type_name": str(mb.Type),
        "offset": int(mb.Offset),
        "image_size": int(mb.ImageSize),
        "image": int(mb.Image),
    }


# --------------------------------------------------------------------------- #
# parsing, fully tolerant of one-sided damage
# --------------------------------------------------------------------------- #
def _read_header(fh: BinaryIO, offset: int, size: int) -> tuple[BlockHeader | None, ParseOutcome]:
    fh.seek(0, 2)
    file_size = fh.tell()
    if offset >= file_size:
        return None, ParseOutcome(
            slot="", block_type=-1, descriptor=None, status="missing",
            detail=f"descriptor offset {offset} is at/beyond EOF ({file_size}); block truncated away",
        )
    try:
        bh = BlockHeader(fh=fh, offset=offset)
    except (EOFError, ValueError, AttributeError) as exc:
        return None, ParseOutcome(
            slot="", block_type=-1, descriptor=None, status="unparseable",
            detail=f"block header at offset {offset} cannot be decoded: {type(exc).__name__}: {exc}",
        )
    if bh.header.TotalSectors == 0:
        return bh, ParseOutcome(
            slot="", block_type=-1, descriptor=None, status="zero_block",
            detail=f"block header at offset {offset} is all-zero/uninitialized (no metadata transaction stored here)",
        )
    return bh, ParseOutcome(
        slot="", block_type=-1, descriptor=None, status="parsed",
        detail="", header=header_dict(bh),
    )


def parse_block(fh: BinaryIO, mb: Any, slot: str, kind: str, file_size: int) -> ParseOutcome:
    btype = int(mb.Type)
    desc = descriptor_dict(mb)
    truncated = mb.Offset >= file_size

    if truncated:
        return ParseOutcome(
            slot=slot, block_type=btype, descriptor=desc, status="missing",
            detail=(f"descriptor points to offset {mb.Offset} image_size {mb.ImageSize} "
                    f"but file is only {file_size} bytes; block is truncated away"),
        )

    bh, outcome = _read_header(fh, int(mb.Offset), int(mb.ImageSize))
    outcome.slot = slot
    outcome.block_type = btype
    outcome.descriptor = desc
    if outcome.status != "parsed":
        return outcome

    try:
        if kind == "control":
            cr = ControlRecord(fh=fh, offset=int(mb.Offset))
            rec = cr.record
            outcome.control = {
                "magic": f"0x{int(rec.Magic):016x}",
                "magic_expected": f"0x{CLFS_CONTROL_RECORD_MAGIC_VALUE:016x}",
                "magic_valid": bool(cr.valid),
                "dump_count": int(rec.RecordHeader.DumpCount),
                "version": int(rec.Version),
                "extend_state": str(rec.ExtendState),
                "extend_block": int(rec.ExtendBlock),
                "flush_block": int(rec.FlushBlock),
                "blocks": int(rec.Blocks),
                "rg_blocks": [descriptor_dict(x) for x in rec.RgBlocks],
            }
        elif kind == "general":
            br = BaseRecord(fh=fh, offset=int(mb.Offset), block_type=btype)
            h = br.record
            outcome.base_header = {
                "dump_count": int(h.RecordHeader.DumpCount),
                "id_log": bytes(h.IdLog).hex(),
                "next_client": int(h.NextClient),
                "next_container": int(h.NextContainer),
                "free_containers": int(h.FreeContainers),
                "active_containers": int(h.ActiveContainers),
                "free_containers_count": int(h.FreeContainersCount),
                "busy_containers": int(h.BusyContainers),
                "symbol_zone": int(h.SymbolZone),
                "sector": int(h.Sector),
                "usn": int(h.Usn),
                "clients": int(h.Clients),
                "client_symbol_table": [int(x) for x in h.ClientSymbolTable],
                "container_symbol_table": [int(x) for x in h.ContainerSymbolTable],
                "security_symbol_table": [int(x) for x in h.SecuritySymbolTable],
            }
            outcome.streams = [stream_dict(s) for s in br.streams]
            outcome.containers = [container_dict(c) for c in br.containers]
        else:  # scratch / truncate
            from dissect.clfs.blf import TruncateRecord

            tr = TruncateRecord(fh=fh, offset=int(mb.Offset))
            outcome.truncate = {
                "dump_count": int(tr.record.RecordHeader.DumpCount),
                "client_change_offset": int(tr.record.ClientChangeOffset),
                "owner_page_offset": int(tr.record.OwnerPageOffset),
            }
    except (ClfsError, EOFError, ValueError, AttributeError) as exc:
        outcome.status = "unparseable"
        outcome.detail = f"header decoded but payload failed: {type(exc).__name__}: {exc}"
    return outcome


def analyze(path: str) -> dict[str, Any]:
    with open(path, "rb") as fh:
        file_size = fh.seek(0, 2)
        fh.seek(0)
        try:
            blf = BLF(fh)
        except ClfsError as exc:
            return {
                "file": path,
                "file_size": file_size,
                "fatal": f"primary control record invalid, BLF cannot be opened: {type(exc).__name__}: {exc}",
                "pairs": {},
                "findings": [],
                "limitations": ["No metadata descriptor table available; nothing further can be compared."],
                "readable_container_evidence": None,
            }

        primary = blf.c_record.record
        report: dict[str, Any] = {
            "file": path,
            "file_size": file_size,
            "primary_control": {
                "source_offset": 0,
                "magic": f"0x{int(primary.Magic):016x}",
                "magic_valid": int(primary.Magic) == CLFS_CONTROL_RECORD_MAGIC_VALUE,
                "dump_count": int(primary.RecordHeader.DumpCount),
                "blocks_declared": int(primary.Blocks),
                "rg_blocks": [descriptor_dict(x) for x in blf.metablocks],
            },
            "pairs": {},
            "findings": [],
            "limitations": [],
            "readable_container_evidence": None,
        }

        descriptors = {int(mb.Type): mb for mb in blf.metablocks}
        for kind, (cur_type, shd_type) in PAIRS.items():
            slots = {}
            for slot, btype in (("current", cur_type), ("shadow", shd_type)):
                mb = descriptors.get(btype)
                if mb is None:
                    slots[slot] = ParseOutcome(
                        slot=slot, block_type=btype, descriptor=None, status="missing",
                        detail="no descriptor for this block type in primary control record",
                    )
                else:
                    slots[slot] = parse_block(fh, mb, slot, kind, file_size)
            report["pairs"][kind] = {
                "current": dataclasses.asdict(slots["current"]),
                "shadow": dataclasses.asdict(slots["shadow"]),
            }

    report["findings"] = classify(report)
    report["limitations"] = collect_limitations(report)
    report["readable_container_evidence"] = container_evidence(report)
    return report


# --------------------------------------------------------------------------- #
# classification
# --------------------------------------------------------------------------- #
def finding(category: str, item: str, detail: str, sources: dict[str, Any],
            note: str | None = None) -> dict[str, Any]:
    """One compared item.

    ``category`` is one of the three reportable buckets.  ``note`` is an
    optional sub-label (currently "divergent") used to mark fields that
    legitimately differ between two snapshots without contradicting identity.
    """
    return {
        "classification": category,
        "note": note,
        "item": item,
        "detail": detail,
        "sources": sources,
    }


def _both_parsed(pair: dict[str, Any]) -> bool:
    return pair["current"]["status"] == "parsed" and pair["shadow"]["status"] == "parsed"


def classify(report: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    src = lambda c, s: {"current": c, "shadow": s}

    # ---- control pair: descriptor table + control record fields ----
    ctrl = report["pairs"]["control"]
    c, s = ctrl["current"], ctrl["shadow"]
    if c["status"] == "parsed":
        out.append(finding(
            "consistent", "primary control block readable",
            f"control block at {c['descriptor']['offset']} has valid magic and "
            f"declares {c['control']['blocks']} metadata descriptors",
            src(c["descriptor"]["offset"], None),
        ))
    if s["status"] == "zero_block":
        out.append(finding(
            "undecidable", "shadow control slot uninitialized",
            "shadow control slot is an all-zero block: no previous control transaction was "
            "persisted there (or it was never used). This is not evidence of corruption and "
            "gives no second control view to compare.",
            src(c["descriptor"]["offset"] if c["status"] == "parsed" else None, s["descriptor"]["offset"]),
        ))
    elif s["status"] in ("unparseable", "missing"):
        out.append(finding(
            "undecidable", "shadow control slot unavailable",
            f"shadow control cannot be read ({s['status']}): {s['detail']}. "
            "Descriptor-table cross-check against a second control copy is not possible.",
            src(None, s["descriptor"]["offset"] if s["descriptor"] else None),
        ))
    elif s["status"] == "parsed":
        if c["control"]["rg_blocks"] == s["control"]["rg_blocks"]:
            out.append(finding(
                "consistent", "control descriptor tables",
                "current and shadow control records name the same block offsets/sizes/types",
                src(c["descriptor"]["offset"], s["descriptor"]["offset"]),
            ))
        else:
            out.append(finding(
                "contradictory", "control descriptor tables",
                "current and shadow control records point at different block offsets/sizes/types; "
                "each view must be followed using its own table",
                src(c["control"]["rg_blocks"], s["control"]["rg_blocks"]),
            ))
        for field in ("dump_count", "extend_state", "extend_block", "flush_block", "blocks"):
            cv, sv = c["control"][field], s["control"][field]
            if cv == sv:
                out.append(finding(
                    "consistent", f"control field {field}",
                    f"current={cv!r} shadow={sv!r}",
                    src(cv, sv),
                ))
            elif field == "dump_count":
                out.append(finding(
                    "undecidable", f"control field {field}",
                    f"current={cv!r} shadow={sv!r}: distinct metadata transaction counters prove the two "
                    "control images were written by different transactions, but DumpCount is a write "
                    "counter, not a clock; it cannot establish wall-clock recency.",
                    src(cv, sv), note="divergent",
                ))
            else:
                out.append(finding(
                    "contradictory", f"control field {field}",
                    f"current={cv!r} shadow={sv!r}",
                    src(cv, sv),
                ))

    # ---- general pair: identity + LSNs ----
    gen = report["pairs"]["general"]
    c, s = gen["current"], gen["shadow"]
    _classify_general(c, s, out)

    # ---- scratch / truncate pair ----
    scr = report["pairs"]["scratch"]
    c, s = scr["current"], scr["shadow"]
    for slot, blk in (("current", c), ("shadow", s)):
        if blk["status"] == "parsed":
            t = blk["truncate"]
            if t["client_change_offset"] == 0 and t["owner_page_offset"] == 0:
                out.append(finding(
                    "consistent", f"scratch ({slot}) present, no truncate change",
                    "scratch block parsed; ClientChangeOffset=0 and OwnerPageOffset=0 indicate "
                    "no staged truncate client/owner change in this copy",
                    src(blk["descriptor"]["offset"], None) if slot == "current" else src(None, blk["descriptor"]["offset"]),
                ))
            else:
                out.append(finding(
                    "undecidable", f"scratch ({slot}) carries truncate staging data",
                    f"truncate staging offsets present: {t}; full sector-change reconstruction "
                    "is out of scope; cannot determine from BLF alone whether truncation completed",
                    src(blk["descriptor"]["offset"], None),
                ))
        elif blk["status"] == "zero_block":
            out.append(finding(
                "undecidable", f"scratch ({slot}) uninitialized",
                "all-zero scratch block: no truncate information stored; cannot confirm or deny truncation",
                src(None, blk["descriptor"]["offset"]),
            ))
        else:
            out.append(finding(
                "undecidable", f"scratch ({slot}) unavailable",
                f"{blk['status']}: {blk['detail']}",
                src(None, blk["descriptor"]["offset"] if blk["descriptor"] else None),
            ))
    return out


def _classify_general(c: dict[str, Any], s: dict[str, Any], out: list[dict[str, Any]]) -> None:
    src = lambda cv, sv: {"current": cv, "shadow": sv}
    if c["status"] != "parsed" or s["status"] != "parsed":
        for slot, blk in (("current", c), ("shadow", s)):
            if blk["status"] == "parsed":
                out.append(finding(
                    "undecidable", f"general block only one side readable ({slot})",
                    f"the {slot} general block parsed; the other side is {({'current':s,'shadow':c}[slot])['status']}. "
                    "Single-view metadata can still establish container identity, but no cross-copy "
                    "comparison is possible and the missing side cannot be assumed equal or deleted.",
                    src(blk["descriptor"]["offset"], None),
                ))
            else:
                out.append(finding(
                    "undecidable", f"general block {slot} unreadable",
                    f"{blk['status']}: {blk['detail']}",
                    src(None, blk["descriptor"]["offset"] if blk["descriptor"] else None),
                ))
        return

    ch, sh = c["base_header"], s["base_header"]
    # block identity
    if ch["id_log"] == sh["id_log"]:
        out.append(finding("consistent", "log identity IdLog",
                           f"both general blocks carry IdLog {ch['id_log']} (same physical log)",
                           src(ch["id_log"], sh["id_log"])))
    else:
        out.append(finding("contradictory", "log identity IdLog",
                           "different IdLog values; the two blocks do not describe the same log",
                           src(ch["id_log"], sh["id_log"])))
    if ch["dump_count"] != sh["dump_count"]:
        out.append(finding(
            "undecidable", "metadata transaction counter (DumpCount)",
            f"DumpCount current={ch['dump_count']} vs shadow={sh['dump_count']}: unequal counters prove the "
            "two blocks belong to different metadata transactions (double-buffer alternation), but they do "
            "not by themselves identify which slot is the committed 'latest' state, nor carry any wall-clock "
            "time. Treat as divergent snapshots, not as an ordering signal.",
            src(ch["dump_count"], sh["dump_count"]), note="divergent",
        ))
    else:
        out.append(finding(
            "consistent", "metadata transaction counter (DumpCount)",
            f"both views DumpCount={ch['dump_count']}",
            src(ch["dump_count"], sh["dump_count"]),
        ))

    # container identity, keyed by id (never unioned)
    c_cont = {x["id"]: x for x in c["containers"]}
    s_cont = {x["id"]: x for x in s["containers"]}
    for cid in sorted(set(c_cont) | set(s_cont)):
        cc, sc = c_cont.get(cid), s_cont.get(cid)
        if cc and sc:
            same = cc["name"] == sc["name"] and cc["size"] == sc["size"]
            out.append(finding(
                "consistent" if same else "contradictory",
                f"container id {cid} identity",
                f"current name/size={cc['name']}/{cc['size']}; shadow name/size={sc['name']}/{sc['size']}",
                src(cc, sc),
            ))
        else:
            present = cc or sc
            out.append(finding(
                "undecidable", f"container id {cid} only in one view",
                f"container present only in the {'current' if cc else 'shadow'} view "
                f"({present['name']}). The other view is a different transaction image; this does NOT "
                "prove the container was created or deleted -- it only shows the two snapshots differ.",
                src(cc, sc),
            ))

    # streams + LSNs, keyed by stream id
    c_strm = {x["id"]: x for x in c["streams"]}
    s_strm = {x["id"]: x for x in s["streams"]}
    for sid in sorted(set(c_strm) | set(s_strm)):
        cc, sc = c_strm.get(sid), s_strm.get(sid)
        if cc is None or sc is None:
            out.append(finding(
                "undecidable", f"stream id {sid} only in one view",
                "a stream appears in only one metadata image; this is a snapshot difference, not a "
                "deletion tombstone -- do not treat the shadow-only/current-only entry as a deleted object",
                src(cc, sc),
            ))
            continue
        for field in ("name", "id", "file_attributes_raw", "container_start_offset"):
            cv, sv = cc[field], sc[field]
            out.append(finding(
                "consistent" if cv == sv else "contradictory",
                f"stream {sid} {field}",
                f"current={cv!r} shadow={sv!r}",
                src(cv, sv),
            ))
        for lsn_field in LSN_FIELDS:
            cl, sl = cc[lsn_field], sc[lsn_field]
            cv, sv = cl["physical_offset"], sl["physical_offset"]
            if cv == sv:
                out.append(finding(
                    "consistent", f"stream {sid} {lsn_field}",
                    f"both views 0x{cv:016x} (container {cl['container_id']} record {cl['record_index']}"
                    + (", CLFS invalid LSN" if cl["is_clfs_invalid"] else "") + ")",
                    src(cl, sl),
                ))
            else:
                out.append(finding(
                    "contradictory", f"stream {sid} {lsn_field}",
                    f"current 0x{cv:016x} (c={cl['container_id']} r={cl['record_index']}) vs "
                    f"shadow 0x{sv:016x} (c={sl['container_id']} r={sl['record_index']}). The two transaction "
                    "images record different logical positions -- an expected snapshot divergence, not proof "
                    "of on-disk corruption. An LSN encodes ContainerId:RecordIndex only; do NOT infer that the "
                    "larger numeric LSN was written later in wall-clock time, and do not merge the two values.",
                    src(cl, sl), note="divergent",
                ))

    # base-header bookkeeping fields
    for field in ("next_client", "next_container", "free_containers", "active_containers",
                  "free_containers_count", "busy_containers", "usn", "clients"):
        cv, sv = ch[field], sh[field]
        out.append(finding(
            "consistent" if cv == sv else "contradictory",
            f"base header {field}", f"current={cv!r} shadow={sv!r}", src(cv, sv),
        ))


# --------------------------------------------------------------------------- #
# limitations + minimum evidence for a readable container set
# --------------------------------------------------------------------------- #
def collect_limitations(report: dict[str, Any]) -> list[str]:
    lim = [
        "dissect.clfs parses block checksums but never verifies them; checksum_raw is evidence only "
        "and cannot authenticate a block's integrity here.",
        "No wall-clock timestamp is stored in the parsed control/base/scratch structures. Nothing in "
        "this report orders events by time; LSN magnitude is explicitly not used as a clock.",
        "Shadow blocks are previous metadata transaction images, not deletion records: a shadow-only "
        "entry is never labelled a deleted object.",
    ]
    for kind, pair in report["pairs"].items():
        for slot in ("current", "shadow"):
            blk = pair[slot]
            if blk["status"] in ("unparseable", "missing", "zero_block"):
                lim.append(
                    f"{kind} {slot}: {blk['status']} at descriptor offset "
                    f"{blk['descriptor']['offset'] if blk['descriptor'] else 'n/a'} -> {blk['detail']}"
                )
    gen = report["pairs"]["general"]
    bad = [slot for slot in ("current", "shadow") if gen[slot]["status"] != "parsed"]
    if bad:
        lim.append(
            "general block(s) not readable on: " + ", ".join(bad) + ". Cross-copy agreement cannot be "
            "evaluated; conclusions rely on the single readable view and are marked undecidable where "
            "the second view would be needed."
        )
    return lim


def container_evidence(report: dict[str, Any]) -> dict[str, Any]:
    """Minimum evidence conditions, evaluated against what is actually readable."""
    gen = report["pairs"]["general"]
    conditions = []
    readable_views = []
    for slot in ("current", "shadow"):
        blk = gen[slot]
        ok = (
            blk["status"] == "parsed"
            and len(blk["streams"]) >= 1
            and len(blk["containers"]) >= 1
            and all(c["name"] and c["size"] > 0 for c in blk["containers"])
        )
        conditions.append({
            "view": slot,
            "general_block_parsed": blk["status"] == "parsed",
            "has_at_least_one_stream": len(blk["streams"]) >= 1,
            "has_at_least_one_container_context": len(blk["containers"]) >= 1,
            "container_contexts_well_formed": (
                all(c["name"] and c["size"] > 0 for c in blk["containers"])
                if blk["containers"] else False
            ),
            "satisfies_metadata_minimum": bool(ok),
        })
        if ok:
            readable_views.append(slot)

    min_explanation = (
        "Minimum BLF-metadata evidence for a readable container set: (1) the primary control record's "
        "magic is valid and its descriptor table locates a general block whose (2) log-block header and "
        "base record parse, (3) client symbol table yields >=1 stream, and (4) container symbol table "
        "yields >=1 container context each with a non-empty name, positive size and an id that can be "
        "matched to a stream. One readable general-block view is sufficient metadata evidence; a second "
        "readable view only corroborates it. To actually read log records, each named .regtrans-ms "
        "container must additionally exist on disk, be readable, and its first log-block header must "
        "parse at the stream's container start offset; archive-tail LSN validity is NOT required."
    )
    return {
        "minimum_conditions": min_explanation,
        "per_view": conditions,
        "metadata_evidence_established": bool(readable_views),
        "established_from_views": readable_views,
        "second_view_corroboration_available": len(readable_views) == 2,
    }


# --------------------------------------------------------------------------- #
# text rendering
# --------------------------------------------------------------------------- #
def render_text(report: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("=" * 78)
    lines.append(f"BLF CURRENT vs SHADOW OFFLINE COMPARISON  -  {report['file']}")
    lines.append("=" * 78)
    if report.get("fatal"):
        lines.append("FATAL: " + report["fatal"])
        return "\n".join(lines)
    pc = report["primary_control"]
    lines.append(f"file size={report['file_size']}  primary magic valid={pc['magic_valid']} "
                 f"dump={pc['dump_count']} descriptors={pc['blocks_declared']}")
    lines.append("")
    for kind, pair in report["pairs"].items():
        lines.append(f"### {kind.upper()} PAIR")
        for slot in ("current", "shadow"):
            blk = pair[slot]
            d = blk["descriptor"]
            head = f"  [{slot:7s}] type={blk['block_type']} status={blk['status']:11s} " \
                   f"offset={d['offset'] if d else 'n/a'} size={d['image_size'] if d else 'n/a'}"
            lines.append(head)
            if blk["detail"]:
                lines.append(f"             detail: {blk['detail']}")
            if blk["control"]:
                cr = blk["control"]
                lines.append(f"             control: magic_valid={cr['magic_valid']} dump={cr['dump_count']} "
                             f"extend={cr['extend_state']} flush_block={cr['flush_block']} blocks={cr['blocks']}")
            if blk["base_header"]:
                bh = blk["base_header"]
                lines.append(f"             base: dump={bh['dump_count']} IdLog={bh['id_log']} "
                             f"active={bh['active_containers']} clients={bh['clients']} usn={bh['usn']}")
            for st in blk["streams"]:
                lines.append(f"             stream id={st['id']} name={st['name']}")
                for lf in LSN_FIELDS:
                    v = st[lf]
                    lines.append(f"                 {lf:18s} phys=0x{v['physical_offset']:016x} "
                                 f"(container={v['container_id']} record={v['record_index']}"
                                 f"{' INVALID' if v['is_clfs_invalid'] else ''})")
            for cn in blk["containers"]:
                lines.append(f"             container id={cn['id']} size={cn['size']} name={cn['name']}")
            if blk["truncate"]:
                lines.append(f"             truncate: {blk['truncate']}")
        lines.append("")

    order = {"consistent": 0, "contradictory": 1, "undecidable": 2}
    lines.append("### FINDINGS  (note 'divergent' = expected snapshot difference, not corruption)")
    for f in sorted(report["findings"], key=lambda x: order[x["classification"]]):
        label = f["classification"]
        if f.get("note"):
            label = f"{label}/{f['note']}"
        lines.append(f"  [{label:21s}] {f['item']}: {f['detail']}")
    lines.append("")
    lines.append("### LIMITATIONS / UNDECIDABLE GROUNDS")
    for lim in report["limitations"]:
        lines.append(f"  - {lim}")
    lines.append("")
    ev = report["readable_container_evidence"]
    lines.append("### READABLE CONTAINER SET - MINIMUM EVIDENCE")
    lines.append("  " + ev["minimum_conditions"])
    for v in ev["per_view"]:
        lines.append(f"  view={v['view']:7s} metadata_minimum_met={v['satisfies_metadata_minimum']} "
                     f"(parsed={v['general_block_parsed']} stream={v['has_at_least_one_stream']} "
                     f"container_ctx={v['has_at_least_one_container_context']} "
                     f"well_formed={v['container_contexts_well_formed']})")
    lines.append(f"  metadata evidence established: {ev['metadata_evidence_established']} "
                 f"from views {ev['established_from_views']}; "
                 f"two-view corroboration: {ev['second_view_corroboration_available']}")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("blf", help="path to a CLFS .blf file (read-only)")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()
    report = analyze(args.blf)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(render_text(report))


if __name__ == "__main__":
    main()
