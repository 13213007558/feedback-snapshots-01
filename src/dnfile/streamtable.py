# -*- coding: utf-8 -*-
"""
.NET metadata stream table bookkeeping.

The CLR metadata root contains a small table of stream headers.  Each header
names a stream and declares an offset and size relative to the metadata root.
Two headers may disagree with each other, alias the same bytes, escape the
metadata directory, or simply be unreadable.  Historically dnfile silently
kept the last stream seen for a name and never checked the declared ranges, so
which bytes were treated as the #Strings, #Blob, or table stream depended on
iteration order.

This module keeps the facts needed to avoid that ambiguity: the header order,
the header location, the declared range, the range that was actually read, and
what evidence the bytes can support.

The policy is chosen on :class:`dnfile.dnPE`:

``StreamPolicy.FORENSIC`` (the default)
    Preserve every decoded stream header in header order.  Conflicting entries
    remain available as raw candidate bytes, but only a structurally valid
    entry is used for a name shortcut or for parsing.  Warnings describe every
    conflict.

``StreamPolicy.STRICT``
    Reject the metadata stream table as a whole if any header is unreadable,
    duplicated, overlapping, truncated, or leaves the metadata directory.
    The metadata object is not exposed, and the reason is reported as a
    warning.
"""

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from . import base


class StreamPolicy(str, enum.Enum):
    """How to treat conflicting metadata stream declarations."""

    FORENSIC = "forensic"
    STRICT = "strict"


class StreamStatus(str, enum.Enum):
    """Issues attached to a stream header."""

    HEADER_INVALID = "header_invalid"
    DUPLICATE_NAME = "duplicate_name"
    OVERLAP_EXACT = "overlap_exact"
    OVERLAP_PARTIAL = "overlap_partial"
    ZERO_LENGTH = "zero_length"
    OUTSIDE_METADATA = "outside_metadata"
    TRUNCATED = "truncated"
    RECOVERED = "recovered"
    PARSE_ERROR = "parse_error"
    MULTIPLE_TABLE_STREAMS = "multiple_table_streams"
    HEAP_EVIDENCE_INCOMPLETE = "heap_evidence_incomplete"


# These statuses mean dnfile cannot establish that the declared bytes belong
# to this stream alone.  They are fatal under the strict policy and make the
# stream candidate-only under the forensic policy.
HARD_STATUSES = frozenset(
    (
        StreamStatus.HEADER_INVALID,
        StreamStatus.OVERLAP_EXACT,
        StreamStatus.OVERLAP_PARTIAL,
        StreamStatus.OUTSIDE_METADATA,
    )
)

# The strict policy additionally refuses to treat an incomplete table or an
# ambiguous name as a successful parse.
STRICT_STATUSES = HARD_STATUSES | frozenset(
    (
        StreamStatus.DUPLICATE_NAME,
        StreamStatus.ZERO_LENGTH,
        StreamStatus.TRUNCATED,
        StreamStatus.RECOVERED,
        StreamStatus.PARSE_ERROR,
        StreamStatus.MULTIPLE_TABLE_STREAMS,
    )
)

# These statuses mean the header describes bytes that could not be fully or
# reliably read, so the bytes may be inspected but not confirmed.
UNCONFIRMED_STATUSES = frozenset(
    (
        StreamStatus.DUPLICATE_NAME,
        StreamStatus.TRUNCATED,
        StreamStatus.RECOVERED,
        StreamStatus.PARSE_ERROR,
        StreamStatus.ZERO_LENGTH,
        StreamStatus.MULTIPLE_TABLE_STREAMS,
        StreamStatus.HEAP_EVIDENCE_INCOMPLETE,
    )
)


def normalize_policy(policy) -> StreamPolicy:
    """Accept a StreamPolicy, its string value, or None."""

    if policy is None:
        return StreamPolicy.FORENSIC
    if isinstance(policy, StreamPolicy):
        return policy
    try:
        return StreamPolicy(str(policy).lower())
    except ValueError:
        raise ValueError(
            "unknown stream policy {!r}, expected one of {}".format(
                policy, ", ".join(p.value for p in StreamPolicy)
            )
        )


def _hex_range(start: Optional[int], end: Optional[int]) -> str:
    if start is None or end is None:
        return "<unknown>"
    return "[0x{:x}, 0x{:x})".format(start, end)


KNOWN_STREAM_NAMES = (b"#~", b"#-", b"#Schema", b"#Strings", b"#US", b"#GUID", b"#Blob")


def find_recovered_header(
    metadata_data: bytes,
    metadata_rva: int,
    candidate_rva: int,
    metadata_end_rva: int,
) -> Optional[int]:
    """Scan four-byte steps for a plausible stream header after a bad one.

    Recovery is intentionally conservative: the name must be a known CLR
    stream name and the declared data range must fit inside the metadata
    directory.  Even then, the recovered entry is only a candidate; the strict
    policy rejects the table outright.
    """

    probe = candidate_rva
    limit = min(metadata_end_rva, metadata_rva + len(metadata_data))
    while probe + 12 <= limit:
        offset = probe - metadata_rva
        name_start = offset + 8
        end = metadata_data.find(b"\x00", name_start, limit - metadata_rva)
        if end < 0:
            probe += 4
            continue
        name = metadata_data[name_start:end]
        if name in KNOWN_STREAM_NAMES:
            declared_offset, declared_size = _read_u32_pair(metadata_data, offset)
            data_start = metadata_rva + declared_offset
            if declared_size > 0 and metadata_rva <= data_start <= limit and data_start + declared_size <= limit:
                return probe
        probe += 4
    return None


def _read_u32_pair(data: bytes, offset: int) -> Tuple[int, int]:
    return int.from_bytes(data[offset:offset + 4], "little"), int.from_bytes(data[offset + 4:offset + 8], "little")


@dataclass
class StreamTableEntry:
    """One entry from the CLR metadata stream table.

    ``index`` is the header-order position (zero based).  ``header_rva`` and
    ``header_offset`` are where the header itself was read.  ``offset`` and
    ``size`` are the values declared in the header, relative to the metadata
    root.  ``declared_rva``/``declared_end_rva`` are their absolute form.
    ``read_size`` is the number of bytes actually available and read from the
    file (bounded by the metadata directory and the file image).
    """

    index: int
    slot: int
    header_rva: int
    header_offset: Optional[int] = None
    header_size: int = 0
    name: Optional[bytes] = None
    offset: Optional[int] = None
    size: Optional[int] = None
    declared_rva: Optional[int] = None
    declared_end_rva: Optional[int] = None
    data_file_offset: Optional[int] = None
    read_size: int = 0
    read_end_rva: Optional[int] = None
    stream: Optional["base.ClrStream"] = None
    statuses: Set[StreamStatus] = field(default_factory=set)
    overlaps_with: List[int] = field(default_factory=list)
    # "selected", "shadowed", "candidate", or "unresolved"
    resolution: str = "unresolved"
    recovered_from: Optional[int] = None
    # Number of entries with this name whose headers are structurally usable.
    # A name shared with only broken headers is still ambiguous in the file,
    # but the selected entry's bytes are the only admissible interpretation.
    same_name_admissible: int = 1

    @property
    def declared_range(self) -> Tuple[Optional[int], Optional[int]]:
        return self.declared_rva, self.declared_end_rva

    @property
    def read_range(self) -> Tuple[Optional[int], Optional[int]]:
        return self.declared_rva, self.read_end_rva

    @property
    def is_empty(self) -> bool:
        return self.size == 0 or (self.size is None and self.read_size == 0)

    @property
    def has_hard_conflict(self) -> bool:
        return bool(self.statuses & HARD_STATUSES)

    @property
    def is_selected(self) -> bool:
        return self.resolution == "selected"

    @property
    def is_admissible(self) -> bool:
        """The header can be used as a stream of its own.

        A duplicate name or a short read does not make the declared range
        ambiguous, but it can still make the evidence incomplete.
        """

        return not self.has_hard_conflict and StreamStatus.HEADER_INVALID not in self.statuses

    @property
    def accepted(self) -> bool:
        """Selected and structurally usable (possibly truncated)."""

        return self.is_selected and self.is_admissible

    @property
    def unconfirmed_statuses(self) -> Set[StreamStatus]:
        statuses = set(self.statuses)
        if StreamStatus.DUPLICATE_NAME in statuses and self.same_name_admissible <= 1:
            # The other headers with this name are structurally broken; there
            # is exactly one admissible interpretation of the bytes.
            statuses.discard(StreamStatus.DUPLICATE_NAME)
        return statuses

    @property
    def is_confirmed(self) -> bool:
        """Selected, structurally usable, and fully readable."""

        return (
            self.is_selected
            and self.is_admissible
            and not (self.unconfirmed_statuses & UNCONFIRMED_STATUSES)
        )

    @property
    def evidence(self) -> str:
        """How the bytes may be cited: ``confirmed``, ``empty``, ``candidate``, ``rejected``."""

        if StreamStatus.HEADER_INVALID in self.statuses or self.stream is None:
            return "rejected"
        if self.resolution == "alias":
            return "candidate"
        if self.is_selected and self.is_admissible and self.is_empty:
            return "empty"
        if self.is_confirmed:
            return "confirmed"
        return "candidate"

    def status_values(self) -> List[str]:
        return sorted(s.value for s in self.statuses)

    def to_dict(self) -> Dict[str, object]:
        return {
            "index": self.index,
            "slot": self.slot,
            "header_rva": self.header_rva,
            "header_offset": self.header_offset,
            "header_size": self.header_size,
            "name": self.name.decode("latin-1") if self.name is not None else None,
            "offset": self.offset,
            "size": self.size,
            "declared_rva": self.declared_rva,
            "declared_end_rva": self.declared_end_rva,
            "data_file_offset": self.data_file_offset,
            "read_size": self.read_size,
            "read_end_rva": self.read_end_rva,
            "statuses": self.status_values(),
            "overlaps_with": list(self.overlaps_with),
            "resolution": self.resolution,
            "recovered_from": self.recovered_from,
            "same_name_admissible": self.same_name_admissible,
            "evidence": self.evidence,
        }


@dataclass
class StreamTableReport:
    """Result of interpreting the CLR stream table."""

    policy: StreamPolicy
    metadata_rva: int
    metadata_declared_size: int
    metadata_read_size: int
    expected_entries: int
    entries: List[StreamTableEntry] = field(default_factory=list)
    invalid_slots: List[int] = field(default_factory=list)
    table_truncated: bool = False
    rejected: bool = False
    rejection_reason: Optional[str] = None
    parse_errors: List[str] = field(default_factory=list)
    table_evidence: str = "missing"
    heap_evidence: Dict[str, str] = field(default_factory=dict)
    resource_evidence: str = "candidate"
    _warnings: List[str] = field(default_factory=list)
    _emitted: int = 0

    @property
    def metadata_end_rva(self) -> int:
        """End of the bytes that could actually be read from metadata."""

        return self.metadata_rva + self.metadata_read_size

    @property
    def metadata_declared_end_rva(self) -> int:
        return self.metadata_rva + self.metadata_declared_size

    @property
    def metadata_truncated(self) -> bool:
        return self.metadata_read_size < self.metadata_declared_size

    @property
    def issues(self) -> List[StreamTableEntry]:
        return [e for e in self.entries if e.statuses]

    @property
    def selected(self) -> List[StreamTableEntry]:
        return [e for e in self.entries if e.is_selected]

    @property
    def usable(self) -> List[StreamTableEntry]:
        """Selected entries that may be parsed or exposed through shortcuts."""

        return [e for e in self.entries if e.is_selected and e.is_admissible]

    def selected_streams(self) -> List["base.ClrStream"]:
        return [e.stream for e in self.usable if e.stream is not None]

    def selected_stream_map(self) -> Dict[bytes, "base.ClrStream"]:
        result: Dict[bytes, "base.ClrStream"] = {}
        for entry in self.selected:
            if entry.name is not None and entry.stream is not None:
                result[entry.name] = entry.stream
        return result

    @property
    def candidates(self) -> List[StreamTableEntry]:
        return [e for e in self.entries if e.evidence == "candidate"]

    @property
    def confirmed(self) -> List[StreamTableEntry]:
        return [e for e in self.entries if e.evidence == "confirmed"]

    @property
    def strict_violations(self) -> List[StreamTableEntry]:
        return [e for e in self.entries if e.statuses & STRICT_STATUSES]

    @property
    def has_issues(self) -> bool:
        return (
            bool(self.issues)
            or bool(self.invalid_slots)
            or self.table_truncated
            or self.metadata_truncated
        )

    @property
    def has_conflicts(self) -> bool:
        return (
            bool(self.invalid_slots)
            or bool(self.strict_violations)
            or self.table_truncated
            or self.metadata_truncated
        )

    @property
    def is_clean(self) -> bool:
        return not self.has_issues

    @property
    def is_complete(self) -> bool:
        """All declared entries were decoded and all bytes were readable."""

        return (
            not self.table_truncated
            and not self.metadata_truncated
            and not self.invalid_slots
            and len(self.entries) == self.expected_entries
            and all(e.stream is not None for e in self.entries)
            and all(e.is_confirmed for e in self.entries)
        )

    @property
    def evidence_incomplete(self) -> List[StreamTableEntry]:
        return [e for e in self.entries if e.evidence in ("candidate", "empty")]

    def entries_by_name(self, name: bytes) -> List[StreamTableEntry]:
        return [e for e in self.entries if e.name == name]

    def selected_entry(self, name: bytes) -> Optional[StreamTableEntry]:
        for entry in self.entries:
            if entry.name == name and entry.is_selected:
                return entry
        return None

    def table_stream_entry(self) -> Optional[StreamTableEntry]:
        entries = [
            e
            for e in self.entries
            if e.stream is not None and e.is_selected and _is_table_stream(e.stream)
        ]
        if not entries:
            return None
        confirmed = [e for e in entries if e.is_confirmed]
        return (confirmed or entries)[-1]

    def parseable_entries(self) -> List[StreamTableEntry]:
        """Selected entries that should be handed to stream.parse()."""

        return [
            e
            for e in self.entries
            if e.is_selected and e.is_admissible and not e.is_empty
        ]

    def legacy_name_winners(self) -> Dict[bytes, StreamTableEntry]:
        """The map the old implementation built: last header with a name wins.

        This deliberately ignores validity.  It is provided so callers (and
        the policy demo) can show why the old behavior was order dependent.
        """

        winners: Dict[bytes, StreamTableEntry] = {}
        for entry in self.entries:
            if entry.name is not None and entry.stream is not None:
                winners[entry.name] = entry
        return winners

    def strict_rejection_message(self) -> str:
        reasons: List[str] = []
        for rva in self.invalid_slots:
            reasons.append("unreadable stream header at rva 0x{:x}".format(rva))
        for entry in self.strict_violations:
            statuses = ", ".join(entry.status_values())
            reasons.append(
                "entry {} {!r} at header 0x{:x}: {}".format(
                    entry.index,
                    entry.name,
                    entry.header_offset if entry.header_offset is not None else entry.header_rva,
                    statuses,
                )
            )
        if self.table_truncated:
            reasons.append(
                "stream table ended after {} of {} declared entries".format(
                    len(self.entries), self.expected_entries
                )
            )
        if self.metadata_truncated:
            reasons.append(
                "metadata directory truncated: declared 0x{:x} bytes, read 0x{:x} bytes".format(
                    self.metadata_declared_size, self.metadata_read_size
                )
            )
        return "rejected .NET stream table: " + "; ".join(reasons)

    def warnings(self) -> List[str]:
        return list(self._warnings)

    def add_warning(self, message: str) -> None:
        if message not in self._warnings:
            self._warnings.append(message)

    def drain_new_warnings(self) -> List[str]:
        """Return warnings not yet emitted to the PE object."""

        new = self._warnings[self._emitted:]
        self._emitted = len(self._warnings)
        return new

    def to_dict(self) -> Dict[str, object]:
        return {
            "policy": self.policy.value,
            "metadata_rva": self.metadata_rva,
            "metadata_declared_size": self.metadata_declared_size,
            "metadata_read_size": self.metadata_read_size,
            "expected_entries": self.expected_entries,
            "table_truncated": self.table_truncated,
            "invalid_slots": list(self.invalid_slots),
            "metadata_truncated": self.metadata_truncated,
            "rejected": self.rejected,
            "rejection_reason": self.rejection_reason,
            "is_clean": self.is_clean,
            "is_complete": self.is_complete,
            "table_evidence": self.table_evidence,
            "heap_evidence": dict(self.heap_evidence),
            "resource_evidence": self.resource_evidence,
            "evidence_incomplete": [e.index for e in self.evidence_incomplete],
            "has_conflicts": self.has_conflicts,
            "entries": [e.to_dict() for e in self.entries],
            "warnings": self.warnings(),
        }


def annotate_conflicts(report: StreamTableReport) -> None:
    """Mark duplicate names, overlapping ranges, and out-of-directory ranges."""

    entries = report.entries
    by_name: Dict[bytes, List[StreamTableEntry]] = {}
    for entry in entries:
        if entry.name is None or entry.stream is None:
            continue
        by_name.setdefault(entry.name, []).append(entry)

    for name, group in by_name.items():
        if len(group) < 2:
            continue
        for entry in group:
            entry.statuses.add(StreamStatus.DUPLICATE_NAME)
        first = group[0]
        others = ", ".join(
            "0x{:x}".format(e.header_offset if e.header_offset is not None else e.header_rva)
            for e in group[1:]
        )
        report.add_warning(
            "Duplicate .NET stream name {!r} at header 0x{:x} and {}; "
            "only a structurally valid entry is selected".format(
                name,
                first.header_offset if first.header_offset is not None else first.header_rva,
                others,
            )
        )

    for entry in entries:
        if entry.stream is None:
            continue
        location = entry.header_offset if entry.header_offset is not None else entry.header_rva
        if StreamStatus.ZERO_LENGTH in entry.statuses:
            report.add_warning(
                "Zero-length .NET stream {!r} at header 0x{:x}; no bytes can be confirmed".format(
                    entry.name, location
                )
            )
        if StreamStatus.OUTSIDE_METADATA in entry.statuses:
            report.add_warning(
                ".NET stream {!r} at header 0x{:x} declares {} outside the metadata directory {}".format(
                    entry.name,
                    location,
                    _hex_range(entry.declared_rva, entry.declared_end_rva),
                    _hex_range(report.metadata_rva, report.metadata_declared_end_rva),
                ).strip()
            )
        if StreamStatus.TRUNCATED in entry.statuses:
            report.add_warning(
                ".NET stream {!r} at header 0x{:x} declared 0x{:x} bytes but only 0x{:x} bytes were readable".format(
                    entry.name, location, entry.size or 0, entry.read_size
                ).strip()
            )

    # Compare declared ranges, not the bytes that happened to be readable.
    ranged = [
        e
        for e in entries
        if e.stream is not None
        and e.declared_rva is not None
        and e.declared_end_rva is not None
        and e.declared_end_rva > e.declared_rva
    ]
    seen_pairs = set()
    for i, left in enumerate(ranged):
        for right in ranged[i + 1:]:
            start = max(left.declared_rva, right.declared_rva)  # type: ignore[type-var]
            end = min(left.declared_end_rva, right.declared_end_rva)  # type: ignore[type-var]
            if start >= end:
                continue
            exact = (
                left.declared_rva == right.declared_rva
                and left.declared_end_rva == right.declared_end_rva
            )
            status = StreamStatus.OVERLAP_EXACT if exact else StreamStatus.OVERLAP_PARTIAL
            left.statuses.add(status)
            right.statuses.add(status)
            if right.index not in left.overlaps_with:
                left.overlaps_with.append(right.index)
            if left.index not in right.overlaps_with:
                right.overlaps_with.append(left.index)
            pair = (left.index, right.index)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            report.add_warning(
                "{} .NET stream ranges: {!r} {} and {!r} {}; overlapping bytes are candidate only".format(
                    "Identical" if exact else "Overlapping",
                    left.name,
                    _hex_range(left.declared_rva, left.declared_end_rva),
                    right.name,
                    _hex_range(right.declared_rva, right.declared_end_rva),
                )
            )

    # Now that overlap statuses are known, record how many same-name entries
    # remain structurally usable.  This distinguishes "two valid streams claim
    # the same name" from "one valid stream plus a broken impostor".
    for name, group in by_name.items():
        usable = sum(1 for e in group if not e.has_hard_conflict)
        for entry in group:
            entry.same_name_admissible = usable


def resolve_entries(report: StreamTableReport) -> None:
    """Choose one entry per name without letting a broken entry shadow a good one.

    Structural validity wins over header order.  Among structurally valid
    entries with the same name, a non-empty stream wins over an empty one, and
    then the last header wins (the runtime's documented behavior).  If every
    entry for a name is structurally damaged, the last non-empty one is kept
    as a candidate so forensic callers can still inspect the raw bytes, but
    that entry is not accepted for parsing or shortcuts.
    """

    by_name: Dict[bytes, List[StreamTableEntry]] = {}
    for entry in report.entries:
        if entry.name is None or entry.stream is None:
            continue
        by_name.setdefault(entry.name, []).append(entry)

    for name, group in by_name.items():
        # Rank: confirmed bytes > usable but incomplete bytes > unusable header.
        # A damaged entry must never outrank a valid one merely by appearing later.
        best_rank = max(_entry_rank(e) for e in group)
        pool = [e for e in group if _entry_rank(e) == best_rank]
        non_empty = [e for e in pool if not e.is_empty]
        pool = non_empty or pool
        chosen = pool[-1]
        if best_rank > 0 and not chosen.has_hard_conflict:
            chosen.resolution = "selected"
            for other in group:
                if other is not chosen:
                    other.resolution = "shadowed" if not other.has_hard_conflict else "candidate"
        else:
            chosen.resolution = "candidate"
            for other in group:
                if other is not chosen:
                    other.resolution = "candidate"


def _entry_rank(entry: StreamTableEntry) -> int:
    if entry.stream is None or entry.has_hard_conflict:
        return 0
    # A recovered header is evidence to inspect, never a stream to trust.
    if StreamStatus.RECOVERED in entry.statuses:
        return 0
    if entry.statuses & frozenset(
        (
            StreamStatus.TRUNCATED,
            StreamStatus.PARSE_ERROR,
        )
    ):
        return 1
    if entry.is_empty:
        return 1
    return 2


def _is_table_stream(value) -> bool:
    if value is None:
        return False
    # Avoid importing stream at module load time (streamtable is imported by
    # dnfile.__init__, which also imports stream); a local import is safe here.
    from . import stream as _stream

    return isinstance(value, _stream.MetaDataTables)


def finalize_structure(report: StreamTableReport) -> None:
    """Resolve cross-name conflicts between table streams."""

    table_entries = [
        e
        for e in report.entries
        if e.stream is not None and e.is_selected and _is_table_stream(e.stream)
    ]
    if len(table_entries) < 2:
        return

    for entry in table_entries:
        entry.statuses.add(StreamStatus.MULTIPLE_TABLE_STREAMS)
    confirmed = [e for e in table_entries if e.is_confirmed]
    chosen = (confirmed or table_entries)[-1]
    for entry in table_entries:
        if entry is not chosen:
            entry.resolution = "alias"
    report.add_warning(
        "Multiple metadata table streams {}; only {!r} at header 0x{:x} is parsed".format(
            ", ".join(
                "{!r}@0x{:x}".format(e.name, e.header_offset if e.header_offset is not None else e.header_rva)
                for e in table_entries
            ),
            chosen.name,
            chosen.header_offset if chosen.header_offset is not None else chosen.header_rva,
        )
    )


def apply_evidence_to_streams(report: StreamTableReport) -> None:
    """Attach the final evidence verdict to each decoded stream object."""

    for entry in report.entries:
        stream = entry.stream
        if stream is None:
            continue
        stream.stream_entry_index = entry.index
        stream.stream_table_entry = entry
        stream.declared_size = entry.size
        stream.read_size = entry.read_size
        stream.header_rva = entry.header_rva
        stream.header_offset = entry.header_offset
        stream.declared_range = entry.declared_range
        stream.read_range = entry.read_range
        stream.statuses = frozenset(entry.statuses)
        stream.evidence = entry.evidence
        stream.is_confirmed = entry.is_confirmed
        stream.is_candidate = entry.evidence == "candidate"
        stream.is_empty = entry.evidence == "empty"


def finalize_evidence(report: StreamTableReport) -> None:
    """Compute what the selected stream bytes can prove.

    The table stream is confirmed only when its own bytes are confirmed.  Names
    and blobs resolved through heaps inherit the weakest selected heap's
    evidence.  Resources inherit the table evidence, because their identities
    come from ManifestResource rows.
    """

    table_entry = report.table_stream_entry()
    heap_evidence: Dict[str, str] = {}
    for heap_name in (b"#Strings", b"#US", b"#GUID", b"#Blob"):
        entry = report.selected_entry(heap_name)
        heap_evidence[heap_name.decode("ascii")] = entry.evidence if entry is not None else "missing"

    type_inputs = [
        heap_evidence.get("#Strings", "missing"),
        heap_evidence.get("#GUID", "missing"),
        heap_evidence.get("#Blob", "missing"),
    ]
    if table_entry is None:
        table_evidence = "missing"
    elif not table_entry.is_confirmed:
        table_evidence = table_entry.evidence
    elif any(value != "confirmed" for value in type_inputs):
        table_evidence = "candidate"
    else:
        table_evidence = "confirmed"

    report.table_evidence = table_evidence
    report.heap_evidence = heap_evidence
    report.resource_evidence = "confirmed" if table_evidence == "confirmed" else "candidate"

    if table_entry is not None and table_evidence != "confirmed":
        report.add_warning(
            "Metadata table stream evidence is {}: heap evidence {}".format(
                table_evidence,
                ", ".join("{}={}".format(k, v) for k, v in heap_evidence.items()),
            )
        )
