"""
A name-evidence view over the Name Resolution Blocks (NRB) of a
pcap-ng capture.

A security backend often wants to know which names a capture file
*claims* for the addresses appearing in its packets. The NRB, however,
is **not** a log of DNS responses observed on the wire: it is a
snapshot of the name-resolution state of whoever wrote the file, saved
so that the file can be read later without re-resolving (see pcap-ng
spec, section 4.5). This module therefore exposes NRB contents as
*evidence with provenance*, not as facts:

* every mapping keeps its raw record bytes, its section, and its
  position (block / record) inside the capture;
* multiple names for the same address -- whether in a single record or
  in several records -- are all preserved;
* identical addresses claimed in different sections are kept separate,
  so conflicting claims can be traced back to their origin;
* records of unknown type are reported as *unexplained*, records with
  a damaged name structure (e.g. a truncated, non NUL-terminated name)
  as *corrupted* -- neither is ever silently turned into a trusted
  name;
* no online resolution is ever performed: queries only accept literal
  IPv4/IPv6 addresses and are matched against what is in the file.

Because an NRB carries no timing information, this view cannot -- and
does not -- assert that any name was valid for an address at the time
any particular packet was captured.
"""

import struct

from pcapng.constants.block_types import BLK_NAME_RESOLUTION
from pcapng.exceptions import StreamEmpty
from pcapng.structs import (
    SECTION_HEADER_MAGIC,
    read_block_data,
    read_int,
    read_section_header,
)
from pcapng.utils import pack_ipv4, pack_ipv6, unpack_ipv4, unpack_ipv6

NRB_RECORD_END = 0x0000
NRB_RECORD_IPv4 = 0x0001
NRB_RECORD_IPv6 = 0x0002

#: Record was fully decoded; its names are as trustworthy as the file is.
STATUS_PARSED = "parsed"
#: Record type is not known to this library; raw bytes are preserved,
#: but no attempt at interpreting (or "completing") it was made.
STATUS_UNEXPLAINED = "unexplained"
#: Record is damaged (e.g. truncated name, bad length); anything
#: recovered from it must not be treated as a trusted name.
STATUS_CORRUPTED = "corrupted"

EVIDENCE_DISCLAIMER = (
    "Name Resolution Block data is a snapshot of the name-resolution "
    "state of the host that wrote the capture, not a record of DNS "
    "responses observed on the wire. It cannot be used to assert that "
    "a name was valid for an address at the time any particular packet "
    "was captured."
)

_ADDRESS_PACKERS = (pack_ipv4, pack_ipv6)


def _normalize_address(address):
    """
    Normalize a literal IPv4/IPv6 address to its packed form.

    Raises :py:exc:`ValueError` for anything that is not a numeric
    address. This is deliberate: looking up a hostname would require a
    DNS resolution, which this module never performs.
    """
    for packer in _ADDRESS_PACKERS:
        try:
            return packer(address)
        except (OSError, TypeError):
            continue
    raise ValueError(
        "not a numeric IPv4/IPv6 address (no name resolution is ever "
        "performed): {0!r}".format(address)
    )


def _decode_names(region):
    """
    Decode the NUL-separated name list of a record value.

    :return: a ``(names, problem)`` tuple. ``names`` is a tuple of
        decoded names (empty if ``problem`` is not ``None``); the
        caller decides how to flag the record.
    """
    if not region:
        return (), None
    if not region.endswith(b"\x00"):
        # The last name runs into the end of the record value: it was
        # truncated (or never terminated). Emitting it would mean
        # presenting a guessed name as a trusted one.
        return (), "truncated name: record value is not NUL-terminated"
    names = []
    for chunk in region.split(b"\x00"):
        if not chunk:
            continue
        try:
            names.append(chunk.decode("utf-8"))
        except UnicodeDecodeError:
            return (), "name is not valid UTF-8: {0!r}".format(chunk)
    return tuple(names), None


class NameRecordEvidence(object):
    """
    Evidence for a single name resolution record.

    :ivar section_index: index of the section containing the record
        (``-1`` if the block appeared before any section header).
    :ivar block_index: index of the Name Resolution Block within its
        section.
    :ivar record_index: index of the record within its block.
    :ivar record_type: the raw record type (``0x0001`` = IPv4,
        ``0x0002`` = IPv6, anything else is unexplained).
    :ivar raw: the raw record bytes (type, length, value, padding),
        exactly as found in the capture.
    :ivar status: one of ``STATUS_PARSED``, ``STATUS_UNEXPLAINED`` or
        ``STATUS_CORRUPTED``.
    :ivar address: the claimed address as a string, or ``None`` if the
        record does not (verifiably) contain one.
    :ivar names: tuple of claimed names; empty unless the record
        parsed cleanly.
    :ivar problem: human-readable description of what is wrong, for
        unexplained and corrupted records; ``None`` otherwise.
    """

    __slots__ = [
        "section_index",
        "block_index",
        "record_index",
        "record_type",
        "raw",
        "status",
        "address",
        "names",
        "problem",
    ]

    def __init__(
        self,
        section_index,
        block_index,
        record_index,
        record_type,
        raw,
        status,
        address=None,
        names=(),
        problem=None,
    ):
        self.section_index = section_index
        self.block_index = block_index
        self.record_index = record_index
        self.record_type = record_type
        self.raw = raw
        self.status = status
        self.address = address
        self.names = tuple(names)
        self.problem = problem

    @property
    def is_name_claim(self):
        """Whether this record is a cleanly parsed address->names claim."""
        return self.status == STATUS_PARSED and self.address is not None

    def describe_origin(self):
        """Human-readable pointer to where this record was found."""
        return (
            "section {0}, name-resolution block #{1}, record #{2} "
            "(type 0x{3:04x})"
        ).format(
            self.section_index,
            self.block_index,
            self.record_index,
            self.record_type,
        )

    def __repr__(self):
        return (
            "<NameRecordEvidence {0} status={1} address={2!r} "
            "names={3!r} problem={4!r}>"
        ).format(
            self.describe_origin(),
            self.status,
            self.address,
            self.names,
            self.problem,
        )


class AddressEvidence(object):
    """
    All the claims a capture makes about one address.

    :ivar address: the queried address (canonical string form).
    :ivar claims: list of cleanly parsed :py:class:`NameRecordEvidence`
        records claiming names for this address, in file order.
    :ivar damaged: list of corrupted records whose address could still
        be recovered; their (partial) contents are *not* trusted names.
    """

    __slots__ = ["address", "claims", "damaged"]

    def __init__(self, address, claims, damaged):
        self.address = address
        self.claims = list(claims)
        self.damaged = list(damaged)

    @property
    def names(self):
        """All claimed names, deduplicated, in order of appearance."""
        seen = []
        for claim in self.claims:
            for name in claim.names:
                if name not in seen:
                    seen.append(name)
        return tuple(seen)

    @property
    def has_conflict(self):
        """Whether different sections disagree on this address's names."""
        return len(self.name_sets_by_section()) > 1

    def name_sets_by_section(self):
        """
        Group the claimed name sets by section index.

        :return: a dict mapping section index to the list of name
            tuples claimed in that section (one entry per record).
        """
        by_section = {}
        for claim in self.claims:
            by_section.setdefault(claim.section_index, []).append(claim.names)
        return by_section

    def explain(self):
        """
        Human-readable explanation of the claims, their origin, and
        any conflict between them. Always ends with the evidence
        disclaimer: none of this may be read as "name X was valid for
        this address at packet time T".
        """
        lines = []
        if not self.claims and not self.damaged:
            lines.append(
                "Address {0}: no name claims found in the capture.".format(
                    self.address
                )
            )
        else:
            sections = sorted(self.name_sets_by_section())
            lines.append(
                "Address {0}: {1} name claim(s) in {2} section(s).".format(
                    self.address, len(self.claims), len(sections)
                )
            )
            for claim in self.claims:
                lines.append(
                    "  {0}: {1}".format(
                        claim.describe_origin(),
                        ", ".join(repr(n) for n in claim.names)
                        or "(no names)",
                    )
                )
            for record in self.damaged:
                lines.append(
                    "  {0}: CORRUPTED record, contents not trusted "
                    "({1})".format(record.describe_origin(), record.problem)
                )
            if self.has_conflict:
                parts = []
                for section in sections:
                    names = set()
                    for name_set in self.name_sets_by_section()[section]:
                        names.update(name_set)
                    parts.append(
                        "section {0} claims {1}".format(
                            section, sorted(names) or ["(no names)"]
                        )
                    )
                lines.append("CONFLICT: " + "; ".join(parts) + ".")
            else:
                lines.append("No conflicting claims between sections.")
        lines.append("Note: " + EVIDENCE_DISCLAIMER)
        return "\n".join(lines)

    def __repr__(self):
        return "<AddressEvidence {0} claims={1} damaged={2}>".format(
            self.address, len(self.claims), len(self.damaged)
        )


class NameEvidenceView(object):
    """
    Evidence view over all Name Resolution Blocks of a capture.

    Build it with :py:meth:`from_stream` or :py:meth:`from_file`, then
    query :py:meth:`claims_for` with a literal IP address, or inspect
    :py:attr:`records` / :py:attr:`problems` directly.
    """

    def __init__(self):
        self.records = []
        self.section_count = 0

    @classmethod
    def from_stream(cls, stream):
        """
        Scan a pcap-ng stream and collect name-resolution evidence.

        Malformed name resolution records never raise: they are
        collected as corrupted/unexplained evidence. Structural
        problems of the capture itself (bad magic, truncated blocks)
        still raise the usual :py:mod:`pcapng.exceptions`.
        """
        view = cls()
        endianness = "="
        section_index = -1
        block_index = 0
        while True:
            try:
                block_type = read_int(stream, 32, False, endianness)
            except StreamEmpty:
                break
            if block_type == SECTION_HEADER_MAGIC:
                section_info = read_section_header(stream)
                endianness = section_info["endianness"]
                section_index += 1
                block_index = 0
                continue
            block_data = read_block_data(stream, endianness)
            if block_type == BLK_NAME_RESOLUTION:
                view._parse_nrb(
                    block_data, endianness, section_index, block_index
                )
                block_index += 1
        view.section_count = section_index + 1
        return view

    @classmethod
    def from_file(cls, path):
        """Open a capture file and return its name evidence view."""
        with open(path, "rb") as stream:
            return cls.from_stream(stream)

    @property
    def problems(self):
        """Records that could not be turned into trusted claims."""
        return [r for r in self.records if r.status != STATUS_PARSED]

    @property
    def unexplained(self):
        """Records of unknown type (raw bytes preserved, not interpreted)."""
        return [r for r in self.records if r.status == STATUS_UNEXPLAINED]

    @property
    def corrupted(self):
        """Damaged records (e.g. truncated names, bad lengths)."""
        return [r for r in self.records if r.status == STATUS_CORRUPTED]

    def addresses(self):
        """All addresses with at least one cleanly parsed name claim."""
        seen = []
        for record in self.records:
            if record.is_name_claim and record.address not in seen:
                seen.append(record.address)
        return sorted(seen)

    def claims_for(self, address):
        """
        Return the :py:class:`AddressEvidence` for a literal address.

        ``address`` must be a numeric IPv4 or IPv6 address; hostnames
        are rejected rather than resolved online.
        """
        packed = _normalize_address(address)
        claims = []
        damaged = []
        canonical = None
        for record in self.records:
            if record.address is None:
                continue
            if _normalize_address(record.address) != packed:
                continue
            canonical = record.address
            if record.is_name_claim:
                claims.append(record)
            else:
                damaged.append(record)
        if canonical is None:
            canonical = (
                unpack_ipv6(packed) if len(packed) == 16
                else unpack_ipv4(packed)
            )
        return AddressEvidence(canonical, claims, damaged)

    def _add_record(self, **kwargs):
        record = NameRecordEvidence(**kwargs)
        self.records.append(record)
        return record

    def _parse_nrb(self, payload, endianness, section_index, block_index):
        offset = 0
        record_index = 0
        payload_len = len(payload)
        while offset < payload_len:
            remaining = payload_len - offset
            if remaining < 4:
                self._add_record(
                    section_index=section_index,
                    block_index=block_index,
                    record_index=record_index,
                    record_type=-1,
                    raw=payload[offset:],
                    status=STATUS_CORRUPTED,
                    problem="trailing bytes too short for a record header",
                )
                break
            record_type, record_length = struct.unpack(
                endianness + "HH", payload[offset:offset + 4]
            )
            if record_type == NRB_RECORD_END:
                break
            if 4 + record_length > remaining:
                self._add_record(
                    section_index=section_index,
                    block_index=block_index,
                    record_index=record_index,
                    record_type=record_type,
                    raw=payload[offset:],
                    status=STATUS_CORRUPTED,
                    problem=(
                        "record length {0} exceeds the {1} bytes left "
                        "in the block".format(record_length, remaining - 4)
                    ),
                )
                break
            padded_length = record_length + (-record_length % 4)
            raw = payload[offset:offset + 4 + padded_length]
            value = payload[offset + 4:offset + 4 + record_length]
            self._parse_record_value(
                record_type,
                value,
                raw,
                section_index,
                block_index,
                record_index,
            )
            offset += 4 + padded_length
            record_index += 1

    def _parse_record_value(
        self,
        record_type,
        value,
        raw,
        section_index,
        block_index,
        record_index,
    ):
        common = {
            "section_index": section_index,
            "block_index": block_index,
            "record_index": record_index,
            "record_type": record_type,
            "raw": raw,
        }
        if record_type == NRB_RECORD_IPv4:
            addr_len, unpack = 4, unpack_ipv4
        elif record_type == NRB_RECORD_IPv6:
            addr_len, unpack = 16, unpack_ipv6
        else:
            self._add_record(
                status=STATUS_UNEXPLAINED,
                problem="unknown record type 0x{0:04x}".format(record_type),
                **common
            )
            return
        if len(value) < addr_len:
            self._add_record(
                status=STATUS_CORRUPTED,
                problem=(
                    "record too short for its address family: "
                    "{0} < {1} bytes".format(len(value), addr_len)
                ),
                **common
            )
            return
        address = unpack(value[:addr_len])
        names, problem = _decode_names(value[addr_len:])
        if problem is not None:
            self._add_record(
                status=STATUS_CORRUPTED,
                address=address,
                problem=problem,
                **common
            )
            return
        self._add_record(
            status=STATUS_PARSED, address=address, names=names, **common
        )

    def __repr__(self):
        return (
            "<NameEvidenceView sections={0} records={1} problems={2}>"
        ).format(self.section_count, len(self.records), len(self.problems))
