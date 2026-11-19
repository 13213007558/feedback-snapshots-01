"""Build the two-port / two-source IGMPv3 byte transcript with Scapy.

Each report is a full Ethernet frame carrying an IP packet with protocol 2
and an IGMPv3 Membership Report (type 0x22) whose group records use the
RFC 3376 record types. Frames are serialized to hex bytes, so the whole
demo stays offline and can be re-parsed from the bytes alone.

The transcript intentionally contains:
  * INCLUDE -> ALLOW -> EXCLUDE mode transitions,
  * a late, duplicate retransmission of a state-change record,
  * trusted capture-gap markers and a subsequent repair,
  * a receiver reporting a source that provisioning does not permit.
"""

from dataclasses import dataclass
import json
import os

from scapy.all import Ether, IP, wrpcap
from scapy.layers.igmp import IGMPv3_MQ, IGMPv3_MR, IGMPv3_MR_Group

from .evidence_model import (
    ALLOW_NEW_SOURCES,
    BLOCK_OLD_SOURCES,
    CHANGE_TO_EXCLUDE_MODE,
    MODE_IS_EXCLUDE,
    MODE_IS_INCLUDE,
)

ALL_ROUTERS = "224.0.0.22"
ALL_SYSTEMS = "224.0.0.1"

G1 = "232.0.0.1"
G2 = "232.0.0.2"
S1 = "192.0.2.11"
S2 = "192.0.2.12"
S21 = "192.0.2.21"
S22 = "192.0.2.22"
S99 = "198.51.100.99"

PORT_MAC = {
    "p1": "00:00:00:00:01:10",
    "p2": "00:00:00:00:02:20",
}
PORT_SENDER_IP = {
    "p1": "10.0.1.10",
    "p2": "10.0.2.20",
}


@dataclass(frozen=True)
class TranscriptEntry:
    frame_id: str
    timestamp: int
    kind: str
    port_id: str | None
    note: str
    hex_bytes: str | None
    lost_seconds: int | None = None


def _report_frame(port_id: str, records: list[tuple[int, str, list[str]]]):
    group_records = [
        IGMPv3_MR_Group(rtype=rtype, maddr=group, srcaddrs=sources)
        for rtype, group, sources in records
    ]
    return (
        Ether(src=PORT_MAC[port_id])
        / IP(
            src=PORT_SENDER_IP[port_id],
            dst=ALL_ROUTERS,
            proto=2,
            ttl=1,
        )
        / IGMPv3_MR(records=group_records)
    )


def _query_frame():
    return (
        Ether()
        / IP(src="10.0.0.1", dst=ALL_SYSTEMS, proto=2, ttl=1)
        / IGMPv3_MQ(gaddr="0.0.0.0", qqic=125)
    )


def _entry(frame_id, timestamp, kind, port_id, note, packet):
    return TranscriptEntry(
        frame_id=frame_id,
        timestamp=timestamp,
        kind=kind,
        port_id=port_id,
        note=note,
        hex_bytes=bytes(packet).hex(),
    )


def build_transcript() -> list[TranscriptEntry]:
    """Return the ordered, fixed-clock demonstration transcript."""
    entries: list[TranscriptEntry] = []

    entries.append(
        _entry(
            "F1",
            10,
            "REPORT",
            "p1",
            "p1 claims INCLUDE for G1, source set {S1}",
            _report_frame("p1", [(MODE_IS_INCLUDE, G1, [S1])]),
        )
    )
    entries.append(
        _entry(
            "F2",
            20,
            "REPORT",
            "p2",
            "p2 claims INCLUDE for G2, source set {S21}",
            _report_frame("p2", [(MODE_IS_INCLUDE, G2, [S21])]),
        )
    )
    entries.append(
        _entry(
            "F3",
            30,
            "REPORT",
            "p1",
            "ALLOW_NEW_SOURCES adds S2 to p1/G1 (INCLUDE, {S1,S2})",
            _report_frame("p1", [(ALLOW_NEW_SOURCES, G1, [S2])]),
        )
    )
    entries.append(
        _entry(
            "F4",
            40,
            "REPORT",
            "p1",
            "p1 periodic CSR re-asserts INCLUDE {S1,S2} (snapshot, not a delta)",
            _report_frame("p1", [(MODE_IS_INCLUDE, G1, [S1, S2])]),
        )
    )
    entries.append(
        _entry(
            "F5",
            50,
            "REPORT",
            "p1",
            "Late duplicate of the F3 ALLOW delta (must be applied once only)",
            _report_frame("p1", [(ALLOW_NEW_SOURCES, G1, [S2])]),
        )
    )
    entries.append(
        _entry(
            "F6",
            60,
            "REPORT",
            "p1",
            "CHANGE_TO_EXCLUDE_MODE: p1/G1 now EXCLUDE {S2}",
            _report_frame("p1", [(CHANGE_TO_EXCLUDE_MODE, G1, [S2])]),
        )
    )
    entries.append(
        _entry(
            "F7",
            70,
            "REPORT",
            "p2",
            "BLOCK_OLD_SOURCES removes S21 from p2/G2",
            _report_frame("p2", [(BLOCK_OLD_SOURCES, G2, [S21])]),
        )
    )
    entries.append(
        _entry(
            "F8",
            80,
            "REPORT",
            "p2",
            "p2 reports INCLUDE {S21,S22}; S21 is re-added by this snapshot",
            _report_frame("p2", [(MODE_IS_INCLUDE, G2, [S21, S22])]),
        )
    )
    entries.append(
        _entry(
            "F9",
            90,
            "QUERY",
            None,
            "General Membership Query from the querier (grants no membership)",
            _query_frame(),
        )
    )
    entries.append(
        _entry(
            "F10",
            100,
            "REPORT",
            "p2",
            "p2 reports unprovisioned source S99 as wanted (never authorized)",
            _report_frame("p2", [(ALLOW_NEW_SOURCES, G2, [S99])]),
        )
    )
    entries.append(
        TranscriptEntry(
            frame_id="GAP-p1",
            timestamp=120,
            kind="GAP",
            port_id="p1",
            note="Trusted monitor marks 60 s of unrecorded frames on p1",
            hex_bytes=None,
            lost_seconds=60,
        )
    )
    entries.append(
        TranscriptEntry(
            frame_id="GAP-p2",
            timestamp=120,
            kind="GAP",
            port_id="p2",
            note="Trusted monitor marks 60 s of unrecorded frames on p2",
            hex_bytes=None,
            lost_seconds=60,
        )
    )
    entries.append(
        _entry(
            "F11",
            180,
            "REPORT",
            "p2",
            "BLOCK delta after the gap; held pending until the next CSR",
            _report_frame("p2", [(BLOCK_OLD_SOURCES, G2, [S22])]),
        )
    )
    entries.append(
        _entry(
            "F12",
            200,
            "REPORT",
            "p2",
            "CSR re-anchors p2/G2 as INCLUDE {S21} and repairs the gap",
            _report_frame("p2", [(MODE_IS_INCLUDE, G2, [S21])]),
        )
    )
    entries.append(
        _entry(
            "F13",
            210,
            "REPORT",
            "p1",
            "CSR re-anchors p1/G1 as EXCLUDE {S2} and repairs the gap",
            _report_frame("p1", [(MODE_IS_EXCLUDE, G1, [S2])]),
        )
    )
    entries.append(
        _entry(
            "F14",
            220,
            "REPORT",
            "p1",
            "BLOCK_OLD_SOURCES removes S2; p1/G1 becomes EXCLUDE empty set",
            _report_frame("p1", [(BLOCK_OLD_SOURCES, G1, [S2])]),
        )
    )
    return entries


def write_artifacts(entries: list[TranscriptEntry], out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    jsonl_path = os.path.join(out_dir, "transcript.jsonl")
    with open(jsonl_path, "w", encoding="utf-8") as handle:
        for entry in entries:
            handle.write(json.dumps(entry.__dict__, ensure_ascii=False) + "\n")
    pcap_path = os.path.join(out_dir, "transcript.pcap")
    wrpcap(
        pcap_path,
        [
            Ether(bytes.fromhex(entry.hex_bytes))
            for entry in entries
            if entry.hex_bytes
        ],
    )


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    target = os.path.join(here, "artifacts")
    transcript = build_transcript()
    write_artifacts(transcript, target)
    print(f"wrote {len(transcript)} entries to {target}")
