"""Decode the byte transcript and feed the evidence engine.

Parsing is done from the stored Ethernet bytes with Scapy, mirroring what an
offline monitor would do on a captured frame. The ingress port and the
capture-gap markers come from the trusted collection plane, never from the
frame content. The sender IP inside the packet is displayed for forensics but
is not used as an authorization input.
"""

import json
import os

from scapy.all import Ether, IP
from scapy.layers.igmp import IGMPv3_MQ, IGMPv3_MR

from .evidence_model import (
    GapObservation,
    MembershipEvidenceEngine,
    QueryObservation,
    RecordObservation,
    RTYPE_NAME,
)


def load_transcript(path: str) -> list[dict]:
    entries = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            entries.append(json.loads(line))
    return entries


def parse_report_bytes(frame_id: str, timestamp: int, port_id: str, raw_hex: str):
    """Dissect one Ethernet frame into RecordObservation objects."""
    packet = Ether(bytes.fromhex(raw_hex))
    observations = []
    if not packet.haslayer(IGMPv3_MR):
        return observations
    sender_ip = packet[IP].src
    for group_record in packet[IGMPv3_MR].records:
        observations.append(
            RecordObservation(
                frame_id=frame_id,
                timestamp=timestamp,
                port_id=port_id,
                rtype=group_record.rtype,
                group=group_record.maddr,
                sources=frozenset(group_record.srcaddrs),
                sender_ip=sender_ip,
            )
        )
    return observations


def parse_query_bytes(frame_id: str, timestamp: int, raw_hex: str):
    packet = Ether(bytes.fromhex(raw_hex))
    if not packet.haslayer(IGMPv3_MQ):
        return None
    return QueryObservation(
        frame_id=frame_id,
        timestamp=timestamp,
        group=packet[IGMPv3_MQ].gaddr,
    )


def build_engine(
    entries: list[dict], gmi: int, until: int | None = None
) -> MembershipEvidenceEngine:
    engine = MembershipEvidenceEngine(gmi)
    for entry in entries:
        if until is not None and entry["timestamp"] > until:
            break
        kind = entry["kind"]
        if kind == "GAP":
            engine.record_gap(
                GapObservation(
                    frame_id=entry["frame_id"],
                    timestamp=entry["timestamp"],
                    port_id=entry["port_id"],
                    lost_seconds=entry["lost_seconds"],
                )
            )
            continue
        if kind == "QUERY":
            query = parse_query_bytes(
                entry["frame_id"], entry["timestamp"], entry["hex_bytes"]
            )
            if query is not None:
                engine.record_query(query)
            continue
        for record in parse_report_bytes(
            entry["frame_id"],
            entry["timestamp"],
            entry["port_id"],
            entry["hex_bytes"],
        ):
            engine.ingest_record(record)
    return engine


def describe_record(record: RecordObservation) -> str:
    sources = ",".join(sorted(record.sources)) or "-"
    return (
        f"{record.frame_id} t={record.timestamp} port={record.port_id} "
        f"{RTYPE_NAME[record.rtype]} group={record.group} sources={{{sources}}} "
        f"sender={record.sender_ip}"
    )


def default_transcript_path() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "artifacts", "transcript.jsonl")
