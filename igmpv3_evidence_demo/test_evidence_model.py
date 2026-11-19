"""Assertions for the offline IGMPv3 evidence model.

Run from the repository root:

    python3 -m igmpv3_evidence_demo.test_evidence_model
"""

import unittest

from .analyze import build_engine, load_transcript, parse_report_bytes
from .config import demo_config
from .evidence_model import (
    ALLOW_NEW_SOURCES,
    BLOCK_OLD_SOURCES,
    CHANGE_TO_EXCLUDE_MODE,
    GapObservation,
    MODE_IS_INCLUDE,
    RecordObservation,
)
from .transcript_build import (
    G1,
    G2,
    S1,
    S2,
    S21,
    S22,
    S99,
)


def record(frame_id, timestamp, port_id, rtype, group, sources):
    return RecordObservation(
        frame_id=frame_id,
        timestamp=timestamp,
        port_id=port_id,
        rtype=rtype,
        group=group,
        sources=frozenset(sources),
        sender_ip="10.0.1.10",
    )


class EngineSemanticsTest(unittest.TestCase):
    def setUp(self):
        self.config = demo_config()
        self.gmi = self.config.group_membership_interval

    def verdict(self, engine, port_id, group, source):
        reason = self.config.policy_lookup(port_id, group, source)
        return engine.evaluate(port_id, group, source, reason)

    def test_csr_replaces_state_and_allow_block_edit_sources(self):
        engine = build_engine([], self.gmi)
        engine.ingest_record(record("F1", 10, "p1", MODE_IS_INCLUDE, G1, [S1]))
        engine.ingest_record(record("F2", 20, "p1", ALLOW_NEW_SOURCES, G1, [S2]))
        engine.advance(20)
        self.assertEqual(
            self.verdict(engine, "p1", G1, S2).decision, "ALLOW"
        )
        engine.ingest_record(
            record("F3", 30, "p1", BLOCK_OLD_SOURCES, G1, [S2])
        )
        self.assertEqual(
            self.verdict(engine, "p1", G1, S2).reason,
            "SOURCE_NOT_IN_INCLUDE_SET",
        )
        engine.ingest_record(
            record("F4", 40, "p1", CHANGE_TO_EXCLUDE_MODE, G1, [S2])
        )
        self.assertEqual(
            self.verdict(engine, "p1", G1, S2).reason, "SOURCE_IN_EXCLUDE_SET"
        )
        self.assertEqual(
            self.verdict(engine, "p1", G1, S1).reason, "EXCLUDE_NOT_BLOCKED"
        )

    def test_duplicate_state_change_is_applied_once(self):
        engine = build_engine([], self.gmi)
        engine.ingest_record(record("F1", 10, "p1", MODE_IS_INCLUDE, G1, [S1]))
        delta = record("F2", 20, "p1", BLOCK_OLD_SOURCES, G1, [S1])
        engine.ingest_record(delta)
        late = RecordObservation(
            frame_id="F3",
            timestamp=30,
            port_id="p1",
            rtype=BLOCK_OLD_SOURCES,
            group=G1,
            sources=frozenset([S1]),
            sender_ip="10.0.1.10",
        )
        engine.ingest_record(late)
        state = engine.states[("p1", G1)]
        applied = [fact.frame_id for fact in state.facts]
        self.assertEqual(applied, ["F1", "F2", "F3"])
        self.assertEqual(state.source_set, frozenset())
        self.assertIn(late.signature(), state.seen_scr_signatures)

    def test_unanchored_state_change_cannot_establish_membership(self):
        engine = build_engine([], self.gmi)
        engine.ingest_record(
            record("F1", 10, "p1", ALLOW_NEW_SOURCES, G1, [S1])
        )
        engine.advance(10)
        verdict = self.verdict(engine, "p1", G1, S1)
        self.assertEqual(verdict.decision, "NOT_PROVABLE")
        self.assertEqual(verdict.reason, "NO_CURRENT_STATE_ANCHOR")

    def test_gap_fails_closed_until_csr_repairs_it(self):
        engine = build_engine([], self.gmi)
        engine.ingest_record(record("F1", 10, "p1", MODE_IS_INCLUDE, G1, [S1]))
        engine.record_gap(GapObservation("G1-gap", 100, "p1", 60))
        engine.advance(150)
        self.assertEqual(
            self.verdict(engine, "p1", G1, S1).reason,
            "CAPTURE_GAP_UNREPAIRED",
        )
        engine.ingest_record(
            record("F2", 160, "p1", MODE_IS_INCLUDE, G1, [S1])
        )
        self.assertEqual(
            self.verdict(engine, "p1", G1, S1).decision, "ALLOW"
        )

    def test_fixed_clock_timer_expiry_is_not_provable(self):
        engine = build_engine([], self.gmi)
        engine.ingest_record(record("F1", 10, "p1", MODE_IS_INCLUDE, G1, [S1]))
        engine.advance(10 + self.gmi - 1)
        self.assertEqual(
            self.verdict(engine, "p1", G1, S1).decision, "ALLOW"
        )
        engine.advance(10 + self.gmi)
        verdict = self.verdict(engine, "p1", G1, S1)
        self.assertEqual(verdict.decision, "NOT_PROVABLE")
        self.assertEqual(verdict.reason, "MEMBERSHIP_TIMER_EXPIRED")

    def test_reported_but_unprovisioned_source_is_denied(self):
        engine = build_engine([], self.gmi)
        engine.ingest_record(record("F1", 10, "p2", MODE_IS_INCLUDE, G2, [S99]))
        engine.advance(10)
        verdict = self.verdict(engine, "p2", G2, S99)
        self.assertEqual(verdict.decision, "DENY")
        self.assertEqual(verdict.reason, "SOURCE_NOT_PERMITTED")

    def test_cross_port_policy_isolation(self):
        engine = build_engine([], self.gmi)
        engine.ingest_record(record("F1", 10, "p1", MODE_IS_INCLUDE, G1, [S1]))
        self.assertEqual(
            self.verdict(engine, "p2", G1, S1).reason, "GROUP_NOT_PERMITTED"
        )


class TranscriptRoundTripTest(unittest.TestCase):
    def test_bytes_decode_to_expected_records(self):
        import os

        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "artifacts",
            "transcript.jsonl",
        )
        entries = load_transcript(path)
        report = next(item for item in entries if item["frame_id"] == "F6")
        decoded = parse_report_bytes(
            report["frame_id"],
            report["timestamp"],
            report["port_id"],
            report["hex_bytes"],
        )
        self.assertEqual(len(decoded), 1)
        self.assertEqual(decoded[0].rtype, CHANGE_TO_EXCLUDE_MODE)
        self.assertEqual(decoded[0].group, G1)
        self.assertEqual(decoded[0].sources, frozenset([S2]))

    def test_full_transcript_end_to_end_checkpoints(self):
        import os

        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "artifacts",
            "transcript.jsonl",
        )
        entries = load_transcript(path)
        config = demo_config()
        engine = build_engine(entries, config.group_membership_interval, until=230)
        engine.advance(230)
        self.assertEqual(
            engine.evaluate(
                "p1", G1, S1, config.policy_lookup("p1", G1, S1)
            ).decision,
            "ALLOW",
        )
        self.assertEqual(
            engine.evaluate(
                "p2", G2, S21, config.policy_lookup("p2", G2, S21)
            ).decision,
            "ALLOW",
        )
        self.assertEqual(
            engine.evaluate(
                "p2", G2, S22, config.policy_lookup("p2", G2, S22)
            ).reason,
            "SOURCE_NOT_IN_INCLUDE_SET",
        )
        stale = build_engine(entries, config.group_membership_interval)
        stale.advance(480)
        self.assertEqual(
            stale.evaluate(
                "p1", G1, S1, config.policy_lookup("p1", G1, S1)
            ).reason,
            "MEMBERSHIP_TIMER_EXPIRED",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
