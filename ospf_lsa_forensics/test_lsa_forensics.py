"""Unit tests for the OSPFv2 LSA forensic comparison criteria.

Run from the repository root:

    python3 -m unittest ospf_lsa_forensics.test_lsa_forensics -v
"""

import unittest

from . import samples
from .lsa_forensics import (
    INITIAL_SEQ,
    MAX_SEQ,
    Action,
    ForensicStore,
    Verdict,
    compare_instances,
    decode_ls_update,
    naive_unsigned_newer,
    seq_to_signed,
)

FRAME_MAP = {name: (frame, t) for name, frame, t in samples.FRAMES}


def lsa_of(name):
    frame, t = FRAME_MAP[name]
    return decode_ls_update(frame, t).lsas[0]


def replay(order):
    store = ForensicStore()
    decisions = {}
    for name in order:
        frame, t = FRAME_MAP[name]
        for clsa in decode_ls_update(frame, t).lsas:
            decisions[name] = store.apply(clsa)
    return store, decisions


class TestSequenceSpace(unittest.TestCase):
    def test_signed_interpretation(self):
        self.assertEqual(seq_to_signed(INITIAL_SEQ), -(2 ** 31) + 1)
        self.assertEqual(seq_to_signed(MAX_SEQ), 2 ** 31 - 1)
        self.assertLess(seq_to_signed(INITIAL_SEQ), seq_to_signed(MAX_SEQ))

    def test_unsigned_sort_inverts_wrap_boundary(self):
        # the backend anti-pattern: raw integer order ranks the restart
        # above MaxSequenceNumber
        self.assertGreater(INITIAL_SEQ, MAX_SEQ)
        older, newer = lsa_of("U6"), lsa_of("U8")
        self.assertTrue(naive_unsigned_newer(older, newer))
        comp = compare_instances(older, newer)
        self.assertIs(comp.verdict, Verdict.A_MORE_RECENT)


class TestValidation(unittest.TestCase):
    def test_valid_samples_pass(self):
        for name in ("U1", "U2", "U4", "U5", "U6", "U7", "U8", "V1"):
            self.assertEqual(lsa_of(name).errors, [], name)

    def test_checksum_mismatch_rejected(self):
        self.assertTrue(any("checksum" in e for e in lsa_of("U9").errors))

    def test_truncated_capture_rejected(self):
        self.assertTrue(any("incomplete" in e
                            for e in lsa_of("U10").errors))

    def test_reserved_sequence_rejected(self):
        self.assertTrue(any("reserved" in e for e in lsa_of("U12").errors))


class TestCompareInstances(unittest.TestCase):
    def test_higher_seq_wins(self):
        comp = compare_instances(lsa_of("U1"), lsa_of("U2"))
        self.assertIs(comp.verdict, Verdict.B_MORE_RECENT)

    def test_same_seq_larger_checksum_wins(self):
        comp = compare_instances(lsa_of("U2"), lsa_of("U4"))
        self.assertIs(comp.verdict, Verdict.B_MORE_RECENT)
        self.assertIn("13.1(2)", comp.reason)

    def test_same_seq_checksum_maxage_wins(self):
        comp = compare_instances(lsa_of("U4"), lsa_of("U5"))
        self.assertIs(comp.verdict, Verdict.B_MORE_RECENT)
        self.assertIn("13.1(3)", comp.reason)

    def test_age_diff_beyond_maxagediff_younger_wins(self):
        comp = compare_instances(lsa_of("V1"), lsa_of("V2"))
        self.assertIs(comp.verdict, Verdict.B_MORE_RECENT)
        self.assertIn("13.1(4)", comp.reason)

    def test_age_diff_within_maxagediff_equivalent(self):
        comp = compare_instances(lsa_of("V2"), lsa_of("V3"))
        self.assertIs(comp.verdict, Verdict.EQUIVALENT)


class TestReplay(unittest.TestCase):
    def test_order_a_decisions(self):
        _, decisions = replay(samples.ORDER_A)
        self.assertIs(decisions["U2"].action, Action.OVERRIDE)
        self.assertIs(decisions["U3"].action, Action.RETAIN)
        self.assertIs(decisions["U4"].action, Action.OVERRIDE)
        self.assertIs(decisions["U5"].action, Action.FLUSH)
        self.assertIs(decisions["U8"].action, Action.WRAP_RESTART)
        self.assertIs(decisions["U9"].action, Action.REJECT_INVALID)
        self.assertIs(decisions["U10"].action, Action.REJECT_INVALID)
        self.assertIs(decisions["U11"].action, Action.UNCERTAIN)
        self.assertIs(decisions["U12"].action, Action.REJECT_INVALID)
        self.assertIs(decisions["V3"].action, Action.DUPLICATE)

    def test_final_state_converges_across_orders(self):
        store_a, _ = replay(samples.ORDER_A)
        store_b, _ = replay(samples.ORDER_B)
        self.assertEqual(set(store_a.current), set(store_b.current))
        for key in store_a.current:
            a, b = store_a.current[key], store_b.current[key]
            self.assertEqual((a.seq, a.chksum), (b.seq, b.chksum), key)
        # the retained instance for 10.0.0.1 is the post-wrap restart
        key = ("0.0.0.0", 1, "10.0.0.1", "10.0.0.1")
        self.assertEqual(store_a.current[key].seq, INITIAL_SEQ)

    def test_restart_without_observed_flush_not_accepted_as_wrap(self):
        # U8 alone after U6 (no MaxSeq flush): signed order ranks the
        # restart older, so it must be retained as history, not installed
        store = ForensicStore()
        for name in ("U6", "U8"):
            frame, t = FRAME_MAP[name]
            for clsa in decode_ls_update(frame, t).lsas:
                dec = store.apply(clsa)
        self.assertIs(dec.action, Action.RETAIN)

    def test_flush_without_incumbent_is_uncertain(self):
        store = ForensicStore()
        frame, t = FRAME_MAP["U5"]
        dec = store.apply(decode_ls_update(frame, t).lsas[0])
        self.assertIs(dec.action, Action.UNCERTAIN)


if __name__ == "__main__":
    unittest.main()
