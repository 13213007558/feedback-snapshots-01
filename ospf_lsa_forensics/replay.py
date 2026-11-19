"""Replay the sample LS Update set in two arrival orders and print an
auditable decision for every captured instance.

Run from the repository root:

    python3 -m ospf_lsa_forensics.replay
"""

from . import samples
from .lsa_forensics import (
    Action,
    ForensicStore,
    Verdict,
    compare_instances,
    decode_ls_update,
    naive_unsigned_newer,
    seq_to_signed,
)

FRAME_MAP = {name: (frame, t) for name, frame, t in samples.FRAMES}


def _decode(name):
    frame, t = FRAME_MAP[name]
    return decode_ls_update(frame, t)


def replay_order(label, order):
    print("=" * 78)
    print("REPLAY %s -- arrival order: %s" % (label, " ".join(order)))
    print("=" * 78)
    store = ForensicStore()
    decisions = []
    for name in order:
        upd = _decode(name)
        print("\n[%s] frame t=%.0f src=%s area=%s authtype=%d (%s)"
              % (name, upd.capture_time, upd.src, upd.area,
                 upd.authtype, upd.auth_note))
        for err in upd.errors:
            print("  frame error: %s" % err)
        if upd.trailing_bytes:
            print("  note: %d trailing bytes beyond OSPF len (unverified "
                  "data, e.g. crypto auth digest)" % upd.trailing_bytes)
        for clsa in upd.lsas:
            print("  raw:      %s" % clsa.raw.hex())
            print("  fields:   %s" % clsa.short())
            dec = store.apply(clsa)
            decisions.append((name, dec))
            print("  decision: %s" % dec.action.value)
            print("  basis:    %s" % dec.reason)
    print("\n-- final retained state after %s --" % label)
    for key, cur in sorted(store.current.items()):
        print("  %s -> %s" % (key, cur.short()))
    return decisions


def counter_examples():
    print("\n" + "=" * 78)
    print("COUNTER-EXAMPLES AGAINST THE COMPARISON LOGIC")
    print("=" * 78)

    def lsa_of(name):
        return _decode(name).lsas[0]

    cases = [
        ("CE1 same seq, different checksum (U2 vs U4)",
         lsa_of("U2"), lsa_of("U4")),
        ("CE2 same seq+checksum, one at MaxAge (U4 vs U5)",
         lsa_of("U4"), lsa_of("U5")),
        ("CE3 same instance, age diff > MaxAgeDiff (V1 vs V2)",
         lsa_of("V1"), lsa_of("V2")),
        ("CE4 same instance, age diff <= MaxAgeDiff (V2 vs V3)",
         lsa_of("V2"), lsa_of("V3")),
        ("CE5 sequence space ends: MaxSequenceNumber vs restart "
         "(U6 vs U8)", lsa_of("U6"), lsa_of("U8")),
    ]
    for title, a, b in cases:
        comp = compare_instances(a, b)
        print("\n%s" % title)
        print("  A: %s" % a.short())
        print("  B: %s" % b.short())
        print("  RFC 2328 verdict: %s" % comp.verdict.value)
        print("  basis: %s" % comp.reason)
        naive = naive_unsigned_newer(a, b)
        rfc_newer_is_b = comp.verdict is Verdict.B_MORE_RECENT
        rfc_newer_is_a = comp.verdict is Verdict.A_MORE_RECENT
        if (a.seq != b.seq
                and ((rfc_newer_is_b and not naive)
                     or (rfc_newer_is_a and naive))):
            print("  DIVERGENCE: unsigned 'larger seq wins' picks the "
                  "other instance (0x%08X vs 0x%08X; signed space: "
                  "%d vs %d)"
                  % (a.seq, b.seq, seq_to_signed(a.seq),
                     seq_to_signed(b.seq)))

    print("\nCE6 corrupted checksum (U9) and CE7 truncated capture "
          "(U10) and CE8 reserved seq 0x80000000 (U12):")
    for name in ("U9", "U10", "U12"):
        clsa = lsa_of(name)
        print("  %s: %s" % (name, "; ".join(clsa.errors) or "valid"))


def main():
    decisions_a = replay_order("A (chronological)", samples.ORDER_A)
    decisions_b = replay_order("B (reordered arrival)", samples.ORDER_B)
    counter_examples()

    print("\n" + "=" * 78)
    print("ORDER SENSITIVITY SUMMARY")
    print("=" * 78)
    by_name_a = {n: d for n, d in decisions_a}
    by_name_b = {n: d for n, d in decisions_b}
    for name in samples.ORDER_A:
        da, db = by_name_a[name].action, by_name_b[name].action
        stable = "stable " if da is db else "DIFFERS"
        print("  %-4s A=%-14s B=%-14s %s"
              % (name, da.value, db.value, stable))
    print("\nConclusions that differ between arrival orders are "
          "order-dependent evidence and must be reported as such, "
          "not as topology changes.")


if __name__ == "__main__":
    main()
