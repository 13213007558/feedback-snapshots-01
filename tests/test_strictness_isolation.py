"""
Task isolation for strictness policies.

The same malformed capture is processed by strict and tolerant tasks in
interleaved order.  Each task must keep its own policy through reading,
deferred option decoding and writer-side repairs.
"""

import contextlib
import io
import warnings

import pytest

import pcapng.blocks as blocks
from pcapng import FileScanner, FileWriter
from pcapng.exceptions import PcapngStrictnessError, PcapngStrictnessWarning
from pcapng.strictness import (
    Strictness,
    StrictnessPolicy,
    get_strict_level,
    get_strictness,
    set_strictness,
    strictness_scope,
)


@contextlib.contextmanager
def no_policy_scope():
    yield


def make_sample(obsolete=True, duplicate_option=True):
    """
    Build a capture with an obsolete Packet Block and a repeated,
    non-repeatable option.  Built under NONE so the fixture itself is clean.
    """

    shb = blocks.SectionHeader(endianness="<", strictness=Strictness.NONE)
    shb.new_member(
        blocks.InterfaceDescription,
        link_type=1,
        snaplen=65535,
        strictness=Strictness.NONE,
    )
    cls = blocks.ObsoletePacket if obsolete else blocks.EnhancedPacket
    blk = shb.new_member(cls, packet_data=b"packet bytes", strictness=Strictness.NONE)
    if duplicate_option:
        option = "pack_flags" if obsolete else "epb_flags"
        blk.options.add(option, 1)
        blk.options.add(option, 2)

    out = io.BytesIO()
    writer = FileWriter(out, shb, strictness=Strictness.NONE)
    writer.write_block(blk, strictness=Strictness.NONE)
    return out.getvalue()


def scan(data, level):
    return list(FileScanner(io.BytesIO(data), strictness=level))


def scan_in_task_scope(data, level):
    """
    Scan without an explicit per-reader policy, capturing the task scope.

    The resulting objects remain subject to a nested task scope later,
    unlike objects whose reader was configured explicitly.
    """
    with strictness_scope(level):
        return list(FileScanner(io.BytesIO(data)))


def write_blocks(shb, blk, level=None):
    out = io.BytesIO()
    writer = FileWriter(out, shb, strictness=level)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        writer.write_block(blk)
    return out.getvalue(), caught


def block_types(data):
    return [type(b).__name__ for b in scan(data, Strictness.NONE)]


def test_policy_is_an_immutable_value():
    policy = StrictnessPolicy(Strictness.FIX)
    assert policy.level == Strictness.FIX
    assert policy.strict_level == Strictness.FIX
    assert policy.strictness == Strictness.FIX
    assert policy == Strictness.FIX
    assert policy == StrictnessPolicy(Strictness.FIX)
    assert policy.should_fix()
    assert not StrictnessPolicy(Strictness.WARN).should_fix()

    with pytest.raises(TypeError):
        StrictnessPolicy("fix")


def test_strict_and_tolerant_reads_are_order_independent():
    old_sample = make_sample(obsolete=True)
    option_sample = make_sample(obsolete=False)
    evidence = {}

    for data, option_name in (
        (old_sample, "pack_flags"),
        (option_sample, "epb_flags"),
    ):
        tolerant_runs = []
        for _ in range(2):
            # Strict first: the strict task never gets partial output.
            with pytest.raises(PcapngStrictnessError, match="repeated option"):
                scan(data, Strictness.FORBID)

            # Then tolerant: its two values and diagnostics are its own.
            with pytest.warns(PcapngStrictnessWarning, match="repeated option"):
                tolerant_blocks = scan(data, Strictness.FIX)
            assert len(tolerant_blocks) == 3
            tolerant_runs.append(
                len(tolerant_blocks[2].options.get_all(option_name))
            )

            # Strict again after tolerant work: still no leakage.
            with pytest.raises(PcapngStrictnessError, match="repeated option"):
                scan(data, Strictness.FORBID)

        assert tolerant_runs == [2, 2]
        evidence[option_name] = tolerant_runs

    assert set(evidence) == {"pack_flags", "epb_flags"}


def test_interleaved_authored_capture_is_stable_and_independent():
    data = make_sample(obsolete=True, duplicate_option=True)

    # Reading the same bytes strictly and tolerantly, then converting the
    # old Packet Block, must not change either task's verdict.
    for _ in range(2):
        with pytest.raises(PcapngStrictnessError, match="repeated option"):
            scan(data, Strictness.FORBID)

        with pytest.warns(PcapngStrictnessWarning, match="repeated option"):
            tolerant = scan(data, Strictness.FIX)

        out, caught = write_blocks(tolerant[0], tolerant[2])
        assert block_types(out) == [
            "SectionHeader",
            "InterfaceDescription",
            "EnhancedPacket",
        ]
        assert any("obsolete" in str(w.message) for w in caught)

        # Conversion must not alter the source evidence.
        assert block_types(data) == [
            "SectionHeader",
            "InterfaceDescription",
            "ObsoletePacket",
        ]


def test_strict_task_rejects_obsolete_packet_repair():
    data = make_sample(obsolete=True, duplicate_option=False)
    blocks_ = scan(data, Strictness.FORBID)

    with pytest.raises(PcapngStrictnessError, match="obsolete"):
        write_blocks(blocks_[0], blocks_[2], Strictness.FORBID)


def test_tolerant_task_repairs_and_stays_attributed():
    data = make_sample(obsolete=True, duplicate_option=False)

    for _ in range(2):
        blocks_ = scan(data, Strictness.FIX)
        out, caught = write_blocks(blocks_[0], blocks_[2])
        assert block_types(out) == [
            "SectionHeader",
            "InterfaceDescription",
            "EnhancedPacket",
        ]
        assert any("obsolete" in str(w.message) for w in caught)
        assert all(issubclass(w.category, PcapngStrictnessWarning) for w in caught)

        # A strict run in between must not change the tolerant result.
        with pytest.raises(PcapngStrictnessError, match="obsolete"):
            strict_blocks = scan(data, Strictness.FORBID)
            write_blocks(strict_blocks[0], strict_blocks[2], Strictness.FORBID)


def test_deferred_option_diagnostics_follow_the_originating_task():
    data = make_sample(obsolete=False, duplicate_option=True)

    # Decode the options in a FIX task, then hand the block to another stage.
    tolerant_blocks = scan_in_task_scope(data, Strictness.FIX)
    option = tolerant_blocks[2].options

    # A later edit under a strict scope is governed by that strict scope.
    with strictness_scope(Strictness.FORBID):
        with pytest.raises(PcapngStrictnessError, match="repeated option"):
            option.add("epb_flags", 3)
    assert len(option.get_all("epb_flags")) == 2

    # Leaving the strict scope restores the tolerant policy, whose own
    # auto-fix behavior now applies to the edit.
    with pytest.warns(PcapngStrictnessWarning, match="repeated option"):
        option.add("epb_flags", 3)
    assert len(option.get_all("epb_flags")) == 1

    # The FIX edit already trimmed the non-repeatable option, so writing
    # the tolerant task's block is clean and round-trips one value.
    out, caught = write_blocks(tolerant_blocks[0], tolerant_blocks[2])
    assert not any("repeated option" in str(w.message) for w in caught)
    reread = scan(out, Strictness.FIX)
    assert len(reread[2].options.get_all("epb_flags")) == 1

    # The strict task independently reparses the original bytes and rejects.
    with pytest.raises(PcapngStrictnessError, match="repeated option"):
        scan(data, Strictness.FORBID)


def test_nested_scope_and_exception_do_not_leak():
    data = make_sample(obsolete=True, duplicate_option=True)

    with strictness_scope(Strictness.FIX):
        # Inner strict scope applies to task-captured objects while active...
        scanner = FileScanner(io.BytesIO(data))
        with strictness_scope(Strictness.FORBID):
            with pytest.raises(PcapngStrictnessError):
                list(scanner)

        # ...and the outer policy is restored for fresh work.
        assert len(list(FileScanner(io.BytesIO(data)))) == 3

        with pytest.raises(RuntimeError):
            with strictness_scope(Strictness.FORBID):
                raise RuntimeError("task failed")

        assert get_strict_level() == Strictness.FIX
        assert len(list(FileScanner(io.BytesIO(data)))) == 3

    # Leaving all scopes returns to the compatibility global.
    set_strictness(Strictness.FORBID)
    assert get_strict_level() == Strictness.FORBID


def test_captured_policy_survives_handover_without_writer_policy():
    data = make_sample(obsolete=True, duplicate_option=False)

    with strictness_scope(Strictness.FIX):
        blocks_ = scan(data, None)

    # Scope is gone; a writer created without a policy uses the objects'
    # captured task policy and still performs the repair.
    out, caught = write_blocks(blocks_[0], blocks_[2], None)
    assert block_types(out) == [
        "SectionHeader",
        "InterfaceDescription",
        "EnhancedPacket",
    ]
    assert any("obsolete" in str(w.message) for w in caught)

    # A strict writer can still override the captured policy explicitly.
    with pytest.raises(PcapngStrictnessError, match="obsolete"):
        write_blocks(blocks_[0], blocks_[2], Strictness.FORBID)


def test_explicit_reader_policy_is_not_downgraded_by_ambient_scope():
    data = make_sample(obsolete=True, duplicate_option=False)

    # A strict request configured explicitly must stay strict even while
    # unrelated tolerant work is running in the same thread/task.
    with strictness_scope(Strictness.FIX):
        strict_blocks = scan(data, Strictness.FORBID)
        with pytest.raises(PcapngStrictnessError, match="obsolete"):
            write_blocks(strict_blocks[0], strict_blocks[2], Strictness.FORBID)

    # Conversely, an explicit tolerant writer stays tolerant inside a strict
    # ambient scope.
    blocks_ = scan(data, Strictness.FIX)
    with strictness_scope(Strictness.FORBID):
        out, caught = write_blocks(blocks_[0], blocks_[2], Strictness.FIX)
    assert block_types(out)[-1] == "EnhancedPacket"
    assert any("obsolete" in str(w.message) for w in caught)


def test_compatibility_global_is_only_a_fallback():
    data = make_sample(obsolete=True, duplicate_option=False)
    old_level = get_strictness()
    try:
        set_strictness(Strictness.FIX)
        blocks_ = scan(data, None)
        out, caught = write_blocks(blocks_[0], blocks_[2], None)
        assert block_types(out)[-1] == "EnhancedPacket"
        assert any("obsolete" in str(w.message) for w in caught)

        set_strictness(Strictness.FORBID)
        blocks_ = scan(data, None)
        with pytest.raises(PcapngStrictnessError, match="obsolete"):
            write_blocks(blocks_[0], blocks_[2], None)

        # An explicit task policy wins over the compatibility global.
        set_strictness(Strictness.FORBID)
        with strictness_scope(Strictness.FIX):
            blocks_ = scan(data, None)
        out, caught = write_blocks(blocks_[0], blocks_[2], None)
        assert block_types(out)[-1] == "EnhancedPacket"
    finally:
        set_strictness(old_level.level)
