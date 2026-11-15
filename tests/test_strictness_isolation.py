"""
Tests for task-isolated strictness policies.

The library used to expose only a process-wide ``strict_level``.  These tests
pin down the older global entry point while checking that independent tasks
(scopes, scanners, writers) can each own a policy, including across lazy
iteration, delayed option decoding and writer-side automatic fixes.
"""

import io
import threading
import warnings

import pytest

import pcapng.blocks as blocks
import pcapng.strictness as strictness
from pcapng import FileScanner, FileWriter
from pcapng.exceptions import PcapngStrictnessError, PcapngStrictnessWarning
from pcapng.strictness import (
    Strictness,
    StrictnessPolicy,
    get_strictness,
    get_strictness_policy,
    set_strictness,
    strictness_scope,
)

MALFORMED_OPTION = "repeated option 2 'if_name' not permitted by pcapng spec"
OBSOLETE_OPTION = "Packet Block is obsolete and must not be used"


def build_repeated_option_capture():
    """
    Build a capture whose IDB repeats a non-repeatable option.

    The repeat is produced with a tolerant policy because constructing it
    under the default strict policy would (correctly) be rejected.
    """
    with strictness_scope(StrictnessPolicy(Strictness.WARN)):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            shb = blocks.SectionHeader(endianness="<")
            idb = shb.new_member(blocks.InterfaceDescription, link_type=1, snaplen=60)
            idb.options.add("if_name", "first")
            idb.options.add("if_name", "second")
            stream = io.BytesIO()
            FileWriter(stream, shb)
    return stream.getvalue()


def read_with(policy):
    """Read the malformed capture under the given policy, with warnings caught."""
    stream = io.BytesIO(MALFORMED_CAPTURE)
    with strictness_scope(policy):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            parsed = list(FileScanner(stream))
    return parsed, caught


MALFORMED_CAPTURE = build_repeated_option_capture()


def load_obsolete_capture():
    with open("test_data/test006-fixed.ntar", "rb") as fp:
        with strictness_scope(StrictnessPolicy(Strictness.WARN, name="reader")):
            return list(FileScanner(fp))


def write_blocks(parsed, policy, strictness_policy=None):
    stream = io.BytesIO()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        writer = FileWriter(
            stream,
            parsed[0],
            policy=policy,
            strictness_policy=strictness_policy,
        )
        writer.write_block(parsed[2])
    return stream.getvalue(), caught


# ---------------------------------------------------------------------------
# Legacy global entry point
# ---------------------------------------------------------------------------


def test_legacy_set_strictness_still_works():
    set_strictness(Strictness.FIX)
    try:
        assert get_strictness() == Strictness.FIX
        assert strictness.strict_level == Strictness.FIX
        assert get_strictness_policy().should_fix()
    finally:
        set_strictness(Strictness.FORBID)

    assert get_strictness() == Strictness.FORBID


# ---------------------------------------------------------------------------
# Delayed option decoding
# ---------------------------------------------------------------------------


def test_delayed_option_error_is_rejected_by_strict_task():
    # The scanner is created inside the strict task; the malformed option is
    # only decoded while iterating later (even after the scope has exited).
    scanner = FileScanner(io.BytesIO(MALFORMED_CAPTURE))
    with strictness_scope(StrictnessPolicy(Strictness.FORBID, name="forensic")):
        scanner = FileScanner(io.BytesIO(MALFORMED_CAPTURE))
    with pytest.raises(PcapngStrictnessError, match="repeated option"):
        list(scanner)


def test_delayed_option_error_is_diagnosed_by_tolerant_task():
    policy = StrictnessPolicy(Strictness.WARN, name="convert", record=True)
    scanner = FileScanner(io.BytesIO(MALFORMED_CAPTURE))
    with strictness_scope(policy):
        scanner = FileScanner(io.BytesIO(MALFORMED_CAPTURE))
    # Iterate outside the scope: the policy must travel with the scanner.
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        parsed = list(scanner)
    assert [type(b).__name__ for b in parsed] == [
        "SectionHeader",
        "InterfaceDescription",
    ]
    assert [str(w) for w in policy.diagnostics] == [MALFORMED_OPTION]
    assert policy.diagnostics[0].policy_name == "convert"
    assert [str(w.message) for w in caught if isinstance(w.message, Warning)] == [
        MALFORMED_OPTION
    ]


def test_tolerant_read_preserves_both_values_and_records_diagnostic():
    policy = StrictnessPolicy(Strictness.FIX, name="repair", record=True)
    parsed, caught = read_with(policy)
    idb = parsed[1]
    # Reading is evidence: the duplicate is reported, not silently dropped.
    assert idb.options.get_all("if_name") == ["first", "second"]
    assert [str(w) for w in policy.diagnostics] == [MALFORMED_OPTION]
    assert any(isinstance(w.message, PcapngStrictnessWarning) for w in caught)


# ---------------------------------------------------------------------------
# Writer-side fixes for the obsolete Packet Block
# ---------------------------------------------------------------------------


def test_obsolete_packet_strict_task_always_rejects():
    parsed = load_obsolete_capture()
    assert isinstance(parsed[2], blocks.ObsoletePacket)

    for name in ("first", "second", "third"):
        with pytest.raises(PcapngStrictnessError, match="obsolete") as excinfo:
            write_blocks(parsed, StrictnessPolicy(Strictness.FORBID, name=name))
        assert excinfo.value.policy_name == name


def test_obsolete_packet_tolerant_task_fixes_and_owns_diagnostics():
    parsed = load_obsolete_capture()
    policy = StrictnessPolicy(Strictness.FIX, name="convert", record=True)
    raw, caught = write_blocks(parsed, policy)

    assert [str(w) for w in policy.diagnostics] == [OBSOLETE_OPTION]
    assert policy.diagnostics[0].policy_name == "convert"
    assert [
        w.message.policy_name for w in caught if hasattr(w.message, "policy_name")
    ] == ["convert"]

    reread = list(FileScanner(io.BytesIO(raw)))
    assert isinstance(reread[2], blocks.EnhancedPacket)
    assert reread[2].packet_data == parsed[2].packet_data


def test_warn_task_writes_obsolete_block_without_fixing():
    parsed = load_obsolete_capture()
    policy = StrictnessPolicy(Strictness.WARN, name="audit", record=True)
    raw, _ = write_blocks(parsed, policy)
    assert [str(w) for w in policy.diagnostics] == [OBSOLETE_OPTION]
    assert isinstance(list(FileScanner(io.BytesIO(raw)))[2], blocks.ObsoletePacket)


# ---------------------------------------------------------------------------
# Interleaved strict / tolerant tasks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("strict_first", [True, False])
def test_interleaved_reads_do_not_depend_on_order(strict_first):
    set_strictness(Strictness.NONE)
    strict_policy = StrictnessPolicy(Strictness.FORBID, name="forensic")
    tolerant_policy = StrictnessPolicy(Strictness.WARN, name="convert", record=True)

    def strict_read():
        with pytest.raises(PcapngStrictnessError, match="repeated option"):
            with strictness_scope(strict_policy):
                list(FileScanner(io.BytesIO(MALFORMED_CAPTURE)))

    def tolerant_read():
        parsed, _ = read_with(tolerant_policy)
        assert isinstance(parsed[1], blocks.InterfaceDescription)
        assert [str(w) for w in tolerant_policy.diagnostics] == [MALFORMED_OPTION]

    for _ in range(3):
        if strict_first:
            strict_read()
            tolerant_read()
            tolerant_policy.diagnostics.clear()
        else:
            tolerant_read()
            tolerant_policy.diagnostics.clear()
            strict_read()

    assert get_strictness() == Strictness.NONE


def test_interleaved_obsolete_writes_do_not_depend_on_order():
    parsed = load_obsolete_capture()
    tolerant_policy = StrictnessPolicy(Strictness.FIX, name="convert", record=True)

    def tolerant_write():
        raw, _ = write_blocks(parsed, tolerant_policy)
        assert isinstance(list(FileScanner(io.BytesIO(raw)))[2], blocks.EnhancedPacket)
        assert [str(w) for w in tolerant_policy.diagnostics] == [OBSOLETE_OPTION]
        tolerant_policy.diagnostics.clear()

    def strict_write():
        with pytest.raises(PcapngStrictnessError, match="obsolete"):
            write_blocks(parsed, StrictnessPolicy(Strictness.FORBID, name="forensic"))

    for _ in range(3):
        tolerant_write()
        strict_write()

    # The policy used to read the blocks is still explainable on the blocks.
    assert parsed[2].strictness_policy is not None
    assert parsed[2].strictness_policy.name == "reader"


# ---------------------------------------------------------------------------
# Policy survives hand-off between processing stages
# ---------------------------------------------------------------------------


def test_block_keeps_read_policy_but_writer_uses_its_own():
    parsed = load_obsolete_capture()
    block = parsed[2]
    assert block.strictness_policy.name == "reader"
    assert block.options.strictness_policy.name == "reader"

    # A strict writer must reject even though the block was read tolerantly.
    with strictness_scope(StrictnessPolicy(Strictness.FORBID, name="writer")):
        with pytest.raises(PcapngStrictnessError, match="obsolete"):
            FileWriter(io.BytesIO(), parsed[0]).write_block(block)

    # Writing the same block directly inside a strict task is rejected too.
    with strictness_scope(StrictnessPolicy(Strictness.FORBID, name="direct")):
        with pytest.raises(PcapngStrictnessError, match="obsolete"):
            block._write(io.BytesIO())

    # A tolerant writer may convert it, attributing the fix to its own task.
    policy = StrictnessPolicy(Strictness.FIX, name="converter", record=True)
    raw, _ = write_blocks(parsed, policy)
    assert [w.policy_name for w in policy.diagnostics] == ["converter"]
    # The source block still reports the policy of the task that read it.
    assert block.strictness_policy.name == "reader"


def test_options_written_under_explicit_writer_policy():
    # Repeated option writing is a strictness problem; the writer's policy
    # decides whether to reject or fix, independently from the reader's.
    with strictness_scope(StrictnessPolicy(Strictness.WARN, name="reader")):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            shb = blocks.SectionHeader(endianness="<")
            idb = shb.new_member(
                blocks.InterfaceDescription, link_type=1, snaplen=0
            )
            idb.options.add("if_name", "one")
            idb.options.add("if_name", "two")

    writer_policy = StrictnessPolicy(Strictness.FIX, name="writer", record=True)
    stream = io.BytesIO()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        # The writer emits the section's IDBs while starting it.
        FileWriter(stream, shb, policy=writer_policy)

    written = list(FileScanner(io.BytesIO(stream.getvalue())))
    assert written[1].options.get_all("if_name") == ["one"]
    assert [w.policy_name for w in writer_policy.diagnostics] == ["writer"]
    assert any("repeated option" in str(w) for w in caught)
    # The reader's policy is untouched by the writer's fix.
    assert idb.strictness_policy.name == "reader"


# ---------------------------------------------------------------------------
# Nested scopes and exceptional exits must not leak
# ---------------------------------------------------------------------------


def test_nested_scopes_restore_even_after_exception():
    set_strictness(Strictness.NONE)
    try:
        assert get_strictness() == Strictness.NONE
        with strictness_scope(StrictnessPolicy(Strictness.FORBID, name="outer")):
            assert get_strictness_policy().name == "outer"
            with pytest.raises(RuntimeError):
                with strictness_scope(StrictnessPolicy(Strictness.WARN, name="inner")):
                    assert get_strictness_policy().name == "inner"
                    raise RuntimeError("boom")
            assert get_strictness_policy().name == "outer"
        assert get_strictness() == Strictness.NONE
    finally:
        set_strictness(Strictness.FORBID)


def test_reused_policy_object_as_context_manager_is_reentrant():
    policy = StrictnessPolicy(Strictness.WARN, name="reused")
    with policy:
        assert get_strictness_policy() is policy
        with policy:
            assert get_strictness_policy() is policy
        assert get_strictness_policy() is policy
    assert get_strictness() == Strictness.FORBID


def test_global_changes_do_not_affect_active_task():
    set_strictness(Strictness.FORBID)
    try:
        with strictness_scope(StrictnessPolicy(Strictness.WARN, name="task")):
            set_strictness(Strictness.NONE)
            assert get_strictness() == Strictness.WARN
        assert get_strictness() == Strictness.NONE
    finally:
        set_strictness(Strictness.FORBID)


# ---------------------------------------------------------------------------
# Concurrent requests
# ---------------------------------------------------------------------------


def test_active_scope_overrides_policy_captured_by_scanner():
    # A scanner remembers its reader, but an explicit scope is an override.
    scanner = FileScanner(io.BytesIO(MALFORMED_CAPTURE))
    with strictness_scope(StrictnessPolicy(Strictness.WARN, name="reader")):
        scanner = FileScanner(io.BytesIO(MALFORMED_CAPTURE))
    assert scanner.strictness_policy.name == "reader"

    with strictness_scope(StrictnessPolicy(Strictness.FORBID, name="override")):
        with pytest.raises(PcapngStrictnessError, match="repeated option"):
            list(scanner)

    # Iterating again outside a scope uses the scanner's own policy.
    policy = StrictnessPolicy(Strictness.WARN, name="reader", record=True)
    scanner = FileScanner(io.BytesIO(MALFORMED_CAPTURE), policy=policy)
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        parsed = list(scanner)
    assert parsed and [str(w) for w in policy.diagnostics] == [MALFORMED_OPTION]


def test_scanner_policy_is_usable_after_hand_off():
    policy = StrictnessPolicy(Strictness.WARN, name="reader", record=True)
    scanner = FileScanner(io.BytesIO(MALFORMED_CAPTURE), policy=policy)
    assert scanner.policy is policy
    parsed = list(scanner)
    assert parsed
    assert [str(w) for w in policy.diagnostics] == [MALFORMED_OPTION]

    scanner = FileScanner(io.BytesIO(MALFORMED_CAPTURE))
    scanner.use_policy(policy)
    assert scanner.strictness_policy is policy


def test_block_and_options_policy_can_be_rebound():
    policy = StrictnessPolicy(Strictness.WARN, name="rebound", record=True)
    scanner = FileScanner(io.BytesIO(MALFORMED_CAPTURE), policy=policy)
    parsed = list(scanner)
    idb = parsed[1]
    assert idb.options.strictness_policy is policy
    new_policy = StrictnessPolicy(Strictness.NONE, name="new")
    idb.options.policy = new_policy
    assert idb.options.strictness_policy is new_policy
    idb.policy = new_policy
    assert idb.strictness_policy is new_policy
    assert idb.options.strictness_policy is new_policy


def test_policies_are_isolated_between_threads():
    strict_policy = StrictnessPolicy(Strictness.FORBID, name="strict")
    tolerant_policy = StrictnessPolicy(Strictness.WARN, name="tolerant", record=True)
    barrier = threading.Barrier(2)
    results = {}

    def worker(name, policy):
        for _ in range(10):
            barrier.wait()
            with strictness_scope(policy):
                try:
                    list(FileScanner(io.BytesIO(MALFORMED_CAPTURE)))
                except PcapngStrictnessError:
                    outcome = "rejected"
                else:
                    outcome = "accepted"
            barrier.wait()
            results.setdefault(name, set()).add(outcome)

    threads = [
        threading.Thread(target=worker, args=("strict", strict_policy)),
        threading.Thread(target=worker, args=("tolerant", tolerant_policy)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results["strict"] == {"rejected"}
    assert results["tolerant"] == {"accepted"}
    assert tolerant_policy.diagnostics
    assert all(w.policy_name == "tolerant" for w in tolerant_policy.diagnostics)
