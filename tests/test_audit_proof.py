"""
Tests for the lifecycle-event proof boundary simulation.

These encode the acceptance criteria from the investigation request:
* one save-committed/publish-failed case,
* one save rollback case (silent and unsafe-early-publish variants),
* public events mapped to committed truth,
* duplicates and missing/gap events distinguishable.
"""

from __future__ import annotations

import json

import pytest

from audit_proof.delivery import Inbox, VerifyingConsumer
from audit_proof.model import (
    PublicCompletionEvent,
    canonical_result_digest,
    stable_event_id,
)
from audit_proof.reconcile import Reconciler, Verdict
from audit_proof.scenarios import (
    JOB_A,
    JOB_G2,
    JOB_L,
    JOB_R1,
    JOB_R2,
    run_simulation,
)
from audit_proof.unit_of_work import (
    AuditUnitOfWork,
    CommittedState,
    make_unbound_early_event,
)


@pytest.fixture(scope="module")
def simulation():
    return run_simulation()


def test_all_built_in_checks_pass(simulation):
    failed = [check for check in simulation.checks if not check.passed]
    assert not failed, "\n".join(f"{c.name}: {c.detail}" for c in failed)


def test_committed_then_publish_failure_is_classified_missing_not_unfinished(
    simulation,
):
    report = simulation.reports["A_after_publish_failure"]
    audit = report.get(JOB_A)
    assert audit.committed is True
    assert audit.received_copies == 0
    assert audit.verdict is Verdict.ended_event_missing_publish_failed


def test_redelivery_is_duplicate_but_effect_happens_once(simulation):
    audit = simulation.reports["final"].get(JOB_A)
    assert audit.verdict is Verdict.verified_ended
    assert audit.received_copies == 2
    assert audit.unique_event_ids == 1
    assert audit.duplicate_copies == 1
    assert audit.accepted_once is True

    event_id = next(iter(simulation.inbox.delivery_count_by_event))
    assert simulation.inbox.delivery_count_by_event[event_id] >= 2
    a_key = simulation.state.facts[JOB_A].idempotency_key
    a_keys = [k for k in simulation.consumer.applied_effects if k == a_key]
    assert len(a_keys) == 1


def test_lost_after_publish_is_distinguished_from_publish_failure(simulation):
    lost = simulation.reports["L_after_loss"].get(JOB_L)
    assert lost.verdict is Verdict.ended_event_lost_after_publish
    assert lost.outbox_status == "published"

    final_l = simulation.reports["final"].get(JOB_L)
    assert final_l.verdict is Verdict.verified_ended


def test_safe_rollback_leaves_no_event(simulation):
    audit = simulation.reports["B1_rollback_silent"].get(JOB_R1)
    assert audit.verdict is Verdict.rolled_back_silent
    assert audit.committed is False
    assert audit.received_copies == 0
    assert JOB_R1 not in simulation.state.facts
    assert simulation.state.outbox_for_job(JOB_R1) == []


def test_early_event_during_rollback_is_phantom_and_quarantined(simulation):
    audit = simulation.reports["B2_early_phantom"].get(JOB_R2)
    assert audit.verdict is Verdict.phantom_early_event
    assert audit.committed is False
    assert audit.received_copies == 1
    assert any("ROLLBACK_CONFIRMED" in finding for finding in audit.findings)
    assert len(simulation.consumer.quarantined) >= 1
    r2_effects = [k for k in simulation.consumer.applied_effects if JOB_R2 in k]
    assert r2_effects == []


def test_sequence_gap_identifies_missing_committed_job(simulation):
    gap_report = simulation.reports["C_gap_open"]
    assert len(gap_report.gaps) == 1
    gap = gap_report.gaps[0]
    assert gap.missing_seq == 2
    assert gap.job_id == JOB_G2
    assert gap.committed is True
    assert gap.received is False

    closed = simulation.reports["C_gap_closed"]
    assert closed.gaps == []
    assert closed.get(JOB_G2).verdict is Verdict.verified_ended


def test_event_id_is_stable_across_redelivery():
    key = "completion|scheduler-1|job-1|success|commit-1"
    assert stable_event_id(key) == stable_event_id(key)


def test_public_event_json_roundtrip_and_no_result_body():
    secret_body = {"token": "super-secret-result", "nested": {"k": "v"}}
    digest = canonical_result_digest(secret_body)
    event = PublicCompletionEvent(
        event_id=stable_event_id("k"),
        job_id="job-1",
        task_id="t",
        outcome="success",
        producer_id="p",
        seq=1,
        idempotency_key="k",
        outbox_id="outbox-1",
        result_ref="apscheduler://job-results/job-1",
        result_digest=digest,
    )
    restored = PublicCompletionEvent.from_json(event.to_json())
    assert restored == event

    frame = event.to_wire()
    assert b"super-secret-result" not in frame
    assert b"sha256:" in frame

    parsed = json.loads(event.to_json())
    assert "return_value" not in parsed
    assert "result_body" not in parsed


def test_digest_detects_tampered_body():
    digest = canonical_result_digest({"a": 1})
    assert canonical_result_digest({"a": 2}) != digest


def test_inbox_duplicate_classification():
    inbox = Inbox()
    event = make_unbound_early_event(
        job_id="j", task_id="t", outcome="success", producer_id="p", seq=1
    )
    assert inbox.receive(event) == "accepted"
    assert inbox.receive(event) == "duplicate"
    assert inbox.duplicate_copy_count == 1


def test_inbox_sequence_gap_tracking():
    inbox = Inbox()

    def event(seq):
        return PublicCompletionEvent(
            event_id=stable_event_id(f"e{seq}"),
            job_id=f"j{seq}",
            task_id="t",
            outcome="success",
            producer_id="p",
            seq=seq,
            idempotency_key=f"k{seq}",
        )

    inbox.receive(event(1))
    inbox.receive(event(3))
    assert [gap.missing_seq for gap in inbox.gaps if gap.producer_id == "p"] == [2]
    inbox.receive(event(2))
    assert [gap for gap in inbox.gaps if gap.producer_id == "p"] == []


def test_verifying_consumer_binds_to_commit():
    state = CommittedState()
    inbox = Inbox()
    consumer = VerifyingConsumer(inbox, state)

    early = make_unbound_early_event(
        job_id="j", task_id="t", outcome="success", producer_id="p", seq=1
    )
    assert consumer.handle(early) == "quarantined_unbound"

    with AuditUnitOfWork(state, producer_id="p") as uow:
        committed_event = uow.stage_completion(
            job_id="j2", task_id="t", outcome="success"
        )

    assert consumer.handle(committed_event) == "applied"
    assert consumer.handle(committed_event) == "duplicate"
    assert len(consumer.applied_effects) == 1


def test_reconciler_reports_phantom_for_unknown_event():
    state = CommittedState()
    inbox = Inbox()
    event = make_unbound_early_event(
        job_id="ghost", task_id="t", outcome="success", producer_id="p", seq=1
    )
    inbox.receive(event)
    report = Reconciler().reconcile(state, inbox, attempted_job_ids=["ghost"])
    assert report.get("ghost").verdict is Verdict.phantom_early_event


# ---------------------------------------------------------------------------
# Real APScheduler integration (skipped if dependencies are unavailable)
# ---------------------------------------------------------------------------


def test_native_proof_event_is_exported_and_reconstitutable():
    pytest.importorskip("apscheduler")
    from datetime import UTC, datetime
    from uuid import uuid4

    from apscheduler import JobCompletionProof
    from apscheduler.serializers.json import JSONSerializer
    from audit_proof.aps_bridge import _ReconstitutionProbe

    proof = JobCompletionProof(
        event_id=uuid4(),
        job_id=uuid4(),
        task_id="t",
        outcome="success",
        producer_id="scheduler-1",
        sequence=1,
        ledger_ref="outbox-1",
        finished_at=datetime.now(UTC),
        committed_at=datetime.now(UTC),
    )
    broker = _ReconstitutionProbe(serializer=JSONSerializer())
    restored = broker.reconstitute_event(broker.generate_notification(proof))
    assert type(restored) is JobCompletionProof
    assert restored.event_id == proof.event_id
    assert restored.outcome.name == "success"


def test_native_event_is_exported_and_visible_to_reconstitute():
    pytest.importorskip("apscheduler")
    import apscheduler
    import apscheduler._events as events_module

    assert apscheduler.JobCompletionProof is events_module.JobCompletionProof
    assert hasattr(events_module, "JobCompletionProof")


def test_live_apscheduler_corroboration():
    from audit_proof.live import run_live_corroboration

    report = run_live_corroboration()
    if not report.available:
        pytest.skip(f"live dependencies unavailable: {report.unavailable_reason}")

    failed = [item for item in report.checks if not item[1]]
    assert not failed, "\n".join(f"{name}: {detail}" for name, _, detail in failed)
    assert len(report.checks) == 3


def test_cli_main_returns_zero(capsys):
    from audit_proof.simulation import main

    exit_code = main(["--no-live"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "ALL CHECKS PASSED" in captured.out
