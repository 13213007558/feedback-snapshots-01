#!/usr/bin/env python3
"""Generate and verify offline, synthetic config-provenance evidence.

Run from the repository root:
    .venv/bin/python scripts/audit_config_evidence.py \
        --output audit-evidence.synthetic.json

The script uses the real Elastic APM Python agent objects but replaces HTTP
sending with an in-process transport. It does not bind a port or contact a
remote service.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import random
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import elasticapm.traces as traces_module  # noqa: E402
from elasticapm import Client  # noqa: E402
from elasticapm.traces import Span, Transaction  # noqa: E402
from elasticapm.transport.base import Transport  # noqa: E402
from elasticapm.utils import disttracing  # noqa: E402

SYNTHETIC_MARKER = "SYNTHETIC-AUDIT-FB7558"
SCHEMA = "elastic-apm-config-evidence/v1"
SEED = 75582807558

APPROVED_FIELDS = [
    "artifact_schema",
    "synthetic_marker",
    "sharing.mode",
    "sharing.approved_field_list",
    "approval.share_gate",
    "approval.human_release_signature",
    "rule_catalog.rule_version",
    "rule_catalog.fingerprint_sha256",
    "rule_catalog.approved_values.exit_span_min_duration_ms",
    "implementation_anchors",
    "events.seq",
    "events.phase",
    "events.kind",
    "events.alias",
    "events.transaction_id",
    "events.span_id",
    "events.trace_id_digest",
    "events.rule_version_at_start",
    "events.rule_version_at_span_creation",
    "events.rule_version_used_by_snapshot",
    "events.current_rule_version_at_decision",
    "events.rule_version_at_enqueue",
    "events.rule_version_at_dequeue",
    "events.rule_version_at_take",
    "events.rule_version_at_send",
    "events.snapshot_exit_span_min_duration_ms",
    "events.current_exit_span_min_duration_ms",
    "events.span_duration_ms",
    "events.discardable",
    "events.decision",
    "events.event_type",
    "events.processor_retained",
    "events.event_refs",
    "events.batch_seq",
    "events.forced_flush",
    "events.payload_sha256",
    "events.observed",
    "events.evidence_status",
    "events.historical_representation",
    "events.prev_hash",
    "events.record_hash",
    "outbound_only_counterfactual",
    "legacy_representation",
    "assertions",
    "verification",
]

# Deterministic IDs and trace IDs make repeated local reviews easy to compare.
_RNG = random.Random(SEED)
traces_module.random = _RNG
disttracing.random = _RNG


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def trace_digest(trace_id: Optional[str]) -> Optional[str]:
    return None if trace_id is None else "sha256:" + sha256_text("trace:" + trace_id)


class EvidenceLedger:
    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []
        self._previous_hash = "0" * 64
        self.tx_aliases: Dict[str, str] = {}
        self.span_aliases: Dict[str, str] = {}
        self.tx_rule_versions: Dict[str, str] = {}

    def append(self, phase: str, kind: str, **fields: Any) -> Dict[str, Any]:
        record: Dict[str, Any] = {
            "seq": len(self.events) + 1,
            "phase": phase,
            "kind": kind,
        }
        record.update({key: value for key, value in fields.items() if value is not None})
        record["prev_hash"] = self._previous_hash
        record["record_hash"] = sha256_text(canonical_json({k: v for k, v in record.items() if k != "record_hash"}))
        self._previous_hash = record["record_hash"]
        self.events.append(record)
        return record

    def alias_tx(self, transaction: Transaction, alias: str, rule_version: str) -> None:
        self.tx_aliases[transaction.id] = alias
        self.tx_rule_versions[transaction.id] = rule_version

    def tx_alias(self, tx_id: str) -> str:
        return self.tx_aliases.get(tx_id, "tx-unmapped")

    def span_alias(self, span_id: str, tx_id: str) -> str:
        return self.span_aliases.get(span_id, f"span-unmapped-{len(self.span_aliases) + 1}")


LEDGER = EvidenceLedger()


class EvidenceTransport(Transport):
    """In-process transport that records the real base-class flush boundary."""

    audit_ledger = LEDGER

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._active_batch: Optional[Dict[str, Any]] = None
        self._batch_count = 0

    def queue(self, event_type: str, data: Any, flush: bool = False) -> None:
        if isinstance(data, dict) and event_type in ("transaction", "span"):
            tx_id = data.get("transaction_id") or data.get("id")
            self.audit_ledger.append(
                "agent_queue",
                "event_enqueued",
                event_type=event_type,
                alias=(
                    self.audit_ledger.span_alias(data["id"], tx_id)
                    if event_type == "span"
                    else self.audit_ledger.tx_alias(data["id"])
                ),
                transaction_id=tx_id,
                span_id=data.get("id") if event_type == "span" else None,
                rule_version_at_enqueue=self.client.config.config_version,
                observed=True,
                evidence_status="observed_at_runtime",
            )
        super().queue(event_type, data, flush=flush)

    def _process_event(self, event_type: str, data: Any) -> Any:
        processed = super()._process_event(event_type, data)
        if event_type in ("transaction", "span") and isinstance(data, dict):
            tx_id = data.get("transaction_id") or data.get("id")
            LEDGER.append(
                "transport_dequeue",
                "event_dequeued",
                event_type=event_type,
                alias=(
                    LEDGER.span_alias(data["id"], tx_id)
                    if event_type == "span"
                    else LEDGER.tx_alias(data["id"])
                ),
                transaction_id=tx_id,
                span_id=data.get("id") if event_type == "span" else None,
                rule_version_at_dequeue=self.client.config.config_version,
                processor_retained=processed is not None,
                observed=True,
                evidence_status="observed_at_runtime",
            )
        return processed

    def _flush(self, buffer: Any, forced_flush: bool = False) -> None:
        self._batch_count += 1
        batch_seq = self._batch_count
        self._active_batch = {
            "batch_seq": batch_seq,
            "forced_flush": forced_flush,
            "rule_version_at_take": self.client.config.config_version,
            "event_refs": [],
        }
        try:
            super()._flush(buffer, forced_flush=forced_flush)
            if self._active_batch is not None:
                LEDGER.append("transport_batch", "batch_taken_and_sent", observed=True, **self._active_batch)
        finally:
            self._active_batch = None

    def send(self, data: Any, forced_flush: bool = False, **kwargs: Any) -> None:
        if self._active_batch is None:
            return
        self._active_batch["rule_version_at_send"] = self.client.config.config_version
        raw = gzip.decompress(bytes(data))
        self._active_batch["payload_sha256"] = "sha256:" + hashlib.sha256(raw).hexdigest()
        for line in raw.splitlines():
            record = json.loads(line.decode("utf-8"))
            if "metadata" in record:
                # Deliberately discarded: host/service/process metadata is not
                # part of the shareable synthetic evidence.
                continue
            event_type, body = next((key, value) for key, value in record.items() if key in ("transaction", "span"))
            tx_id = body.get("transaction_id") or body.get("id")
            ref = {
                "event_type": event_type,
                "alias": (
                    LEDGER.span_alias(body["id"], tx_id)
                    if event_type == "span"
                    else LEDGER.tx_alias(body["id"])
                ),
                "transaction_id": tx_id,
                "span_id": body.get("id") if event_type == "span" else None,
                "observed_fields": {
                    "name": body.get("name"),
                    "sampled": body.get("sampled"),
                    "span_count": body.get("span_count"),
                    "duration_ms": body.get("duration"),
                    "outcome": body.get("outcome"),
                    "composite": body.get("composite"),
                    "dropped_spans_stats_count": len(body.get("dropped_spans_stats", [])),
                },
            }
            self._active_batch["event_refs"].append(ref)


def install_probes() -> None:
    original_begin_transaction = traces_module.Tracer.begin_transaction
    original_begin_span = Transaction._begin_span
    original_report = Span.report

    def begin_transaction_probe(self: traces_module.Tracer, *args: Any, **kwargs: Any) -> Transaction:
        tx = original_begin_transaction(self, *args, **kwargs)
        version = self.config.config_version
        LEDGER.alias_tx(tx, f"tx-{len(LEDGER.tx_aliases) + 1}", version)
        LEDGER.append(
            "transaction_start",
            "transaction_started",
            alias=LEDGER.tx_alias(tx.id),
            transaction_id=tx.id,
            trace_id_digest=trace_digest(tx.trace_parent.trace_id),
            rule_version_at_start=version,
            rule_version_used_by_snapshot=version,
            snapshot_exit_span_min_duration_ms=(
                tx.config_exit_span_min_duration.total_seconds() * 1000
            ),
            observed=True,
            evidence_status="observed_at_runtime",
        )
        return tx

    def begin_span_probe(self: Transaction, *args: Any, **kwargs: Any) -> Span:
        span = original_begin_span(self, *args, **kwargs)
        if isinstance(span, Span):
            tx_alias = LEDGER.tx_alias(self.id)
            alias = f"span-for-{tx_alias}"
            LEDGER.span_aliases[span.id] = alias
            LEDGER.append(
                "span_decision",
                "span_created",
                alias=alias,
                transaction_id=self.id,
                span_id=span.id,
                rule_version_at_span_creation=LEDGER.tx_rule_versions.get(self.id),
                rule_version_used_by_snapshot=LEDGER.tx_rule_versions.get(self.id),
                snapshot_exit_span_min_duration_ms=(
                    self.config_exit_span_min_duration.total_seconds() * 1000
                ),
                current_exit_span_min_duration_ms=(
                    self.tracer.config.exit_span_min_duration.total_seconds() * 1000
                ),
                observed=True,
                evidence_status="observed_at_runtime",
            )
        return span

    def report_probe(self: Span) -> None:
        tx = self.transaction
        threshold = tx.config_exit_span_min_duration
        would_drop = bool(
            self.discardable and self.duration is not None and self.duration < threshold
        )
        LEDGER.append(
            "span_decision",
            "span_report_rule_evaluated",
            alias=LEDGER.span_alias(self.id, tx.id),
            transaction_id=tx.id,
            span_id=self.id,
            rule_version_at_span_creation=LEDGER.tx_rule_versions.get(tx.id),
            rule_version_used_by_snapshot=LEDGER.tx_rule_versions.get(tx.id),
            current_rule_version_at_decision=tx.tracer.config.config_version,
            snapshot_exit_span_min_duration_ms=threshold.total_seconds() * 1000,
            current_exit_span_min_duration_ms=(
                tx.tracer.config.exit_span_min_duration.total_seconds() * 1000
            ),
            span_duration_ms=self.duration.total_seconds() * 1000 if self.duration else None,
            discardable=self.discardable,
            decision="dropped_by_exit_span_min_duration" if would_drop else "eligible_for_agent_queue",
            observed=True,
            evidence_status="observed_at_runtime",
        )
        return original_report(self)

    traces_module.Tracer.begin_transaction = begin_transaction_probe  # type: ignore[assignment]
    Transaction._begin_span = begin_span_probe  # type: ignore[assignment]
    Span.report = report_probe  # type: ignore[method-assign]


def build_client() -> Client:
    return Client(
        service_name="synthetic-audit-service",
        environment="synthetic",
        server_url="http://127.0.0.1:0",
        transport_class="__main__.EvidenceTransport",
        central_config=False,
        metrics_sets=[],
        metrics_interval="0s",
        breakdown_metrics=False,
        api_request_time="1s",
        transaction_sample_rate=1.0,
        enabled=True,
        disable_send=False,
        capture_stack_traces=False,
        span_stack_trace_min_duration=-1,
    )


def rule_catalog() -> List[Dict[str, Any]]:
    rules = [
        ("R1", 10),
        ("R2", 0),
    ]
    catalog = []
    for version, threshold_ms in rules:
        approved_values = {"exit_span_min_duration_ms": threshold_ms}
        catalog.append(
            {
                "rule_version": version,
                "approved_values": approved_values,
                "fingerprint_sha256": sha256_text(canonical_json(approved_values)),
            }
        )
    return catalog


def run_scenario(output: Path) -> Dict[str, Any]:
    install_probes()
    client = build_client()
    try:
        client.config.update(version="R1", exit_span_min_duration="10ms")

        old_tx = client.begin_transaction("synthetic-audit")
        client.config.update(version="R2", exit_span_min_duration="0ms")

        new_tx = client.begin_transaction("synthetic-audit")
        new_span = new_tx.begin_span(
            "synthetic-fast-exit",
            "synthetic.exit",
            leaf=True,
            context={"destination": {"service": {"resource": "synthetic-resource"}}},
            auto_activate=False,
        )
        new_span.set_success()
        new_span.end(duration=timedelta(milliseconds=5))
        client.end_transaction(
            name="tx-new-sent-first", result="synthetic-ok", duration=timedelta(milliseconds=42)
        )
        client._transport.flush()  # noqa: SLF001 - deterministic offline batch boundary

        traces_module.execution_context.set_transaction(old_tx)
        old_span = old_tx.begin_span(
            "synthetic-fast-exit",
            "synthetic.exit",
            leaf=True,
            context={"destination": {"service": {"resource": "synthetic-resource"}}},
            auto_activate=False,
        )
        old_span.set_success()
        old_span.end(duration=timedelta(milliseconds=5))
        client.end_transaction(
            name="tx-old-started-first-sent-last", result="synthetic-ok", duration=timedelta(milliseconds=84)
        )
        client._transport.flush()  # noqa: SLF001 - deterministic offline batch boundary
    finally:
        client.close()

    artifact = build_artifact()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(artifact, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return artifact


def build_artifact() -> Dict[str, Any]:
    batches = [event for event in LEDGER.events if event["kind"] == "batch_taken_and_sent"]
    assertions = evaluate_assertions(LEDGER.events, batches)
    return {
        "artifact_schema": SCHEMA,
        "synthetic_marker": SYNTHETIC_MARKER,
        "sharing": {
            "mode": "synthetic-only",
            "approved_field_list": "approval.approved_fields",
            "metadata_handling": "agent metadata record is parsed only in memory and omitted",
        },
        "approval": {
            "share_gate": "synthetic_marker_and_approved_field_allowlist_only",
            "approved_fields": APPROVED_FIELDS,
            "human_release_signature": "attach-out-of-band-before-external-sharing",
        },
        "rule_catalog": rule_catalog(),
        "implementation_anchors": [
            {"point": "transaction_config_snapshot", "path": "elasticapm/traces.py", "line": 229},
            {"point": "transaction_sampling_rule", "path": "elasticapm/traces.py", "line": 974},
            {"point": "exit_span_report_decision", "path": "elasticapm/traces.py", "line": 717},
            {"point": "transport_event_dequeue", "path": "elasticapm/transport/base.py", "line": 129},
            {"point": "transport_ndjson_serialize", "path": "elasticapm/transport/base.py", "line": 152},
            {"point": "transport_batch_flush", "path": "elasticapm/transport/base.py", "line": 176},
        ],
        "events": LEDGER.events,
        "outbound_only_counterfactual": {
            "recorded_field": "current_rule_version_at_outbound",
            "batch_1": {
                "outbound_rule_version": "R2",
                "would_claim_for": ["tx-2", "span-for-tx-2"],
                "correct_for_collection": True,
            },
            "batch_2": {
                "outbound_rule_version": "R2",
                "would_claim_for": ["tx-1"],
                "correct_for_collection": False,
                "actual_collection_rule_version": "R1",
            },
            "proof_limit": (
                "An outbound label proves only the version current when the batch was taken/sent, "
                "not the immutable rule used at transaction/span collection."
            ),
        },
        "legacy_representation": {
            "known_version_token": "R1/R2/... only when an immutable collection record exists",
            "collection_rule_version": "UNVERIFIABLE_NOT_RECORDED",
            "collection_rule_fingerprint_sha256": None,
            "send_rule_version": "UNVERIFIABLE_NOT_RECORDED",
            "outbound_only_version_if_separately_logged": "R2_OUTBOUND_OBSERVED_BUT_COLLECTION_STILL_UNKNOWN",
            "missing_span_with_drop_count": "ABSENT_SPAN_DROP_COUNTED_BUT_RULE_UNVERSIONED",
            "missing_span_without_drop_count": "ABSENT_BUT_NOT_PROVEN_NEVER_CREATED",
            "allowed_inference": (
                "Only payload fields, IDs, counts, and collector/batch records independently retained "
                "may be treated as evidence."
            ),
            "forbidden_inference": (
                "Do not backfill the outbound/current rule version as the historical collection rule version."
            ),
        },
        "assertions": assertions,
        "verification": verify_event_chain(LEDGER.events),
    }


def evaluate_assertions(events: List[Dict[str, Any]], batches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    starts = [e for e in events if e["kind"] == "transaction_started"]
    decisions = [e for e in events if e["kind"] == "span_report_rule_evaluated"]
    dequeued = [e for e in events if e["kind"] == "event_dequeued"]
    decision_by_tx = {event["transaction_id"]: event for event in decisions}
    old_start = next((e for e in starts if e.get("rule_version_at_start") == "R1"), {})
    new_start = next((e for e in starts if e.get("rule_version_at_start") == "R2"), {})
    old_tx_id = old_start.get("transaction_id")
    new_tx_id = new_start.get("transaction_id")
    first_batch = batches[0] if batches else {"event_refs": []}
    second_batch = batches[1] if len(batches) > 1 else {"event_refs": []}
    checks = [
        ("two_transactions_started", len(starts) == 2),
        ("old_transaction_uses_R1", old_start.get("rule_version_at_start") == "R1"),
        ("new_transaction_uses_R2", new_start.get("rule_version_at_start") == "R2"),
        (
            "new_span_is_queued_under_R2",
            decision_by_tx.get(new_tx_id, {}).get("decision") == "eligible_for_agent_queue",
        ),
        (
            "old_span_is_dropped_under_R1_snapshot",
            decision_by_tx.get(old_tx_id, {}).get("decision")
            == "dropped_by_exit_span_min_duration",
        ),
        (
            "new_batch_is_first",
            first_batch.get("batch_seq") == 1
            and any(r.get("transaction_id") == new_tx_id for r in first_batch.get("event_refs", [])),
        ),
        (
            "first_batch_contains_new_span",
            any(
                r.get("event_type") == "span" and r.get("transaction_id") == new_tx_id
                for r in first_batch.get("event_refs", [])
            ),
        ),
        (
            "old_batch_is_second_and_has_no_span",
            second_batch.get("batch_seq") == 2
            and any(r.get("transaction_id") == old_tx_id for r in second_batch.get("event_refs", []))
            and not any(r["event_type"] == "span" for r in second_batch.get("event_refs", [])),
        ),
        (
            "dequeue_order_is_new_span_new_tx_old_tx",
            [event.get("alias") for event in dequeued]
            == ["span-for-tx-2", "tx-2", "tx-1"],
        ),
        ("both_batches_send_under_R2", all(b.get("rule_version_at_send") == "R2" for b in batches)),
    ]
    return [{"name": name, "passed": bool(passed)} for name, passed in checks]


def verify_event_chain(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    previous_hash = "0" * 64
    errors: List[str] = []
    for event in events:
        expected_prev = event.get("prev_hash")
        if expected_prev != previous_hash:
            errors.append(f"previous hash mismatch at seq {event.get('seq')}")
        stored_hash = event.get("record_hash")
        unsigned = {k: v for k, v in event.items() if k != "record_hash"}
        actual_hash = sha256_text(canonical_json(unsigned))
        if stored_hash != actual_hash:
            errors.append(f"record hash mismatch at seq {event.get('seq')}")
        previous_hash = stored_hash
    return {
        "status": "verified" if not errors else "failed",
        "event_count": len(events),
        "final_hash": previous_hash,
        "errors": errors,
        "offline_command": ".venv/bin/python scripts/audit_config_evidence.py --verify audit-evidence.synthetic.json",
    }


def verify_file(path: Path) -> int:
    artifact = json.loads(path.read_text(encoding="utf-8"))
    events = artifact.get("events", [])
    result = verify_event_chain(events)
    batches = [event for event in events if event.get("kind") == "batch_taken_and_sent"]
    recomputed = evaluate_assertions(events, batches)
    failed_assertions = [a["name"] for a in recomputed if not a["passed"]]
    rule_errors = []
    for rule in artifact.get("rule_catalog", []):
        expected = sha256_text(canonical_json(rule.get("approved_values", {})))
        if rule.get("fingerprint_sha256") != expected:
            rule_errors.append(rule.get("rule_version", "<unknown>"))
    if result["status"] != "verified" or failed_assertions or rule_errors:
        print(
            json.dumps(
                {
                    "verification": result,
                    "failed_assertions": failed_assertions,
                    "bad_rule_fingerprints": rule_errors,
                },
                indent=2,
            )
        )
        return 1
    print(
        json.dumps(
            {
                "verification": "verified",
                "event_chain": result["status"],
                "events": result["event_count"],
                "assertions": len(recomputed),
                "rule_versions": [r.get("rule_version") for r in artifact.get("rule_catalog", [])],
                "synthetic_marker": artifact.get("synthetic_marker"),
            },
            indent=2,
        )
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("audit-evidence.synthetic.json"))
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.verify:
        return verify_file(args.verify)
    artifact = run_scenario(args.output)
    failed = [a["name"] for a in artifact["assertions"] if not a["passed"]]
    print(
        json.dumps(
            {
                "output": str(args.output),
                "verification": artifact["verification"]["status"],
                "failed_assertions": failed,
            },
            indent=2,
        )
    )
    return 1 if failed or artifact["verification"]["status"] != "verified" else 0


if __name__ == "__main__":
    raise SystemExit(main())
