"""Tests for the multi-target safe-deployment reference demo.

These cover the promises made in the design note:

* the review plan is complete and writes nothing;
* mid-stream source failures are caught per target;
* staging aborts cleanly and a new generation commits/verifies;
* commit failures roll the live tree back;
* write-once keys/sessions cannot be reused and recover via new generations;
* the strict one-shot double requires a replacement target;
* independent read-back verification detects tampering;
* large members are read in fixed-size chunks.
"""

from __future__ import annotations

import os
from io import BytesIO
from pathlib import Path

import pytest
from installer._core import install
from installer.sources import WheelFile

from deploy_demo.deploy import (
    default_metadata,
    deploy_staging_with_retry,
    deploy_write_once,
    wheel_source_factory,
)
from deploy_demo.demo import run_demo
from deploy_demo.errors import (
    CommitFailed,
    TransitReadError,
    VerificationFailure,
    WriteOnceViolation,
)
from deploy_demo.flaky import FailurePolicy, FlakyWheelSource, preflight_read_all
from deploy_demo.paths import safe_resolve
from deploy_demo.plan import build_plan
from deploy_demo.staging import StagingWheelDestination
from deploy_demo.verify import (
    verify_filesystem_installation,
    verify_worm_generation,
)
from deploy_demo.wheels import build_demo_wheel, deterministic_blob
from deploy_demo.worm import WormStore, WriteOnceDestination

SCHEMES = ("purelib", "platlib", "headers", "scripts", "data")
BLOB_MEMBER_SUFFIX = "blob.bin"
BLOB_LOGICAL_PATH = "demopkg/blob.bin"


def scheme_dict(root: Path) -> dict[str, str]:
    return {name: str(root / "live" / name) for name in SCHEMES}


def open_plan(wheel: Path, schemes: dict[str, str], metadata=None):
    with WheelFile.open(wheel) as source:
        return build_plan(
            source,
            scheme_dict=schemes,
            additional_metadata=metadata or default_metadata(),
        )


def test_plan_is_complete_and_touches_nothing(tmp_path: Path) -> None:
    wheel = build_demo_wheel(
        tmp_path / "demopkg-1.0.0-py3-none-any.whl", big_size=200_000
    )
    schemes = scheme_dict(tmp_path)
    metadata = default_metadata()

    # An always-failing policy proves planning never reads member bytes.
    armed = FailurePolicy(BLOB_MEMBER_SUFFIX, fail_after=1, times_to_fail=None)
    with WheelFile.open(wheel) as wheel_file:
        source = FlakyWheelSource(wheel_file, armed)
        plan = build_plan(source, scheme_dict=schemes, additional_metadata=metadata)
        blob_reports = [
            report
            for report in source.stream_reports
            if report.member.endswith(BLOB_MEMBER_SUFFIX)
        ]
        assert blob_reports
        assert all(report.delivered == 0 for report in blob_reports)

    path_set = plan.expected_path_set()
    assert ("purelib", BLOB_LOGICAL_PATH) in path_set
    assert ("scripts", "demopkg") in path_set
    assert ("data", "demopkg/note.txt") in path_set
    assert ("purelib", "demopkg-1.0.0.dist-info/RECORD") in path_set
    assert ("purelib", "demopkg-1.0.0.dist-info/INSTALLER") in path_set

    blob_entry = next(
        entry
        for entry in plan.entries
        if entry.path == BLOB_LOGICAL_PATH and entry.kind == "wheel-file"
    )
    assert blob_entry.size == 200_000
    assert blob_entry.record_hash and blob_entry.record_hash.startswith("sha256=")

    # JSON artifact for the security review must be serializable.
    assert '"declared_total_size"' in plan.to_json()
    assert not (tmp_path / "live").exists()


def test_preflight_read_failure_happens_before_target_writes(tmp_path: Path) -> None:
    wheel = build_demo_wheel(
        tmp_path / "demopkg-1.0.0-py3-none-any.whl", big_size=200_000
    )
    schemes = scheme_dict(tmp_path)
    store = WormStore(tmp_path / "worm")
    policy = FailurePolicy(BLOB_MEMBER_SUFFIX, fail_after=4096, times_to_fail=None)

    with WheelFile.open(wheel) as wheel_file:
        source = FlakyWheelSource(wheel_file, policy)
        with pytest.raises(TransitReadError, match="simulated transport reset"):
            preflight_read_all(source)

    assert store.keys() == []
    assert not Path(schemes["purelib"]).exists()


def test_staging_failure_aborts_then_retry_commits_and_verifies(
    tmp_path: Path,
) -> None:
    size = 300_000
    wheel = build_demo_wheel(tmp_path / "demopkg-1.0.0-py3-none-any.whl", big_size=size)
    schemes = scheme_dict(tmp_path)
    metadata = default_metadata()
    plan = open_plan(wheel, schemes, metadata)

    purelib = Path(schemes["purelib"])
    purelib.mkdir(parents=True)
    sentinel = purelib / "sentinel.txt"
    sentinel.write_text("keep me\n", encoding="utf-8")
    sentinel_before = sentinel.read_bytes()

    policy = FailurePolicy(BLOB_MEMBER_SUFFIX, fail_after=50_000, times_to_fail=1)
    outcome = deploy_staging_with_retry(
        source_factory=wheel_source_factory(wheel, policy),
        scheme_dict=schemes,
        stage_root=str(tmp_path / "stage"),
        root_scheme=plan.root_scheme,
        record_file_path=plan.record_file_path,
        generation_names=["g1", "g2"],
        additional_metadata=metadata,
        plan=plan,
    )

    assert [attempt.succeeded for attempt in outcome.attempts] == [False, True]
    first = outcome.attempts[0]
    assert first.error_type == "TransitReadError"
    assert first.aborted is True
    assert not (tmp_path / "stage" / "g1").exists()

    assert sentinel.read_bytes() == sentinel_before
    landed_blob = purelib / "demopkg" / "blob.bin"
    assert landed_blob.read_bytes() == deterministic_blob(size)

    assert outcome.verification.ok, outcome.verification.problems
    assert any("sentinel.txt" in extra for extra in outcome.verification.extra)

    strict = verify_filesystem_installation(
        scheme_dict=schemes,
        root_scheme=plan.root_scheme,
        record_file_path=plan.record_file_path,
        plan=plan,
        strict_extra=False,
    )
    assert strict.ok


def test_staging_commit_failure_rolls_live_tree_back(
    tmp_path: Path, monkeypatch
) -> None:
    wheel = build_demo_wheel(
        tmp_path / "demopkg-1.0.0-py3-none-any.whl", big_size=100_000
    )
    schemes = scheme_dict(tmp_path)
    metadata = default_metadata()
    plan = open_plan(wheel, schemes, metadata)

    # Pre-existing blob that commit would replace; rollback must restore it.
    live_blob = Path(schemes["purelib"]) / "demopkg" / "blob.bin"
    live_blob.parent.mkdir(parents=True, exist_ok=True)
    live_blob.write_bytes(b"old-live-blob-contents")

    def snapshot() -> dict[str, bytes]:
        live_root = tmp_path / "live"
        return {
            str(path.relative_to(live_root)): path.read_bytes()
            for path in live_root.rglob("*")
            if path.is_file()
        }

    before = snapshot()

    destination = StagingWheelDestination(
        final_scheme_dict=schemes,
        stage_root=str(tmp_path / "stage"),
        generation="txn",
    )
    with WheelFile.open(wheel) as wheel_file:
        install(wheel_file, destination, metadata)

    real_replace = os.replace
    fault_state = {"used": False}

    def replace_with_one_blob_fault(src, dst):
        src_path = Path(os.fspath(src))
        dst_path = Path(os.fspath(dst))
        if (
            not fault_state["used"]
            and dst_path.name == "blob.bin"
            and src_path.is_relative_to(destination.stage_dir)
        ):
            fault_state["used"] = True
            raise OSError("injected commit fault")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", replace_with_one_blob_fault)

    with pytest.raises(CommitFailed):
        destination.commit()

    # The live tree is byte-for-byte the pre-commit snapshot.
    assert snapshot() == before

    # Recovery = a brand-new generation; the spent fault does not re-fire.
    recovered = deploy_staging_with_retry(
        source_factory=wheel_source_factory(wheel),
        scheme_dict=schemes,
        stage_root=str(tmp_path / "stage2"),
        root_scheme=plan.root_scheme,
        record_file_path=plan.record_file_path,
        max_attempts=1,
        generation_names=["clean"],
        additional_metadata=metadata,
        plan=plan,
    )
    assert recovered.verification.ok


def test_write_once_refuses_same_key_and_recovers_with_new_generation(
    tmp_path: Path,
) -> None:
    wheel = build_demo_wheel(
        tmp_path / "demopkg-1.0.0-py3-none-any.whl", big_size=300_000
    )
    schemes = scheme_dict(tmp_path)
    metadata = default_metadata()
    plan = open_plan(wheel, schemes, metadata)
    store = WormStore(tmp_path / "worm")

    policy = FailurePolicy(BLOB_MEMBER_SUFFIX, fail_after=40_000, times_to_fail=1)
    outcome = deploy_write_once(
        source_factory=wheel_source_factory(wheel, policy),
        store=store,
        scheme_dict=schemes,
        root_scheme=plan.root_scheme,
        record_file_path=plan.record_file_path,
        generation_names=["g1", "g2"],
        additional_metadata=metadata,
        plan=plan,
    )

    assert [a.succeeded for a in outcome.attempts] == [False, True]
    failed_attempt = outcome.attempts[0]
    assert failed_attempt.error_type == "TransitReadError"
    assert failed_attempt.partial_key is not None
    assert failed_attempt.partial_bytes == 40_000
    assert store.state_of(failed_attempt.partial_key) == "failed"

    with pytest.raises(WriteOnceViolation, match="already used"):
        store.open_write(failed_attempt.partial_key)

    sealed_blob_key = outcome.destination.key_for("purelib", BLOB_LOGICAL_PATH)
    with pytest.raises(WriteOnceViolation, match="already used"):
        store.open_write(sealed_blob_key)

    # Used-key memory survives reopening the store (ledger replay).
    reloaded = WormStore(tmp_path / "worm")
    with pytest.raises(WriteOnceViolation):
        reloaded.open_write(sealed_blob_key)

    assert outcome.verification.ok, outcome.verification.problems
    assert outcome.manifest_key == "generations/g2/_manifest.json"
    assert store.state_of(outcome.manifest_key) == "sealed"


def test_poisoned_write_once_session_refuses_more_writes(tmp_path: Path) -> None:
    wheel = build_demo_wheel(
        tmp_path / "demopkg-1.0.0-py3-none-any.whl", big_size=100_000
    )
    schemes = scheme_dict(tmp_path)
    store = WormStore(tmp_path / "worm")
    destination = WriteOnceDestination(store, "g1", scheme_dict=schemes)
    policy = FailurePolicy(BLOB_MEMBER_SUFFIX, fail_after=10, times_to_fail=1)

    with WheelFile.open(wheel) as wheel_file:
        source = FlakyWheelSource(wheel_file, policy)
        with pytest.raises(TransitReadError):
            install(source, destination, default_metadata())

    assert destination.dead is True
    with pytest.raises(WriteOnceViolation, match="poisoned"):
        destination.write_file("purelib", "whatever.txt", BytesIO(b"x"), False)


def test_strict_one_shot_target_requires_replacement(tmp_path: Path) -> None:
    wheel = build_demo_wheel(
        tmp_path / "demopkg-1.0.0-py3-none-any.whl", big_size=100_000
    )
    schemes = scheme_dict(tmp_path)
    plan = open_plan(wheel, schemes)

    strict = WormStore(tmp_path / "strict", brick_on_failure=True)
    policy = FailurePolicy(BLOB_MEMBER_SUFFIX, fail_after=100, times_to_fail=1)

    with pytest.raises(TransitReadError):
        deploy_write_once(
            source_factory=wheel_source_factory(wheel, policy),
            store=strict,
            scheme_dict=schemes,
            root_scheme=plan.root_scheme,
            record_file_path=plan.record_file_path,
            max_attempts=1,
            generation_names=["one-1"],
        )
    assert strict.bricked is True

    # Even a brand-new generation on the same physical target is refused.
    with pytest.raises(WriteOnceViolation, match="bricked"):
        deploy_write_once(
            source_factory=wheel_source_factory(wheel),
            store=strict,
            scheme_dict=schemes,
            root_scheme=plan.root_scheme,
            record_file_path=plan.record_file_path,
            max_attempts=1,
            generation_names=["one-2"],
        )

    # Recovery: a replacement target instance/endpoint.
    replacement = WormStore(tmp_path / "strict-replacement")
    outcome = deploy_write_once(
        source_factory=wheel_source_factory(wheel),
        store=replacement,
        scheme_dict=schemes,
        root_scheme=plan.root_scheme,
        record_file_path=plan.record_file_path,
        max_attempts=1,
        generation_names=["r1"],
        plan=plan,
    )
    assert outcome.verification.ok


def test_worm_verification_detects_tampered_landing(tmp_path: Path) -> None:
    wheel = build_demo_wheel(
        tmp_path / "demopkg-1.0.0-py3-none-any.whl", big_size=200_000
    )
    schemes = scheme_dict(tmp_path)
    metadata = default_metadata()
    plan = open_plan(wheel, schemes, metadata)
    store = WormStore(tmp_path / "worm")

    outcome = deploy_write_once(
        source_factory=wheel_source_factory(wheel),
        store=store,
        scheme_dict=schemes,
        root_scheme=plan.root_scheme,
        record_file_path=plan.record_file_path,
        max_attempts=1,
        generation_names=["g1"],
        additional_metadata=metadata,
        plan=plan,
    )
    assert outcome.verification.ok

    blob_key = outcome.destination.key_for("purelib", BLOB_LOGICAL_PATH)
    landing = store.actual_path(blob_key)
    data = bytearray(landing.read_bytes())
    data[0] ^= 0xFF
    landing.write_bytes(bytes(data))

    report = verify_worm_generation(
        store,
        "g1",
        scheme_dict=schemes,
        root_scheme=plan.root_scheme,
        record_file_path=plan.record_file_path,
        plan=plan,
    )
    assert not report.ok
    assert any(check.hash_ok is False for check in report.checks)
    with pytest.raises(VerificationFailure):
        report.raise_if_failed()


def test_filesystem_verification_detects_wrong_bytes(tmp_path: Path) -> None:
    wheel = build_demo_wheel(
        tmp_path / "demopkg-1.0.0-py3-none-any.whl", big_size=50_000
    )
    schemes = scheme_dict(tmp_path)
    metadata = default_metadata()
    plan = open_plan(wheel, schemes, metadata)

    outcome = deploy_staging_with_retry(
        source_factory=wheel_source_factory(wheel),
        scheme_dict=schemes,
        stage_root=str(tmp_path / "stage"),
        root_scheme=plan.root_scheme,
        record_file_path=plan.record_file_path,
        max_attempts=1,
        generation_names=["g1"],
        additional_metadata=metadata,
        plan=plan,
    )
    assert outcome.verification.ok

    blob = Path(schemes["purelib"]) / BLOB_LOGICAL_PATH
    blob.write_bytes(blob.read_bytes()[:-1] + b"X")  # truncate/modify last byte
    report = verify_filesystem_installation(
        scheme_dict=schemes,
        root_scheme=plan.root_scheme,
        record_file_path=plan.record_file_path,
        plan=plan,
    )
    assert not report.ok
    assert any("checksum mismatch" in problem for problem in report.problems)


def test_large_member_is_streamed_in_fixed_chunks(tmp_path: Path) -> None:
    size = 2 * 1024 * 1024
    wheel = build_demo_wheel(tmp_path / "demopkg-1.0.0-py3-none-any.whl", big_size=size)
    schemes = scheme_dict(tmp_path)
    metadata = default_metadata()

    destination = StagingWheelDestination(
        final_scheme_dict=schemes,
        stage_root=str(tmp_path / "stage"),
        generation="big",
    )
    with WheelFile.open(wheel) as wheel_file:
        source = FlakyWheelSource(wheel_file, None)
        install(source, destination, metadata)
        report = destination.commit()

    blob_reports = [
        item
        for item in source.stream_reports
        if item.member.endswith(BLOB_MEMBER_SUFFIX)
    ]
    assert len(blob_reports) == 1
    observed = blob_reports[0]
    assert observed.delivered == size
    positive_reads = [n for n in observed.requested_sizes if n and n > 0]
    assert positive_reads
    assert max(positive_reads) <= 64 * 1024

    assert len(report.promoted) >= 9
    landing = Path(schemes["purelib"]) / BLOB_LOGICAL_PATH
    assert landing.stat().st_size == size

    verification = verify_filesystem_installation(
        scheme_dict=schemes,
        root_scheme="purelib",
        record_file_path="demopkg-1.0.0.dist-info/RECORD",
    )
    assert verification.ok


def test_safe_resolve_rejects_traversal(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="outside"):
        safe_resolve(tmp_path / "root", "../../etc/passwd")


def test_end_to_end_demo(tmp_path: Path) -> None:
    result = run_demo(tmp_path / "demo", big_mb=1, echo=lambda *_args, **_kwargs: None)
    assert result.all_verified
    assert result.sentinel_preserved
    assert result.worm_same_key_refused
    assert result.worm_failed_key_refused
    assert "WriteOnceViolation" in result.strict_refused_error
    assert result.plan_json.exists()
    assert result.entry_count >= 9


def test_fanout_isolates_failed_target(tmp_path: Path) -> None:
    from deploy_demo.fanout import fanout

    wheel = build_demo_wheel(
        tmp_path / "demopkg-1.0.0-py3-none-any.whl", big_size=100_000
    )
    schemes = scheme_dict(tmp_path)
    metadata = default_metadata()
    plan = open_plan(wheel, schemes, metadata)
    store = WormStore(tmp_path / "worm")

    def staging_job():
        return deploy_staging_with_retry(
            source_factory=wheel_source_factory(wheel),
            scheme_dict=schemes,
            stage_root=str(tmp_path / "stage"),
            root_scheme=plan.root_scheme,
            record_file_path=plan.record_file_path,
            max_attempts=1,
            generation_names=["s1"],
            additional_metadata=metadata,
            plan=plan,
        )

    always_fail = FailurePolicy(BLOB_MEMBER_SUFFIX, fail_after=10, times_to_fail=None)

    def broken_worm_job():
        return deploy_write_once(
            source_factory=wheel_source_factory(wheel, always_fail),
            store=store,
            scheme_dict=schemes,
            root_scheme=plan.root_scheme,
            record_file_path=plan.record_file_path,
            max_attempts=1,
            generation_names=["w1"],
            additional_metadata=metadata,
        )

    results = fanout({"staging": staging_job, "write-once": broken_worm_job})
    by_name = {result.name: result for result in results}

    assert by_name["staging"].ok is True
    assert by_name["staging"].verification is not None
    assert by_name["staging"].verification.ok
    assert by_name["write-once"].ok is False
    assert by_name["write-once"].error_type == "TransitReadError"
    assert store.keys("failed")

    # Recover only the failed target with a new generation.
    recovered = deploy_write_once(
        source_factory=wheel_source_factory(wheel),
        store=store,
        scheme_dict=schemes,
        root_scheme=plan.root_scheme,
        record_file_path=plan.record_file_path,
        max_attempts=1,
        generation_names=["w2"],
        additional_metadata=metadata,
        plan=plan,
    )
    assert recovered.verification.ok
