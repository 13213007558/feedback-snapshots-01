"""End-to-end narrative: review, stage, fail mid-read, recover, verify."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from installer.sources import WheelFile

from deploy_demo.deploy import (
    StagingOutcome,
    WormOutcome,
    default_metadata,
    deploy_staging_with_retry,
    deploy_write_once,
    wheel_source_factory,
)
from deploy_demo.flaky import FailurePolicy, FlakyWheelSource, preflight_read_all
from deploy_demo.plan import build_plan
from deploy_demo.worm import WormStore
from deploy_demo.wheels import build_demo_wheel

Echo = Callable[..., None]


@dataclass
class DemoResult:
    """Structured outcome of :func:`run_demo`, used by the smoke test."""

    workdir: Path
    wheel: Path
    plan_json: Path
    entry_count: int
    preflight_error: str
    staging: StagingOutcome
    sentinel_preserved: bool
    worm: WormOutcome
    worm_same_key_refused: bool
    worm_failed_key_refused: bool
    strict_refused_error: str
    replacement: WormOutcome

    @property
    def all_verified(self) -> bool:
        return (
            self.staging.verification.ok
            and self.worm.verification.ok
            and self.replacement.verification.ok
        )


def run_demo(
    workdir: str | Path | None = None,
    *,
    big_mb: int = 8,
    echo: Echo = print,
) -> DemoResult:
    """Run every scenario inside ``workdir`` and print a readable narrative."""
    if workdir is None:
        workdir = Path(tempfile.mkdtemp(prefix="installer-deploy-demo-"))
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    echo("=" * 78)
    echo("0. 构造带大成员的真实 wheel（RECORD 哈希/size 正确）")
    wheel = build_demo_wheel(
        workdir / "wheels" / "demopkg-1.0.0-py3-none-any.whl",
        big_size=big_mb * 1024 * 1024,
    )
    echo(f"    wheel: {wheel} ({wheel.stat().st_size / 1024 / 1024:.1f} MiB on disk)")

    scheme_names = ("purelib", "platlib", "headers", "scripts", "data")
    scheme_dict = {name: str(workdir / "live" / name) for name in scheme_names}
    stage_root = workdir / "stage"

    echo("-" * 78)
    echo("1. 动目标前先生成审查计划（不读成员字节、不写任何目标）")
    metadata = default_metadata()
    with WheelFile.open(wheel) as source:
        plan = build_plan(source, scheme_dict=scheme_dict, additional_metadata=metadata)
    plan_json = workdir / "plan.json"
    plan_json.write_text(plan.to_json(), encoding="utf-8")
    echo(
        f"    entries={len(plan.entries)} skipped={len(plan.skipped)} "
        f"declared_bytes={plan.declared_total_size}"
    )
    for entry in plan.entries[:8]:
        digest = (entry.record_hash or "")[:24]
        echo(f"    [{entry.kind:19}] {entry.scheme:8} {entry.path}  {digest}")
    echo(f"    ... 完整计划: {plan_json}")
    touched = (
        [p for p in (workdir / "live").rglob("*")]
        if (workdir / "live").exists()
        else []
    )
    echo(f"    计划后 live/ 下条目数: {len(touched)}（应为 0）")

    echo("-" * 78)
    echo("2. 最强事前检查：通读全部字节并哈希（常量内存）。演示永久故障：")
    always_bad = FailurePolicy("blob.bin", fail_after=4096, times_to_fail=None)
    preflight_error = ""
    with WheelFile.open(wheel) as wheel_file:
        bad_source = FlakyWheelSource(wheel_file, always_bad)
        try:
            preflight_read_all(bad_source)
        except Exception as exc:  # noqa: BLE001 - demo narrative
            preflight_error = f"{type(exc).__name__}: {exc}"
    echo(f"    预检在触碰目标前失败: {preflight_error}")

    echo("-" * 78)
    echo("3. 可暂存目标：第一次安装在读取 blob 途中失败 -> abort -> 新 generation 重试")
    purelib = Path(scheme_dict["purelib"])
    purelib.mkdir(parents=True, exist_ok=True)
    sentinel = purelib / "sentinel.txt"
    sentinel.write_text("pre-existing, must survive\n", encoding="utf-8")
    sentinel_before = sentinel.read_bytes()

    stage_policy = FailurePolicy("blob.bin", fail_after=200_000, times_to_fail=1)
    staging = deploy_staging_with_retry(
        source_factory=wheel_source_factory(wheel, stage_policy),
        scheme_dict=scheme_dict,
        stage_root=str(stage_root),
        root_scheme=plan.root_scheme,
        record_file_path=plan.record_file_path,
        generation_names=["stage-try1", "stage-try2"],
        additional_metadata=metadata,
        plan=plan,
    )
    for attempt in staging.attempts:
        if attempt.succeeded:
            echo(f"    尝试 {attempt.attempt} gen={attempt.generation} 成功并提交")
        else:
            echo(
                f"    尝试 {attempt.attempt} gen={attempt.generation} "
                f"{attempt.error_type}: {attempt.error} | aborted={attempt.aborted}"
            )
    sentinel_preserved = sentinel.read_bytes() == sentinel_before
    echo(f"    既有文件保持不变: {sentinel_preserved}")
    echo(f"    提升文件数: {len(staging.commit.promoted)}")
    blob_final = purelib / "demopkg" / "blob.bin"
    echo(
        f"    实际落点: {blob_final} (exists={blob_final.exists()}, "
        f"size={blob_final.stat().st_size if blob_final.exists() else 0})"
    )
    echo(
        f"    独立 RECORD 校验: ok={staging.verification.ok} "
        f"checks={len(staging.verification.checks)}"
    )

    echo("-" * 78)
    echo("4. 一次写替身：同 key 不可重写；中途失败后只能换新 generation")
    worm_root = workdir / "worm"
    store = WormStore(worm_root)
    worm_policy = FailurePolicy("blob.bin", fail_after=200_000, times_to_fail=1)
    worm = deploy_write_once(
        source_factory=wheel_source_factory(wheel, worm_policy),
        store=store,
        scheme_dict=scheme_dict,
        root_scheme=plan.root_scheme,
        record_file_path=plan.record_file_path,
        generation_names=["rel-0001", "rel-0002"],
        additional_metadata=metadata,
        plan=plan,
    )
    first = worm.attempts[0]
    echo(f"    gen rel-0001 失败: {first.error_type}: {first.error}")
    echo(
        f"    半写对象: {first.partial_key} ({first.partial_bytes} bytes, state=failed)"
    )

    same_key_refused = False
    try:
        store.open_write(first.partial_key)  # type: ignore[arg-type]
    except Exception as exc:  # noqa: BLE001
        same_key_refused = type(exc).__name__ == "WriteOnceViolation"
        echo(f"    重写半写 key 被拒绝: {exc}")

    sealed_key = worm.destination.key_for("purelib", "demopkg/__init__.py")
    failed_key_refused = False
    try:
        store.open_write(sealed_key)
    except Exception as exc:  # noqa: BLE001
        failed_key_refused = type(exc).__name__ == "WriteOnceViolation"
        echo(f"    重写已封板 key 被拒绝: {exc}")

    echo(f"    gen rel-0002 成功，manifest: {worm.manifest_key}")
    blob_key = worm.destination.key_for("purelib", "demopkg/blob.bin")
    echo(f"    WORM 实际文件: {store.actual_path(blob_key)}")
    echo(
        f"    回读校验: ok={worm.verification.ok} "
        f"checks={len(worm.verification.checks)}"
    )

    echo("-" * 78)
    echo("5. 最严格的“整个目标只写一次”模式：失败即砖化，必须换目标实例")
    strict_store = WormStore(workdir / "worm-strict", brick_on_failure=True)
    strict_policy = FailurePolicy("blob.bin", fail_after=100_000, times_to_fail=1)
    strict_refused_error = ""
    try:
        deploy_write_once(
            source_factory=wheel_source_factory(wheel, strict_policy),
            store=strict_store,
            scheme_dict=scheme_dict,
            root_scheme=plan.root_scheme,
            record_file_path=plan.record_file_path,
            generation_names=["one-1", "one-2"],
            additional_metadata=metadata,
        )
    except Exception as exc:  # noqa: BLE001
        strict_refused_error = f"{type(exc).__name__}: {exc}"
    echo(f"    同实例新 generation 也被拒绝: {strict_refused_error}")

    replacement_store = WormStore(workdir / "worm-replacement")
    replacement = deploy_write_once(
        source_factory=wheel_source_factory(wheel),
        store=replacement_store,
        scheme_dict=scheme_dict,
        root_scheme=plan.root_scheme,
        record_file_path=plan.record_file_path,
        generation_names=["repl-0001"],
        max_attempts=1,
        additional_metadata=metadata,
        plan=plan,
    )
    echo(
        f"    替换目标上部署成功: {replacement.generation} "
        f"verify={replacement.verification.ok}"
    )

    echo("-" * 78)
    echo(
        f"结论: 全部落点校验通过={staging.verification.ok and worm.verification.ok and replacement.verification.ok}"
    )
    echo(f"工作目录（含 plan.json、ledger.jsonl、实际文件）: {workdir}")

    return DemoResult(
        workdir=workdir,
        wheel=wheel,
        plan_json=plan_json,
        entry_count=len(plan.entries),
        preflight_error=preflight_error,
        staging=staging,
        sentinel_preserved=sentinel_preserved,
        worm=worm,
        worm_same_key_refused=same_key_refused,
        worm_failed_key_refused=failed_key_refused,
        strict_refused_error=strict_refused_error,
        replacement=replacement,
    )
