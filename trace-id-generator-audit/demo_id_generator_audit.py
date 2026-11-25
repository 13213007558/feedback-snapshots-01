# SPDX-License-Identifier: Apache-2.0
#
# 准入审计演示：替换 OpenTelemetry Python SDK 的 IdGenerator。
# 仅使用公开 SDK/API；不修改 SDK 源码。运行: .venv/bin/python trace-id-generator-audit/demo_id_generator_audit.py
#
# 角色：
#   A. ApprovedSecretsIdGenerator —— 批准型替身：os.urandom 真随机，is_trace_id_random()=True，
#      且 trace_id 高 16 bit 固定为 0x7A1D（便于在导出记录里识别“本服务生成的新根”）。
#   B. DeterministicCounterIdGenerator —— 合法替身：实现了完整接口、永不返回非法 ID，
#      但输出是确定性计数器、is_trace_id_random()=False，因此不能宣称 W3C random-trace-id。
#
# 输出：
#   audit-evidence.jsonl —— 每条 span 一行结构化证据（采样器输入 + 决策 + 输出标志）
#   控制台同时打印人类可读表。

import json
import os
import platform
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional, Sequence

from opentelemetry import context as context_api
from opentelemetry import trace as trace_api
from opentelemetry.sdk import trace as sdk_trace
from opentelemetry.sdk.trace import sampling
from opentelemetry.sdk.trace.id_generator import IdGenerator
from opentelemetry.trace import Link, SpanContext, SpanKind, TraceFlags, TraceState

INVALID_TRACE_ID = trace_api.INVALID_TRACE_ID
INVALID_SPAN_ID = trace_api.INVALID_SPAN_ID
EVIDENCE_PATH = Path(__file__).with_name("audit-evidence.jsonl")


class ApprovedSecretsIdGenerator(IdGenerator):
    """批准候选：OS CSPRNG + 可识别前缀 + 诚实的随机性声明。"""

    PREFIX = 0x7A1D << 112
    NAME = "ApprovedSecretsIdGenerator"

    def __init__(self) -> None:
        self.trace_id_calls = 0
        self.span_id_calls = 0

    def generate_trace_id(self) -> int:
        self.trace_id_calls += 1
        candidate = self.PREFIX | int.from_bytes(os.urandom(14), "big")
        while candidate == INVALID_TRACE_ID:
            candidate = self.PREFIX | int.from_bytes(os.urandom(14), "big")
        return candidate

    def generate_span_id(self) -> int:
        self.span_id_calls += 1
        candidate = int.from_bytes(os.urandom(8), "big")
        while candidate == INVALID_SPAN_ID:
            candidate = int.from_bytes(os.urandom(8), "big")
        return candidate

    def is_trace_id_random(self) -> bool:
        # 低 56 bit 来自 os.urandom，满足 W3C random-trace-id 声明前提。
        return True


class DeterministicCounterIdGenerator(IdGenerator):
    """合法但非随机的替身：接口合规、可复现，用于对照与压测。"""

    PREFIX = 0x0BAD << 112
    NAME = "DeterministicCounterIdGenerator"

    def __init__(self) -> None:
        self._trace_counter = 0
        self._span_counter = 0
        self.trace_id_calls = 0
        self.span_id_calls = 0

    def generate_trace_id(self) -> int:
        self.trace_id_calls += 1
        self._trace_counter += 1
        return self.PREFIX | self._trace_counter

    def generate_span_id(self) -> int:
        self.span_id_calls += 1
        self._span_counter += 1
        return (1 << 63) | self._span_counter

    def is_trace_id_random(self) -> bool:
        # 计数器分布，绝不允许声明随机。
        return False


@dataclass
class SamplerInput:
    """采样端实际收到的全部输入（对应 Sampler.should_sample 的 6 个参数）。"""

    parent_context_present: bool
    parent_span_context_valid: Optional[bool]
    parent_is_remote: Optional[bool]
    parent_trace_id_hex: Optional[str]
    parent_trace_flags: Optional[int]
    parent_sampled: Optional[bool]
    parent_random_trace_id: Optional[bool]
    trace_id_hex: str
    name: str
    kind: str
    attributes: Optional[dict]
    links: list
    trace_state: Optional[str]


@dataclass
class Evidence:
    case_id: str
    path: str  # root | inherited
    id_generator: str
    generator_trace_id_calls: int
    generator_span_id_calls: int
    sampler_description: str
    sampler_input: SamplerInput
    decision: str
    output_trace_id_hex: str
    output_span_id_hex: str
    output_trace_flags: int
    output_sampled: bool
    output_random_trace_id: bool
    trace_id_equals_parent: Optional[bool]
    span_is_recording: bool


class RecordingSampler(sampling.Sampler):
    """包装真实采样器，原样转发决策，同时固化 should_sample 的输入证据。"""

    def __init__(self, delegate: sampling.Sampler) -> None:
        self._delegate = delegate
        self.records: list[SamplerInput] = []

    def should_sample(
        self,
        parent_context: Optional[context_api.Context],
        trace_id: int,
        name: str,
        kind: Optional[SpanKind] = None,
        attributes=None,
        links: Optional[Sequence[Link]] = None,
        trace_state: Optional[TraceState] = None,
    ) -> sampling.SamplingResult:
        parent_span = trace_api.get_current_span(parent_context)
        parent_ctx = parent_span.get_span_context()
        if isinstance(parent_ctx, SpanContext) and parent_ctx.is_valid:
            parent_info = {
                "parent_span_context_valid": True,
                "parent_is_remote": parent_ctx.is_remote,
                "parent_trace_id_hex": f"{parent_ctx.trace_id:032x}",
                "parent_trace_flags": int(parent_ctx.trace_flags),
                "parent_sampled": parent_ctx.trace_flags.sampled,
                "parent_random_trace_id": parent_ctx.trace_flags.random_trace_id,
            }
        else:
            parent_info = {
                "parent_span_context_valid": False if parent_ctx is None else parent_ctx.is_valid,
                "parent_is_remote": None,
                "parent_trace_id_hex": None,
                "parent_trace_flags": None,
                "parent_sampled": None,
                "parent_random_trace_id": None,
            }
        record = SamplerInput(
            parent_context_present=parent_context is not None,
            **parent_info,
            trace_id_hex=f"{trace_id:032x}",
            name=name,
            kind=str(kind),
            attributes=dict(attributes) if attributes else None,
            links=[
                {"trace_id": f"{link.context.trace_id:032x}", "attributes": link.attributes}
                for link in (links or [])
            ],
            trace_state=str(trace_state) if trace_state is not None else None,
        )
        self.records.append(record)
        return self._delegate.should_sample(
            parent_context, trace_id, name, kind, attributes, links, trace_state
        )

    def get_description(self) -> str:
        return f"RecordingSampler({self._delegate.get_description()})"


def remote_parent(trace_id: int, flags: TraceFlags) -> context_api.Context:
    """构造带已知标志的远端父上下文（模拟传播器 extract 后的结果）。"""
    span_context = SpanContext(
        trace_id=trace_id,
        span_id=0x0BADCAFE00000001,
        is_remote=True,
        trace_flags=flags,
        trace_state=TraceState([("vendor", "p1")]),
    )
    return trace_api.set_span_in_context(trace_api.NonRecordingSpan(span_context))


def run_case(
    case_id: str,
    path: str,
    id_generator: IdGenerator,
    delegate: sampling.Sampler,
    parent_context: Optional[context_api.Context],
) -> Evidence:
    recorder = RecordingSampler(delegate)
    provider = sdk_trace.TracerProvider(sampler=recorder, id_generator=id_generator)
    tracer = provider.get_tracer("audit.demo", "1.0.0")

    link_target = SpanContext(
        trace_id=0x11111111111111112222222222222222,
        span_id=0x3333333333333333,
        is_remote=True,
    )
    span = tracer.start_span(
        name=f"{case_id}-span",
        context=parent_context,
        kind=SpanKind.SERVER,
        attributes={"audit.case": case_id},
        links=[Link(link_target, {"link.role": "causal"})],
    )
    output = span.get_span_context()
    parent_ctx = (
        trace_api.get_current_span(parent_context).get_span_context()
        if parent_context is not None
        else None
    )
    evidence = Evidence(
        case_id=case_id,
        path=path,
        id_generator=getattr(id_generator, "NAME", type(id_generator).__name__),
        generator_trace_id_calls=id_generator.trace_id_calls,
        generator_span_id_calls=id_generator.span_id_calls,
        sampler_description=delegate.get_description(),
        sampler_input=recorder.records[0],
        decision=recorder._delegate.__class__.__name__,  # noqa: SLF001
        output_trace_id_hex=f"{output.trace_id:032x}",
        output_span_id_hex=f"{output.span_id:016x}",
        output_trace_flags=int(output.trace_flags),
        output_sampled=output.trace_flags.sampled,
        output_random_trace_id=output.trace_flags.random_trace_id,
        trace_id_equals_parent=(
            output.trace_id == parent_ctx.trace_id
            if isinstance(parent_ctx, SpanContext) and parent_ctx.is_valid
            else None
        ),
        span_is_recording=span.is_recording(),
    )
    provider.shutdown()
    return evidence


def ratio_demo() -> list[dict]:
    """比例采样约定演示：TraceIdRatioBased 只看 trace_id 低 64 bit 与 bound 比较。"""
    rate = 0.5
    sampler = sampling.TraceIdRatioBased(rate)
    bound = sampler.bound
    rows = []
    for generator in (ApprovedSecretsIdGenerator(), DeterministicCounterIdGenerator()):
        sampled_hits = 0
        first_ids = []
        for _ in range(20):
            trace_id = generator.generate_trace_id()
            decision = sampler.should_sample(None, trace_id, "ratio-probe", SpanKind.INTERNAL)
            sampled_hits += int(decision.decision.is_sampled())
            if len(first_ids) < 3:
                first_ids.append(
                    {
                        "trace_id": f"{trace_id:032x}",
                        "low64": trace_id & ((1 << 64) - 1),
                        "below_bound": (trace_id & ((1 << 64) - 1)) < bound,
                        "sampled": decision.decision.is_sampled(),
                    }
                )
        rows.append(
            {
                "id_generator": generator.NAME,
                "rate": rate,
                "bound": bound,
                "n": 20,
                "sampled_count": sampled_hits,
                "observed_fraction": sampled_hits / 20,
                "first_ids": first_ids,
                "note": "短样本比例仅供说明，不能证明分布；生产需独立长周期观测。",
            }
        )
    return rows


def main() -> int:
    parent_sampled_flags = TraceFlags(TraceFlags.SAMPLED | TraceFlags.RANDOM_TRACE_ID)
    parent_sampled_ctx = remote_parent(0xABCDEF0123456789ABCDEF0123456789, parent_sampled_flags)
    parent_not_sampled_ctx = remote_parent(
        0x99887766554433229988776655443322, TraceFlags(TraceFlags.DEFAULT)
    )

    parent_based = sampling.ParentBased(sampling.ALWAYS_ON)

    cases = [
        # 用例 A1/A2：两个合法替身各走一次新根路径
        ("A1", "root", ApprovedSecretsIdGenerator(), parent_based, None),
        ("A2", "root", DeterministicCounterIdGenerator(), parent_based, None),
        # 用例 B1：批准生成器 + 已知标志远端父链路（sampled=1, random=1）
        ("B1", "inherited", ApprovedSecretsIdGenerator(), parent_based, parent_sampled_ctx),
        # 用例 B2：替换生成器后，trace_id 与两个标志仍由旧父上下文决定
        ("B2", "inherited", DeterministicCounterIdGenerator(), parent_based, parent_sampled_ctx),
        # 用例 B2b：父链路 sampled=0, random=0，证明标志继承对两个方向都成立
        ("B2b", "inherited", DeterministicCounterIdGenerator(), parent_based, parent_not_sampled_ctx),
    ]

    evidences = [run_case(*case) for case in cases]
    ratio_rows = ratio_demo()

    with EVIDENCE_PATH.open("w", encoding="utf-8") as handle:
        for evidence in evidences:
            handle.write(json.dumps(asdict(evidence), ensure_ascii=False) + "\n")
        for row in ratio_rows:
            handle.write(json.dumps({"ratio_demo": row}, ensure_ascii=False) + "\n")

    print("=" * 110)
    print(f"Python {platform.python_version()} | opentelemetry-sdk {sdk_trace.__version__ if hasattr(sdk_trace, '__version__') else _importlib_version()}")
    print(f"证据文件: {EVIDENCE_PATH}")
    print("=" * 110)
    header = (
        f"{'case':<5}{'path':<10}{'generator':<32}{'gen.tid':<8}{'decision':<18}"
        f"{'flags':<7}{'sampled':<9}{'random':<8}{'tid==parent':<12}recording"
    )
    print(header)
    print("-" * 110)
    for evidence in evidences:
        print(
            f"{evidence.case_id:<5}{evidence.path:<10}{evidence.id_generator:<32}"
            f"{evidence.generator_trace_id_calls:<8}{evidence.decision:<18}"
            f"{evidence.output_trace_flags:<7}{str(evidence.output_sampled):<9}"
            f"{str(evidence.output_random_trace_id):<8}{str(evidence.trace_id_equals_parent):<12}"
            f"{evidence.span_is_recording}"
        )
    print("-" * 110)
    print("采样器输入示例（用例 B1，即采样端实际得到的 6 项输入）:")
    b1 = next(item for item in evidences if item.case_id == "B1")
    print(json.dumps(asdict(b1.sampler_input), ensure_ascii=False, indent=2, default=str))
    print("-" * 110)
    print("比例采样约定（TraceIdRatioBased(0.5)，bound = round(0.5 * 2^64)）:")
    for row in ratio_rows:
        print(
            f"  {row['id_generator']:<32} n={row['n']} sampled={row['sampled_count']:<3}"
            f"observed={row['observed_fraction']:.2f}（短样本，不作分布证明）"
        )
    return 0


def _importlib_version() -> str:
    import importlib.metadata

    return importlib.metadata.version("opentelemetry-sdk")


if __name__ == "__main__":
    sys.exit(main())
