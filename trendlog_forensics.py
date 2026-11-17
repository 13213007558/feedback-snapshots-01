"""
Trend Log 环形缓冲离线证据整理（基于 bacpypes3 日志结构）。

原则：
- 当前缓冲索引不是历史记录号；绝对序号只能来自 ReadRange 的
  firstSequenceNumber 与页内偏移，或 totalRecordCount/recordCount 推算。
- 序号回绕（Unsigned32 回绕）、环形覆盖、采集缺页是三种不同现象，分开标注。
- 不按时间戳重排记录；时钟回退（timeChange 记录）原地保留。
- 已被覆盖的记录不可恢复，报告只标注未知区间，不编造内容。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from bacpypes3.basetypes import (
    DateTime,
    LogRecord,
    LogRecordLogDatum,
    LogStatus,
)

SEQUENCE_MODULUS = 2**32  # BACnet 记录序号为 Unsigned32


# ---------------------------------------------------------------- 样本构造

@dataclass
class DeviceSnapshot:
    """采集时刻从设备读到的 Trend Log 属性。"""

    buffer_size: int
    record_count: int
    total_record_count: int
    stop_when_full: bool
    enable: bool


@dataclass
class ReadRangePage:
    """一次 ReadRange(byPosition) 应答的离线记录。"""

    reference_index: int          # 请求中的起始缓冲位置（1 基）
    first_sequence_number: int    # 应答 firstSequenceNumber
    first_item: bool              # resultFlags
    last_item: bool
    more_items: bool
    items: list[LogRecord] = field(default_factory=list)


def build_sample() -> tuple[DeviceSnapshot, list[ReadRangePage]]:
    """
    构造小样本：bufferSize=5 的环形 Trend Log，共写入 9 条（绝对序号 1..9），
    序号 1..4 已被覆盖。第 7 条为 timeChange=-300s（时钟回退 5 分钟），
    其后记录时间戳随之变小，原地保留。
    """
    # 设备侧环形缓冲当前内容（位置 1..5 对应绝对序号 5..9）
    buffer: list[LogRecord] = [
        LogRecord(timestamp=DateTime("2026-11-18 10:00:00.00"),
                  logDatum=LogRecordLogDatum(realValue=21.5)),          # seq 5
        LogRecord(timestamp=DateTime("2026-11-18 10:01:00.00"),
                  logDatum=LogRecordLogDatum(realValue=21.6)),          # seq 6
        LogRecord(timestamp=DateTime("2026-11-18 10:02:00.00"),
                  logDatum=LogRecordLogDatum(timeChange=-300.0)),       # seq 7 时钟回退
        LogRecord(timestamp=DateTime("2026-11-18 09:58:00.00"),
                  logDatum=LogRecordLogDatum(realValue=21.4)),          # seq 8 回退后的时钟
        LogRecord(timestamp=DateTime("2026-11-18 09:59:00.00"),
                  logDatum=LogRecordLogDatum(logStatus=LogStatus([2]))),# seq 9 logInterrupted
    ]
    snapshot = DeviceSnapshot(
        buffer_size=5,
        record_count=5,
        total_record_count=9,
        stop_when_full=False,
        enable=True,
    )

    # 采集侧：两次 ReadRange，第二次跳过了缓冲位置 4（绝对序号 8）→ 采集缺页
    page1 = ReadRangePage(
        reference_index=1, first_sequence_number=5,
        first_item=True, last_item=False, more_items=True,
        items=buffer[0:3],   # 位置 1..3 → 序号 5,6,7
    )
    page2 = ReadRangePage(
        reference_index=5, first_sequence_number=9,
        first_item=False, last_item=True, more_items=False,
        items=buffer[4:5],   # 位置 5 → 序号 9；位置 4（序号 8）缺失
    )
    return snapshot, [page1, page2]


# ---------------------------------------------------------------- 离线分析

@dataclass
class EvidenceRecord:
    sequence: int            # 绝对序号（依据 firstSequenceNumber + 页内偏移）
    page: int                # 来自第几次 ReadRange
    position_in_page: int    # 页内偏移（1 基）
    timestamp: str
    datum_kind: str
    datum_value: str
    notes: list[str] = field(default_factory=list)


def datum_summary(record: LogRecord) -> tuple[str, str]:
    datum = record.logDatum
    choice = datum._choice
    value = getattr(datum, choice)
    if choice == "logStatus":
        return choice, str(LogStatus(value))
    return choice, str(value)


def analyze(snapshot: DeviceSnapshot, pages: list[ReadRangePage]):
    records: list[EvidenceRecord] = []
    gaps: list[tuple[int, int]] = []          # 采集缺页区间（闭区间，绝对序号）
    prev_seq: int | None = None

    for page_no, page in enumerate(pages, start=1):
        if prev_seq is not None and page.first_sequence_number > prev_seq + 1:
            gaps.append((prev_seq + 1, page.first_sequence_number - 1))
        for offset, item in enumerate(page.items):
            seq = page.first_sequence_number + offset
            kind, value = datum_summary(item)
            rec = EvidenceRecord(
                sequence=seq, page=page_no, position_in_page=offset + 1,
                timestamp=str(item.timestamp), datum_kind=kind, datum_value=value,
            )
            if kind == "timeChange":
                rec.notes.append(
                    f"时钟调整 {value}s：设备时钟在此记录处发生跳变，"
                    "后续时间戳不保证单调，禁止按时间重排"
                )
            if kind == "logStatus":
                rec.notes.append(f"日志状态记录（{value}）：采集/记录曾中断，非数据点")
            records.append(rec)
            prev_seq = seq

    # 覆盖区间：由 totalRecordCount 与 recordCount 推算，与采集无关
    overwritten: tuple[int, int] | None = None
    wrap_note: str | None = None
    if snapshot.total_record_count >= snapshot.record_count:
        oldest = snapshot.total_record_count - snapshot.record_count + 1
        if oldest > 1:
            overwritten = (1, oldest - 1)
    else:
        wrap_note = (
            f"totalRecordCount({snapshot.total_record_count}) < "
            f"recordCount({snapshot.record_count})：序号 Unsigned32 回绕，"
            "需先按 2^32 展开再比较；回绕本身不是覆盖，也不是缺页"
        )

    return records, gaps, overwritten, wrap_note


# ---------------------------------------------------------------- 报告输出

def render(snapshot: DeviceSnapshot, pages: list[ReadRangePage]) -> str:
    records, gaps, overwritten, wrap_note = analyze(snapshot, pages)
    lines: list[str] = []
    add = lines.append

    add("# Trend Log 离线证据整理报告")
    add("")
    add("## 设备属性快照（采集时刻）")
    add("")
    add(f"- `bufferSize` = {snapshot.buffer_size}（环形，`stopWhenFull` = "
        f"{str(snapshot.stop_when_full).lower()}）")
    add(f"- `recordCount` = {snapshot.record_count}（当前缓冲内有效记录数）")
    add(f"- `totalRecordCount` = {snapshot.total_record_count}（自清除以来累计写入数）")
    add(f"- `enable` = {str(snapshot.enable).lower()}")
    add("")
    add("由 `totalRecordCount - recordCount + 1` 推得当前缓冲最老绝对序号为 "
        f"{snapshot.total_record_count - snapshot.record_count + 1}。"
        "缓冲位置（当前索引）只是槽位，不是历史记录号。")
    add("")

    add("## ReadRange 采集记录")
    add("")
    for i, p in enumerate(pages, 1):
        flags = f"firstItem={p.first_item}, lastItem={p.last_item}, moreItems={p.more_items}"
        add(f"- 第 {i} 页：byPosition referenceIndex={p.reference_index}，"
            f"firstSequenceNumber={p.first_sequence_number}，返回 {len(p.items)} 条（{flags}）")
    add("")

    add("## 逐条证据")
    add("")
    add("| 绝对序号 | 顺序依据 | 时间戳（原样） | 内容 | 备注 |")
    add("|---|---|---|---|---|")
    for r in records:
        basis = f"第{r.page}页 firstSequenceNumber + 页内偏移{r.position_in_page - 1}"
        datum = f"{r.datum_kind}={r.datum_value}"
        note = "；".join(r.notes) if r.notes else "—"
        add(f"| {r.sequence} | {basis} | {r.timestamp} | {datum} | {note} |")
    add("")

    add("## 可证明的顺序")
    add("")
    seqs = [r.sequence for r in records]
    add(f"- 已采集记录的全序（按绝对序号，非时间戳）：{' → '.join(map(str, seqs))}")
    for r in records:
        if r.datum_kind == "timeChange":
            add(f"- 序号 {r.sequence} 为 timeChange={r.datum_value}s，时钟回退原地保留；"
                "其后记录时间戳变小是回退的直接后果，不构成乱序证据")
    add("- 未按时间戳重排任何记录；时间戳仅作原样存档")
    add("")

    add("## 未知区间与缺失分类")
    add("")
    if overwritten:
        add(f"- **环形覆盖**：绝对序号 {overwritten[0]}..{overwritten[1]} "
            "已被后续写入覆盖，内容不可恢复，本报告不作任何还原性陈述")
    for lo, hi in gaps:
        add(f"- **采集缺页**：绝对序号 {lo}..{hi} 在两次 ReadRange 之间被跳过；"
            "采集时该记录仍在缓冲中，属于采集缺失而非设备覆盖，可补采")
    if wrap_note:
        add(f"- **序号回绕**：{wrap_note}")
    else:
        add("- **序号回绕**：本样本未发生（totalRecordCount 远小于 2^32）；"
            "若出现 totalRecordCount < recordCount 才按 Unsigned32 回绕处理")
    add("")
    add("## 不能声称的事项")
    add("")
    add("- 不能声称恢复序号 1..4 的内容：环形覆盖是破坏性的")
    add("- 不能把缓冲位置当作历史记录号：位置随写入滚动复用")
    add("- 不能据时间戳推断缺失区间内的记录数或取值")
    add("")
    return "\n".join(lines)


if __name__ == "__main__":
    snapshot, pages = build_sample()
    report = render(snapshot, pages)
    with open("trendlog_report.md", "w", encoding="utf-8") as f:
        f.write(report)
    print(report)
