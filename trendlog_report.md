# Trend Log 离线证据整理报告

## 设备属性快照（采集时刻）

- `bufferSize` = 5（环形，`stopWhenFull` = false）
- `recordCount` = 5（当前缓冲内有效记录数）
- `totalRecordCount` = 9（自清除以来累计写入数）
- `enable` = true

由 `totalRecordCount - recordCount + 1` 推得当前缓冲最老绝对序号为 5。缓冲位置（当前索引）只是槽位，不是历史记录号。

## ReadRange 采集记录

- 第 1 页：byPosition referenceIndex=1，firstSequenceNumber=5，返回 3 条（firstItem=True, lastItem=False, moreItems=True）
- 第 2 页：byPosition referenceIndex=5，firstSequenceNumber=9，返回 1 条（firstItem=False, lastItem=True, moreItems=False）

## 逐条证据

| 绝对序号 | 顺序依据 | 时间戳（原样） | 内容 | 备注 |
|---|---|---|---|---|
| 5 | 第1页 firstSequenceNumber + 页内偏移0 | 2026-11-18 wed 10:00:00.00 | realValue=21.5 | — |
| 6 | 第1页 firstSequenceNumber + 页内偏移1 | 2026-11-18 wed 10:01:00.00 | realValue=21.6 | — |
| 7 | 第1页 firstSequenceNumber + 页内偏移2 | 2026-11-18 wed 10:02:00.00 | timeChange=-300.0 | 时钟调整 -300.0s：设备时钟在此记录处发生跳变，后续时间戳不保证单调，禁止按时间重排 |
| 9 | 第2页 firstSequenceNumber + 页内偏移0 | 2026-11-18 wed 09:59:00.00 | logStatus=log-interrupted | 日志状态记录（log-interrupted）：采集/记录曾中断，非数据点 |

## 可证明的顺序

- 已采集记录的全序（按绝对序号，非时间戳）：5 → 6 → 7 → 9
- 序号 7 为 timeChange=-300.0s，时钟回退原地保留；其后记录时间戳变小是回退的直接后果，不构成乱序证据
- 未按时间戳重排任何记录；时间戳仅作原样存档

## 未知区间与缺失分类

- **环形覆盖**：绝对序号 1..4 已被后续写入覆盖，内容不可恢复，本报告不作任何还原性陈述
- **采集缺页**：绝对序号 8..8 在两次 ReadRange 之间被跳过；采集时该记录仍在缓冲中，属于采集缺失而非设备覆盖，可补采
- **序号回绕**：本样本未发生（totalRecordCount 远小于 2^32）；若出现 totalRecordCount < recordCount 才按 Unsigned32 回绕处理

## 不能声称的事项

- 不能声称恢复序号 1..4 的内容：环形覆盖是破坏性的
- 不能把缓冲位置当作历史记录号：位置随写入滚动复用
- 不能据时间戳推断缺失区间内的记录数或取值
