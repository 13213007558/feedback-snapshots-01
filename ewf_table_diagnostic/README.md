# EWF `table` / `table2` 分歧的可重复诊断

本目录不修改 `dissect.evidence` 的任何源码，也**不覆盖任何源镜像中的主表**。它在
`dissect.evidence` 的块定位路径之外，建立一条独立、可重复、可追溯的诊断流程，用于在
EWF 主表（`table`）与备表（`table2`）内容不一致时，区分“可恢复 / 只能报告冲突 /
证据不足”，而不是默认选择一个能解压的表继续取证。

## 源码依据（dissect.evidence 的实际行为）

- `dissect/evidence/ewf/ewf.py:282` — `Segment.tables` 使用
  `type(section) is TableSection`，显式忽略 `Table2Section`。备表存在但永不参与读取。
- `dissect/evidence/ewf/ewf.py:177-227` — `read_chunk` 的块定位路径：
  - `ewf.py:196` `offset_of_chunk = table.base_offset + (entry & 0x7FFFFFFF)`
  - `ewf.py:197` `compressed = entry >> 31 == 1`（最高位即压缩标志）
  - `ewf.py:202-212` 末块边界：落在本 section 之前用 section 起点，落在 section
    内部用 section 末尾，否则抛出 `Unknown size of last chunk`
  - `ewf.py:214` 非末块边界直接取下一个条目的低 31 位
  - `ewf.py:219-220` 非压缩块末尾 4 字节为块校验，读取时被剔除
- `dissect/evidence/ewf/c_ewf.py:104-110` — `TableSection` 字段：`number_of_entries`、
  `base_offset`（uint64）、`checksum`；条目为连续 uint32。
- 全库没有任何 Adler-32 校验调用：descriptor、table header、entry array、非压缩块尾
  的校验都不会被验证。因此“能解压”只说明字节可被 zlib/边界逻辑消费，不代表内容真实。

字节序结论（用 `tests/_data/ewf` 中 libewf 生成的镜像实测）：descriptor 与 table 的
Adler-32 均为**小端**存储，覆盖各自 checksum 字段之前的字节。本诊断与构造器都据此实现。

## 目录结构

- `src/build_images.py` — 纯标准库的字节级 EWF 构造器，生成基线与四个场景，输出 manifest。
- `src/diagnose.py` — 独立诊断器，输出文本与逐镜像 JSON 报告。
- `src/dissect_reference.py` — 记录未修改的 dissect 在每个镜像上的真实表现。
- `src/run_all.sh` — 一键重建并重新诊断（可复现，校验和稳定）。
- `images/` — 5 个小型 E01 镜像（各 18321 字节）与 `manifest.json`。
- `output/` — `diagnostic.txt`、逐镜像 `*.diagnostic.json`、`dissect_reference.txt`。
- 测试：`tests/test_ewf_table_diagnostic.py`（6 个用例，全部通过）。

## 场景构造与判定条件

每个镜像含 4 个 4096 字节块，压缩标志序列为 `[未压缩, 压缩, 未压缩, 压缩]`，
`base_offset=0`，条目存绝对偏移。SET-A 与 SET-B 是两组不同载荷（块内带 `SET-A|` /
`SET-B|` 标记），可通过 SHA-256 与预览直接区分。

| 镜像 | 构造 | 诊断判定 | 条件说明 |
| --- | --- | --- | --- |
| `baseline.E01` | 两表结构合法、指向同一 SET-A | `RECOVERABLE` | 两表交叉一致、全部块校验通过，互为佐证 |
| `case1_primary_corrupt.E01` | 主表表头校验损坏且 entry0 重定向到文件外 | `RECOVERABLE` | 仅备表结构合法且全部块可验证，主表被证伪 |
| `case2_backup_corrupt.E01` | 备表同样方式损坏 | `RECOVERABLE` | 仅主表可验证；注意 dissect 对此损坏完全无感知 |
| `case3_divergent_legal.E01` | 两表均结构合法，主表指向 SET-A、备表指向 SET-B | `CONFLICT` | 两表都能完整解压但内容不同，禁止静默二选一 |
| `case4_both_tables_corrupt.E01` | 两表表头/条目校验均损坏（条目其余不变） | `INSUFFICIENT` | 部分块仍可解压，但没有任何一张表整体自洽可验证 |

判定规则（见 `src/diagnose.py` 的 `decide`）：

- 仅一张表结构合法且其全部块通过边界与校验 → `RECOVERABLE`，并指明存活表。
- 两张表都合法可读但任一块的解码结果不同 → `CONFLICT`，只能报告冲突。
- 两张表都无法提供整体自洽、逐块验证通过的证据 → `INSUFFICIENT`；部分块解压成功
  不会提升判定等级，读取成功不等于内容真实。

## 核对项与可追溯性

诊断器对每张表分别核对：descriptor/table header/entry array 三处 Adler-32、
`base_offset`、每个条目的压缩标志（bit31）、块跨度是否在文件内、末块边界（复刻
`read_chunk` 的三条规则）、非压缩块尾 Adler-32、压缩块 zlib 解码，以及两表逐块
SHA-256 交叉比对。

每个块结果都记录：所用表（`table`/`table2`）、原始 entry 值、绝对偏移、
`[span_start, span_end)`、压缩标志、校验结果、载荷 SHA-256 与预览。JSON 与文本报告中
的任意候选读取结果，都可回溯到具体的表和字节偏移。

## 复现方式

```bash
bash ewf_table_diagnostic/src/run_all.sh
.venv/bin/python -m pytest tests/test_ewf_table_diagnostic.py -q
```

## 取证边界

dissect 在 case3 上静默返回主表 SET-A、对 case2 的备表损坏无感知、在 case1/case4 上
直接抛错——这三种结果都不能作为内容真实性的依据。诊断器的结论仅在对应表通过结构与
逐块校验时成立；`CONFLICT` 与 `INSUFFICIENT` 必须原样进入取证报告，交由人工结合外部
哈希或采集链证据进一步判断。
