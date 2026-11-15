# EWF `table` / `table2` 分歧的可重复取证诊断

本目录提供一套**只读、可重复**的实验，用于在 Expert Witness Format (EWF/E01)
镜像的主块表 `table` 与备份块表 `table2` 内容不一致时，避免“挑一个能解压的
版本继续取证”。所有产物由源码重新生成，`dissect/evidence` 库源码与任何既有
证据文件都不会被修改；损坏只作用于基线镜像的副本。

## 1. 块定位路径（源码依据）

`dissect/evidence/ewf/ewf.py` 的实际行为：

- `Segment.tables`（`ewf.py:280-282`）用 `type(section) is TableSection`
  过滤，**显式忽略 `table2`**，库本身没有主备切换逻辑。
- `EWF.read_chunk`（`ewf.py:177-227`）对每个 32 位条目：
  - 绝对偏移 `offset_of_chunk = table.base_offset + (entry & 0x7FFFFFFF)`；
  - 压缩标志 `compressed = (entry >> 31) == 1`；
  - 非末块的结束位置来自下一条条目的偏移；末块结束位置在表段起点与
    表段 raw 结尾之间判定（`ewf.py:202-212`）；
  - 未压缩块扣除末尾 4 字节 Adler-32；压缩块直接 `zlib.decompress`。
- 结构定义见 `dissect/evidence/ewf/c_ewf.py:34-110`：段描述符 76 字节、
  表头 24 字节（`number_of_entries`、保留位、`base_offset`、保留 4 字节、
  表头 checksum）。

本审计工具 `src/ewf_table_audit.py` 独立解析同一份字节，不调用库的
`tables` 过滤，因此两个表都能被检查；定位公式与 `read_chunk` 保持一致，
末块边界按“该表基址绑定的数据段 raw 结尾”泛化，使 `table2` 也可定位。

## 2. 可用校验及其覆盖范围（经夹具验证）

用 `tests/_data/ewf/single/image.E01` 实测确认：

| 校验 | 覆盖字节 | 不能发现什么 |
| --- | --- | --- |
| 段描述符 Adler-32 | 描述符前 72 字节（类型/next/size/40 字节 padding） | 段内数据被改 |
| 表头 Adler-32 | 24 字节表头的前 16 字节（条目数、保留、`base_offset`） | **条目数组被改** |
| volume 段 Adler-32 | 1048 字节正文（不含末尾 4 字节 checksum） | 块数据被改 |
| 未压缩块尾部 Adler-32 | 该块解压后载荷 | 压缩块无此尾部 |
| 压缩块 zlib 流 | zlib 自带 Adler-32，仅保证流完整 | 被替换为另一组合法流时无效 |

关键结论：**没有任何 EWF 内部校验覆盖表条目数组**。改一个条目字（场景 02/03）
后所有 Adler-32 仍然有效，问题只会在沿块映射读取时暴露。因此“校验全过”
只能证明结构未被随机破坏，不能证明块映射指向的是原始内容。

## 3. 场景集（`images/`，由 `src/generate_scenarios.py` 生成）

每个镜像 1.8–7.2 KB、6 个块（5 个 512 字节满块 + 1 个部分末块）。

| 文件 | 构造 | table | table2 | 判定 |
| --- | --- | --- | --- | --- |
| `00_baseline_uncompressed` | 干净基线，两表一致 | 合法/完整 | 合法/完整 | `RECOVERABLE_CONSISTENT` |
| `01_baseline_compressed` | 同上但全块 zlib 压缩 | 合法/完整 | 合法/完整 | `RECOVERABLE_CONSISTENT` |
| `02_primary_entry_tampered_checksums_valid` | 主表条目 +0x40，校验仍有效 | 合法但读取失败 | 合法/完整 | `INSUFFICIENT_EVIDENCE` |
| `03_backup_flag_flipped_checksums_valid` | 备表压缩标志位被翻 | 合法/完整 | 合法但读取失败 | `INSUFFICIENT_EVIDENCE` |
| `04_tables_divergent_both_valid` | 两个 sectors 段，两表各自合法且完整 | 完整（集合 A） | 完整（集合 B） | `CONFLICT` |
| `05_primary_stale_checksums` | 主表表头+描述符 Adler-32 失效 | 结构非法 | 合法/完整 | `RECOVERABLE_SINGLE_TABLE` |
| `06_both_tables_stale_checksums` | 两表 Adler-32 均失效 | 结构非法 | 结构非法 | `INSUFFICIENT_EVIDENCE` |
| `07_primary_wrong_base_offset` | 主表基址改写并重算校验 | 结构非法（基址不匹配） | 合法/完整 | `INSUFFICIENT_EVIDENCE` |
| `08_primary_last_chunk_overflow` | 主表末块条目移到表段边界并重算校验 | 合法但末块越界 | 合法/完整 | `INSUFFICIENT_EVIDENCE` |

## 4. 结论分级的条件

- **可恢复（RECOVERABLE_CONSISTENT）**：两表都通过结构校验，条目映射与
  `base_offset` 完全相同，且两条读取路径产出的逻辑镜像 SHA-256 一致。
  场景 00/01 满足。
- **可恢复但仅单表可信（RECOVERABLE_SINGLE_TABLE）**：恰好一张表结构
  非法，另一张表结构合法、读取完整，且两表映射一致（场景 05）。此时可
  报告“备表支持的候选”，但仍需外部哈希（采集时记录的 MD5/SHA）才能主张
  内容真实。
- **只能报告冲突（CONFLICT）**：两张表都结构合法、都能完整读取，但映射
  不同、候选 SHA-256 不同（场景 04）。EWF 内部不存在任何字段可以裁决，
  必须借助采集哈希、文件系统一致性或外部证言；不得任选其一继续。
- **证据不足（INSUFFICIENT_EVIDENCE）**：
  - 两表都结构非法（06）；
  - 一张表读取失败且两表映射不一致，无法认证幸存者（02/03/07/08）；
  - 结构合法但无完整候选。
  注意 02/03/08 中所有 Adler-32 都有效——**读取失败本身就是证据缺口**。

“读取成功 ≠ 内容真实”由交叉验证量化：`reports/dissect_crosscheck.json`
记录原版库在每个镜像上的行为。场景 02、07、08 中 `EWF.open().read()`
不抛异常，却返回与基线不同的 SHA-256；场景 04 中库静默采用 `table`，
完全看不到备表的另一个候选。

## 5. 可追溯性

- 每个块读取都记录：来源表名、表段偏移、条目索引、原始 32 位描述符字、
  绝对偏移、结束偏移、压缩标志、块级校验结果与该块 SHA-256
  （JSON 报告 `tables.<name>.reads[]`）。
- 场景 04 用 `src/forced_table_reader.py` 分别强制走 `table` 与 `table2`，
  输出 `reports/04_forced_table*.json`，两个候选的每一块都可回溯到所用
  表和文件偏移。
- 每个镜像的 SHA-256、变更字节说明在
  `reports/scenario_manifest.json`；镜像级哈希在各审计 JSON 的
  `file_sha256`。

## 6. 复现方式

```bash
.venv/bin/python ewf-table-audit/run_all.py
.venv/bin/python -m pytest ewf-table-audit/test_table_audit.py -v
.venv/bin/python ewf-table-audit/src/ewf_table_audit.py <image.E01> --json out.json
.venv/bin/python ewf-table-audit/src/forced_table_reader.py <image.E01> --table table2
```

## 7. 文件清单

- `src/ewf_builder.py`：最小 EWF 写入器与双数据段分歧镜像构造；
- `src/ewf_table_audit.py`：独立双表诊断 CLI（文本 + JSON）；
- `src/generate_scenarios.py`：9 个场景的确定性生成器；
- `src/cross_check_dissect.py`：原版库行为交叉验证；
- `src/forced_table_reader.py`：强制按指定表读取并输出 provenance；
- `test_table_audit.py`：20 个 pytest 断言锁定判决矩阵；
- `images/`、`reports/`：生成的镜像、JSON 报告与运行日志。
