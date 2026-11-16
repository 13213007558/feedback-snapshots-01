# BLF 当前/影子元数据离线对照诊断

基于 `dissect.clfs` 的**只读离线**对照工具，用来回答一个问题：BLF（Base Log
File）里成对保存的 current（偶数 block type）与 shadow（奇数 block type）元数据，
各自能证明什么、哪里一致、哪里只是事务快照分歧、哪里无法判定。

## 为什么不能把两份 stream 列表合并

CLFS 对每类元数据块做双缓冲（double-buffer / shadow）：

| block type | 枚举 | 角色 |
|---|---|---|
| 0 / 1 | Control / ControlShadow | 控制记录 + 元数据块描述符表 |
| 2 / 3 | General / GeneralShadow | base record：stream（client context）+ container context |
| 4 / 5 | Scratch / ScratchShadow | truncate（截断）暂存记录 |

一次元数据事务先写其中一个槽，下一次写另一个槽，崩溃时靠另一个槽回滚。因此两份
General 块是**两个历史事务时刻的完整快照**，不是同一状态的两半。把两份 stream /
container 列表做并集，会凭空造出从未同时存在过的对象集合。本工具对两个视图
**分别解析、分别保留字段原值与来源块偏移**，从不合并。

## 文件

- `blf_shadow_diff.py` — 诊断工具（文本或 `--json` 输出），对单侧损坏完全容错。
- `make_corrupt_sample.py` — 用仓库自带完好夹具确定性地造出局部损坏样本。
- `sample_corrupt.blf` — 生成的损坏样本（33792 字节）。
- `report_normal.txt` / `report_corrupt.txt` — 两个样本的完整对照报告。
- 测试：`../tests/test_blf_shadow_diff.py`。

运行：

```bash
SRC="tests/data/DRIVERS{53b39e70-18c4-11ea-a811-000d3aa4692b}.TM.blf"
python diagnostics/blf_shadow_diff.py "$SRC"            # 文本
python diagnostics/blf_shadow_diff.py "$SRC" --json     # 机器可读
python diagnostics/make_corrupt_sample.py "$SRC" diagnostics/sample_corrupt.blf
```

## 正常样本结论（DRIVERS…TM.blf，65536 字节）

两份 General 块都可解析。以下为字段原值（来源：current=offset 0x800/type2，
shadow=offset 0x8200/type3）。

### 一致项（两视图相等，可作为身份事实）

- `IdLog = 752f16000519ea11a810000d3aa41ef3`：两块描述的是同一个物理 log。
- container 身份：id 0 与 id 1 的名称（`%BLF%\...Container0000...0001/0002.regtrans-ms`）
  与大小（524288）两份完全一致。
- stream 0 的名称、client id、文件属性（258 = HIDDEN|TEMPORARY）、容器起始偏移
  （36864）一致。
- `lsn_last = 0x9200`、`lsn_physical_base = 0x9001` 两份一致。
- `lsn_archive_tail = 0xffffffff00000000`（CLFS invalid LSN，container 0xffffffff、
  record 0）两份一致，表示没有归档尾。
- base header 簿记字段（NextClient/NextContainer/Active/Busy/Usn/Clients 等）一致。
- 主控制块 magic `0xc1f5c1f500005f1c` 有效，描述符表声明 6 个块，偏移/大小可跟随。
- Scratch(current) 可解析且 `ClientChangeOffset=0, OwnerPageOffset=0`，该副本没有
  暂存的 truncate 变更。

### 矛盾/分歧项（值不同，但属预期快照分歧，不是损坏证据）

- `DumpCount`：current=33 vs shadow=34。只能证明两块来自不同元数据事务；
  DumpCount 是写计数不是时钟，**不能据此判定哪个槽是“最新提交”，也没有墙钟时间**。
- `lsn_base`：current=`0x8401` vs shadow=`0x9001`。
- `lsn_flush`：current=`0x8401` vs shadow=`0x9001`。

这两个 LSN 差异标为 `contradictory/divergent`：它们是两个事务时刻的不同逻辑位置。
LSN 仅编码 `ContainerId:RecordIndex`，**数值更大不等于墙钟更晚**，也绝不取并集或
“挑大的那个”。

### 无法判定项

- ControlShadow（offset 0x400）与 ScratchShadow（offset 0xfe00）是**全零未初始化块**
  （header TotalSectors=0）。这不是损坏，只是这些槽从未落盘过事务；因此没有第二份
  控制记录 / truncate 记录可交叉验证，也无法确认或否认发生过截断。

## 局部损坏合成案例（sample_corrupt.blf）

在保持主控制块与 current General 块逐字节不变的前提下注入两个独立缺陷：

- **缺陷 A（单侧损坏）**：覆写 shadow General 块头部（0x8200）的
  TotalSectors/ValidSectors，使其无法解码（`dissect.clfs` 抛
  `ValueError: memoryview assignment...`）。
- **缺陷 B（截断）**：在 0x8400 处截断文件，描述符表指向的两个 Scratch 块
  （0xfc00/0xfe00）全部落在 EOF 之外。

诊断结果：

- current General 仍完整解析 → stream 0、container 0/1 的身份与 LSN 原值照常给出。
- shadow General `unparseable`、两个 Scratch `missing`，全部进入**无法判定**，
  工具不猜测、不补全、不把缺失侧当作“被删除对象”。
- 所有跨副本比较项都不再下一致/矛盾结论；最小容器证据仍可由**单一可读视图**建立，
  但标注“无双视图佐证（two-view corroboration = False）”。

仓库自带的 `tests/data/control_record.blf`（仅 1024 字节）是另一种纯截断情形：
主控制块可读，但描述符表的所有目标都在 EOF 外，工具同样逐块标 `missing` 而不崩溃。

## 建立“可读容器集合”的最小证据条件

仅靠 BLF 元数据，需要**同时**满足：

1. 主控制记录 magic 有效，其描述符表能定位到至少一个 General 块；
2. 该 General 块的 log-block header 与 base record 能成功解析；
3. client 符号表产出 **≥1 个 stream**；
4. container 符号表产出 **≥1 个 container context**，且每个都有非空名称、正大小、
   以及能与某个 stream 匹配的 container id。

**一个可读 General 视图即满足元数据最小条件**；第二个可读视图只起佐证作用，损坏
样本正是靠单视图满足条件。若要进一步真正读出日志记录，还额外要求：被命名的
`.regtrans-ms` 容器文件在磁盘上存在且可读，并且其首个 log-block header 能在 stream
给出的容器起始偏移处解析。`lsn_archive_tail` 是否为有效 LSN **不**是前置条件。

## 明确的边界（不做的推断）

- `dissect.clfs` 只解析 checksum 字段、**不校验**，报告中的 `checksum_raw` 仅作线索，
  不能用来认证块完整性。
- 解析的控制/base/scratch 结构里没有墙钟时间戳；本工具不输出任何时间先后结论。
- shadow 块是先前事务镜像，不是删除墓碑；shadow-only / current-only 条日记为
  “快照差异（无法判定）”，从不宣称该对象已删除。
- 截断或单侧损坏时只陈述能读到的部分与读不到的原因，不做外推。
