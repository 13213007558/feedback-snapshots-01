# SQLite schema 演变对取证结果的影响 — 离线诊断报告

基于 `dissect.database`（本仓库 `dissect/database/sqlite3/`）复现并分析：
证据库在采集前经历过 `ALTER TABLE ... ADD COLUMN`，旧记录的字节布局与新记录不同。
诊断脚本：`diagnostics/schema_evolution.py`；逐行输出：`diagnostics/schema_evolution_output.txt`
（修复前对照：`diagnostics/schema_evolution_output_before_fix.txt`）。

## 1. 实验构造

WAL 模式、`wal_autocheckpoint=0`（全部变更留在 WAL），6 个事务：

| 事务 | 操作 |
|---|---|
| tx1 | `CREATE TABLE t(id INTEGER PRIMARY KEY, b TEXT)`；插入 id=1,2（旧 schema） |
| tx2 | `ALTER TABLE t ADD COLUMN c TEXT DEFAULT 'dflt'` |
| tx3 | 插入 id=3，`c` 显式写入 `NULL` |
| tx4 | 插入 id=4，`c='real-4'`（实际值） |
| tx5 | `ALTER TABLE t ADD COLUMN d INTEGER DEFAULT 99` |
| tx6 | 插入 id=5，`c='real-5', d=555` |

连接关闭前冻结 `frozen.db` + `frozen.db-wal`（关闭会 checkpoint 并删除 WAL）。
比较三种组合：主文件单独（VIEW A）、主文件+WAL 最新（VIEW B）、主文件+WAL 逐 commit 历史视图（VIEW C1–C7）。

## 2. 物理存储事实（默认值是否在记录字节中）

SQLite record 格式只存储 **INSERT 时存在的列**；`ALTER TABLE ADD COLUMN` 不会重写旧记录。
逐行物理证据（记录头的 serial types，见输出 VIEW B）：

- **id=1,2（ALTER 前写入）**：`serial types=[0, 23]`，只有 2 个物理值。
  `c='dflt'`、`d=99` **不在记录字节中**，是解析器按当前 schema 的 DEFAULT 补出的
  （`sqlite3.py` `Row._match_columns_to_values`，缺失列用 `column.default_value` 填充）。
- **id=3（显式 NULL）**：`serial types=[0, 23, 0]` —— 第三个 serial type `0` 表示
  **NULL 确实物理存在于记录字节中**（0 字节载荷，但类型槽位存在）。它与"列缺失"
  只能通过记录头长度区分，值都是 `None`。
- **id=4,5（实际值）**：`serial types=[0, 23, 25]` / `[0, 23, 25, 2]`，值物理存在。
- **INTEGER PRIMARY KEY 列**：所有行物理存 `NULL`（serial type 0），真实值来自 b-tree
  单元格的 rowid key（`ROWID-ALIAS`），不是记录内容。

**结论：默认值不存在于记录字节中；显式 NULL 存在；rowid 别名存的 NULL 也不是主键值。**
报告中每个字段必须标注来源：`PHYSICAL` / `ROWID-ALIAS` / `PARSER-DEFAULT` / `ABSENT->NULL` / `UNKNOWN`。

## 3. 各视图逐行结果（修复后，`schema_evolution_output.txt`）

- **VIEW A（仅主文件）**：`(no user tables visible in this view)` —— 建表本身在 WAL 里，
  未 checkpoint 时主文件没有任何用户表。主文件单独分析会漏掉全部证据。
- **VIEW B（主文件+WAL 最新）**：5 行，4 列 schema。id=1,2 的 `c`,`d` 为 PARSER-DEFAULT；
  id=3 的 `c=None` 为 PHYSICAL（serial type 0）；id=4,5 全 PHYSICAL。
  与官方 `sqlite3` 的 `SELECT *` 逐行比对一致（见 §5 证据）。
- **VIEW C1（commit #1，建表）**：schema 2 列，无数据行（插入在下一 commit）。
- **VIEW C2（commit #2，插入后、ALTER 前）**：schema 2 列，id=1,2 各 2 个物理值，
  **没有** `c`/`d` 字段 —— 该时刻列尚不存在，正确的历史解释。
- **VIEW C3（commit #3，ALTER c 后）**：schema 3 列，id=1,2 的 `c='dflt'` 为 PARSER-DEFAULT
  （此刻起 SQLite 自己也会这样补，语义正确）。
- **VIEW C4/C5**：id=3（c 物理 NULL）、id=4（c 物理实际值）依次出现，schema 均 3 列。
- **VIEW C6（ALTER d 后）**：schema 4 列，id=1–4 的 `d=99` 为 PARSER-DEFAULT。
- **VIEW C7（最终）**：与 VIEW B 一致。

## 4. 发现的错配与修复

**错配（WAL checkpoint 视图被未来 commit 污染）**：
`SQLite3.raw_page()` 在指定 checkpoint 时，若该 checkpoint 的帧不含某页，会回退到
`wal.commits` 里**最新**的提交帧 —— 包括请求点**之后**的提交。证据（修复前输出
`schema_evolution_output_before_fix.txt`）：

- VIEW C2（ALTER 前）却显示 4 列 schema，id=1,2 被补出 `c='dflt'`、`d=99`
  —— 未来 schema 泄漏进历史视图；
- VIEW C3（commit #3）里出现 id=4,5（commit #4/#6 才插入的行），且 id=5 的
  第 4 个物理值 `555` 因 schema 只有 3 列而落入 `unknowns` 被静默丢弃。

**修复**（`dissect/database/sqlite3/sqlite3.py` `raw_page`）：checkpoint 视图只允许
使用该 checkpoint **及其之前**的 commit 帧，再回退主文件；未来 commit 不再泄漏。
同时保持原行为：checkpoint 分支不做 `frame.valid`（salt）检查，因为历史 checkpoint
的帧本来就不是当前 WAL epoch 的 salt（该特性正是 test_wal.py 依赖的取证时间线能力）。
回归测试：`tests/sqlite3/test_wal.py::test_wal_checkpoint_view_isolation`（修复前
失败，修复后通过；既有 47 个 sqlite3 测试全部通过）。

## 5. 没有错配的部分（附证据）

- **最新视图与官方实现一致**：用官方 `sqlite3` 对同一冻结库 `SELECT id,b,c,d`，
  与 dissect 的 VIEW B 逐行比对完全相同（含补出的默认值）——
  `dissect` 的默认值填充语义与 SQLite 本身一致，错配只发生在历史视图（已修复）。
- **默认值补全逻辑本身正确**：`Column.default_value` 解析（`test_default_values.py`）
  与 `_match_columns_to_values` 的填充顺序（按列序对齐、缺失补默认、多余进 `unknowns`）
  与 SQLite record 格式规范一致；id=3 的物理 NULL 未被默认值覆盖（值缺失才补，
  物理 NULL 原样保留）。
- **schema 来源正确**：每个视图使用的 schema 来自该视图自己的 page 1（sqlite_master），
  修复后历史视图使用历史 schema（C2 为 2 列、C3 为 3 列、C6 为 4 列），
  不存在"用最新列布局解释所有历史页"的问题。

## 6. 不可确定的部分（取证声明中必须标注）

- **主文件的新旧不可知**：若采集时 WAL 已部分 checkpoint，主文件页可能比某个历史
  checkpoint 更新，但主文件头没有按页版本信息，无法仅从字节判断主文件对应哪个
  checkpoint —— 该视图只能标注为"主文件现状"。
- **默认值 vs 物理同值不可区分于行值层面**：`Row` 的值字典里 `c='dflt'` 不区分
  物理存储还是解析器补出；必须回到 `cell.types`/`cell.values` 的长度判断
  （本诊断的 `PROVENANCE` 标注即基于此方法）。
- **被覆盖的旧记录版本不可恢复**：WAL 中已被后续 commit 覆盖的同页旧版本，
  若帧已被新帧物理覆盖（WAL 重用空间），则无法从现存字节恢复。
- **WAL 中未提交的残留帧**：`WAL.commits` 只组构有 commit 记录的帧，尾部残留帧
  被忽略（库内已有 log 提示），其中可能含未提交数据，需另行手工雕刻。
- **schema 曾 DROP 列的情况**：记录中多出的值进入 `Row._unknowns`，
  若该列定义已从 sqlite_master 消失，列名与类型不可确定，只能给出原始字节。

## 7. 取证建议

1. 报告每行每字段标注物理来源（PHYSICAL / PARSER-DEFAULT / ROWID-ALIAS / UNKNOWN），
   不要把解析器补出的默认值写成"记录中存储的内容"。
2. 用 WAL commit 序列重建历史视图（`SQLite3(db, wal, checkpoint=commit)`），
   每个视图用当时的 schema 解释当时的记录；不要以最新 schema 解释所有历史页。
3. 主文件、WAL 必须同时采集并分别校验（WAL 帧 salt/checksum），缺失 WAL 时
   明确标注"仅主文件，可能丢失未 checkpoint 的全部变更"。
4. 对 `unknowns`（记录有值但 schema 无列）单独报告，不要静默丢弃。
