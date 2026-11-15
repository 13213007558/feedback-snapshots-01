# ASDF 多流证据标识方案（源码依据版）

## 1. 背景与问题

ASDF（Acquire Snapshot Data Format）在一个容器内用单字节 `idx` 区分多条流，取证平台目前只能展示
数字 `idx`，无法回答“这条流对应哪块物理盘/哪个分区/是不是内存”。本方案在**不改动底层块格式、
不破坏旧文件读取**的前提下，增加一层可实施的证据身份标识。

设计红线：

- 同一磁盘的不同区间（extent）必须能归并；不同磁盘上的相同偏移**绝不能**据此合并。
- 没有序列号或采集声明时，**不得**声称识别了同一台设备。
- 旧 ASDF 文件（无任何元数据）必须继续可读，且结论只能降级表述、不得臆造。

## 2. 现有格式能提供哪些身份依据（含源码位置）

### 2.1 容器级依据

| 依据 | 字段 / 机制 | 源码位置 | 能证明什么 |
| --- | --- | --- | --- |
| 写入者 GUID | `header.guid[16]`，写盘时 `guid=self.guid.bytes_le` | `dissect/evidence/asdf/c_asdf.py:22`、`dissect/evidence/asdf/asdf.py:219` | 同一写入者/采集会话的容器归属；读取侧 `self.guid = uuid.UUID(bytes_le=...)` 还原（`asdf.py:328`） |
| 采集时间戳 | `header.timestamp` | `c_asdf.py:20`、`asdf.py:218` | 容器创建时间（时间维度的弱关联，非设备标识） |
| 容器完整性 | 页脚 `sha256[32]` 覆盖整段数据 | `c_asdf.py:48`、`asdf.py:301` | 容器未被篡改；`asdf-verify` 据此校验（`tools/asdf/verify.py:83`） |

### 2.2 流与块级依据

| 依据 | 字段 / 机制 | 源码位置 | 能证明什么 |
| --- | --- | --- | --- |
| 流索引 | `block.idx` / `table_entry.idx`（uint8） | `c_asdf.py:28`、`c_asdf.py:36` | 字节归属哪条流；**仅是写入者分配的命名空间，不含物理设备绑定** |
| 绝对流内偏移 | `block.offset`，写入时 `absolute_offset = base + offset` | `asdf.py:233`、`asdf.py:262` | 字节在该流内的绝对位置 |
| 相对卷 base | 仅作为写入入参，落盘只存 `base+offset` 的绝对值 | `asdf.py:113`、`asdf.py:125`、`asdf.py:245` | 卷相对磁盘的起点信息当前**不会被格式持久化**，必须由本方案补记 |
| 保留流 | `IDX_MEMORY=254`、`IDX_METADATA=255`、`MAX_IDX=253` | `asdf.py:34`-`asdf.py:37` | 254 内存、255 元数据 TAR 在结构上即可区分；0–253 为磁盘/卷流 |
| 每块 CRC32 | `BLOCK_FLAG.CRC32` + 尾部 4 字节 | `c_asdf.py:11`、`stream.py:40`、`verify.py:99` | 单块数据完整性（块级，非身份） |
| 按流独立去重 | 块表按 `idx` 分桶，`_table_fit` 仅在同一 idx 内合并/裁剪 | `asdf.py:235`、`asdf.py:363`、`asdf.py:588` | 不同 idx 的块永不互相覆盖；同 idx 的多个区间天然属于同一流 |

关键推论（直接决定合并规则）：

1. **偏移是流内寻址，不是设备身份。** 两块盘都可以在 `offset=0` 存放块，`idx` 不同即不同流，
   格式本身就把它们隔离（`_table` 以 `idx` 为键，`asdf.py:235`）。
2. **同一 `idx` 的多个不连续区间可安全归并**为一条流：它们共享同一个写入者分配的流命名空间，
   读取侧 `AsdfStream` 也是把同 idx 的 runlist 拼成一条连续、稀疏处填 `SPARSE_BYTES` 的流
   （`asdf.py:450`-`asdf.py:540`）。
3. **卷的 `base` 在落盘后丢失。** `copy_bytes(..., base=...)` 只保存 `base+offset`（`asdf.py:233`），
   因此“卷在磁盘上的字节起点”无法从旧块表反推，必须在身份层显式记录。

### 2.3 元数据目录（TAR，idx=255）

- 写入端已有通用 API：`AsdfWriter.add_metadata_file(path, fh)`（`asdf.py:91`），
  关闭时整个 TAR 写入 `IDX_METADATA`（`asdf.py:278`-`asdf.py:284`）。
- 读取端 `Metadata` 是对 `tarfile` 的薄封装，提供 `names()/members()/open(path)`
  （`asdf.py:421`-`asdf.py:447`），CLI `asdf-meta ls/cat/hash` 已可用。
- 元数据 TAR 本身没有强制 schema，条目名自由（测试 `tests/test_asdf.py:172` 仅写入普通文件）。
  这正好提供了一个**版本化、向后兼容**的扩展承载点。

## 3. 置信度模型（把“事实”与“声明”分开）

| 级别 | 含义 | 成立条件 |
| --- | --- | --- |
| `verified` | 硬件级识别 | 存在序列号等硬件标识，且容器/块完整性校验通过 |
| `declared` | 采集声明 | 由采集清单显式断言（含采集分组声明），但无序列号佐证 |
| `structural` | 仅结构事实 | 只凭块表与保留 idx 能证明的内容；旧文件恒为此级 |

内容哈希（如整条流 SHA256）只作为**弱关联提示**：数据相似不能证明同源设备，因此
`IdentityReader.can_merge()` 不接受哈希作为同设备依据（实现见 `identity.py` 的 `stream_sha256`
文档与 `can_merge`）。

## 4. 标识方案设计

### 4.1 承载方式：元数据 TAR 内的版本化清单

在 idx=255 的 TAR 中增加固定路径 `asdf-identity/manifest.json`，schema 标识 `asdf-identity/v1`。
清单只是一个普通元数据文件，复用 `add_metadata_file`，块格式、魔数、页脚、块表全部不变。

清单 JSON 结构（`IdentityManifest.to_dict`）：

```json
{
  "schema": "asdf-identity/v1",
  "writer_guid": "11111111-2222-3333-4444-555555555555",
  "acquisition": {"case_id": "CASE-2026-0001", "acquirer": "acquire-agent/3.1", "group_id": "run-7f3a"},
  "streams": {
    "0": {"kind": "disk", "serial": "S1AXNS0AA90001", "device": "/dev/sda", "label": "evidence-disk-A"},
    "1": {"kind": "disk", "device": "/dev/sdb", "label": "evidence-disk-B", "group_id": "run-7f3a"},
    "2": {"kind": "volume", "parent_idx": 0, "volume_base": 1048576, "filesystem": "ntfs"}
  }
}
```

写入时 `attach_manifest()` 校验 `writer_guid` 与当前 writer 一致，防止把 A 容器的清单挂到 B 容器。

### 4.2 规范化字节定位符（Canonical Locator）

格式：`urn:asdf:{writer_guid}:stream/{idx}/{kind}#offset={abs}[&size={n}]`

- 偏移被 `writer_guid + idx` 限定作用域：不同 idx 即使偏移相同，定位符也不同；
  同一 idx 的不同区间共享同一作用域，可归并。
- 保留流自带 kind：`.../stream/254/memory#...`、`.../stream/255/metadata#...`。
- 定位符不依赖任何易失挂载点，可作为跨工具引用的稳定句柄。

### 4.3 卷回磁盘的映射

`IdentityReader.disk_extent(idx, offset, size)` 对卷流返回 `(parent_idx, volume_base + offset)`，
把卷内字节偏移换算成父盘绝对偏移；整盘流与保留流原样返回。`volume_base` 的语义与写入端
`base` 参数完全一致（`asdf.py:125`-`asdf.py:141`）。

### 4.4 同设备判定矩阵（`can_merge`）

| 情形 | 结论 | 置信度 | 理由 |
| --- | --- | --- | --- |
| 同一 idx 的多个区间 | 可归并 | structural | 同流命名空间，读取侧本就拼成一条流 |
| 不同 idx，序列号都存在且相等 | 同一设备 | verified | 硬件标识匹配 |
| 不同 idx，序列号都存在但不等 | 不同设备 | verified | 硬件标识冲突 |
| 不同 idx，被同一 `group_id` 采集声明显式绑定 | 同一设备 | declared | 采集者声明，非硬件证明 |
| 不同 idx，仅有相同偏移 / 相似哈希 | **拒绝合并** | structural | 偏移与哈希都不是设备身份 |

## 5. 缺失元数据时允许展示的最强结论

旧文件或清单缺项时，`IdentityReader` 走结构回退（`source="structure"`、`confidence=structural`），
`strongest_conclusion()` 给出不越界的措辞：

- 普通磁盘流（0–253）：
  “容器 `{guid}` 内的独立字节流 idx=N；设备身份未证实，不得仅凭偏移合并。”
- 卷流（清单有 base 但无序列号）：
  “卷 idx=N 相对磁盘 idx=P，字节 base=B；物理设备未识别。”
- 内存流（idx=254）：“保留内存流 idx=254；内容来源未声明。”
- 元数据流（idx=255）：“保留元数据 TAR 流 idx=255。”
- 有序列号且完整性通过：才可写“磁盘 idx=N 由序列号 … 识别（verified）”。

## 6. 扩展元数据 vs 改变底层块格式：代价对比

| 维度 | 方案 A：元数据 TAR 扩展（本方案） | 方案 B：修改块/表头格式 | 方案 C：外部 sidecar 文件 |
| --- | --- | --- | --- |
| 旧读取器兼容 | 完全兼容，未知 TAR 条目被忽略 | 破坏兼容，需升 `version` 并双解析路径 | 容器本身兼容，但证据与身份分离 |
| 旧文件读取 | 不受影响，自动降级 structural | 旧 reader 遇新结构报错/误判 | 不受影响 |
| 完整性覆盖 | 清单在页脚 SHA256 与块表覆盖范围内，随容器一体封存 | 同样被覆盖，但格式面扩大 | sidecar 需另行签名，易与容器脱节 |
| 恢复路径 | `asdf-repair` 刮块机制无需改动 | 刮块/校验/修复全部要适配新结构 | 不影响修复，但需单独保管 |
| 实现成本 | 新增一个纯标准库模块 + 清单写入，零格式改动 | 改 cstruct、writer、reader、repair、verify、全部测试 | 低，但引入多文件保管与同步问题 |
| 可演进性 | `schema` 字段独立版本化，可加 v2 条目 | 受单字节 `version` 与固定结构约束，演进刚性 | 灵活但缺乏容器内约束力 |
| 取证可采性 | 声明与数据同容器、同哈希封存，链证清晰 | 清晰但升级窗口内新旧混杂 | 最弱，需额外证明 sidecar 未被替换 |

结论：**采用方案 A**。它把变化限制在已经存在、本就自由格式的元数据 TAR 内，
块格式与所有现有读取/修复/校验路径零改动；只有当未来需要在每个块上携带逐块硬件归属
（而非流级声明）时，才值得评估方案 B 的格式升级。

## 7. 落地物与验证

- `dissect/evidence/asdf/identity.py`：`IdentityManifest`（写）、`IdentityReader`（读/回退）、
  `StreamIdentity`、`MergeDecision`、`attach_manifest()`、`stream_sha256()`。
- `examples/asdf_identity_demo.py`：纯内存端到端样例（两块盘 + 一个卷 base + 一个内存流）。
- `tests/test_asdf_identity.py`：13 个单测，覆盖结构回退、保留流、verified/declared、
  同偏移拒绝合并、序列号匹配/冲突、采集分组、locator、卷 base 映射、GUID 防错挂、旧文件兼容。

运行：

```sh
.venv/bin/python examples/asdf_identity_demo.py
.venv/bin/python -m pytest -q -o addopts= tests
```
