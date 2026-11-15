# 同 GUID、不同版本 manifest 的离线冲突诊断

两台采集机导出的 ETL 使用**相同 provider GUID**，却携带**不同版本的 manifest**。本目录基于
`dissect.etl` 构造一个完全离线、可运行的最小复现，定位“差异从哪一行进入解析链”，并给出可实施的
冲突处理建议。不依赖网络，也不实现新的模板仓库服务。

## 1. 运行方式

```bash
# 使用仓库自带 .venv
.venv/bin/python -m diagnostics.manifest_conflict.run_diagnosis
# 或指定输出目录
.venv/bin/python -m diagnostics.manifest_conflict.run_diagnosis --output-dir "$TMPDIR/diag"

# 运行固化结论的测试
.venv/bin/python -m pytest tests/test_manifest_conflict_diagnosis.py -q
```

产物（默认写入 `diagnostics/output/`）：

- `collector-a-events.etl` / `collector-b-events.etl`：两份**逐字节相同**的合成 ETL（相同 GUID、
  相同事件描述符、相同 12 字节 payload），模拟两台机器导出的同类事件。
- `repos/collector-{a,b,c}/{GUID}.xml`：三个采集机各自的 manifest 仓库（同 GUID，不同版本）。
- `report.json` / `report.txt`：每个场景下的 manifest 来源、事件描述符、布局、解析值与未消费字节。

## 2. 构造的冲突

provider GUID 固定为 `f1c2a3b4-1111-2222-3333-444455556666`，事件描述符 `(opcode=11, version=0)`，
payload（12 字节，小端）：

```
07000000 41004200 0000 ccdd
└─ u32 ─┘ └─ "AB" UTF-16LE + NUL ─┘ └ 尾部2字节
```

| 采集机 | manifest 提供者名 | 模板布局 | 对同一 payload 的解释 |
| --- | --- | --- | --- |
| collector-a | `ConflictProvider-CollectorA` | `UInt32 Counter; UnicodeString Label` | `Counter=7, Label='AB'` |
| collector-b | `ConflictProvider-CollectorB` | `UInt32 Counter; UInt32 NextDword; UInt16 TrailingWord` | `Counter=7, NextDword=0x00420041=4325441, TrailingWord=0` |
| collector-c | `ConflictProvider-CollectorC` | 仅有键 `(99,0)`，与描述符 `(11,0)` 不匹配 | provider 命中但 `_struct=None`，0 字段被解析 |

A 把 `41 00 42 00 00 00` 当字符串 `AB`，B 把同样的字节当两个整数。**两者都不抛异常**，但字段语义
完全不同；二者各消费 10 字节、都留下 2 个未消费字节 `ccdd`。这正说明“没有抛异常”不能证明模板选对。

## 3. 差异进入解析链的确切位置（源码调用链）

```
ETL.__iter__                         dissect/etl/etl.py:95
└─ Buffer.__iter__ / read_record     dissect/etl/etl.py:158,168
   └─ select_event_header            dissect/etl/headers/utils.py:49   按 marker 选 EventHeader
      └─ EventRecord.event           dissect/etl/etl.py:206
         └─ parse_payload(header)    dissect/etl/etl.py:295
            ├─ manifest.lookup(header.provider_id)   dissect/etl/manifest.py:167
            │    1) CACHE[guid] 命中即返回            manifest.py:170-173
            │    2) import_module("...manifests.{guid}")  manifest.py:175-181（本诊断离线置为 ImportError）
            │    3) get_resource_string("manifests/xml/{guid}.xml") + compile_xml  manifest.py:183-189
            │    4) 都失败 -> ManifestNotFoundError   manifest.py:191
            └─ Event(header, mf)     dissect/etl/etl.py:230
                 key = (header.opcode, header.version)          etl.py:236-238
                 self._event = mf.EVENTS[key]                   etl.py:242
                 self._struct = self._event.template(header.payload)  etl.py:243  ← 布局在此落地
                 except KeyError: self._struct = None           etl.py:244-245  ← 静默未命中
```

三个关键事实：

1. **缓存键只有 GUID**。`manifest.CACHE: dict[UUID, ModuleType]`（`manifest.py:162`）不含版本、来源或
   模板指纹。同 GUID 的第二份 manifest 永远无法替换已缓存的第一份。
2. **模板在 `Event.__init__` 里通过 `EVENTS[(opcode, version)]` 选定并立即实例化**（`etl.py:242-243`）。
   字节本身不带模板标识，选哪份布局完全取决于上一步 `lookup` 返回哪个模块。
3. **未命中是静默的**。`KeyError` 被吞成 `_struct=None`（`etl.py:244`）；`ManifestNotFoundError` 在
   `parse_payload` 被吞成 `mf=None`（`etl.py:305`）。两条路径都不抛异常，调用方只拿到“空解析结果”。

补充：`EVENTS` 字典的键由 manifest 的 `(event value, version)` 生成（`manifest.py:269-274`），而查询用
的是事件头的 `(opcode, version)`（`etl.py:238,242`）。因此本复现令 manifest 的 `value == opcode == 11`
以保证命中；真实数据里这对“value/opcode”错配本身就是另一类静默未命中来源。

## 4. 加载顺序与缓存命中的影响（实测，见 `report.json`）

- **冷缓存 + 顺序 A→B**：清掉 `CACHE` 后先 A 后 B，各自重新编译，结论随“当前活动来源”变化
  （`cold_cache_order_a_then_b` / `..._b_then_a`）。冷缓存下“谁被查就用谁”，结论对加载顺序敏感。
- **暖缓存粘性 A→B**：先解析 A 再把活动来源切到 B，第二次 `cache_hit=true`、`compiled_sources=[]`，
  仍然得到 A 的 `Label='AB'`（`sticky_cache_a_then_b`）。反向同理得到 B 的整数解释
  （`sticky_cache_b_then_a`）。**进程内首个加载者决定后续全部同 GUID 事件的解释**，切换来源无效。
- **静默未命中（collector-c）**：manifest 成功加载、provider 名可读出，但描述符键不存在，
  `parsed_values={}`、`consumed=0`、`unconsumed=12`，`exception=null`
  （`missing_event_entry_collector_c`）。
- **未消费字节**：A/B 各留 `ccdd`；C 留下全部 12 字节。未消费字节可作为“模板可能不匹配”的信号，但
  A、B 未消费字节数相同，单靠它**不足以**在两个看似合理的布局间裁决。

## 5. 哪些情况能精确消歧，哪些必须交给调用方

### 可在库内精确判定（确定性信号，无需调用方介入）

- **描述符键不存在**：`(opcode, version)` 不在 `EVENTS` 中 → 当前 manifest 与事件不兼容，应显式标注
  “无匹配模板”，而不是静默返回空（对应 collector-c）。
- **越界/截断**：模板静态尺寸超过 `len(payload)`，cstruct 读取触发 `EOFError`；可确定该模板不适用。
- **显式长度/计数字段自相矛盾**：模板声明的长度前缀、计数或尺寸与实际 payload 边界对不上。
- **未消费字节为非零且无合法解释**：配合模板的 `__sizes__` 可精确定位多出来的偏移。
- **同进程出现第二个、内容不同的同 GUID 模块**：对生成模块做内容指纹（XML 哈希或模板结构哈希）即可
  确定性地检测到“同 GUID 多版本”这一事实本身。

### 库无法裁决、必须由调用方选定来源

- **两个布局都能完整、不越界地消费 payload**（本复现的 A 与 B：都消费 10 字节、都不报错）。字节流没有
  模板自标识，dissect.etl 无法从位级信息判断字段“本来是字符串还是整数”。
- **未消费字节数相同、解析值都自洽**时，没有任何位级信号可用于排序。
- 此时需要调用方基于**外部出处**选择：ETL 的生成主机/采集机身份、文件时间戳与 manifest 发布时间、
  操作系统版本/KB、带签名的 manifest 分发渠道、或显式的来源优先级/白名单。

## 6. 可实施的冲突处理建议（不新增模板仓库服务）

1. **缓存键加入版本/来源维度**：把 `CACHE: dict[UUID, ModuleType]` 改为
   `dict[(UUID, source_id | content_hash), ModuleType]`，或在首次为某 GUID 缓存时记录内容指纹；后续
   遇到不同指纹时**不要**静默复用，转为显式冲突状态。改动集中在 `manifest.lookup`（`manifest.py:167`）。
2. **冲突显式化，取代静默 `None`**：在 `Event.__init__`（`etl.py:240-245`）把 `KeyError` 转为带 GUID、
   描述符、可用键集合的告警/异常对象；在 `parse_payload`（`etl.py:297-308`）区分“无 manifest”与
   “有 manifest 但无匹配事件”，并把 `except (ManifestNotFoundError, AttributeError)` 收窄，避免吞掉
   非预期错误。
3. **暴露 provenance 与布局指纹**：让 `Event` 输出 manifest 来源标识、提供者名、事件 symbol、每个字段
   的类型/偏移/尺寸（本诊断的 `manifest_origin` 与 `layout` 即是范例），供调用方比对。
4. **把未消费字节作为一等诊断输出**：`payload_size - len(struct)` 与剩余 hex 应随事件返回；非零残留
   触发“模板可能不匹配”提示（本诊断已在 `EventDiagnosis.unconsumed_*` 实现）。
5. **由调用方注入来源选择策略**：提供一个 `lookup(guid, source_hint=None)` 形式的可选入口，来源优先级、
   主机归属、时间窗匹配等策略留在调用方；库只负责在“无法位级裁决”时把候选集合与冲突原因交出去，而不是
   按进程内加载顺序偷偷拍板。
6. **调用方侧的操作守则**：同一分析会话不要混跑不同来源的同 GUID ETL；若必须混跑，按“每来源独立进程 /
   独立解释器状态”隔离，或在切换来源时清空 `manifest.CACHE`，并对结论附上 manifest 指纹。

## 7. 过程中发现的两个上游既有缺陷（与本冲突独立，未改库代码）

诊断为让**真实解析链**跑通，在 `diagnose.py` 内做了局部绕行（`repair_variable_type_bindings`），并未修改
库源码：

1. **32 位下 `EtwPointer.as_32bit()` / `UserSID_blob.as_32bit()` 绑定丢失**。`manifest.CLASS_FMT`
   生成的类用 `@classmethod` 定义这些方法，但 cstruct 的 `add_custom_type()` 会派生新的 MetaType，
   classmethod 绑定未被保留。64 位路径（`as_64bit`）恰好可用，32 位路径在 `parse_payload`
   （`etl.py:299-304`）必抛 `TypeError: ... missing 1 required positional argument: 'cls'`；而该
   `TypeError` 不在 `except (ManifestNotFoundError, AttributeError)` 内，会直接冒泡。任何 32 位 ETL
   命中 manifest 都会触发，与字段是否为指针无关。
2. **`Event.event_values()` 仍用已不存在的 `Structure._values`**（`etl.py:277,281`）。当前 cstruct
   （4.8.dev9）已更名为 `__values__`，调用 `event_values()` 会抛 `AttributeError`。本诊断改用
   `structure.__values__` 与 `len(structure)` 取字段与已消费字节。

这两个缺陷说明：现有“异常处理”既会吞掉该报的冲突（`KeyError`），又会放过本可处理的兼容性错误
（`TypeError` 冒泡、`_values` 失配），进一步支持建议 2 的“显式化 + 收窄 except”。

## 8. 文件清单

- `synthetic_etl.py`：单 buffer、32 位最小 ETL 构造器（buffer header + logfile 事件 + EVENT_HEADER32）。
- `manifests.py`：同 GUID 的三份冲突 manifest（A/B 布局冲突，C 描述符键不匹配）及仓库落盘。
- `diagnose.py`：离线源路由、`lookup` 调用链插桩、描述符/来源/布局/未消费字节记录、上游绑定缺陷垫片。
- `run_diagnosis.py`：可运行 CLI，编排冷缓存顺序、暖缓存粘性、静默未命中场景并产出 JSON/文本报告。
- 对应测试：`tests/test_manifest_conflict_diagnosis.py`（9 个用例，含顺序无关性隔离）。
