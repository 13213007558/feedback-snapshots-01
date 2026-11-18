# Plyara 接入链语法能力清单（升级前预检）

适用对象：规则仓库启用新 YARA 语法前的预检。配套探针：`preflight/syntax_capability_probe.py`
（`.venv/bin/python preflight/syntax_capability_probe.py`，出现 RED 即以退出码 1 阻断升级）。

## 1. 被评估的接入链与判定口径

接入链三个环节，能力必须逐环节评估，不能以"解析不报错"代替支持：

1. 解析：`plyara.Plyara().parse_string()`，词法/语法产物为字典，条件段只有扁平 token 流（`condition_terms`），没有 AST，见 `src/plyara/core.py:1136`。
2. 重建：`rebuild_yara_rule()`，按关键字空格启发式重新拼接，见 `src/plyara/utils.py:308`。
3. 依赖分析：`detect_dependencies()` 与逻辑哈希 `generate_hash()`，均已标注将在 2.3.0 移除（DeprecationWarning），见 `src/plyara/utils.py:110`、`src/plyara/utils.py:186`。

三级判定：

- **支持（GREEN）**：解析通过、重建后再次解析与原结构等价、且该构造所经过的工具函数结果可靠。
- **仅原样保存（AMBER）**：能解析并以原文形式保留（多为 `value` 字段直存），重建可还原文本，但语义不被建模，或依赖/哈希分析存在已知盲区、噪声、信息丢失。
- **无法可靠分析/拒绝（RED）**：工具链直接报错，或不报错但产物被静默破坏（典型：64 位 hex 常量被切成两个 token、哈希碰撞）。

关键原则：RED 只表示**本工具链**无法处理，不等于规则非法；凡工具链与真实 YARA 引擎判定可能不一致的条目，一律列入第 5 节交引擎确认，不为凑成功率改写检测条件。

## 2. 能力总矩阵

| 构造 | 解析 | 重建 | 依赖分析/哈希 | 判定 | 探针 |
|---|---|---|---|---|---|
| 文本串：纯文本、`\t \r \n \" \\ \xHH` | 保真（转义按字面反斜杠序列保存） | 可往返 | 哈希可靠 | GREEN | T1-T4 |
| 文本串：非法转义 `\a`、`\0`、`\xZZ` | 报错拒绝 | — | — | RED（引擎同样拒绝） | T5 |
| 文本串：YARA 5 `\u{...}` Unicode 转义 | 报错拒绝 | — | — | RED（引擎版本相关） | T6 |
| 文本串：非 ASCII UTF-8 字面量 | 通过、直存 | 可往返 | 不解释编码 | AMBER | T7 |
| 正则：常规模式、`/i`、`/s`、`/is` | 通过、整串直存 | 可往返 | 无语义模型，仅文本哈希 | AMBER | R1-R3 |
| 正则：后缀逆序 `/si` | **报错拒绝** | — | — | RED（引擎接受，顺序无关） | R4 |
| 正则：行内作用域标记 `(?i)` | 通过、直存 | 可往返 | 不分析作用域 | AMBER（引擎确认） | R5 |
| 正则：非 ASCII 字符 | 报错拒绝（REXSTRING 仅 `\x20-\x7f`） | — | — | RED（引擎确认） | R6 |
| 条件中的正则字面量（`matches /.../`） | 作为单 token 直存 | 可往返 | 不解释 | AMBER | R7 |
| Hex：定长字节、`??`/`?` 通配、嵌套组、`\|` 多选、jump | 通过、整段直存 | 可往返 | 不建模结构 | AMBER | H1-H3,H7 |
| Hex：空 jump `[]` | **通过**（引擎拒绝） | 可往返 | 不校验语义 | AMBER（引擎确认） | H4 |
| Hex：YARA 5 否定号 `~AA` | 通过、直存 | 可往返 | **哈希碰撞**：`~` 被归一化剥离 | RED | H5 |
| Hex：组前否定 `~( AA \| BB )` | 报错拒绝 | — | — | RED（引擎确认） | H6 |
| Hex：内部注释 | 解析进字符串值，同时复制到规则级 `comments` | 字符串值内保留，规则级副本丢失 | — | AMBER | H8 |
| Hex：多选结构的逻辑哈希 | — | — | `( AA \| BB )` 与 `AA BB` 哈希相同（括号/竖线被剥离） | AMBER | H9 |
| 修饰符：`nocase/wide/ascii/fullword/private` | 保真 | 可往返 | 进 `<MODIFIED>` 哈希段 | GREEN | M1,M5 |
| 修饰符：`xor`/`xor(范围)`（含 hex 边界混写） | 保真为文本 | 可往返 | 不分析密钥空间 | GREEN | M2 |
| 修饰符：单字母表 `base64("...")`/`base64wide` | 保真，含 64 字符长度校验 | 可往返 | 字母表内容进哈希 | GREEN | M3 |
| 修饰符：多字母表（YARA 4.3，两个 `base64(...)`） | **按重复修饰符报错** | — | — | RED | M4 |
| 修饰符：互斥组合（如 `nocase xor`） | 报错拒绝 | — | — | RED（引擎同样拒绝） | M6 |
| 条件：布尔/算术/比较/括号、`for..of`、`of/them`、模块调用 | 扁平 token 化 | 启发式拼接，可再解析 | 无语义树 | AMBER | C1,C2,C10 |
| 条件：`defined(规则引用)` | 通过 | 可往返 | `detect_dependencies` 漏报 | AMBER | C3 |
| 条件：`for ... : ( 规则引用 )` 函数体 | 通过 | 可往返 | 函数体内规则引用漏报 | AMBER | C4 |
| 条件：`icontains/iequals/...` 新字符串关键字 | 通过 | 可往返 | 跳过清单只含 `matches/contains`，复合条件下产生误报 | AMBER | C5 |
| 条件：64 位 hex 常量（16 位 hex） | **静默切词**：`0x...CDEF` → `0x...CDE` + `F` | 重建产物语义已坏 | 哈希基于坏 token | RED | C6 |
| 条件：`entrypoint` | 通过 | 可往返 | — | AMBER（YARA 5 已移除） | C7 |
| `include "..."` | 路径入 `includes` | **重建不输出 include** | 不做跨文件解析 | AMBER | C8 |
| Meta：浮点值 | 解析后 `int()` 崩溃（ValueError） | — | — | RED（引擎同样不允许） | C9 |
| 条件：未定义字符串引用 `@ghost/#ghost/!ghost` | 通过 | 可往返 | 哈希记 "Unhandled" 日志但仍返回摘要 | AMBER | C11 |

当前实测汇总（探针输出）：GREEN=8，AMBER=22，RED=10。

## 3. 最小不支持案例与迁移处置（RED 清单）

| ID | 最小案例 | 工具链行为 | 迁移处置 |
|---|---|---|---|
| T5 | `$a = "bad \a escape"` | `ParseTypeError: Invalid escape sequence` | 预检拒收；该写法引擎也非法，退回规则作者修正，不代改检测内容 |
| T6 | `$a = "snowman \u{2603}"` | 同上（`\u` 不在转义字符集，`src/plyara/core.py:360`） | 冻结迁移，等 plyara 支持；原规则保留，在 YARA 5 引擎上验证后再入仓 |
| R4 | `$a = /x/si` | 词法后缀正则仅接受 `/(?:i?s?)`，`/si` 落到 ID 报错（`src/plyara/core.py:723`） | 允许的**唯一**自动改写是后缀顺序归一 `/si` → `/is`，模式体一字不动；改写后必须重跑探针 |
| R6 | `$a = /utf8 é/` | `Illegal rexstring character` | 不自动转义；交规则作者确认字节级意图后引擎验证 |
| H5 | `$h = { ~AA BB }` | 解析正常，但 `generate_hash` 用 `re.sub(r'[^-a-fA-F?0-9\[\]{}]+','',...)` 剥掉 `~`，与 `{ AA BB }` 哈希完全相同（`src/plyara/utils.py:219`） | 含 `~` 的规则整体退出哈希去重流程，改用 `raw_strings` 比对；引擎确认否定语义 |
| H6 | `$h = { ~( AA \| BB ) }` | `Illegal bytestring character`（否定号只在字节对前被词法接受） | 冻结迁移，源规则原样保留交引擎确认 |
| M4 | `$a = "x" base64("...+/") base64("...-_")` | 重复修饰符检查先于语法产生，直接报 Duplicate（`src/plyara/core.py:1041`） | 等语法升级；禁止删第二个字母表冒充支持（会改变检测覆盖面） |
| M6 | `$a = "x" nocase xor` | `Incompatible modifiers`，与引擎互斥规则一致 | 拒收并退回作者，工具不猜测保留哪一个 |
| C6 | `uint32(0) == 0x1234567890ABCDEF` | `t_HEXNUM` 限 1-15 位（`src/plyara/core.py:527`），第 16 位被切成独立 ID；重建文本变为 `...ABCDE F`，语义损坏且无异常 | 预检直接阻断；禁止截断常量凑解析；跟踪 plyara 词法修复 |
| C9 | `meta: v = 1.5` | meta 取值强制 `int()` 抛 ValueError（`src/plyara/core.py:981`） | 拒收；YARA meta 只支持字符串/整数/布尔，退回作者改类型 |

## 4. AMBER 构造的使用边界（"没报错"不等于可分析）

- **正则与 hex 一律没有语义模型**：`value` 是带分隔符的原文（如 `/foo.bar/i`、`{ AA ( BB | CC ) }`），重建保真只证明文本往返；任何"这条正则匹配什么/hex 覆盖多少字节"的问题都不在本链能力内。
- **hex 逻辑哈希不可用于去重**：除 H5 的否定号碰撞外，H9 实测 `{ ( AA | BB ) }` 与 `{ AA BB }` 归一化后哈希相同；jump 因 `[]` 字符保留尚不会碰撞，但这是副作用而非保证。去重应基于 `raw_strings`/原文。
- **条件段是 token 流不是 AST**：`rebuild_yara_rule` 的空格规则靠关键字表启发（`src/plyara/utils.py:399` 起），输出格式变化（如 `uint32( 0 )`、`( 0 .. 3 )`、多字符运算符 `== != >= <= >> ..` 无前导空格的 `a== 1` 形态）不影响再解析，但不要做重建文本的字节级 diff，应 diff 再解析后的结构。
- **依赖分析三个已实测盲区**：`defined(x)` 漏报（C3）、`for` 函数体内规则引用漏报（C4）、`icontains/iequals/startswith` 系列不在外部变量跳过清单，复合条件下把普通标识符误判为依赖（C5，实测 `left icontains "q" and right` → 误报 `right`）。该函数本身已废弃，升级前只可在旧语法白名单场景使用，结果需人工复核。
- **哈希的 "Unhandled" 是静默降级**：未定义的 `@/#/!` 引用会打 error 日志但照常返回摘要（C11，`src/plyara/utils.py:271`、`src/plyara/utils.py:292`），消费方必须同时捕获日志，不能只收返回值。
- **include 与注释不归重建管**：include 路径只存 `includes`，`rebuild_yara_rule` 模板无该槽位（`src/plyara/utils.py:318`）；规则级 comments 同理不输出。需要完整原文时使用 `raw_meta/raw_strings/raw_condition`（`store_raw_sections=True` 为默认值）。
- **非 ASCII 分裂对待**：字符串段内的 UTF-8 可过（T7），但 README 已声明 meta/注释中的非 ASCII 是已知问题（issue #155），预检不得对这两类内容宣称支持。
- **空 jump `[]`、`entrypoint`、`??`、`(?i)`**：工具链放行不代表目标引擎放行，属于版本门控项。

## 5. 必须留给真实引擎确认的规则（本环境无 yara/yara-python）

本工作区未安装 `yara` 二进制或 `yara-python`，以下条目探针只能证明 plyara 侧行为，引擎结论须在目标版本上实测，预检清单中应单独打标、不计入工具链成功率：

1. YARA 5.0 专属：`\u{...}` 文本转义（T6）、hex 否定 `~`（H5/H6）、`entrypoint` 移除后的等价性（C7，官方迁移目标是 `pe.entry_point`，是否改写由规则负责人决定）。
2. YARA 4.3 门控：hex `??` 双通配（H7）、多 base64 字母表（M4）。
3. 引擎接受而 plyara 拒绝的形态：`/si` 后缀（R4，仅允许顺序归一这一种机械改写）、非 ASCII 正则（R6）。
4. plyara 放行但引擎可能拒绝：空 jump `[]`（H4）、行内正则标记 `(?i)`（R5）、所有 hex jump 边界与组平衡的**语义**有效性（词法只做括号配对和有界 jump 的数值比较，`src/plyara/core.py:657`）。
5. 所有正则的匹配语义、base64 字母表有效性（plyara 只查长度 64）、xor 密钥空间、模块函数（`pe.*`/`hash.*` 等）的存在性与返回类型。
6. 多规则间的真实依赖闭环：`detect_dependencies` 盲区之外，include 的跨文件解析本链完全不做（C8）。

## 6. 预检使用方式

```sh
.venv/bin/python preflight/syntax_capability_probe.py
```

- 退出码 0：无 RED；AMBER 条目按第 4 节边界处置后方可迁移。
- 退出码 1：存在 RED 构造，升级闸门保持关闭，按第 3 节逐条处置；探针内每个 Case 都携带最小规则、实测行为与迁移指令，可直接作为预检工单模板。
- 升级 plyara 或 YARA 引擎后重跑探针：GREEN/AMBER/RED 的预期写在每个 Case 上，工具行为变化会立刻在输出中暴露，防止"上游修了但清单没更新"。
