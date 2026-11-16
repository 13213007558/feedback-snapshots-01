# ASN.1 授权字段升级兼容性评审（基于 asn1tools 0.169.0）

## 0. 结论速览

开发方“加了 OPTIONAL 就兼容”的判断**只在 BER 下成立，在 PER/UPER 下不成立**。
“能解码”“字段意义相同”“原始签名字节不变”是三个互相独立的性质，本评审全部拆开验证。

三个判定维度（针对某一方向的线型字节）：

- **DECODE**：对端 schema 解码是否抛异常。
- **MEANING**：两版 schema 中**显式声明的同名字段**（脚本里 `shared_fields` 逐字段列出，不做类型名推断）解码后业务值是否相同。
- **SIGN**：用接收方 schema 对解码结果再编码，是否得到与原字节**逐字节相同**的输出（作为“对原载荷的签名仍有效”的代理判定）。注意：若系统只在原始字节上验签、解码后不重签，则应以 `wire_hex` 是否被改动为准，而非以再编码为准。

复现：`python3 run_review.py`；机器可读结果见 `artifacts/results.json`，文本矩阵见 `artifacts/review_table.txt`。

## 1. 总决策矩阵

图例：✅ 通过　❌ 失败/报错　⚠️ 解码成功但语义漂移（最危险）　— 不适用

| 变更 | 方向 | 编码 | DECODE | MEANING | 再编码字节相同 | 是否需换版本/重签 |
|---|---|---|:--:|:--:|:--:|---|
| C1a 根插入(必填) | old→new | BER/PER/UPER | ❌ | — | — | 必须换协议版本 |
| C1a 根插入(必填) | new→old | BER | ❌ | — | — | 必须换协议版本 |
| C1a 根插入(必填) | new→old | PER/UPER | ✅ | ⚠️ level admin→none | ❌ | 必须换版本+重签 |
| C1b 根插入(OPTIONAL) | old→new | **BER** | ✅ | ✅ | ✅ | 该方向安全（见反方向） |
| C1b 根插入(OPTIONAL) | old→new | PER | ❌ | — | — | 必须换协议版本 |
| C1b 根插入(OPTIONAL) | old→new | **UPER** | ✅ | ⚠️ deviceId 7→15, level admin→none | ✅(同字节但已错义) | **必须换版本+重签（静默）** |
| C1b 根插入(OPTIONAL) | new→old | BER | ❌ | — | — | 必须换协议版本 |
| C1b 根插入(OPTIONAL) | new→old | PER/UPER | ✅ | ⚠️ 字段错位 | ❌ | 必须换版本+重签 |
| C2 扩展区追加 | 双向 | BER | ✅ | ✅ | ✅ | 兼容；新字段对旧端忽略 |
| C2 扩展区追加 | 双向 | PER/UPER | ✅ | ✅ | 原字节可验；**再编码会改包装字节** | 若解码后重签则需重签；只验原字节则不必 |
| C3a 约束放宽(宽度变) | old→new | BER | ✅ | ✅ | ✅ | BER 兼容（但需应用层补范围校验） |
| C3a 约束放宽(宽度变) | old→new | PER/UPER | ❌ OutOfData | — | — | 必须换协议版本 |
| C3a 约束放宽(宽度变) | new→old | BER | ✅ | ✅(300 原样) | ✅ | BER 不报约束错，需应用层拒绝越界值 |
| C3a 约束放宽(宽度变) | new→old | PER/UPER | ✅ | ⚠️ 300→1 截断 | ❌ | 必须换版本+重签 |
| C3b 约束收窄(同宽度) | 双向 | BER/PER/UPER | ✅ | 同宽度内 ✅；越界值 PER 也不拦 | ✅ | 线型兼容，但必须应用层强制新范围 |
| C4a ENUM 中插 | old→new | **BER/PER/UPER** | ✅ | ⚠️ **admin→user 全部漂移** | ✅(同字节错义) | **必须换版本+重签（静默提权/降权）** |
| C4a ENUM 中插 | new→old | BER/PER/UPER | ❌ 未知枚举 3 | — | — | 必须换协议版本 |
| C4b ENUM 扩展(...) | old→new | 三者 | ✅ | ✅ | ✅ | 兼容 |
| C4b ENUM 扩展(...) | new→old | 三者 | ✅ | ⚠️ guest→None | ❌ | 兼容方向可解码；应用层必须把 None 当拒绝，勿当默认放行 |

## 2. 重点反例：解码无报错、授权字段却被赋予不同含义

### 反例一（最贴合开发主张）：C1b 根插入 OPTIONAL，UPER，old→new

旧 schema 没有 `scope`，新 schema 在 `deviceId` 和 `level` 之间插入 `scope OCTET STRING OPTIONAL`。
旧端发出的授权消息 `{deviceId:7, level:admin}`：

- 原始 UPER 字节：`0780`（仅 2 字节，16 bit）。
- 新 schema **解码不报错**，得到 `{'deviceId': 15, 'level': 'none'}`。
- 原因：UPER 为新出现的 OPTIONAL 位图分配了 1 个前置 bit，旧字节没有该位图，后续所有 bit 整体错位。`deviceId` 由 7 被读成 15，`level` 由 `admin(2)` 被读成 `none(0)`。
- 更隐蔽的是：用新 schema 再编码仍得到 `0780`（SIGN 维度表面“相同”），但承载的已是错误语义——**签名有效 ≠ 语义正确**。
- 同一变更在 PER 下直接 `OutOfDataError`（显式失败），在 BER 下因 TLV 带标签而正确。可见“OPTIONAL 兼容”是编码规则相关的偶然，不是 ASN.1 的普遍保证。

### 反例二：C4a ENUMERATED 中间插入，三种编码全部静默漂移

旧 `Level ::= ENUMERATED { none(0), user(1), admin(2) }`，新 schema 在中间插入 `guest(1)`，使 `user`、`admin` 序号被改写为 2、3。

- 旧端发出 `level=admin`，BER `30030a0102`、PER/UPER `80`。
- 新 schema 三种编码均**解码成功**，统一解释为 `level=user`（数值 2 在新枚举表里叫 user）。
- 再编码字节与原字节完全相同（BER `30030a0102`、PER/UPER `80`），因此原始签名仍然通过，但授权等级已被静默改写。这是“同字节、异含义、签名不变”的典型提权/降权面。

### 反例三：C3a 约束放宽改变位宽，PER/UPER，new→old 截断

`INTEGER(0..65535)` 的 300 编码为 PER `012c`（16 bit），旧 schema `(0..255)` 按 8 bit 读取，解码“成功”得到 `1`（高字节被当作独立值），再编码只剩 `01`。BER 因带长度字节则保留 300，但其默认不强制约束，300 会原样进入应用层。

## 3. 逐组合线型字节 ↔ 字段对照

### C1a / C1b 根成员插入（值 deviceId=7, level=admin）

旧 v1 字节（无 scope）：

- BER `30 06 02 01 07 0a 01 02`
  - `30 06` SEQUENCE，长度 6；`02 01 07` INTEGER(deviceId)=7；`0a 01 02` ENUMERATED(level)=2(admin)。
- PER `07 80`：bit 流 `00000111 10……`，前 8 bit 为受约束整数 deviceId=7，随后枚举索引 `10`=admin(2)，补零对齐。
- UPER `07 80`：与 PER 同布局（本例恰好字节对齐）。

新 v2（含 scope=`de ad`）：

- BER `30 0a 02 01 07 04 02 de ad 0a 01 02`：多了 `04 02 de ad`（OCTET STRING，带标签）。旧 BER 端按标签找 `0a` 却遇到 `04`，报 `DecodeTagError`。
- PER（optional 版）`80 07 02 de ad 80`：首字节 `80`=前置 OPTIONAL 位图（scope 存在），其后字段重排。
- UPER（optional 版）`83 81 6f 56 c0`：位图与各字段按 bit 紧凑排列。旧端没有 scope 的位图概念，从第 1 bit 起全部错位。
- 必填版 PER `07 02 de ad 80`：无位图，scope 被当作内联必填，旧端把 `de ad` 的 bit 错配给后续枚举。

### C2 扩展区追加（值 deviceId=7, level=admin, label='x'，新增 token=aa bb）

- BER old→new `30 09 02 01 07 0a 01 02 0c 01 78`：`0c 01 78` 为 UTF8String label='x'；新 token 缺席。新端追加 `04 02 aa bb` 即 `30 0d …… 04 02 aa bb`，旧端按 TLV 跳过未知成员。BER 再编码逐字节相同。
- PER old→new `80 07 80 40 02 01 78`：首字节含扩展位图；扩展区内的 label 按开放类型编码（带长度前缀 `02`）。经新 schema 解码后再编码为 `80 07 80 c0 02 01 78`，差异仅在开放类型头部封装字节（`40`→`c0`），解码得到的语义值完全不变。
- UPER old→new `83 c0 20 40 2f 00`：同样含扩展位图与开放类型长度，重封装后为 `83 c0 60 20 17 80`。
- 关键：**原始字节始终能被对端原样解码并验签**；PER/UPER 的字节差异仅在“解码→再编码”时出现。若签名只覆盖传输的原始字节，C2 不需要为旧消息重签。

### C3a/C3b 约束范围改变

- BER 200（0..255）：`30 04 02 02 00 c8`，INTEGER 内容长度 2，值 200；放宽到 65535 后 BER 布局不变，解码=200，再编码相同。300 编码 `30 04 02 02 01 2c`，旧约束端也原样给出 300（asn1tools BER 解码默认不强制子类型约束）。
- PER 200（0..255，8 bit）：`c8`；放宽后该字段按 16 bit 读取，1 字节即 `OutOfDataError`。新端 300 为 `01 2c`（16 bit），旧端按 8 bit 截成 `01`=1。
- UPER 与 PER 同位宽现象：`c8` 失败、`01 2c`→`01`。
- C3b 同宽度收窄（0..255→0..254，仍 8 bit）：255 编码 `ff`，三种编码都解码为 255 且再编码 `ff`；asn1tools 不在解码时强制新上界，必须由应用层校验，否则 255 这类越界值会穿透。

### C4a / C4b ENUMERATED 调整

- C4a 旧 admin：BER `30 03 0a 01 02`（ENUMERATED 内容字节=2），PER/UPER `80`（2 bit 索引 `10`=2）。新表把数值 2 命名为 user，三编码均静默解成 user；新端 admin(3) 发出 BER `30 03 0a 01 03`、PER/UPER `c0`，旧端遇到未知枚举 3 报错。
- C4b 带 `(...)` 的可扩展枚举：旧 admin PER/UPER `40`（根枚举 2，扩展位 0）；新 guest 走扩展编码 `80`，旧端解码得到 `None`（未知扩展枚举），BER 同理 `0a 01 03`→None。实测该 `None` 无法再编码（`EncodeError: Expected data of type str, but got None`），天然不可被错误重签；旧端仍必须把 None 显式按最小权限拒绝，不能映射成默认授权。

## 4. 哪些修改必须换协议版本 / 重新签名

**必须升级协议版本（线格式不向后/向前兼容，或会静默错义）：**

1. 在 SEQUENCE 根区（无扩展标记）插入任何成员，无论是否 OPTIONAL——C1a/C1b。BER 靠 TLV 标签只在部分方向侥幸可用，PER/UPER 出现报错或静默错位。正确做法是首次定义就放 `...`，新字段只能进扩展区。
2. 改变受约束整型/位串的约束范围导致编码位宽变化——C3a 的 PER/UPER。
3. 在 ENUMERATED 根枚举中间插入或重排枚举项——C4a。只能在 `...` 之后追加，且永不复用旧数值。

**线格式可兼容、但要处理签名/语义的：**

- 扩展区追加成员（C2）：BER 全兼容且字节稳定；PER/UPER 原始字节可验签，但若业务流程是“解码后用本端 schema 重签”，开放类型封装会改变字节，必须重签。建议签名绑定原始传输字节或引入规范化编码（如 CPER/CER 固定规则），不要依赖再编码的确定性。
- 同宽度约束收窄（C3b）：线格式不变、字节稳定，但 asn1tools 解码不强制约束，越界值需应用层拒绝；是否换版本取决于业务对范围语义的承诺，建议升小版本并补校验。
- 可扩展枚举追加（C4b）：旧端收到未知项得到 `None`，必须按“拒绝/最小权限”处理。

**对开发方的直接答复：** OPTIONAL 不是兼容开关。BER 的 TLV 自描述标签让它对根区增删相对宽容，PER/UPER 是无标签的紧凑位流，根区结构变化必然引起位图/位偏移变化。要让授权字段升级真正兼容且不破坏签名，应：SEQUENCE 预留 `...`、ENUM 预留 `...` 且只追加不复用、约束只做不变位宽的调整并在应用层校验、签名覆盖原始线字节并对未知枚举/未知扩展值默认拒绝。

## 5. 环境与口径说明

- asn1tools 0.169.0，Python 3.12；BER 指其 BER 编解码（同一编解码器也接受 DER 输入）。
- “再编码字节相同”是接收方 schema 对解码结果重序列化的结果，用于暴露开放类型封装/规范化差异；真实验签应以收到的原始 `wire_hex` 为准。
- 字段同一性由 `run_review.py` 中每个用例的 `shared_fields` 显式给出，schema 文件成对显式提供，未使用任何按类型名自动推断。
