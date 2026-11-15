# 证据接收服务 · 全盘加密（FVE）探测契约

基于 `dissect.fve` 的只读探测层，供上游证据接收服务调用。核心目标：**不让任何“猜测”被写成已确认的调查事实**。

支持格式：LUKS1/2、BitLocker(BDE)、VeraCrypt。本层不新增任何解密实现，仅驱动库的公共识别/解锁 API，并对每条结论附加可审计的证据等级。

## 1. 三级证据契约（核心）

| 等级 | 名称 | 含义 | 允许的措辞 | 禁止的措辞 |
|----|------|------|-----------|-----------|
| L0 `INCONCLUSIVE` | 无法判断 | 数据为空/过短/无可识别信号 | “证据不足，未得出结论” | “未加密/明文” |
| L1 `POSSIBLE_ENCRYPTED` | 可能是加密数据 | 仅统计/结构嗅探（高熵、扇区对齐），无格式专有字节 | “高熵数据，可能为加密容器（假设）” | “是 VeraCrypt/已加密确认” |
| L2 `HEADER_RECOGNIZED` | 识别到格式头 | 魔数/GUID 与结构字段被格式解析器接受 | “识别为 LUKS/BitLocker 容器（未解锁）” | “可访问/已解密” |
| L3 `KEY_VERIFIED` | 授权密钥验证成功 | 提供的口令/密钥通过该格式自身的密码学校验 | “经授权密钥验证，确认可访问” | — |

等级单调可比较（`L3>L2>L1>L0`），高级别隐含低级别证据。

### 每种结论所需证据与判定来源

| 格式 | L1 来源 | L2 来源（魔数/结构） | L3 来源（密码学确认） |
|------|---------|--------------------|----------------------|
| LUKS | （通常不触发，头含零字段，熵低） | `is_luks_volume` 命中 `LUKS\xba\xbe`/`SKUL\xba\xbe` | `LUKS.unlock_with_passphrase` 后卷密钥匹配存储摘要 |
| BitLocker | （通常不触发） | `is_bde_volume` 命中 `-FVE-FS-` OEM 或 FVE GUID | `BDE.unlock_with_passphrase` 恢复 VMK/FVEK 且 `unlocked` |
| VeraCrypt | `is_veracrypt_volume`：大小%512==0 且首 4KiB 熵>7.9 | **不存在**（加密头无明文魔数，无法仅凭头识别） | `VeraCrypt.unlock_with_passphrase` 解密头后 `magic==b"VERA"` |

## 2. 误判边界（明确红线）

- **高熵 ≠ VeraCrypt。** `is_veracrypt_volume` 是“嗅探”而非识别：随机数据、压缩包、加密视频、其他加密容器都会过 7.9 阈值。该路径最高只能产出 L1，且候选 `veracrypt` 的 `key_verified=false`。只有解密头出现 `VERA` 才升到 L3。
- **无信号 ≠ 未加密。** 空输入、截断到不足一个扇区、解析抛 `EOFError` 一律归 L0 `INCONCLUSIVE`。系统没有“证明它是明文”的能力，因此绝不输出“未加密”。
- **识别到格式头 ≠ 可访问。** L2 只证明容器格式；没有正确密钥时永远停在 L2，错误口令记录为 `errors`，不降级、不翻转成“明文”。
- **验证失败保持开放结论。** 口令错误、不支持的 KDF/加密套件（如 VeraCrypt 的 Serpent/Streebog、BDE 仅 BEK 保护器）返回 `verified=false` + 原因，候选维持其 L1/L2 级别，不做否定性断言。
- **不支持的已知格式不是“未加密”。** 如 PDF 魔数：不产生受支持候选（结论为 L0 或仅 L1），不会被错误地归入三种 FVE，也不会被宣称明文。
- **冲突候选并存。** 不同探测器可对同一对象给出矛盾候选（魔数 L2 与熵嗅探 L1）。聚合器保留全部候选并按最高证据排序，**不合并、不互相覆盖**。

## 3. 失败后文件位置必须保持

- 每个探测器在 `finally` 中显式 `fh.seek(start)`；`@guarded` 包装器作为不变量断言，发现漂移会抛 `PositionDriftError` 并把偏移复位。
- 聚合器在每次调用前后比对 `tell()`，任何漂移都会令报告 `position_preserved=false` 并再次复位。
- 实验与 `test_stream_position_preserved_for_all_inputs`（含非零起始偏移 17/512/4096）锁定该行为。

## 4. 接口方案

### Python API

```python
from evidence_probe.probe import probe

report = probe(
    binary_stream,                 # 任意 BinaryIO，只读；调用后偏移不变
    source="evidence-001",
    credentials={"luks": "password"},   # 可选；不给则只做 L1/L2，不做 L3
)
report.to_dict()                  # 可直接落库/上链的 JSON（schema 见 report_schema.json）
report.confirmed                  # 仅 L3 候选 —— 上游唯一允许写成“已确认”的列表
report.strongest_level            # EvidenceLevel 枚举
report.position_preserved         # 偏移不变量
report.errors                     # 各探测器/验证器的非致命错误原因
```

`credentials` 是 `{格式: 口令}`，键限 `luks` / `bitlocker` / `veracrypt`。验证是“尽力而为”：成功才追加 L3，失败只写 `errors`，绝不伪造或降低候选。

### 上游落库策略（强制）

- 只有 `confirmed_formats`（等价 L3）可写入“已确认事实”表。
- L1/L2 写入“待证假设”表，携带 `detector`、`level`、`supports_claim`、`detail`，等待后续密钥或人工复核。
- L0 与 `errors` 写入“无法判定”记录，保留原因，禁止出现 `unencrypted=true` 之类字段。
- 输出 JSON 校验：`evidence_probe/report_schema.json`（`confirmed_formats` 被约束为仅含 L3 格式）。

## 5. 运行方式

```bash
# 可运行探测实验（高熵普通文件 / 空输入 / 截断头 / 有效测试卷，含错误口令与位置检查）
.venv/bin/python -m evidence_probe.experiments.run_experiment

# 契约测试
.venv/bin/python -m pytest evidence_probe/tests -q
```

实验会在 `$TMPDIR/evidence_probe_exp` 生成夹具（高熵随机文件、空文件、截断 LUKS 头），真实卷复用仓库 `tests/_data`。

## 6. 模块结构

| 文件 | 职责 |
|------|------|
| `contract.py` | `EvidenceLevel`、`Evidence`、`Candidate`、`ProbeReport` 与落库策略字段 |
| `entropy.py` | 香农熵、扇区对齐、流大小工具（阈值与库一致：7.9 / 4096 / 512） |
| `detectors.py` | 三个位置安全的探测器；LUKS/BDE 为 L2，VeraCrypt 嗅探为 L1 |
| `verifiers.py` | L3 密钥验证，封装库解锁 API，失败回落而非误判 |
| `probe.py` | 聚合器：跑全部探测器、保留冲突、可选 L3、检查偏移 |
| `experiments/run_experiment.py` | 可运行对照实验 |
| `tests/test_probe_contract.py` | 16 项契约/边界/位置测试 |
| `report_schema.json` | 报告 JSON Schema |
