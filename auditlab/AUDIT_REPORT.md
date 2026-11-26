# Wheel 安装来源与中断取证审计报告

- 被审计 wheel：`wheelhouse/auditdemo-1.0.0-py3-none-any.whl`
- wheel 文件 sha256（hex）：`d6cfb888b99d8ece449a295c19437aa06676e353e3e516b7a2829163aa917eea`
- 安装器：本仓库内的参考实现 `pypa/installer`（`src/installer`），解释器 Python 3.11.15（conda）
- 审计器：`drivers/audit.py`，独立重算哈希，不采信安装器自报值
- 日期：2026-11-26

## 1. 审计问题与结论

问题：目标 `bin/scripts` 下的可执行文件，究竟是 wheel 归档成员的改写副本，还是 installer 依据入口定义（entry point）新生成的？

结论（两类，归属各自保留）：

1. `scripts/bundled-tool` —— **归档成员改写/拷贝件**。
   - wheel 内存在同名成员 `auditdemo-1.0.0.data/scripts/bundled-tool`（见 `wheel.members.txt`）。
   - 该成员首行是 `#!/bin/sh`，不匹配 `fix_shebang` 仅识别的 `#!python` 前缀，因此内容**逐字节不变**。
   - 源 RECORD 哈希 `sha256=32lm9Ty245lBCGSd9D5xmqtCye1wBRkET2LmD4zp8wI` 与各目标实际文件重算值一致（hex `df6966f5…f302`）。
2. `scripts/audited-entry` —— **installer 据入口定义新生成的启动器**。
   - wheel 内**不存在**该成员（`unzip -l | grep audited-entry` 命中数为 0）；其依据是 dist-info 内的 `entry_points.txt`：
     `[console_scripts] audited-entry = auditdemo.core:main`。
   - 由 `installer/scripts.py::Script.generate` 用内置模板生成，含解释器 shebang 与
     `from auditdemo.core import main`，wheel 中无任何对应字节。
   - 生成件 sha256（RECORD 的 urlsafe-b64）：`sha256=6QFV1m-6H3hsFSFYVzbeWxQjv6u053vmvBwLPLRmZjE`
     （等价 hex `e90155d6…6631`），完整与中断两个目标中字节完全相同。

## 2. 安装顺序（决定中断语义）

依据 `src/installer/_core.py::install` 与 `destinations.py`，真实写入顺序为：

1. 若存在 `entry_points.txt`：先 `write_script(...)` 生成入口启动器（**生成件，非归档成员**）。
2. 遍历 `source.get_contents()`：对每个归档成员 `write_file(...)`；scripts 方案经 `fix_shebang` 处理。
3. 写额外元数据（本实验为空）。
4. 最后 `finalize_installation(...)`：构造并写出**目标 `*.dist-info/RECORD`**。

因此“文件已在盘上”与“已被目标 RECORD 正式收录”是两个不同时刻。中断注入点设在第 4 步之前
（`drivers/common.py` 的 `ABORT_BEFORE_RECORD`），此时所有载荷与生成件已落盘，但目标 RECORD 尚未写出。

## 3. 四态判定口径（不把临时事实当作完成）

| 状态 | 判定条件 | 含义 |
|---|---|---|
| `COMMITTED` 已正式完成 | 目标 RECORD 存在、收录该路径且重算哈希匹配 | 写入并被最终记录确认 |
| `VERIFIED_SOURCE` 源已核验 | 目标 RECORD 存在但未收录该路径；重算哈希仍匹配**源** RECORD | 来源可证，但未进入最终记录 |
| `WRITTEN_PENDING` 已写入待提交 | 目标 RECORD 不存在（中断）；归档成员能匹配源 RECORD，或为已生成的启动器 | 落盘但无最终记录，不得视为安装完成 |
| `UNVERIFIABLE` 无法证实 | 既不匹配源 RECORD 也不匹配目标 RECORD，或缺收录依据 | 来源/完整性无法证明 |

RECORD 自身一行按 PEP 376 约定哈希与长度留空，单独以 `RECORD_SELF` 归属，以“存在且空哈希”为校验。

## 4. 四个目标目录对照

| 目标 | 目标 RECORD | 状态计数 | 说明 |
|---|---|---|---|
| `targets/full` | 存在 | COMMITTED×10 | 正常完整安装 |
| `targets/interrupted` | **不存在** | WRITTEN_PENDING×9 | 写 RECORD 前中断；9 个文件在盘但无最终记录 |
| `targets/tampered` | 存在 | COMMITTED×9, UNVERIFIABLE×1 | 安装后篡改 `core.py`，与源/目标 RECORD 均不符 |
| `targets/partial-record` | 存在（缺一行） | COMMITTED×9, VERIFIED_SOURCE×1 | 删除 `data.txt` 的 RECORD 行，文件本身仍匹配源 |

逐行明细见 `evidence/itemized-evidence.csv` 与 `evidence/itemized-evidence.md`；
机读全量结果见 `evidence/audit-report.json`。

### 4.1 中断时“实际做到哪一步”

`evidence/interrupted.trace.jsonl` 最后两条：

- 所有 `write_file:done`（8 个归档成员，哈希均与源 RECORD 相同）与 `write_script:done`（生成件）已完成；
- 末条 `ABORT_BEFORE_RECORD`，`pending_record_count=10`，进程以非零退出码终止，目标 RECORD 缺失。

即中断目标里 9 个实体文件全部 `WRITTEN_PENDING`，其中 `scripts/audited-entry` 是
**已生成但未进入任何最终 RECORD 的生成件**（`generated_artifacts_missing_from_final_record`）。

## 5. 归档记录 vs 目标记录（各自归属）

- 归档记录（源）：`evidence/source.RECORD`，描述 wheel 原始成员，含 8 条带哈希成员 + RECORD 自身空哈希；
  **不含** `audited-entry`，因为它不是归档成员。
- 目标记录：`targets/full/purelib/auditdemo-1.0.0.dist-info/RECORD`，描述实际写出的路径：
  purelib 成员用相对包路径，scripts 方案以 `../scripts/<name>` 前缀收录，**包含**新生成的
  `../scripts/audited-entry` 及其安装期哈希。
- 中断与部分记录目标分别缺失目标 RECORD、或缺特定行，差异可逐行比对两份 RECORD。

## 6. 审计人员可自行重算的复核命令

```sh
BASE=auditlab
WHL=$BASE/wheelhouse/auditdemo-1.0.0-py3-none-any.whl

# (a) wheel 指纹
shasum -a 256 "$WHL"

# (b) 重算任意落盘文件并与 RECORD 对照（hex；RECORD 存 urlsafe-base64）
shasum -a 256 "$BASE/targets/full/scripts/bundled-tool"
shasum -a 256 "$BASE/targets/full/scripts/audited-entry"

# (c) 证明 audited-entry 不是 wheel 成员（命中数应为 0）
unzip -l "$WHL" | grep -c audited-entry

# (d) 查看驱动生成的入口定义
unzip -p "$WHL" "auditdemo-1.0.0.dist-info/entry_points.txt"

# (e) 全量重算清单（不经审计器，纯系统工具）
cat "$BASE/evidence/manifest.sha256"

# (f) 重新运行独立审计器（重算 + 四态分类）
python3 "$BASE/drivers/audit.py" "$(pwd)"
```

RECORD 的 `sha256=` 是 urlsafe-base64 无填充；与 `shasum` 的 hex 互转示例（已验证相等）：
`df6966f5…f302` ↔ `sha256=32lm9Ty245lBCGSd9D5xmqtCye1wBRkET2LmD4zp8wI`。

## 7. 运行性验证

见 `evidence/runtime-checks.txt`：
- 归档 shell 脚本 `bundled-tool` 直接可执行，输出 `bundled-tool from archive member`。
- 生成启动器 `audited-entry` 在将目标 `purelib` 加入 `PYTHONPATH` 后输出 `auditdemo entry point ran`
  （完整与中断目标均可运行；不加 PYTHONPATH 的失败仅因自定义 purelib 不在默认搜索路径，与生成正确性无关）。

## 8. 复现步骤

```sh
PY=$(command -v python3)          # 需 3.11+，本实验用 conda 3.11.15
# 1) 构建 wheel（离线，--no-build-isolation）
(cd auditlab/src_project && "$PY" -m pip wheel . --no-build-isolation --no-deps -w ../wheelhouse)
# 2) 完整安装 / 中断安装 / 两个对照目标
"$PY" auditlab/drivers/run_full.py "$(pwd)"
"$PY" auditlab/drivers/run_interrupted.py "$(pwd)"          # 预期非零退出
"$PY" auditlab/drivers/run_tampered_setup.py "$(pwd)"
"$PY" auditlab/drivers/run_partial_record_setup.py "$(pwd)"
# 3) 独立审计与表格
"$PY" auditlab/drivers/audit.py "$(pwd)"
"$PY" auditlab/drivers/render_tables.py "$(pwd)"
```

## 9. 证据清单（`evidence/`）

- `wheel.sha256`、`wheel.members.txt`、`source.RECORD`：源侧冻结证据（源已核验基线）。
- `full.trace.jsonl`、`interrupted.trace.jsonl`、`tampered.trace.jsonl`、`partial-record.trace.jsonl`：带毫秒时间戳的逐次写入/中断追踪。
- `manifest.sha256`：系统 `shasum` 重算的全部落盘文件 hex 摘要。
- `audit-report.json`：独立审计器的重算哈希、来源归属与四态分类。
- `itemized-evidence.csv` / `.md`：逐项对照表。
- `runtime-checks.txt`：两类脚本的实际运行结果。
