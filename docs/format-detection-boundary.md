# OfficeFile 格式识别边界分析（多候选 OLE 容器）

针对"同一 OLE 文件同时携带 `EncryptionInfo` 与旧式 Office 特征流"的场景，
本目录配套了可运行的诊断材料：

- `tools/diagnose_format_detection.py` — 独立诊断脚本，构造多候选容器并打印
  每条代码路径实际查询/读取了哪些流、结果如何分类、失败后句柄是否仍可继续读取。
- `tests/cfbbuild.py` — 最小 CFB(OLE) 写出器（olefile 0.47 不能新建 OLE 文件）。
- `tests/multicontainers.py` — 用 `tests/inputs` 真实样本流拼装的多候选容器。
- `tests/test_format_detection_boundary.py` — 固化上述边界的回归测试（11 例）。

运行方式（仓库根目录）：

```sh
.venv/bin/python tools/diagnose_format_detection.py
.venv/bin/python -m pytest -q -o addopts= tests/test_format_detection_boundary.py
```

## 识别顺序与各自读取的流

`OfficeFile()` 自动识别是按流名"首个命中即定"（`msoffcrypto/__init__.py`）：
`EncryptionInfo` → `wordDocument` → `Workbook` → `PowerPoint Document`。
诊断脚本用钩子记录 `OleFileIO.exists()`/`openstream()`，实测：

| 容器（结构均合法） | 自动识别结果 | 自动路径读到的流 | 显式解析读到的流 |
| --- | --- | --- | --- |
| EncryptionInfo(agile) + EncryptedPackage + 明文 WordDocument | OOXMLFile, encrypted | 仅 `EncryptionInfo` | Doc97File 仅读 `wordDocument`，判明文 |
| EncryptionInfo(agile) + EncryptedPackage + RC4-CryptoAPI WordDocument/1Table | OOXMLFile, encrypted | 仅 `EncryptionInfo` | Doc97File 仅读 `wordDocument`，判加密 |
| EncryptionInfo(Extensible 4.3) + 明文 WordDocument | 抛 DecryptionError | 仅 `EncryptionInfo` | Doc97File 正常解析，判明文 |
| 仅 EncryptionInfo（无 EncryptedPackage） | OOXMLFile, encrypted | 仅 `EncryptionInfo` | decrypt 时才暴露缺流（见下） |
| 仅明文 WordDocument | Doc97File, plain | `wordDocument` | — |
| 无任何已知流 | 抛 FileFormatError | 无（仅 4 次 exists 查询） | — |

关键事实：自动识别命中 `EncryptionInfo` 后**从不读取** `wordDocument`，
旧式候选是否存在、是否加密，自动路径完全没有证据。

## 四类结果的区分

诊断脚本与测试按异常的确切类型分类，避免互相误报：

- **确认加密（ENCRYPTED）**：`is_encrypted()` 为 True，且口令通过
  `verify_password` / `verifypw` 校验。
- **普通未加密（PLAIN）**：解析成功、`is_encrypted()` 为 False；
  此时 `load_key` 抛 `DecryptionError("File is not encrypted")`，
  **不是** `InvalidKeyError`。
- **格式不支持（UNSUPPORTED/STRUCTURAL）**：`FileFormatError`（未识别）
  或 `DecryptionError`（如 Extensible Encryption 版本 4.3）；
  两者都不是口令问题。
- **特征冲突（CONFLICT）**：两个及以上候选各自可独立解析
  （测试 `test_conflict_container_supports_two_independent_candidates`
  证明同一容器里 agile OOXML 与 RC4-CryptoAPI doc97 都能用同一口令验证通过）。
  自动识别只报第一个候选；`InvalidKeyError` 只对被验证的那个候选有效，
  **不能据此把整个文件改报成"口令错误"**。

## 识别失败是否影响调用方继续读取

不影响。所有失败路径（`FileFormatError`、`DecryptionError`、构造中途抛出）
都不关闭传入句柄；测试确认失败后 `handle.closed` 为 False、
`olefile.isOleFile` 仍为 True，调用方 `seek(0)` 后可继续用 olefile
枚举流、或改用显式格式类解析（Extensible 4.3 容器自动识别失败后，
同一句柄上显式 `Doc97File` 成功）。注意文件位置会移动，继续读前需 `seek(0)`。

## 兼容方案

1. **新增显式格式选择**（已实现）：`OfficeFile(file, format="doc97")`
   支持 `"ooxml"/"doc97"/"xls97"/"ppt97"`，CLI 增加 `-f/--format`。
   显式选择**不绕过**被选格式的结构验证——各构造器照旧校验
   （OOXMLFile 要求可解析的 EncryptionInfo 或合法 zip；Doc97File 要求
   存在 WordDocument 流并能读 FIB）；未知格式名在触碰文件前抛
   `FileFormatError`。测试 `test_explicit_format_selection_still_validates`
   固化这一点。
2. **自动识别行为不变**：仍是首个命中即定，不做静默回退——静默回退会
   掩盖容器损坏。需要确定性的接收端应枚举候选后显式选择。
3. **证据结论的表述**：对冲突容器，结论应列出证据支持的候选清单
   （本例：agile 加密 OOXML 包 + RC4-CryptoAPI 加密 doc97 文档，两者均成立），
   而不是只报自动识别选中的那一个；口令校验失败只能表述为
   "对该候选口令校验失败"。

## 已记录但未改动的边界（避免破坏下游 catch）

- EncryptionInfo 存在但缺 `EncryptedPackage`：`is_encrypted()` 为 True，
  `decrypt()` 时抛裸 `OSError`（olefile 的 "file not found"），
  不是 msoffcrypto 异常。测试 `test_missing_encryptedpackage_surfaces_as_oserror_at_decrypt`
  固化了当前行为；如要改成 `FileFormatError` 需主版本说明。
- `Doc97File`/`Xls97File`/`Ppt97File` 构造器对缺失流同样抛裸 `OSError`。
