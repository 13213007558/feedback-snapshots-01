# OLE 扇区布局边界验证

加密后的 Office 文件会作为可复核的派生证据保存。本目录独立验证
`msoffcrypto.method.container.ecma376_encrypted.ECMA376Encrypted` 写出的
OLE/CFB 容器在三类布局边界上的可靠性：

1. **mini-stream 边界** — 流长度 ≤ 4096 字节时进入 64 字节 mini 扇区；
2. **普通 FAT 增长** — 每个 FAT 扇区覆盖 128 个数据扇区（约 65 KiB）；
3. **DIFAT 扩展** — FAT 扇区超过 header 内 109 个指针后，溢出到专用 DIFAT 扇区。

## 为什么是“独立”验证

验证路径**不使用 msoffcrypto 自己的读取器**去读回它写出的内容：

- 容器结构（目录项、FAT/miniFAT 扇区链、流长度、扇区归属与重叠）用独立的
  `olefile` 解析，并在 `ole_validator.py` 中用原始字节算术重新推导每一个扇区归属；
- 密文解密与完整性在 `independent_crypto.py` 中按 MS-OFFCRYPTO 2.3.4.1 从零实现，
  只依赖 `cryptography`（AES-CBC、HMAC、SHA-512）与 `olefile`；
- 每个成功文件都要求解密结果与原始明文字节**逐字节相等**且 HMAC 完整性通过。

## 固定夹具与生产随机性

`fixtures.py` 使用计数器模式 SHA-256 确定性随机源，仅在单次夹具构建期间通过
上下文管理器临时替换 `ecma376_agile._random_buffer`，退出即恢复；salt 固定、
目录时间戳冻结，因此整个容器可复现。生产代码与生产 `secrets.token_bytes`
CSPRNG 不被修改，测试 `test_deterministic_source_does_not_alter_production_rng`
会断言退出后随机源已恢复且输出仍变化。

## 尺寸矩阵

矩阵定义在 `matrix.py`，证据结果保留在：

- `SIZE_MATRIX.txt` — 人类可读的固定宽度表格；
- `SIZE_MATRIX.csv` — 归档用 CSV。

关键经验阈值（明文/原始包字节长度）：

| 边界 | 明文尺寸 | 现象 |
| --- | --- | --- |
| EncryptedPackage 进入 mini 区 | 包长 ≤ 4096（明文 ≤ 4080 等） | 见下方已知缺陷 |
| FAT 达到 109 个扇区（header DIFAT 满） | 7,081,984 | `num_fat=109, num_difat=0` |
| DIFAT 扩展启动 | **7,083,505** | `num_fat=110, num_difat=1`，首个 DIFAT 扇区为 0 |

## 失败定位工具

对任意容器文件运行（不依赖本库读取路径）：

```bash
python -m tests.ole_boundary.locate CONTAINER.bin            # 人类可读
python -m tests.ole_boundary.locate CONTAINER.bin --json     # 机器可读
python -m tests.ole_boundary.locate CONTAINER.bin --password ''   # 跳过密码学检查
```

退出码非零表示存在结构缺陷、泄漏或完整性失败；每条缺陷都带流名、扇区号或字节偏移。

重新生成矩阵：

```bash
python -m tests.ole_boundary.report            # 文本
python -m tests.ole_boundary.report --csv      # CSV
```

## 已确认的写入器缺陷（mini-stream）

当 `EncryptedPackage` 流长度 ≤ 4096 字节时，`_write_Content` 把它写入 mini 数据区，
但 `_set_sector_locations_of_streams` 在计算 miniFAT 时显式排除了 EncryptedPackage，
没有为它建立 miniFAT 链，同时普通 FAT 仍按大扇区为其计数。后果：

- 该流的起始 mini 扇区与 `EncryptionInfo` 等小流**重叠**（`OVERLAP_MINI`）；
- miniFAT 链长度与目录声明尺寸不符（`CHAIN_LENGTH`）；
- 较长的 mini 包（如明文 1500/3000/4080）经 `olefile` 只能读到 mini 流剩余的
  1472 字节（`STREAM_LENGTH`），8 字节原始尺寸前缀被破坏，无法解密还原；
- FAT 中为其计数的大扇区成为无人拥有的非零游离扇区。

常规 FAT 与 DIFAT 区域（包长 > 4096）的全部矩阵行均结构完美、零泄漏、逐字节还原、
HMAC 通过。相关回归在 `test_ole_structure.py::test_mini_stream_package_defect_is_localized`
中以显式断言固定该缺陷，修复后该测试应转为正常断言。

## 运行测试

```bash
python -m pytest tests/ole_boundary/ -q
```
