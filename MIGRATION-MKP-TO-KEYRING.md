# 迁移说明：Master Key Provider → Keyring / MPL 材料管理

适用版本：aws-encryption-sdk-python 4.x（本仓库当前 4.0.7），材料管理由 MPL
（`aws_cryptographic_material_providers`）接管。目标：存量归档继续可读、
强制归属信息（encryption context 中的 tenant/owner 等键）在路径切换中不丢失。

## 1. 当前调用链

`client.encrypt/decrypt` 的三个互斥入参在流式客户端配置里归一化为 CMM
（`src/aws_encryption_sdk/streaming_client.py:165`）：

- `key_provider=`（旧路径）→ 包一层 `DefaultCryptoMaterialsManager`
  （`src/aws_encryption_sdk/materials_managers/default.py:24`），
  由它按 commitment policy 选算法套件并注入 `aws-crypto-public-key` 签名公钥。
- `keyring=`（新路径）→ MPL `create_default_cryptographic_materials_manager`，
  再经 `CryptoMaterialsManagerFromMPL` 适配
  （`src/aws_encryption_sdk/materials_managers/mpl/cmm.py:38`）。
- `materials_manager=` → 若直接传 MPL CMM（如 required-EC CMM），同样经适配层包装。

读路径上，commit 策略在解析消息头时强制校验
（`validate_commitment_policy_on_decrypt`，`src/aws_encryption_sdk/streaming_client.py:1032`）；
required EC 的分区/认证在 `streaming_client.py:618`（写）和
`streaming_client.py:1049`（读）完成。

## 2. 归属信息在两条路径上的行为差异

- 旧 MKP 路径：完整 encryption context 全部存入消息头；**解密时不接受传入
  EC 做校验**，必须像 `examples/src/migration/migration_raw_aes_key_example.py`
  那样手工断言 `header.encryption_context` 包含期望键值（注意是包含，不是相等，
  SDK 会自行加 `aws-crypto-public-key`）。
- 新 keyring 默认 CMM：EC 同样全存，但 `client.decrypt(encryption_context=...)`
  会逐键校验，归属断言交给 SDK。
- Required Encryption Context CMM：列入 `required_encryption_context_keys`
  的归属键**不写进消息体**，只进头部签名；解密必须提供 reproduced
  encryption context，缺任一键即报
  `AWSEncryptionSDKClientError: No reproduced encryption context on decrypt.`
  切换到此 CMM 时，新旧两端 `required_encryption_context_keys` 清单必须一致，
  且不要把 `aws-crypto-public-key` 列入（SDK 自动管理）。

## 3. 兼容矩阵（本地静态 AES-256 测试键实测）

复现脚本：`migration_matrix_check.py`（Raw AES keyring ↔ RawMasterKeyProvider，
同一包装密钥；EDK 格式兼容：`provider_id`↔`key_namespace`，`key_id`↔`key_name`）。

| # | 写入路径 | 读取路径 | 结果 | commit 策略要求 |
|---|----------|----------|------|------------------|
| 1 | 旧写（MKP，非 commit，等同 1.x 归档） | 新读 keyring，`FORBID_ENCRYPT_ALLOW_DECRYPT` | ✅ | 读端必须下调策略 |
| 2 | 同上 | 新读 keyring，`REQUIRE_ENCRYPT_REQUIRE_DECRYPT`（默认） | ❌ `ActionNotAllowedError`（算法 0x0378 等非 commit 套件被拒） | **读路径强制**，默认策略直接拒绝 |
| 3 | 旧写（MKP + 默认策略，committing 套件） | 新读 keyring，`REQUIRE_*` | ✅ | 无额外要求 |
| 4 | 新写 keyring，`REQUIRE_*` | 新读 keyring，`REQUIRE_*` | ✅ | 写路径强制 committing 套件 |
| 5 | 新写 keyring | 旧读 MKP | ✅ | 回滚安全：过渡期内旧读端仍可解 |
| 6 | 新写 required-EC CMM | 读时缺 reproduced context | ❌ `No reproduced encryption context on decrypt.` | 归属键缺失即失败，与策略无关 |
| 7 | 新写 required-EC CMM | 读时带完整 reproduced context | ✅ | — |

补充实测结论：

- 默认 client 策略就是 `REQUIRE_ENCRYPT_REQUIRE_DECRYPT`
  （`src/aws_encryption_sdk/__init__.py:48`），所以**存量非 commit 归档在默认
  配置下不可读**，迁移期读端必须显式 `FORBID_ENCRYPT_ALLOW_DECRYPT`。
- 当前 MPL 版本下 required-EC CMM 在非 commit 套件（v1 消息格式）上也能工作，
  归属保护不依赖 commit 策略；但终态仍应统一到 committing 套件。
- MKP 路径没有 required-EC 能力，归属键只能依赖全量存储 + 手工校验。

## 4. 迁移步骤

1. **读端先行**：所有读取方升级到 4.x，策略设为 `FORBID_ENCRYPT_ALLOW_DECRYPT`，
   改用 keyring 读取（行 1、3、5 保证新旧密文都可解）。归属校验从手工断言
   切换到 `decrypt(encryption_context=...)`。
2. **写端切换**：写入方逐服务切到 keyring（或 required-EC CMM），策略保持
   `REQUIRE_ENCRYPT_*`。切换前后对比新旧路径产出消息的
   `header.encryption_context` 键集合，确认归属键无丢失。
3. **停止旧写入的判定条件**（全部满足才可停）：
   - 代码与运行时均无 `key_provider=` 调用残留（静态扫描 + 运行时指标）；
   - 读取侧按消息头算法套件打监控，非 commit 套件的新增写入流量降为 0
     （只剩历史归档读取）；
   - 归属键监控：新旧路径写出的消息中 tenant/owner 等键覆盖率 100%。
4. **归档处置**：存量非 commit 归档二选一——批量重加密为 committing 套件，
   或长期保留一个 `FORBID_ENCRYPT_ALLOW_DECRYPT` 的只读兜底客户端。
5. **收紧终态**：确认无任何非 commit 读取流量后，读端策略升回
   `REQUIRE_ENCRYPT_REQUIRE_DECRYPT`；若启用 required-EC CMM，同步固化
   `required_encryption_context_keys` 清单并纳入变更管控。
