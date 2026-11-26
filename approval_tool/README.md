# CycloneDX 密钥轮换审批工具

这个自包含工具用虚构资产演示“旧密钥停止新用、保留历史签名核验”的审批闭环。它不按组件名更新资产，只认 CycloneDX 清单内唯一的 `bom-ref`；证书与密钥的关系以 `certificateProperties.subjectPublicKeyRef` 为准，1.7 输出还会携带 `relatedCryptographicAssets` 关联。

## 运行

```sh
.venv/bin/python -m approval_tool --out artifacts/key-rotation-approval
# 或
.venv/bin/python tools/key_rotation_approval.py
```

测试：

```sh
.venv/bin/python -m pytest -q tests/test_key_rotation_approval.py
```

## 场景资产

- 两把轮换密钥：
  - `asset:key:checkout-signing-2024q1`：旧材料，轮换后 `deactivated`，禁止新用，仅保留历史签名核验。
  - `asset:key:checkout-signing-2026q4`：新材料，批准后 `active`，允许新用。
- 两张虚构证书：
  - `asset:cert:checkout-signing-2024q1` 显式关联旧密钥，轮换后仍保留该历史关系。
  - `asset:cert:checkout-signing-2026q4` 显式关联新密钥。
- 一个同名哨兵资产 `asset:key:catalog-search-index-2024q4`：它与轮换密钥同名但 `bom-ref` 不同，用于证明不会被批量改名或更新。

所有密钥指纹均由虚构 `bom-ref` 派生，不包含真实私钥或真实证书。每个密钥资产表示逻辑签名密钥对的公开验证材料；审批中的“新用”针对该密钥对/证书的签发与签名用途。

## 输出文件

默认写入 `artifacts/key-rotation-approval/`：

1. `01-before-rotation.cdx-1.7.json`：轮换前 CycloneDX 清单。
2. `02-rotation-request.json`：一次已批准的轮换申请。
3. `03-approval-output.evidence-v2.json`：可携带决定、权限和证据摘要的新版批准输出。
4. `04-internal-archive.json`：内部存档，包含申请、审计事件、同名防护记录和制品摘要。
5. `05-after-rotation.cdx-1.7.evidence.json`：轮换后的 CycloneDX 1.7 清单，保留证据和 1.7 证书生命周期状态。
6. `06-approval-output.old-v1-trimmed.json`：裁剪到旧审批 schema 的输出，只保留 `assetRef`、名称和材料状态。
7. `07-after-rotation.cdx-1.6-trimmed.json`：裁剪到 CycloneDX 1.6 的清单；保留密钥状态和 `subjectPublicKeyRef`，移除 1.7 的 `certificateState`。
8. `verification-report.json` / `verification-report.md`：重新读盘后的逐项核对结果。

## 判定口径

- 新版证据输出中，旧密钥为 `verification_only` 且 `new_use=denied`，新密钥为 `new_use_allowed`，两者均为 `confirmed`。
- CycloneDX 1.6 仍可证明旧密钥 `deactivated` 以及旧证书到旧密钥的历史引用，因此历史核验关系为 `confirmed`。
- 旧审批 schema 缺少扩展决定和证据块时，不把缺失内容解释成“已批准”，确认状态为 `pending_confirmation`，并记录：
  - `approval-v1:extended-decision-field-omitted`
  - `approval-output:evidence-block-missing`
  - `cyclonedx-1.6:certificateState-1.7-omitted`
- 单独的 `active` 状态只说明材料状态，不证明当前仍有新用许可；旧格式读回会标为待确认。
- 批准输出的 `document_kind` 是 `approval_decision`，内部存档是 `internal_rotation_archive`；撤销新用许可的前值/现值审计只保存在内部存档中。
