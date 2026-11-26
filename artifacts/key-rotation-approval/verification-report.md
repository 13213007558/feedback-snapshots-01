# Key rotation approval verification

Result: **PASS** (12/12)

| Check | Result |
|---|---|
| 提交的是一次已批准轮换 | passed |
| 新版证据输出：旧材料禁止新用且仅用于历史核验 | passed |
| 新版证据输出：新材料允许新用 | passed |
| 旧证书仍通过清单内 bom-ref 关联旧密钥 | passed |
| 裁剪到 CycloneDX 1.6 后历史证书关系仍可读回 | passed |
| 旧审批 schema 丢失扩展判定/证据时标记为待确认 | passed |
| CycloneDX 1.7 证书生命周期状态裁剪后识别为 schema 缺口 | passed |
| 旧格式中 active 状态只能推断用途姿态，不能替代新用批准证据 | passed |
| 同名但不同 bom-ref 的材料保持不变 | passed |
| 批准输出与内部存档类型、内容和审计职责可区分 | passed |
| 内部存档中的摘要与重新读入的批准输出和清单一致 | passed |
| 生成的 BOM 可由 CycloneDX 库重新读入 | passed |

## Asset read-back

- `old/enriched` `asset:key:checkout-signing-2024q1`: decision=`verification_only`, inventory_posture=`verification_only`, new_use=`denied`, confirmation=`confirmed`, history_status=`confirmed`, certificate_refs=`asset:cert:checkout-signing-2024q1`, gaps=none
- `new/enriched` `asset:key:checkout-signing-2026q4`: decision=`new_use_allowed`, inventory_posture=`new_use_allowed`, new_use=`allowed`, confirmation=`confirmed`, history_status=`confirmed`, certificate_refs=`asset:cert:checkout-signing-2026q4`, gaps=none
- `old/old-schema` `asset:key:checkout-signing-2024q1`: decision=`pending_confirmation`, inventory_posture=`verification_only`, new_use=`denied`, confirmation=`pending_confirmation`, history_status=`confirmed`, certificate_refs=`asset:cert:checkout-signing-2024q1`, gaps=`cyclonedx-1.6:certificateState-1.7-omitted`, `approval-v1:extended-decision-field-omitted`, `approval-output:evidence-block-missing`, `approval-output:decision-evidence-link-missing`, `decision-confirmation:pending-rich-approval-evidence`
- `new/old-schema` `asset:key:checkout-signing-2026q4`: decision=`pending_confirmation`, inventory_posture=`new_use_allowed`, new_use=`pending_confirmation`, confirmation=`pending_confirmation`, history_status=`confirmed`, certificate_refs=`asset:cert:checkout-signing-2026q4`, gaps=`cyclonedx-1.6:certificateState-1.7-omitted`, `approval-v1:extended-decision-field-omitted`, `approval-output:evidence-block-missing`, `approval-output:decision-evidence-link-missing`, `inventory-state:active-does-not-prove-current-new-use-approval`
