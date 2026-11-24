# 上传授权最小权限合同（POST 表单 / 预签 PUT）

给内部归档客户发放 MinIO 上传凭据时，审批登记了对象前缀、大小区间、
数据标签和有效期。应用可以选择 **POST 上传表单** 或 **预签 PUT URL**。
本包给两个发放入口一个共同的、可核对的最小权限合同：

1. 先求“业务申请 ∩ 审批条件”的共同允许范围（`resolve_scope`），
   任何一侧不允许的范围直接 `ScopeConflict`，不会被放宽；
2. 按目标通道的**实际表达能力**检查缺项（`missing_for_channel`）；
3. 只有全部必要条件都能表达时才调用 SDK 签名；
4. 从真正发出去的 policy / URL 中解码回读，逐项对照目标对象、
   已登记条件和有效期（`verify_scope`）；
5. 每次发放决策（含拒绝）写入本地 JSONL 签名台账，供审计。

全程离线：使用 AWS 文档中公开的合成凭据
（`AKIAIOSFODNN7EXAMPLE` / 对应示例 secret），端点标为
`127.0.0.1:9000`，不发送任何网络请求；secret 只参与 HMAC，不写入台账。

## 通道表达能力矩阵

| 条件（scope 字段） | POST 表单 `post_form` | 预签 PUT `put_url` |
| --- | --- | --- |
| 单个目标对象 `key`（精确） | `eq $key` | URL 路径锁定该对象 |
| 对象前缀 `key_prefix` | `starts-with $key` | 不可表达（PUT 只能锁单对象） |
| 大小区间 `size_range` | `content-length-range` | 不可表达（不签名长度区间） |
| 数据标签 `tags` | `eq $x-amz-tagging` | 不可表达 |
| 有效期 `ttl` | policy `expiration`（绝对时间） | `X-Amz-Expires` + `X-Amz-Date` |

PUT 侧的限制来自当前仓库实现：`minio/signer.py` 的
`_get_presign_canonical_request_hash` 固定
`X-Amz-SignedHeaders=host`，因此额外的 `x-amz-tagging` 等请求头不会被
签名，服务端无法据预签 URL 强制它们；路径也只对应一个对象键。

当目标通道缺少必要条件时，`issue(...).as_dict()` 给出：

- `status = "unexpressible"`；
- `missing[].condition`：稳定机器名，如 `content_length_range`、`tags`、
  `key_prefix`；
- `missing[].label/detail`：缺的是哪一项、为什么该通道表达不了；
- `missing[].expressible_in` 与顶层 `available_methods`：可用的发放方式。

严格语义：存在缺项时**不会**调用 `presigned_put_object` /
`presigned_post_policy`，台账只记一条 `event="refused", signed=false`。

## 两份请求（合成凭据 + 本地签名记录）

场景定义在 `upload_grants/scenarios.py`：

- **REQ-059-01**：审批前缀 `customers/huaxin/ledger/`，业务申请单个对象
  `…/2026/q4-vouchers.zip`，共同范围把前缀收紧为该精确对象，TTL 取
  申请 15 分钟与审批上限 30 分钟的较小值。表单和预签 PUT 都签发，
  回读核对 bucket、目标对象、有效期、签名，并交叉比较两种输出表达的
  范围完全一致。
- **REQ-059-02**：同一工作流追加审批要求的大小区间与数据标签，且业务
  申请了更窄的大小区间 `[1 MiB, 2 GiB]`（与审批
  `[1 MiB, 5 GiB]` 相交）和额外标签。POST 表单成功签发，解码 policy
  可看到 `content-length-range` 与 `eq $x-amz-tagging`；PUT 调用返回
  `unexpressible`，缺项为 `content_length_range` 和 `tags`，
  `available_methods=["post_form"]`。台账中该请求没有任何
  `signed=true` 的 PUT 记录，审计确认不存在扩大权限的 PUT。

## 运行

```sh
# 生成 upload_grants/demo_artifacts/ 下的台账与报告，并打印核对过程
.venv/bin/python -m upload_grants.demo

# 单元测试（19 个，含“拒绝时绝不调用 PUT 签名器”的 spy 验证）
.venv/bin/python -m pytest -q tests/unit/upload_grants_test.py
```

产物：

- `upload_grants/demo_artifacts/signature_records.jsonl` — 本地签名记录，
  每行含 scope 快照、通道、`issued/refused/denied`、完整产物与签名、
  逐项核对结果；
- `upload_grants/demo_artifacts/demo_report.json` — 两份请求的结构化结果；
- `upload_grants/demo_artifacts/demo_run.txt` — 一次实际运行的控制台记录。

## 模块

- `model.py` — `UploadRequest` / `Approval` / `GrantScope` /
  `SizeRange` 与 `resolve_scope` 共同范围求解；
- `capabilities.py` — 通道能力矩阵与 `missing_for_channel`；
- `inspector.py` — 解码 POST policy、解析 PUT URL、`verify_scope` 与
  `compare_channels`；
- `journal.py` — JSONL 追加台账；
- `audit.py` — 审计台账中是否存在范围外 / 带表单专属条件的 PUT；
- `issuer.py` — `GrantIssuer` 发放服务与结构化 `IssueOutcome`；
- `scenarios.py` / `demo.py` — 两份标准请求与可运行演示。
