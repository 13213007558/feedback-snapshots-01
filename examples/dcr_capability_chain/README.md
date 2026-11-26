# 动态客户端登记（DCR）能力验证链 — 本地 mock

用 Authlib 真实的 RFC 7591 / 7592 / 8414 / 6749 扩展点，演示一条从
**注册资料 → 发现元数据 → 实际 grant** 的能力验证链，覆盖：

- 两条不同的伙伴批准记录（standard / premium）
- 一次申请扩大能力（先拒后批，RFC 7592 `PUT`）
- 已登记客户端的平滑收紧（只改策略、不动客户端行）

不绑定任何端口：用 Flask 的 in-process `test_client` 跑，可在禁端口的沙箱内运行。

## 运行

```bash
.venv/bin/python -m examples.dcr_capability_chain.demo      # 带分层标注的叙事输出
.venv/bin/pytest examples/dcr_capability_chain/test_chain.py -q  # 12 条断言作为验证证据
```

## 四层各做什么决策

| 层 | 模块 | 决策内容 | 依据 |
|----|------|----------|------|
| L0 发现 | `app.py` / RFC 8414 | 只发布**服务器天花板**（支持哪些 grant/scope/注册端点），不暴露某个伙伴的权限 | `AuthorizationServerMetadata.validate()` |
| L1 身份 | `endpoints.RegistrationEndpoint.authenticate_token` | 用 Initial Access Token 解析出是哪个伙伴；无/错 token 直接 401 | RFC 7591 §3.2.2、RFC 6750 §3.1 |
| L2 登记/管理 | `claims.PartnerEntitlementClaims` + `policy.enforce` | 把请求的 grant/scope 与该伙伴**批准档案**求交：grant 越界硬拒绝，scope 越界静默收窄 | RFC 7591 §2/§3.2.2、RFC 7592 §2.2 |
| L3 令牌 grant | `grants.ScopedClientCredentialsGrant` + `models.Client.check_*` | 运行时再校验：grant 仍被批准才发令牌；未知 scope 报 `invalid_scope`，未授予的已知 scope 过滤 | RFC 6749 §4.4/§5.1、§3.3 |

关键设计：**批准档案（`policy.py`）是唯一事实源**。客户端表只存登记时的快照，
真正的能力判断（`Client.check_grant_type` / `get_allowed_scope`）每次都拿
「快照 ∩ 实时策略」。因此运营侧收紧策略后，老客户端无需迁移即被立即约束。

## 拒绝如何反馈

所有 OAuth 错误在 `app.py` 的 `handle_oauth2_error` 统一转成 RFC 形态 JSON：

| 触发场景 | HTTP | `error` | 决策层 |
|----------|------|---------|--------|
| 未带 Authorization 头 | 401 | （无 error code，仅 `WWW-Authenticate: Bearer`） | L1 |
| token 无效/吊销 | 401 | `invalid_token` | L1 |
| 请求未批准的 grant_type | 400 | `invalid_client_metadata`（描述点名 `grant_types` 与越界值） | L2 |
| 请求服务器不认识的 scope | 400 | `invalid_client_metadata`（`Invalid claim: 'scope'`） | L2 claims |
| grant 阶段用了未授权的 grant | 400 | `unauthorized_client` | L3 |
| grant 阶段请求未知 scope | 400 | `invalid_scope` | L3 |
| 请求了已知但未授予该客户端的 scope | 200 | 不报错，令牌里该 scope 被过滤 | L3（静默收窄） |
| 管理端点读别人的记录 | 403 | `unauthorized_client` | L2 RFC 7592 |

grant 与 scope 的区别是刻意的：**grant 是协议级能力选择，越界必须显式拒绝；
scope 是令牌内容，按 RFC 6749 §3.3 允许下发请求范围的子集**。

## 演示叙事（`demo.py` 15 个交互）

1. 发现元数据只给服务器天花板。
2. standard 伙伴登记：`authorization_code`+`refresh_token`、只读 scope → 201。
3. premium 伙伴登记：额外 `client_credentials` + `orders:write` → 201。
4. standard 申请 `client_credentials` → 400 `invalid_client_metadata`。
5. premium 申请未知 scope `admin:root` → 400。
6. 无 token / 错 token 登记 → 401（分别无 code / `invalid_token`）。
7. premium 用 client_credentials 拿到双 scope 令牌。
8. premium 多要 `email`（未登记）→ 200 但 scope 被过滤。
9. standard 用 client_credentials → 400 `unauthorized_client`。
10. standard 经 RFC 7592 `PUT` 申请扩权 → 先 400；运营 `policy.widen` 后再 `PUT` → 200，随后成功拿到令牌。
11. legacy 客户端：宽松基线下能拿 client_credentials 令牌；运营收紧策略（不改客户端行）后同请求变 400，`authorization_code` 仍可用、`orders:write` 被过滤。

## 兼容/平滑收紧的验证证据

`test_chain.py` 中与兼容路径直接相关的断言：

- `test_expansion_denied_then_allowed_after_policy_widening`：同一 RFC 7592 `PUT`，
  策略未批时 400、策略放宽后 200，证明扩权走标准管理端点而非私有接口。
- `test_tightening_takes_effect_without_touching_client_row`：收紧后客户端表里
  `grant_types` 快照仍含 `client_credentials`，但 `check_grant_type("client_credentials")`
  返回 `False`、`get_allowed_scope` 丢掉 write —— 证明收紧由实时策略生效，老数据无需迁移。
- `test_grant_layer_clamps_unentitled_scope`：未授予的已知 scope 被静默过滤而非报错，
  保证老客户端按旧请求体调用不会因新增 scope 治理而整体失败（向后兼容）。

## 文件

- `policy.py` — 伙伴批准档案、IAT 映射、`enforce` 求交决策。
- `models.py` — 内存 SQLAlchemy 客户端/令牌模型，能力检查委托实时策略。
- `claims.py` — `ClientMetadataClaims` 子类，在校验期施加伙伴权限。
- `endpoints.py` — RFC 7591 注册端点、RFC 7592 管理端点。
- `grants.py` — client_credentials grant，运行时 grant/scope 裁决。
- `app.py` — Flask 装配、RFC 8414 发现、统一错误反馈。
- `demo.py` / `test_chain.py` — 叙事脚本与断言证据。
