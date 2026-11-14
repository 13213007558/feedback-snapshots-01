# `act` 委托链验证原型（基于 ruby-jwt）

一个可直接接入 API 网关的原型，用于校验 RFC 8693 令牌交换定义的 `act`（actor /
委托）声明链。它复用 ruby-jwt 现有的外层签名与标准声明验证，只在**外层已验签通过的
payload** 之上叠加委托拓扑策略，不改动 gem 核心代码。

## 背景与威胁模型

请求经多个服务转交时，身份记录在嵌套的 `act` 声明里：

```jsonc
// user 经 gateway、billing 转交给 shipping 处理
{
  "sub": "user-1",
  "aud": "https://api.example/orders",
  "act": {
    "sub": "gateway",
    "act_token": "<gateway 自签的同意 JWT>",
    "act": {
      "sub": "billing-svc",
      "act_token": "<billing 自签的同意 JWT>",
      "act": { "sub": "shipping-svc", "act_token": "<shipping 自签的同意 JWT>" }
    }
  }
}
```

读取顺序是 `sub -> act.sub -> act.act.sub ...`，最深层是最近一个执行者。

关键事实：**整个 payload 只有外层一个签名**。外层签名只能证明“最外层签发者（IdP/
网关）背书了这串字节”，不能证明链中每个参与者都真的同意授权。因此本原型把两件事
严格分开：

- 拓扑合法性（可由外层签名 + 服务端策略证明）
- 逐跳同意（必须由各参与者**独立密钥**的凭据证明，无法从外层签名推出）

## 目录结构

```
lib/act_chain/
  errors.rb             各类拒绝的错误类型（均为 ActChain::Error）
  policy.rb             服务端策略：允许边、最大深度、租户映射、受众授权表
  chain.rb              把嵌套 act 展平成有序路径，原样保留每跳证据
  evidence_verifier.rb  用各参与者自己的密钥验内层 act_token，验不了只标记不补信任
  result.rb             结构化结果：valid? 与 fully_consented? 刻意分离
  verifier.rb           核心校验，inspect 收集全部错误 / verify! 遇错即抛
  gateway.rb            接入层：先 JWT.decode 验外层，再跑链校验；含授权决策接口
demo/                   本地 RS256 签发与三个样例
spec/                   RSpec，22 个用例
```

## 服务端策略如何表达

`ActChain::Policy` 只接受运维显式配置的信任，令牌自身无法扩大它：

- `allowed_edges`：允许的有向委托边集合 `[[actor, next_actor], ...]`
- `max_depth`：最大委托跳数（`act` 嵌套层数）
- `tenants` + `cross_tenant_allowed`：主体到租户的映射；默认禁止跨租户边
- `audience_subjects`：每个最终受众允许哪些主体触达

## 校验规则（硬性拒绝）

按下列顺序收集错误，一次返回全部违规，便于审计而不是只报第一个：

1. **最大深度**：`chain.depth > max_depth` → `DepthExceeded`
2. **重复主体 / 循环**：路径上同一 `sub` 出现多次 → `DuplicateSubject`
3. **跨租户跳转**：相邻主体租户不同且未显式放行 → `CrossTenantJump`
4. **委托边**：每条相邻边必须在 `allowed_edges` 内 → `EdgeNotAllowed`
5. **受众匹配**：路径上**每个**主体都须在最终 `aud` 的授权表里 → `AudienceMismatch`
6. （可选严格模式）**逐跳同意**：任一跳缺少可验证凭据 → `UnverifiedEvidence`

注意第 5 条校验的是“主体与最终受众是否匹配”，而非仅校验最外层 `sub`，避免中间参与者
触达它本无权访问的受众。

## 能证明什么 / 不能证明什么

**能证明（在 ruby-jwt 已验外层签名、且策略可信的前提下）：**

- 外层 JWT 的签名、`exp/nbf/iss/aud` 等标准声明有效（由 `JWT.decode` 保证）
- 委托路径的拓扑符合服务端策略：深度受限、无环、不跨租户、边走允许列表、全员匹配受众
- 当且仅当每跳的 `act_token` 都能用该参与者注册公钥验签且内容正确时，
  `fully_consented?` 为真——这才是“每个参与者都同意”的证据

**不能证明（本原型明确不越界）：**

- 外层签名**不能**推出链内参与者的同意。没有逐跳独立凭据时，`valid?` 可为真而
  `fully_consented?` 为假，二者在 `Result` 上刻意分开
- 委托**不会扩大原主体权限**。`AuthorizationDecision#permit?` 只查原始 `sub` 的能力表，
  中间 actor 自带的权限不会附加到请求上
- 无法验证来源的声明不会被“补”成可信：`EvidenceVerifier` 对无密钥、验签失败、证据缺失
  分别标记 `:none / :unverified`，并在 `Step#raw` 与结果里**原样保留证据**供审计，
  绝不伪造一个通过结论
- 不证明策略本身的业务正确性、不做细粒度授权、不防重放（`jti` 吊销需外部状态）

## 从验证结果到上层授权的接口

```ruby
result = gateway.authenticate(token)        # 外层 JWT::Error 会上抛；链错误收集在结果里
result.valid?            # 拓扑是否合法（仅回答策略问题）
result.fully_consented?  # 是否每跳都有可验证同意（敏感操作应要求此项）
result.original_subject  # 始终以原始主体作为授权锚点
result.hop_evidence      # 每跳 :verified / :none / :unverified 及原因、原始声明
result.policy_errors     # 全部硬性违规

decision = ActChain::AuthorizationDecision.new(result, capabilities: iam_capabilities)
decision.permit?(:orders_read)  # 链合法 && 原始主体持有该权限，否则拒绝
```

建议网关把 `valid?` 作为准入门槛，把 `fully_consented?` 作为敏感/写操作的附加门槛，
最终权限仍由外部 IAM/ACL 基于 `original_subject` 裁决。

## 仍需业务策略或独立凭据支持的部分

- **能力与职责分离**：`permit?` 的能力表来自外部 IAM，本原型不持有也不推断业务权限
- **逐跳同意的凭据体系**：需要为每个服务签发/轮换独立密钥（KMS、JWKS、mTLS 身份），
  并约定 `act_token` 的 schema；没有它就只能得到“拓扑合法但同意不可验证”
- **重放与吊销**：`jti` 黑名单、短 TTL、令牌绑定（DPoP/mTLS）依赖有状态基础设施
- **租户归属来源**：`tenants` 映射需与权威目录同步，原型不自行发现租户
- **策略治理**：允许边与受众表的变更审批、最小化与审计是业务流程，不在代码内

## 本地运行

```bash
# 三个签发样例：合法委托 / 循环 / 越权（跨租户 + 非法边 + 受众不匹配）
ruby demo/run_demo.rb

# 测试
rspec spec
```

三个样例的外层 JWT 都带**有效 RS256 签名**；样例 2、3 的拒绝完全来自委托策略而非签名
失败，以此说明“外层签名有效”与“委托可信”是两件事。
