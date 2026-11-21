# Basic → Token 迁移接入方案

基于本仓库 `src/flask_httpauth.py` 当前定义的 API（`HTTPBasicAuth.verify_password`、
`HTTPTokenAuth.verify_token`、`MultiAuth`）。可运行示例见
`examples/basic_to_token_migration.py`，行为验证见
`tests/test_basic_token_migration.py`。

## 1. 并存架构

```
Authorization: Basic ...   ──▶ HTTPBasicAuth  ──▶ verify_password(username, password)
Authorization: Bearer ...  ──▶ HTTPTokenAuth  ──▶ verify_token(token)
                                        │
                        MultiAuth(basic_auth, token_auth)
                                        │
                        @multi_auth.login_required 保护所有业务路由
```

- `MultiAuth` 按请求头里的 scheme 自动分派（`is_compatible_auth`），两种客户端
  互不感知；视图内统一用 `multi_auth.current_user()` 取用户。
- `MultiAuth` 的第一个参数是 main_auth：无凭据或 scheme 无法识别时，用它发
  401 质询。迁移期建议保留 `basic_auth` 在前，旧客户端看到的
  `WWW-Authenticate: Basic realm="Authentication Required"` 不变。
- 关键约束：定义了 `verify_password` 后，`get_password`/`hash_password`
  回调不再被调用（见 `src/flask_httpauth.py:342`），所以新旧两条链路的
  取数逻辑完全独立，各取所需。

## 2. 两条验证链路的取数分工

### 旧链路 `verify_password(username, password)` —— 只读 accounts 表

| 字段 | 方向 | 说明 |
|---|---|---|
| `accounts.username` | 读 | 按用户名定位账号 |
| `accounts.password_hash` | 读 | 用 `check_password_hash` 比对，明文口令只存在于请求内存中，不落库、不外传 |

### 新链路 `verify_token(token)` —— 只读 tokens 表

| 字段 | 方向 | 说明 |
|---|---|---|
| `tokens.token_hash` | 写/读 | 只存令牌摘要（如 SHA-256），永不存原始令牌 |
| `tokens.user_id` | 写/读 | 关联回 accounts，回调据此返回用户对象 |
| `tokens.expires_at` | 写/读 | 过期即视为无效 |
| `tokens.revoked`（或 `revoked_at`） | 写/读 | 支持主动吊销 |
| `tokens.last_used_at`（可选） | 写 | 审计与退役判断用 |

accounts 表**不需要**为新接口增加任何明文或等价物字段；新接口也**不读**
`password_hash`。令牌签发端点（示例中的 `POST /tokens`）在迁移期用
`@basic_auth.login_required` 保护，是明文口令唯一经过的地方，签完即弃。

## 3. 故障交付行为（fixture 已验证）

| 场景 | 结果 |
|---|---|
| 旧客户端口令正确 | 200，`current_user()` 返回用户 |
| 新客户端令牌有效 | 200，同上 |
| 口令错误 | 401 + `WWW-Authenticate: Basic realm="Authentication Required"` |
| 令牌未知 / 已吊销 / 已过期 | 401 + `WWW-Authenticate: Bearer realm="Authentication Required"` |
| 无凭据 | 401，由 main_auth（Basic）发质询 |
| 需要自定义错误体 | 用各自的 `@error_handler` 覆盖（两套互不影响） |

## 4. 旧回调的退役条件

`verify_password` 可退役的判定，建议同时满足：

1. 遥测（在 `verify_password` 成功分支打点，或按 `g.auth_method` 统计）
   连续 N 天无 Basic 成功请求；
2. 所有已知旧客户端版本已低于支持下限或被强制升级；
3. `POST /tokens` 已改由其他方式保护（如已登录会话或刷新令牌流程）。

退役步骤：从 `MultiAuth(...)` 中移除 `basic_auth` → 删除 `verify_password`
回调与 `POST /tokens` 的 Basic 保护 → 观察一个版本周期后，方可考虑删除
`accounts.password_hash` 列（若仍需口令登录 Web 端则保留）。
