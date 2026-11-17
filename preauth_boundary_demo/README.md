# aioimaplib PREAUTH 信任边界接入示例

aioimaplib 在收到连接问候中的 `PREAUTH` 时，会直接把协议状态切到 `AUTH`
（见 `aioimaplib/aioimaplib.py` 的 `IMAP4ClientProtocol.welcome`）。这只是对
协议字节的状态解释，**不是授权决定**。本示例在不修改库的前提下，于库外增加
一道明确的策略门，区分“传输层能独立证明什么”和“服务器在欢迎语里自称什么”。

## 核心边界

- 服务器自报状态：问候行 `* OK` / `* PREAUTH` / `* BYE`，由 `greeting.py` 解析。
  `PREAUTH` 不含可独立验证的用户证明，欢迎语里的 `user=root`、`as admin`
  等文字永远不会被解析成身份。
- 传输验证：由 `transport.py` 从真实通道（证书链、主机名、显式本地通道配置）
  得到 `TransportEvidence`。一个“已经开启 SSL 的 socket”若证书链未验证或主机名
  不匹配，只会被归类为 `TLS_UNVERIFIED`，不能当作已确认对端身份。
- 信任决策：只在 `policy.py` 一处发生。是否允许 `SELECT`、是否允许发送
  `LOGIN` 凭据，都由 `GateDecision` 给出，业务侧不得再从问候文本反推信任。

## 接受政策

| 问候 | 通道证据 | 决策码 | 可选邮箱 | 可发凭据 |
| --- | --- | --- | --- | --- |
| PREAUTH | 明文 | `reject-preauth-plaintext` | 否 | 否 |
| PREAUTH | TLS 已加密但未验证对端 | `reject-preauth-tls-unverified` | 否 | 否 |
| PREAUTH | TLS 已验证，但主机不在受信来源配置 | `reject-preauth-source-not-trusted` | 否 | 否 |
| PREAUTH | TLS 已验证且主机命中受信来源 | `accept-preauth` | 是 | 否 |
| PREAUTH | 显式受信本地通道且命中配置 | `accept-preauth` | 是 | 否 |
| OK | 已验证 TLS | `require-login` | 否（登录前） | 是 |
| OK | 受信本地通道且配置允许凭据 | `require-login` | 否（登录前） | 是 |
| OK | 明文 / 未验证 TLS / 本地通道未授权凭据 | `reject-credentials` | 否 | 否 |
| BYE | 任意 | `rejected-bye` | 否 | 否 |
| 畸形问候 | 任意 | `rejected-malformed`（失败关闭） | 否 | 否 |

预认证身份的来源由 `TrustedPreauthSource`（受信配置）指定，匹配的是通道证明
的身份（验证过的 TLS 主机名或显式本地通道 id），不是问候文本。默认
`TrustPolicy()` 不信任任何来源。

## 模块结构

- `transport.py`：传输证据与分类；真实 TLS 用 `getpeercert()` 判断链是否验证，
  再用证书 SAN 做主机名匹配（Python 3.12 已移除 `ssl.match_hostname`）。
- `greeting.py`：RFC 9051 问候解析，只认状态记号位置，不提取用户。
- `policy.py`：受信来源配置与完整决策矩阵、错误原因。
- `fake_imap.py`：无网络的内存假传输，驱动**真实的**
  `IMAP4ClientProtocol`，脚本化返回 PREAUTH/OK/BYE 及 CAPABILITY/LOGIN/SELECT。
- `client.py`：`GuardedImapClient`，所有 `login`/`select` 先过策略门，违规抛
  `PolicyError`；同时提供真实连接入口 `connect_tcp`。
- `demo.py`：可运行的 11 个场景。

## 运行

```bash
.venv/bin/python -m preauth_boundary_demo.demo
.venv/bin/python -m pytest preauth_boundary_demo/tests/ -q
```

演示与测试均不绑定端口、不发起网络连接。TLS 分类测试在 `socketpair` 上用
asyncio 并发完成真实加密握手（含自签证书生成），用以证明“加密但未验证”与
“对端身份已验证”的区别。

## 生产接入要点

- 用 `connect_tcp` 建立真实连接，传入会校验证书的 `ssl_context`；证据由握手
  结果回读得到，而不是因为用了 `IMAP4_SSL` 就假定对端已认证。
- 受信 PREAUTH 来源放进配置/密钥管理，按“通道身份”匹配；新增来源是显式运营
  决策，默认拒绝。
- 真正的预认证来源不应再需要密码，因此 `accept-preauth` 始终
  `may_send_credentials=False`。
