# Gunicorn 两种 TLS 接法与本地握手矩阵

本目录基于仓库现有的 SSL 设置（`gunicorn/config.py` 的 SSL 段）和 worker 代码
（`gunicorn/sock.py`、`gunicorn/workers/{sync,gthread,ggevent,gasgi}.py`、
`gunicorn/http/message.py`）整理两种部署接法，并提供一套只在本机运行、不绑定
网络端口的握手矩阵。

- 接法 A：相互认证 TLS（mTLS）终结在 Gunicorn 监听器。
- 接法 B：TLS 由负载均衡/代理终结，Gunicorn 只听明文 HTTP。

## 1. 两种接法总览

| 维度 | A：mTLS 在 Gunicorn | B：LB 终结 TLS |
|---|---|---|
| 监听器 | `https://`，`cfg.is_ssl` 为真 | `http://`，`cfg.is_ssl` 为假 |
| 必备配置 | `certfile`、`keyfile`、`ca_certs`、`cert_reqs=2` | 无证书；`forwarded_allow_ips`、`secure_scheme_headers` |
| 谁校验客户端证书 | Gunicorn 进程内的 `SSLContext` | LB；Gunicorn 看不到 TLS 会话 |
| 应用拿到的身份证明 | 来自 `SSLSocket` 的对端证书（密码学证据） | 来自受信代理的转发头（可被策略约束的声明） |
| `wsgi.url_scheme` | 直接是 `https` | 仅当受信对端的 `X-Forwarded-Proto: https` 等头匹配时才是 `https` |
| HTTP/2 | TLS ALPN 协商 `h2`/`http/1.1` | 无 ALPN；需要 h2 时走 h2c（`http2_cleartext`，同信任名单） |
| 握手失败位置 | worker 接受连接后的 TLS 握手阶段 | 发生在 LB，Gunicorn 无感知 |

对应配置文件：`gunicorn.mtls.conf.py`（A）、`gunicorn.proxy.conf.py`（B）。

## 2. 应用能依赖的身份材料

### 接法 A：mTLS 在监听器

worker 用 `gunicorn/sock.py::ssl_wrap_socket()` 包装连接后，WSGI environ 里的
`gunicorn.socket` 就是一个已完成握手的 `ssl.SSLSocket`，应用可以直接读取：

- `environ["gunicorn.socket"].getpeercert()`：解析后的对端证书链信息（subject、
  issuer、有效期、SAN）。`CERT_REQUIRED` 下握手成功即代表链已通过校验；
  `CERT_OPTIONAL` 下客户端未给证书时返回 `None`，应用必须自己判空并决定是否放行。
- `getpeercert(binary_form=True)`：DER 编码证书，可做指纹/审计转发。
- `selected_alpn_protocol()`：`h2` 或 `http/1.1`；`version()`、`cipher()` 给出
  协商的 TLS 版本和套件。
- `REMOTE_ADDR`/`REMOTE_PORT` 仍是 TCP 对端；mTLS 直连场景下即真实客户端。

参考实现见 `identity_app.py`。注意 Gunicorn 不会把对端证书自动展开成
`SSL_CLIENT_*` 之类的 CGI 变量，需要应用（或自定义中间件/`ssl_context` 钩子）
自行从 socket 提取。ASGI worker 走 asyncio 的 `SSLTransport`，scope 里只有
`scheme`、`client`/`server` 元组，证书同样要从 transport 取，没有现成字段。

### 接法 B：LB 终结 TLS

Gunicorn 的 socket 是明文的，`gunicorn.socket` 不是 `SSLSocket`，因此
`getpeercert()` 这条路径不存在，应用能依赖的只有：

- 转发头：`X-Forwarded-Proto`（决定 `wsgi.url_scheme`）、`X-Forwarded-For`
  （真实客户端地址，需自行解析），以及可选的客户端证书头，例如
  `X-SSL-Client-Cert` / `X-Client-Cert-DN`——这些头的名称和格式完全由 LB 决定，
  Gunicorn 不做任何校验，**必须由 LB 覆写且禁止客户端直连携带**。
- 信任边界：`gunicorn/http/message.py::_peer_trusted_for_forwarded()` 只在对端
  命中 `forwarded_allow_ips`（默认 `127.0.0.1,::1`，Unix socket 无条件信任）时
  才承认这些头；非受信对端发来的 `X-Forwarded-Proto` 被忽略，scheme 保持 `http`。
- 受信对端若发送互相矛盾的安全头（如两个值不同的 `X-Forwarded-Proto`），解析期
  直接抛 `InvalidSchemeHeaders`，请求以 400 失败，而不是静默选一个。
- 需要原始 L4 端点时可启用 `proxy_protocol`，从 environ 的 `REMOTE_ADDR`、
  `PROXY_PROTOCOL`、`PROXY_ADDR` 读取（见 `wsgi.py::proxy_environ`）。

关键区别：A 的身份是 Gunicorn 自己用信任锚验证过的证书；B 的身份是代理的声明，
安全性取决于 `forwarded_allow_ips` 是否收窄、LB 是否剥掉/覆写客户端伪造头。

## 3. 证书链校验

两种接法的校验发生在不同位置，Gunicorn 的行为由 `sock.py::ssl_context()` 决定：

1. 上下文用 `ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=ca_certs)`
   创建，默认开启链校验、有效期校验和基本约束检查；随后 `load_cert_chain()`
   装载服务端证书，`verify_mode` 取 `cert_reqs`。
2. `cert_reqs`：`0=CERT_NONE`（默认，不要求客户端证书）、`1=CERT_OPTIONAL`
   （有就校验、没有也放行）、`2=CERT_REQUIRED`（mTLS 必须选它，无证书或链不被
   `ca_certs` 信任都在握手阶段断开）。
3. 校验锚点是 `ca_certs` 指定的 PEM（可含多个 CA）。客户端证书必须链到其中某个
   CA；由无关 CA 签发的证书报 `CERTIFICATE_VERIFY_FAILED / unknown CA`。Gunicorn
   不校验客户端证书的 SAN 主机名（对端是客户端而非被访问主机），若要绑定
   CN/OID/spiffe 等身份，应用需在 `getpeercert()` 结果上自行断言。
4. 更深的策略（TLS 下限、固定证书、按 SNI 返回不同证书、CRL/OCSP 策略）通过
   `ssl_context` 配置钩子实现，参考 `gunicorn.mtls.conf.py` 与
   `examples/example_config.py`。
5. 接法 B 下 Gunicorn 没有 `SSLContext`，链校验（含 mTLS）整体上移到 LB；
   Gunicorn 只能保证转发头来源受信，无法验证头里声明的证书本身。

## 4. HTTP/2 协商

- 接法 A（TLS）：`sock.py::_get_alpn_protocols()` 仅在 `http_protocols` 含 `h2`
  且装了 `h2` 包时调用 `SSLContext.set_alpn_protocols()`，按配置顺序给出
  `h2`、`http/1.1`（RFC 7301 ALPN）。gthread 在连接初始化时
  `do_handshake()` 后用 `is_http2_negotiated()` 分流到 HTTP/2 解析器。
  sync worker 不支持 h2，会打印 warning 并只提供 HTTP/1.1——mTLS + h2 请选
  gthread、gevent 或 asgi worker。
- 接法 B（明文）：TLS 不存在，ALPN 无从谈起。若 LB 要对上游说 HTTP/2，走
  h2c：`http2_cleartext` 选 `prior-knowledge`/`upgrade`/`both`，且只接受
  `forwarded_allow_ips` 内对端的 h2c（`http2/negotiation.py::peer_trusted_for_h2c`）；
  非受信对端一律按 HTTP/1.1 处理。默认 `off`，即只讲 HTTP/1.1。

## 5. 启动失败会在哪里出现

| 故障 | 触发点 | 表现 |
|---|---|---|
| `certfile`/`keyfile` 路径不存在 | `sock.py::create_sockets()`，master 建监听套接字时 | `ValueError`，arbiter 在 fork worker 前退出 |
| 证书与私钥不匹配、PEM 损坏、密码错误 | `SSLContext.load_cert_chain()` | gevent/asgi 在 worker boot 时失败（`WORKER_BOOT_ERROR=3`，arbiter 停服）；sync/gthread 延迟到第一条连接包装 socket 时抛 `ssl.SSLError` |
| `ca_certs` 文件无效 | 构建 `SSLContext` 时 | 同上，按 worker 类型落在 boot 或首连接 |
| `http_protocols` 含 h2 但未装 `h2` | `Config.validate()` | `ConfigError`，启动即失败 |
| 客户端证书不受信 / 未提供（REQUIRED） | worker 内 TLS 握手，应用代码之前 | `SSLCertVerificationError` / `PEER_DID_NOT_RETURN_A_CERTIFICATE`，对端收到 TLS alert，无 HTTP 响应 |
| 转发头冲突（接法 B） | HTTP 请求解析期 | `InvalidSchemeHeaders`，返回 400 |
| 非受信对端伪造转发头（接法 B） | 解析期策略判定 | 头被忽略，不报错，scheme 保持 `http` |

## 6. 本地握手矩阵

### 6.1 不绑端口的进程内矩阵（本沙箱可直接跑）

`handshake_matrix.py` 用 `socketpair` 跑真实 TLS 握手，服务端上下文就是
`gunicorn.sock.ssl_context()` 生成的对象，代理模式的明文行走真实的
`gunicorn.http.parser.RequestParser`，因此覆盖的是 Gunicorn 本身的判定逻辑，
而不是模拟。

```bash
./examples/mtls_handshake_matrix/make_pki.sh        # 首次：生成本机 PKI
.venv/bin/python examples/mtls_handshake_matrix/handshake_matrix.py
```

验收矩阵（当前实现 12/12 通过）：

| 编号 | 场景 | 期望结果 | 区分的身份类别 |
|---|---|---|---|
| A1 | 受信 CA 签发的客户端证书，ALPN 提 h2 | 握手成功，ALPN=`h2`，`getpeercert()` 可见 CN | 客户端证书通过 |
| A2 | 无关 CA 签发的客户端证书 | 服务端 `CERTIFICATE_VERIFY_FAILED`，无 SSLSocket，对端收到 unknown CA alert | 证书不受信 |
| A3 | REQUIRED 下不提供客户端证书 | `PEER_DID_NOT_RETURN_A_CERTIFICATE`，握手失败 | 证书缺失（拒绝） |
| A4 | OPTIONAL 下不提供客户端证书 | 握手成功，`getpeercert()` 为 `None` | 证书缺失（放行，应用自判） |
| A5 | 受信证书但只提 http/1.1 | ALPN=`http/1.1`，握手成功 | h1 回退 |
| A6 | 客户端不信任服务端证书 | 客户端侧 `unknown CA`，握手失败 | 服务端身份不被信 |
| B1 | 受信回环对端带 `X-Forwarded-Proto: https` | `scheme=https` | 代理终结的可信流量 |
| B2 | 外部 IP 对端带同样的头 | 头被忽略，`scheme=http` | 伪造转发头 |
| B3 | 受信对端带冲突的转发头 | `InvalidSchemeHeaders`（400） | 代理配置错误 |
| B4 | 明文无转发头 | `scheme=http`，无任何 TLS 材料 | 纯明文 |
| S1 | certfile 缺失 | master 启动期 `ValueError` | 启动失败位置 |
| S2 | 证书/私钥不匹配 | 建上下文时 `KEY_VALUES_MISMATCH` | 启动失败位置 |

A1/A2/A3 直接满足验收的三类区分：**证书通过有对端证书且握手成功；证书不受信
在握手阶段被拒、应用完全不运行；代理终结的流量根本没有 SSLSocket，只可能带
转发头（B1/B4）**。

### 6.2 端到端实时矩阵（需要本机绑定端口）

`run_live_matrix.sh` 起两个真实 Gunicorn（`:8443` mTLS、`:8080` 明文）并用
`curl`/`openssl s_client` 打流量。本环境沙箱禁止 `bind(127.0.0.1, ...)`
（EPERM），脚本开头有预检并提示改用 6.1；在允许本地绑定的机器上直接运行：

```bash
./examples/mtls_handshake_matrix/run_live_matrix.sh
```

其中 `openssl s_client -alpn h2 ...` 一行直接打印协商出的 ALPN 与
`Verify return code`，可人工复核 A1/A2。

## 7. 文件清单

- `make_pki.sh`：生成两套独立 CA、服务端证书（SAN=localhost）、受信/不受信客户端证书。
- `pki/`：上述 PKI 产物，仅本机测试用，`*.key` 权限 600，勿提交到仓库。
- `identity_app.py`：转储 `wsgi.url_scheme`、对端证书、ALPN、转发头的 WSGI 应用。
- `gunicorn.mtls.conf.py` / `gunicorn.proxy.conf.py`：两种接法的配置。
- `handshake_matrix.py`：进程内握手矩阵（无需端口）。
- `run_live_matrix.sh`：真实监听器版矩阵（需本地绑定权限）。
