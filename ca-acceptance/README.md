# 公司自建 CA 切换：pip 调用关系与验收方案

适用对象：后端构建平台中所有由 pip 发起的 Python 包抓取。本文结论对照本仓库
源码（pip 27.0.dev0）逐一核对，引用均为仓库内路径。

## 1. pip 三类网络调用与证书落点

一次 `pip install` / `pip download` 会产生三类 HTTPS 调用，它们共用同一个
`PipSession`（`src/pip/_internal/network/session.py:306`），但构建依赖存在
一条独立的子进程/进程内路径。

### 1.1 主索引抓取（计划阶段）

调用链：

- `PackageFinder` → `LinkCollector` → `PipSession`
- PEP 503 简单索引页、JSON 元数据、`HEAD` 探测全部走 session 的 `get/head`
- 认证由 `MultiDomainBasicAuth` 挂载在 session 上
  （`src/pip/_internal/network/auth.py`），支持 URL 内嵌凭据、`.netrc`、
  keyring（仅父进程可交互）。

### 1.2 文件下载（下载阶段）

调用链：

- `pip._internal.operations.prepare` 解析出 `Link` 后调用
  `pip._internal.network.download.Downloader`
  （`src/pip/_internal/network/download.py:186`），底层仍是
  `self._session.get(target_url, stream=True)`（同文件 `:384`）。
- 因此文件下载与索引抓取是**同一个 session、同一套 TLS 配置**，没有独立的
  证书开关；区别只是 URL 主机可能不同（索引主机 vs. 工件主机/CDN/重定向目标）。
- 落盘位置：`pip download` 由 `--dest` 显式指定
  （`src/pip/_internal/commands/download.py:54`）；普通安装下载到 HTTP 缓存/
  临时目录。下载完成后由 `Hashes.check_against_path`
  （`src/pip/_internal/operations/prepare.py:164`）做哈希校验，哈希来自
  `--require-hashes` 或索引片段，与 TLS 信任是两道独立防线。

### 1.3 构建依赖安装（PEP 517/518 隔离环境）

sdist 的 `pyproject.toml` 声明 `build-system.requires` 时，pip 必须把这些
依赖装进隔离环境，存在两种安装器（`src/pip/_internal/cli/req_command.py:270`）：

- 默认 `SubprocessBuildEnvironmentInstaller`
  （`src/pip/_internal/build_env/installer.py:37`）：再起一个 pip 子进程。
- 特性开关 `--use-feature=inprocess-build-deps` 时使用
  `InprocessBuildEnvironmentInstaller`（同文件 `:155`）：复用父进程的
  finder 与 session，不产生新进程。

## 2. 证书配置从哪里来、谁能继承

### 2.1 本版本的默认信任库

未显式指定 CA 时，pip 构建一个 truststore 的 `SSLContext`，同时加载
certifi 与操作系统信任库（`src/pip/_internal/cli/index_command.py:36`）。
也就是说，把公司 CA 装进系统钥匙串理论上可被默认路径信任；但容器/CI 节点
通常没有可控的系统钥匙串，平台不应依赖这一点。`--use-deprecated=legacy-certs`
可退回纯 certifi 行为（`src/pip/_internal/cli/cmdoptions.py:1335`）。

### 2.2 四条 CA 注入通道及优先级

| 通道 | 生效位置 | 关键代码 |
|---|---|---|
| `--cert <PEM>` / `PIP_CERT` / pip.conf `cert=` | 设为 `session.verify`（字符串路径） | `src/pip/_internal/cli/index_command.py:119` |
| `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE` | 仅当 `trust_env=True` 且 verify 为 True/None 时由 requests 合并 | `src/pip/_vendor/requests/sessions.py:855` |
| 系统钥匙串 + certifi | truststore 默认上下文 | `src/pip/_internal/cli/index_command.py:49` |
| `--trusted-host` | 对该主机挂 `InsecureHTTPAdapter`，**关闭校验**，不是 CA 方案 | `src/pip/_internal/network/session.py:286` |

优先级：显式 `--cert`（字符串 verify）最高，会使 requests 不再读取
`REQUESTS_CA_BUNDLE`（见 merge 逻辑中 `verify is True or None` 的判断）。
urllib3 拿到字符串 verify 后以 `ca_certs` 注入连接池，并在已有 truststore
上下文上再 `load_verify_locations` 一次
（`src/pip/_vendor/requests/adapters.py:100`、
`src/pip/_vendor/urllib3/util/ssl_.py:413`），即「公司 PEM + 系统 + certifi」
叠加生效。注意 `--proxy`/`--no-proxy-env` 会把 `trust_env` 置 False
（`index_command.py:138`），此时 `REQUESTS_CA_BUNDLE` 静默失效——平台若用
代理，必须走 `--cert`/`PIP_CERT` 而不是 requests 环境变量。

### 2.3 三处调用各自能继承什么

| 调用 | 可自动继承 | 必须平台显式传递/保证 |
|---|---|---|
| 主索引抓取 | 同一 session 上的 `verify`、`cert`、trusted-host、代理；URL 内嵌 basic auth；`.netrc` | CA 路径本身（CLI/env/conf 三选一）；mTLS 的 `--client-cert` |
| 文件下载 | 与索引**完全相同**的 session 配置，无需重复传递 | 工件主机/重定向主机必须被同一张 CA 覆盖；pip 无主机白名单，目的地管控在平台侧 |
| 构建依赖（子进程） | 进程环境变量（`PIP_CERT`、`REQUESTS_CA_BUNDLE` 等）、pip 配置文件、代理环境变量 | 本版本 `SubprocessBuildEnvironmentInstaller` 会显式转发 `--cert`/`--client-cert`/`--trusted-host`/索引 URL（含内嵌凭据）/`--proxy`（`src/pip/_internal/build_env/installer.py:114`）；但 keyring 交互凭据不可用，且其他 pip 版本/打包工具不一定转发 |
| 构建依赖（进程内） | 直接复用父 session，CA 天然一致 | 仅在 `inprocess-build-deps` 特性下成立 |

给平台的工程结论：

1. **最稳的传递方式是环境变量 `PIP_CERT=<公司PEM>`（或全局 pip.conf 的
   `cert=`），而不是只给 CLI `--cert`。** 环境变量/配置文件对父进程、
   子进程安装器、进程内安装器三条路径同时生效，不依赖某一版 pip 的参数转发。
2. 平台若同时下发 `--proxy`，不要再依赖 `REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE`。
3. `--client-cert`（mTLS）与 CA 信任是两件事；本版本子进程会转发
   `--client-cert`，但私钥文件必须在隔离构建节点上同样可读。
4. 禁止用 `--trusted-host` 替代 CA：它对命中主机整体关闭 TLS 校验
   （`src/pip/_internal/network/session.py:292` 的 `verify=False`）。
5. 「批准的文件下载目的地」pip 自身不强制：它只按索引给出的 URL 跟随
   重定向。平台必须在出口代理/防火墙层做主机白名单，并把白名单主机的
   证书签发链全部纳入公司 PEM。

## 3. 两阶段证据边界（不要把预检当全链通过）

| 阶段 | pip 实际发生的网络动作 | 能证明什么 | 不能证明什么 |
|---|---|---|---|
| 计划阶段（resolve；本版本可用 `pip install --dry-run --ignore-installed --report` 固定产物） | 对索引主机的 GET 简单索引、JSON 元数据、少量 HEAD | 索引主机 TLS 信任链正确、basic auth/mTLS 被接受、候选版本与哈希可见 | 工件主机/CDN/重定向目标的 TLS；sdist 构建依赖子进程；大文件完整性 |
| 下载阶段（实际 GET 工件、构建隔离安装） | 对工件 URL 的流式 GET、落盘、哈希校验、子进程 pip 再次访问索引 | 全链路：每个被访问主机的 CA 信任、客户端证书、目的地白名单、哈希匹配 | —（这才是全链证据） |

关键陷阱：索引与工件常托管在不同主机（或经重定向到对象存储）。计划阶段
成功只说明索引主机证书被信任；工件主机由另一张证书签发时，下载阶段才会
以 `SSLVerificationError` 失败。构建依赖同理：父进程能拉索引，不代表隔离
子进程拿到了 CA。因此验收必须分别固定两阶段证据，且包含负例。

## 4. 本地替身与可重复验收

`acceptance/` 目录提供不依赖外网的替身与用例：

- `acceptance/pki.py`：用 `cryptography` 在临时目录生成公司根 CA、由其签发的
  「索引主机」「工件主机」「未批准主机」三套证书，以及 mTLS 客户端证书。
- `acceptance/tls_peer.py`：基于 `socketpair` 的 TLS 对端，无需绑定端口
  （本沙箱禁止 `bind`），直接驱动 pip 同款 truststore/urllib3 验证路径。
- `acceptance/evidence.py`：以 pip 真实入口构建 `PipSession`，覆盖
  `--cert`、`PIP_CERT`、`REQUESTS_CA_BUNDLE`、代理下 env 失效、
  `--trusted-host` 关闭校验等矩阵。
- `acceptance/run_acceptance.py`：一键跑全部用例并把证据（命令、退出码、
  错误类型、握手日志）写入 `evidence/`。
- `acceptance/live_index/`：在允许端口绑定的环境（CI、普通开发机）运行的
  端到端替身：带 basic auth 的 PEP 503 索引 + 独立主机名的文件服务 +
  一个带构建依赖的 sdist，用于真实 `pip download`/`pip install --dry-run`。
  本沙箱因禁止本地端口绑定无法运行，脚本会自检并跳过、给出说明。
- `tests/unit/test_ca_cert_propagation.py`：可在本沙箱直接运行的 pytest
  单测，断言 session 配置与子进程参数转发，不绑定端口。

用例与需求条目的对应：

| 需求 | 用例 | 期望 |
|---|---|---|
| 认证的主索引 | `A1` basic auth 头被接受；`A2` mTLS 客户端证书被对端收到 | 正例握手成功，凭据/证书出现在证据中 |
| 批准的文件下载目的地 | `D1` 索引主机 + 批准工件主机均在公司 CA 下成功；`D2` 未批准主机（异签发者）被拒 | 白名单内 200，白名单外 TLS 失败而非静默放行 |
| 不可用的 CA | `N1` 指向缺失/不含签发者的 PEM；`N2` 计划阶段用例通过但下载阶段用例失败 | 明确 `SSLCertVerificationError`、非零退出，无回退到不校验 |
| 构建依赖继承 | `B1` 仅 `PIP_CERT` 时子进程参数与环境可用；`B2` 仅 CLI 且无转发时子进程失败 | 证明环境变量路径跨进程可靠 |

运行方式见 `acceptance/RUNBOOK.md`。
