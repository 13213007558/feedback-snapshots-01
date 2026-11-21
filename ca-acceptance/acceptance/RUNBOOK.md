# 验收运行手册（RUNBOOK）

所有命令默认在仓库根目录执行，使用仓库自带虚拟环境 `.venv`。

## 0. 前置条件

- Python 3.12，依赖 `cryptography`（见 `.feedback/requirements.txt`）。
- 离线套件（A/D/N/S/B 组）不需要网络、不绑定端口，可在受限沙箱运行。
- 端到端套件（live）需要允许 `bind(127.0.0.1)`；受限沙箱会输出
  `ENV_SKIP` 并以 0 退出，不算失败但也不构成端到端证据。

## 1. 离线可重复验收（无网络、无端口）

```sh
.venv/bin/python ca-acceptance/acceptance/run_acceptance.py
```

产物：

- `ca-acceptance/evidence/acceptance.txt`：人读摘要，逐用例 PASS/FAIL。
- `ca-acceptance/evidence/acceptance.json`：机读证据，含每条用例的输入、
  实际握手结果、错误类型、pip session 解析出的 verify 值、构建子进程完整 argv。
- `ca-acceptance/evidence/pki/`：本次生成的全部 PEM（公司 CA、未批准 CA、
  三套服务器证书、mTLS 客户端证书），可用于手工复核。

对应的 pytest 形式（CI 建议直接跑这个）：

```sh
.venv/bin/python -m pytest -q tests/unit/test_ca_cert_propagation.py
```

用例与需求映射：

| 用例 | 覆盖需求 | 关键断言 |
|---|---|---|
| A1 | 认证的主索引（basic auth） | 握手成功且 `Authorization` 头原样到达 |
| A2 | 认证的主索引（mTLS） | 带客户端证书成功；不带则被服务端拒绝 |
| D1 | 批准的文件下载目的地 | 索引主机与工件主机在公司 PEM 下均成功 |
| D2 | 目的地管控 | 异 CA 主机在公司 PEM 下失败，换其自身签发 CA 才成功 |
| N1 | 不可用的 CA | PEM 缺失/默认信任库均产生显式 TLS 错误 |
| N2 | 两阶段证据边界 | 计划阶段（索引）成功、下载阶段（异主机）失败 |
| S1–S6 | CA 注入通道 | CLI、`PIP_CERT`、`REQUESTS_CA_BUNDLE`、代理下 env 失效、trusted-host 关闭校验、client-cert |
| B1/B2 | 构建依赖继承 | 子进程 argv 中 `--cert`/`--client-cert`/带凭据索引 URL 的转发与缺失 |

## 2. 端到端验收（真实 pip 进程，需本地绑定）

1. 准备主机名映射（证书 SAN 依赖它）：

   ```sh
   echo '127.0.0.1 index.corp.example files.corp.example cdn.unapproved.example' \
     | sudo tee -a /etc/hosts
   ```

2. 启动并执行：

   ```sh
   .venv/bin/python ca-acceptance/acceptance/live_index/run_live.py
   ```

   脚本会：在 18443/18444/18445 起三个 HTTPS 替身；构建一个普通 wheel、
   一个构建后端 wheel 和一个声明 `build-system.requires` 的 sdist；
   依次运行真实 pip 命令。

3. 产物（`ca-acceptance/evidence/live/`）：

   - `01-plan-stage.log` + `plan-report.json`：**计划阶段证据**。执行的是
     `pip install --dry-run --ignore-installed --report`（本版本
     `--dry-run/--report` 只属于 install 命令，且 dry-run 在解析后、
     `prepare_linked_requirements_more` 之前返回，不下载工件）。只能证明
     索引主机 TLS 通过、basic auth 被接受、解析出候选与工件 URL；访问日志中
     此阶段只应出现索引主机请求。
   - `02-download-wheel.log`：**下载阶段证据（工件主机）**。证明另一个主机名
     的 TLS 链同样被公司 PEM 信任，文件落盘到 `--dest`。
   - `03-download-sdist-builddeps.log`：**构建依赖证据**。隔离环境中的嵌套
     pip 再次带认证访问索引并拉取 `seabuild`，证明 CA 配置跨进程生效。
   - `04-unapproved-host.log`：负例，期望非零退出且错误为证书验证失败。
   - `access.log`：替身服务端逐请求记录（主机、路径、认证头、状态码），
     与客户端日志交叉印证。
   - `live-result.json`：每条命令的退出码与日志路径汇总。

## 3. 证据判读规则（防止把预检当全链）

- 只有 `01` 成功而 `02/03` 缺失或失败时，结论只能写「索引主机信任链通过」，
  不得写「全链通过」。N2 用例专门固化这一陷阱。
- 负例必须看到明确的 `SSLCertVerificationError`/`SSLVerificationError` 与
  非零退出码；任何静默回退（回退到不校验、回退到默认 bundle 后成功）都判失败。
- 审计构建依赖时，以 `B1` 捕获的子进程 argv 为准；平台若只下发 CLI 参数，
  应在升级 pip 版本前重新跑 B 组，确认转发行为未变。跨版本最稳的做法仍是
  `PIP_CERT` 环境变量或全局 pip.conf。
- `--trusted-host` 出现即视为不合规（S5 证明它挂载的是 Insecure 适配器）。

## 4. 在真实平台上的推广检查清单

- [ ] 公司根 PEM 以只读方式下发到每个构建节点，路径固定（如
      `/etc/ssl/corp/corp-ca.pem`），并通过 `PIP_CERT` 暴露。
- [ ] 出口代理白名单只放行批准的索引主机与工件主机；白名单内所有主机的
      证书链都能被该 PEM 验证（D1/D2）。
- [ ] 若启用 mTLS，`--client-cert` 的私钥文件在隔离构建节点同样可读（A2）。
- [ ] 若同时配置 `--proxy`/`--no-proxy-env`，不得依赖 `REQUESTS_CA_BUNDLE`（S4）。
- [ ] 每次镜像/ pip 版本变更后重跑第 1、2 节并归档 evidence 目录。
