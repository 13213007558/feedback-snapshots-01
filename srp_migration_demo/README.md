# pysrp SHA-1 → SHA-256 记录迁移演示

基于仓库内 pysrp 的可运行演示，说明如何把旧的 SHA-1 SRP 验证记录逐步迁到
SHA-256，而**不是**把旧验证值改贴一个新算法标签。

## 运行

```sh
python -m srp_migration_demo.demo      # 7 个场景、38 项断言的端到端演示
python -m unittest srp_migration_demo.test_demo -v   # 13 个单元测试
```

## 为什么不能直接改标签

pysrp 中验证器是 `v = g^x mod N`，而

```text
x = H(salt, H(username + ":" + password))
```

`H` 由 `hash_alg` 决定。SHA-1 记录里的 `v` 是用 SHA-1 算出的 `x` 的单向结果；
服务端不持有口令，无法从 `v` 反推 `x` 或口令，也就无法算出 SHA-256 下的
`v'`。直接把 `param_set` 改成 SHA-256 而保留旧 `salt/v`，握手时
`Verifier.verify_session` 必然失败（场景 6 实证）。新验证器只能由**持有口令的
客户端**用新盐重新生成。

## 记录格式

每个用户一份 JSON 文档（`users/<username>.json`，原子写入），每条记录只属于
一个明确参数集，只含一对 `salt`/`verifier`：

```json
{
  "version": 1,
  "username": "alice",
  "param_set": "srp-2048-sha1-pysrp-v1",
  "params": {
    "param_set": "srp-2048-sha1-pysrp-v1",
    "group": "NG_2048",
    "digest": "sha1",
    "x_rule": "srp_default_username_in_x",
    "rfc5054_padding": false,
    "salt_encoding": "hex",
    "verifier_encoding": "hex"
  },
  "salt": "<hex, 16 字节随机盐>",
  "verifier": "<hex, g^x mod N 的字节表示>",
  "revision": 1,
  "created_at": "...", "updated_at": "...",
  "history": [{"event": "legacy registration", "at": "..."}]
}
```

绑定的四件事（见 `params.py`）：

- **组**：固定 `NG_2048`；参数集名 `srp-2048-sha{1,256}-pysrp-v1`。
- **摘要**：SHA-1（旧）/ SHA-256（目标），贯穿 `User` 与 `Verifier` 构造。
- **用户名参与规则**：pysrp 默认 `x = H(s, H(I:p))`，用户名参与 `x`。
  pysrp 的 `rfc5054_enable()` / `no_username_in_x()` 是**进程级全局开关**，
  无法在同进程里按记录切换；演示在启动时固定开关（`assert_globals_pinned`），
  并把固定值写进每条记录，拒绝任何漂移。
- **盐值格式**：16 字节随机盐，与验证器统一以 hex 存储；读写都做 hex 校验。

记录里禁止出现 `verifier_sha1`/`new_verifier` 之类双份材料字段
（`store.validate_record` 强制），保证一条记录不存在两种解释。

## 握手不重新协商

服务端 `AuthService.challenge` 先读记录，再用**记录自己的参数集**构造
`srp.Verifier`；客户端请求的参数集与记录不一致时，`assert_consistent`
直接抛 `ParameterError`，SRP 消息都不会发出。握手全程没有“先按一种解释开始、
中途换成另一种”的路径（场景 7）。

## 迁移流程

无需口令就能做的元数据工作（`migration.review` / `open_store`）：

- 加载与校验记录、盘点哪些用户仍在旧参数集；
- 崩溃恢复：清理已应用的日志、隔离未应用的日志；
- 这些步骤**不能**产生新验证器，报告里只标记 `needs_password`。

必须有口令的升级（`migration.upgrade_after_login`）：

1. 用**现有旧记录**完成一次完整 SRP 登录（SHA-1），证明口令正确；
2. 客户端用口令生成**全新随机盐**与 SHA-256 验证器（不复用旧盐、旧验证器）；
3. 升级信封用本次会话密钥 K 做 HMAC-SHA-256 认证后发给服务端；
4. 服务端校验升级路径、HMAC、材料形状，写入 `pending/` 日志（旧记录不动）；
5. 基于 `revision` 的 CAS + 原子 `os.replace` 换入新记录，再删日志。

新用户直接以目标参数集注册，不经过 SHA-1。

## 失败与中断语义

- **错误口令**：SRP 证明校验失败，记录的 salt/verifier/revision 全部不变，
  无 pending 残留，正确口令仍可登录（场景 3）。
- **并行旧登录**：两个完整 SHA-1 会话可同时成功；先提交者换入 SHA-256，
  后提交者因 `revision` CAS 失败被拒，日志清理，赢家记录不被覆盖（场景 4）。
- **切换中断**：
  - 崩溃发生在 replace 之后、删日志之前：重启恢复识别为“已应用”，只清日志；
  - 日志已 staged 但 replace 未发生：重启后移入 `quarantine/` 审计，
    **不自动提交**，旧记录原样可用；用户需重新登录再升级（场景 5）。
- 任何升级异常都不会覆盖仍可用的旧记录。

## 代码地图

- `params.py`：参数集注册表、全局开关固定、禁止重协商守卫。
- `store.py`：记录格式与校验、原子写、revision CAS、升级日志与恢复。
- `protocol.py`：客户端模拟、`AuthService` 握手、HMAC 升级信封。
- `migration.py`：区分无口令元数据工作与需要口令的升级编排。
- `demo.py` / `test_demo.py`：七个演示场景与单元测试。

## 生产化注意事项（演示之外）

- 演示用进程内对象与线程锁模拟客户端/服务端；真实部署中升级信封应走
  TLS，并用会话密钥做通道绑定，HMAC 仅演示认证意图。
- 存储是 JSON 文件；真实系统应换成带条件事务（CAS）的数据库。
- 若需要与 RFC 5054 实现互通，应新建独立参数集名并在部署层面固定全局开关，
  不能在同一进程混用两种 `x` 推导规则。
