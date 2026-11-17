# 受限的安全邮件迁移接入方案

只迁移**事先获准的固定源/目标邮箱中的固定 UID**。这不是通用邮件管理系统：不枚举、
不发现、不删除任何未获准的新邮件。所有判断只依赖服务器签发的身份证据
（UID / UIDVALIDITY / COPYUID），不接受“目标里有一封正文相似的邮件”这类推断。

## 1. 基于 aioimaplib 现有能力的映射

| 需要的动作 | aioimaplib 调用 | 说明 |
| --- | --- | --- |
| 能力探测 | `IMAP4.has_capability("MOVE"/"UIDPLUS")`，底层 `protocol.capabilities` | 每次连接、SELECT 后读取 |
| 固定邮箱身份 | `select()` 响应行解析 `UIDVALIDITY` | 作业启动时钉住，每次重连复核 |
| 源邮件取证 | `uid("fetch", uid, "(UID INTERNALDATE RFC822.SIZE BODY.PEEK[])")` | 任何写操作之前先取指纹 |
| 原子移动 | `uid("move", uid, mailbox)`（无 MOVE 时库直接 `Abort`） | RFC 6851 |
| 复制 | `uid("copy", uid, mailbox)` | 成功响应携带 `OK [COPYUID ...]` |
| 单 UID 删除 | `uid("store", uid, "+FLAGS", "(\\Deleted)")` 后 `uid("expunge", uid)` | 库在无 UIDPLUS 时拒绝 `UID EXPUNGE` |
| 有界重查 | `uid_search("HEADER", "MESSAGE-ID", mid)` | 仅用于断线后定位，命中后仍要全指纹核验 |
| 断线感知 | 构造 `IMAP4(..., conn_lost_cb=...)` + 命令 `timeout` | 见下节 |

### 断线语义（关键事实）

`aioimaplib` 的 `connection_lost` **只调用 `conn_lost_cb`，不会让挂起命令失败**；
该命令最终由 `timeout` 触发 `CommandTimeout`。因此“连接断开”在本方案里一律归为
**结果未知**，而不是成功或失败。适配层 `AioimaplibGateway` 把 `CommandTimeout`、
`asyncio.TimeoutError`、transport 已关闭的 `Abort` 统一归一化为 `ImapTimeout` /
`ImapDisconnected`，把明确的 `NO/BAD` 归一化为 `ImapRefused`。

## 2. 两类服务端的分支比较

作业固定：源 `src.example:INBOX`（UIDVALIDITY 9001）、目标
`dst.example:Archive/Migrated`（UIDVALIDITY 9002）、获准 UID 集合（示例为 7）。

### A. 支持 MOVE（通常同时有 UIDPLUS）

1. 先 `UID FETCH` 取源指纹（Message-ID、RFC822.SIZE、正文 SHA-256、INTERNALDATE）。
2. 发 `UID MOVE`。
   - 收到 `OK [COPYUID 9002 7 437]`：解析出单 UID 映射，再 SELECT 目标 FETCH 437，
     指纹一致才置 `CONFIRMED`。
   - 收到 `NO/BAD`：置 `FAILED`（确定失败，可安全重试或人工排查，源邮件未动）。
   - 断线/超时：置 `MOVE_SENT_UNKNOWN`，**禁止**立刻改走 COPY+EXPUNGE。

### B. 缺少 MOVE

1. 同样先取源指纹。
2. `UID COPY`：
   - `NO/BAD` → `FAILED`，源邮件未动。
   - `OK [COPYUID]` 且能解析出单 UID 映射 → 记录 target UID，FETCH 目标核验指纹。
   - `OK` 但无可用 COPYUID → `REVIEW`，**不删除源**。
3. 目标核验通过后 `UID STORE +FLAGS (\Deleted)`。
4. 删除源：
   - 有 UIDPLUS：只发 `UID EXPUNGE 7`（单 UID 作用域），**永不发裸 `EXPUNGE`**，
     因此不会波及同邮箱内未获准的新邮件。
   - 无 UIDPLUS：库会拒绝 `UID EXPUNGE`，本方案也不退回全邮箱 EXPUNGE；保留
     `\Deleted` 标记并置 `REVIEW (no-uidplus-expunge)`，交人工用 UID 作用域手段处理。

## 3. 三种结果与重查所需证据

| 结果 | 进入条件 | 重查/终态所需证据 |
| --- | --- | --- |
| 已确认移动 `CONFIRMED` | COPYUID 单 UID 映射 + 目标 UID FETCH 指纹一致；或重查满足下述组合 | 源 UID FETCH 不存在 **且** 目标侧证据成立（COPYUID 命名 UID，或唯一 Message-ID 命中且全指纹一致） |
| 确定失败 `FAILED` | 写命令收到明确 `NO/BAD` | 无需重查即终态；源邮件保证未被删除 |
| 结果未知 `MOVE_SENT_UNKNOWN` / `COPY_OK_DELETE_UNKNOWN` | 写命令发出后断线/超时，无标签响应 | 必须重连后用下表证据分类，分类不了保持 `REVIEW` |

`MOVE_SENT_UNKNOWN` 重查（新连接、先复核两端 UIDVALIDITY）：

- 源 UID 不存在 + 目标存在且指纹一致 → `CONFIRMED`。
- 源 UID 仍存在 + 目标无该 Message-ID → 证明 MOVE 未生效，按全新尝试重跑。
- 其余组合（两边都有、两边都无、搜索多命中、指纹不符）→ `REVIEW`，不猜。

`COPY_OK_DELETE_UNKNOWN` 重查：

- 源已不存在 + 目标核验通过 → `CONFIRMED`。
- 源仍存在 + 目标核验通过 → 仅重试单 UID 的 STORE/UID EXPUNGE，不重新 COPY。
- 目标核验失败 → `REVIEW`。

**反伪造规则**：目标侧即使存在正文/主题高度相似的邮件，只要 Message-ID 或
SHA-256/SIZE 对不上，就不算成功（见测试
`test_lookalike_message_is_not_accepted_as_success`）。

## 4. 后端最小进度（每个获准 UID 一条 JSON 记录）

原子写（临时文件 + `os.replace`），每次状态跃迁先落盘再发下一条命令：

- 固定锚点：源/目标的 `host`、`mailbox`、`uidvalidity`。
- `source_uid`、`status`（六态枚举）、`attempts`。
- `fingerprint`：迁移前源指纹。
- `copyuid` / `target_uid`：服务器签发的映射证据。
- `last_command`、`last_error`、`review_reason`、`log[]`（审计轨迹）。

终态 `CONFIRMED / FAILED / REVIEW` 不可被自动改写。

## 5. 人工处置门槛（出现即停，转人工）

- 任一邮箱 `UIDVALIDITY` 与作业锚点不符（UID 身份可能已失效）。
- `OK` 但缺少单 UID COPYUID，或目标 UID FETCH 指纹核验失败。
- MOVE/COPY 结果重查后仍无法二选一（两边都在/都不在、搜索多命中、指纹不符）。
- 无 UIDPLUS 时需要删除源（只允许人工做 UID 作用域删除，禁止全邮箱 EXPUNGE）。
- `STORE` / `UID EXPUNGE` 被明确拒绝，或重查次数耗尽（默认 3 次）。

## 6. 合成命令转录

`python -m safe_migration.demo` 用 `ScriptedGateway` 在无 socket 情况下产出四段转录：

1. MOVE 发出后服务器执行但断线丢响应 → 重查后凭证据 `CONFIRMED`。
2. COPY 成功（COPYUID）但 UID EXPUNGE 确认丢失 → 重查后单 UID 重试 `CONFIRMED`。
3. MOVE 收到 `NO [TRYCREATE]` → 确定 `FAILED`。
4. 无 MOVE/UIDPLUS → COPY 成功但源删除转 `REVIEW`，全程无裸 EXPUNGE。

## 7. 测试

`python -m pytest tests/safe_migration -q`（19 项，不绑定端口）。仓库原有的
基于本地 IMAP 测试服务器的用例需要 TCP 端口绑定，在禁止本地绑定的沙箱里会因
`Operation not permitted` 失败，与本包改动无关。
