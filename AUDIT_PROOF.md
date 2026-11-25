# 作业生命周期事件的证明边界（APScheduler 核查 / 重发 / 重复与缺失）

调查组的问题：**一项作业到底结束了没有？订阅者收到的完成通知，是真的、提前到的、还是后来丢了？**
业务结果体由业务侧单独授权，公开事件不能携带结果。本目录给出一个可运行的「事务发件箱 + 幂等收件箱 + 对账」参照实现，并用真实 APScheduler 代码路径佐证两个必须模拟的故障。

## 一键运行

```sh
.venv/bin/python audit_proof_demo.py          # 完整模拟 + 真实 APScheduler/SQLite 佐证
.venv/bin/python -m audit_proof               # 等价入口
.venv/bin/python audit_proof_demo.py --no-live # 只跑零依赖核心模拟
.venv/bin/python -m pytest tests/test_audit_proof.py -q
```

核心包 `audit_proof/` 只用标准库，系统 `python3` 也能跑 `--no-live`；live 段落需要 `.feedback/requirements.txt` 中的 `apscheduler / sqlalchemy / aiosqlite`。最近一次完整输出保存在 `AUDIT_PROOF_RUN.txt`，末尾应为 `ALL CHECKS PASSED`。

## 真实代码里的三个边界（为什么单看事件不够）

1. **执行结束**：任务函数返回/抛错，调度器构造 `JobResult` 与 `JobReleased`
   （`src/apscheduler/_schedulers/async_.py:1174` 的 `_run_job`）。
2. **结果提交**：`SQLAlchemyDataStore.release_job` 在一个事务里写 `job_results`、
   递减计数、删 job，事务退出即提交（`src/apscheduler/datastores/sqlalchemy.py:1071`，
   核心写入在 `_release_job`，同文件 `:1036`）。
3. **跨进程发布**：提交**之后**才 `await self._event_broker.publish(event)`
   （`src/apscheduler/datastores/sqlalchemy.py:1085`）。

因此存在两条不对称的失败缝（已用真实临时 SQLite 复现，见 demo 第 [9] 节）：

- **提交成功、发布失败**：`release_job` 抛出 broker 错误，但 `job_results` 有 1 行、
  `jobs` 行已删 —— 作业在事实上已结束，订阅者却可能永远收不到 `JobReleased`（**缺失**）。
- **保存回滚**：事务内写结果失败 → 回滚，`job_results` 0 行、`jobs` 行仍在，
  官方代码不会发布 `JobReleased`。但如果业务方在提交前就发布“完成”事件
  （或按自己的 publish 调用次数计数），订阅者就会持有一个**提前到达 / 无提交事实绑定的空头事件**。

结论：**订阅者收到事件 ≠ 作业已提交结束；调用方发布次数也不是事实。** 唯一事实源是已提交状态（结果行/账本），事件必须能回绑到它。

## 公开事件：低敏感、可重放、可去重、可查缺口

新增原生事件 `apscheduler.JobCompletionProof`（`src/apscheduler/_events.py`，并从 `apscheduler` 顶层导出），
可直接被股票 broker 的 `generate_notification` / `_reconstitute_event` 序列化与还原：

| 字段 | 核查作用 |
| --- | --- |
| `event_id` | 同一逻辑事件在所有重发中保持不变（由幂等键 `uuid5` 派生），用于辨别**重复** |
| `producer_id` + `sequence` | 单生产者单调序号，订阅者据此发现**缺口（缺失）** |
| `ledger_ref` / `outbox_id` | 回绑已提交的账本 fact / 发件箱行，证明“这是提交后事件” |
| `job_id` / `task_id` / `outcome` / 时间戳 | 生命周期关联：哪个作业、何种结局、何时完成/提交 |
| `result_ref` | 结果体的**不透明授权取数指针**（如 `apscheduler://job-results/<job_id>`），不含结果 |
| `result_digest` | 结果体规范 JSON 的 `sha256`，授权取数后可校验完整性/发现篡改 |

事件**不包含** `return_value`，也不包含 `JobReleased` 上可能携带的
`exception_message` / `exception_traceback`（异常文本也可能含敏感信息）。
测试 `test_public_event_json_roundtrip_and_no_result_body` 与 live 段断言密钥串不出现在任何公开帧中。

> 注意：股票 `JobReleased` 在出错时会带 `exception_type/message/traceback`。
> 对“公开、跨租户/跨进程”的审计总线，应只发 `JobCompletionProof` 这类脱敏事件，
> 详情留在授权侧。

## 推荐机制：事务发件箱 + 幂等收件箱 + 对账

- `audit_proof/unit_of_work.py`：`AuditUnitOfWork` 把**完成 fact 与 outbox 行放在同一事务**，
  干净退出才原子应用，异常即整体丢弃（模拟提交/回滚）。`CommittedState` 是唯一事实源。
- `audit_proof/delivery.py`：
  - `ControllableBroker` 可注入“接下来几次发布失败 / 下一次扇出两份”；
  - `OutboxRelay.publish_pending()` 发布未确认的 outbox 行，失败保留 `pending + attempts + last_error`，可无限重发同一 `event_id`；
  - `Inbox` 记录每次原始投递、按 `event_id` 判 `accepted/duplicate`、按 `(producer_id, seq)` 算缺口；
  - `VerifyingConsumer` 在去重之外再校验事件是否匹配已提交 fact：匹配才产生一次业务副作用，否则隔离（quarantine）。**去重不能替代提交绑定**——提前事件第一次到达时并不重复。
- `audit_proof/reconcile.py`：`Reconciler` 连接「已提交 fact × outbox × 收件箱」，逐作业给出判定。

判定码（`Verdict`）与调查组结论：

| Verdict | 已提交? | 订阅者 | 含义 / 处置 |
| --- | --- | --- | --- |
| `verified_ended` | 是 | 收到且唯一受理 | **确已结束**，事件与事实一致；重复份数另计，副作用仅一次 |
| `ended_event_missing_publish_failed` | 是 | 0 | **结束了但事件缺失**：保存已提交、发布失败；查 outbox `pending/last_error`，重发即可 |
| `ended_event_lost_after_publish` | 是 | 0，但 outbox=`published` | broker 已接受、订阅者那段**后来丢了**；从 outbox 用同一 `event_id` 重放 |
| `ended_event_missing` | 是 | 0 | 已结束但无公开事件/无 outbox 状态，按缺失核查 |
| `phantom_early_event` | 否 | 有 | **提前到达或回滚后的空头事件**；若状态库有对应回滚记录会标 `ROLLBACK_CONFIRMED`；不得据此结案，消费者应隔离 |
| `rolled_back_silent` | 否 | 无 | 保存已回滚且无完成事件——正确表现 |
| 缺口 `GapAudit` | — | 缺某个 `seq` | 序号缺口可经 `(producer, seq) → outbox` 精确定位到缺失的是哪个 job/event、是否已提交 |

**重复 vs 缺失怎么辨**：重复 = 同一 `event_id` 有多条原始投递（`duplicate_copies>0`），
但只受理一次；缺失 = 已提交 fact 存在而收件箱没有匹配 `event_id`，或序号出现空洞。
两者由不同字段表达，不会再出现“重复事件被算成两个完成”或“没收到就误以为作业没结束”。

## 两个规定动作的模拟结果

`run_simulation()`（`audit_proof/scenarios.py`）内置 13 条断言，全部通过；摘要：

- **A 保存成功后发布失败 + 重发**：提交后 broker 第一次发布报错 → 判定
  `ended_event_missing_publish_failed`；relay 重发时该次投递扇出两份 → 收件箱
  `copies=2 / duplicate=1`，业务副作用 1 次，最终 `verified_ended`。
- **B 保存回滚**：
  - B1 正确发件箱顺序：`rolled_back_silent`（无 fact/outbox/事件）；
  - B2 先发布后回滚：订阅者持有 1 条 `JobReleased`，账本无 fact 且有回滚记录 →
    `phantom_early_event` + `ROLLBACK_CONFIRMED`，事件被 `VerifyingConsumer` 隔离、零副作用。
- **附加 L（发布后丢失）与 C（序号缺口）**：区分“发布失败”和“发布后在订阅段丢失”；
  三个连续序号只收到 1、3 时，缺口 `seq=2` 被 outbox 定位到 `job-G2...`，补齐同 id 重发后缺口消失。

## 与真实仓库的集成点 / 上生产还需什么

- 本交付**没有改动 `release_job` 的既有提交-发布顺序**（避免影响现有数据存储与测试），
  而是用参照 UoW/outbox 演示目标形态，并在 `audit_proof/live.py` 中直接驱动真实
  `SQLAlchemyDataStore.release_job` 复现失败缝。落地时可：
  - 在 `_release_job(conn, ...)` 同一连接/事务内额外 insert 一行 outbox，提交后由 relay
    调 `event_broker.publish`（或将 `JobCompletionProof` 写入 outbox 表）；
  - 持久化 `Inbox`/已处理 `event_id`（唯一约束）与 relay 游标，保证进程重启后仍能去重/续发；
  - 多调度器时用 `(producer_id, sequence)` 或数据库全局序列，避免单序号假设；
  - result 取数接口做业务鉴权与过期清理，`result_ref` 仅作指针，`result_digest` 用于校验；
  - 对“提前事件”采用延迟绑定复核（消费时查 fact，查不到则 nack/重试/隔离），以容忍读副本延迟。

## 文件导航

- `src/apscheduler/_events.py`：新增原生 `JobCompletionProof`
- `audit_proof/model.py`：脱敏公开事件、稳定 event_id、结果摘要
- `audit_proof/unit_of_work.py`：账本 fact + 事务 outbox、提交/回滚
- `audit_proof/delivery.py`：故障 broker、幂等 inbox、绑定校验 consumer、relay
- `audit_proof/reconcile.py`：三源对账与判定码
- `audit_proof/scenarios.py` / `report.py` / `simulation.py`：场景、文本报告、CLI
- `audit_proof/aps_bridge.py` / `live.py`：原生事件双向转换、股票 broker 事件重构还原、真实调度器/DB 佐证
- `tests/test_audit_proof.py`：18 条测试
