# Flower 取消任务「先取消后成功」对账方案

适用对象：值班 / SRE、Flower 与 Celery 维护者。
配套代码（无 broker、可复跑）：`experiments/cancel_reconciliation/`。

## 1. 问题与三个必须分开的问题

「我点了取消，后来又看到成功」实际上混淆了三个独立事实，它们由三条独立的
证据通道产生，各自的证据边界不同，不能互相替代：

| 事实 | 含义 | 证据通道 | 能证明什么 | 不能证明什么 |
|------|------|----------|------------|--------------|
| F1 本地接受取消 | Flower 进程受理了 revoke 请求并发出了控制命令 | API 通道：`POST /api/task/revoke/<id>` 的 HTTP 回复 | 请求被本地接受、命令已投递到控制总线 | worker 是否收到、任务是否真的停下 |
| F2 远端处理了控制命令 | 某个 worker 执行了 `revoke` 控制命令 | 控制通道：worker 对控制命令的 reply | 至少一个 worker 把该 id 记入其内存 revoked 集合（`terminate` 时还会发信号） | 任务的最终状态；命令到达时任务是否还活着 |
| F3 任务自身的最终状态 | 某次具体执行以什么终态结束 | 事件通道：worker 发出的 `task-*` 事件，经 `EventsState` 合并 | 这次执行发出过 `task-revoked` / `task-succeeded` 等终态事件 | 单凭一个 id 无法区分是哪一次执行（重试/晚到结果共用 id） |

核心原则：**任何单通道的「成功」都不足以回答「这次执行有没有被中断」。**
- `TaskRevoke` 当前用 `control.revoke(...)` 且**没有** `reply=True`
  （`flower/api/control.py:449`），随后无条件 `self.write({"message": ...})`
  返回 200（`flower/api/control.py:452`）。因此这个 200 只覆盖 F1。
- worker 侧 `revoke` 处理函数确实会 `return ok(...)`
  （`celery/worker/control.py:142` 起），但因为请求端没要 reply，这个回执
  不会回到 Flower；要拿到 F2 必须显式 `reply=True` 并落库。
- F3 是异步事件，存在延迟、乱序、重复，且重试复用同一 task id。

## 2. 为什么「回复成功」不能独立证明当次执行已中断

两条机制性原因，均由配套实验直接验证：

1. **API 200 与 worker 处理是解耦的。** `control.revoke` 默认 `reply=False`
   （`celery/app/control.py:488` 的 `revoke` → `broadcast(...)`），调用在
   命令写入控制总线后即返回，HTTP 200 不等待任何 worker。
2. **同一 task id 不等于同一次执行，且终态会被后到事件覆盖。**
   - Celery 重试复用同一 uuid；上一次执行的晚到结果也带同一 id。
   - `EventsState` 走 Celery `Task.event` 的 precedence 规则：
     `SUCCESS(0) < FAILURE(1) < REVOKED(3) < ...`，数值越小优先级越高。
     一旦某 id 已合并 `task-succeeded`，后到的 `task-revoked` 无法把显示态
     改回 REVOKED；而晚到的 `task-succeeded` 却能把 REVOKED 翻成 SUCCESS。
   - 但即便状态被翻成 SUCCESS，`revoked` 时间戳字段仍保留在 state 中
     （见实验 `test_late_duplicate_success_does_not_erase_revoked_timestamp`）。
   - 结论：**界面上的单个 `state` 不是权威结论；时间戳与到达顺序才是证据。**

因此，重试或同 id 晚到结果场景下，「revoke 回复成功」只能证明 F1（最多到
F2），对「当次执行被中断」既不充分也不必要。

## 3. 对账模型（不改现有 API/回复/事件语义）

约束：保留现有 HTTP API、控制回复、事件状态各自的证据范围，不修改它们的
返回含义；在其之上叠加一张**只追加（append-only）的对账台账**，把三条通道
的原始观察分别记录，再用纯函数做对账。

### 3.1 台账记录（每条只写一次，不可变）

每条记录至少包含：

- `task_id`：任务 id（注意不是执行的唯一键）
- `attempt_no`：执行序号，用于区分重试/晚到结果（见 §5 的额外记录）
- `channel`：`api` / `control` / `event`，三通道物理隔离
- `kind`：`revoke-http`、`revoke-reply`、`task-received`、`task-revoked`、
  `task-succeeded` ...
- `observed_at`：Flower 本地单调时钟的接收时刻
- `clock`：事件自带的逻辑时钟（celery `clock`），HTTP/控制回复没有则为空
- `payload`：原始字段（HTTP 状态码、worker 名、`terminated/signum/expired`、
  result 等），原样保留
- `duplicate` / 投递幂等 id：用于识别重复投递（依赖传输层支持）

### 3.2 对账判定（纯函数，可重跑）

按「执行（task_id + attempt_no）」聚合，再汇总到 id 级，输出六类结论：

| 结论 | 触发条件 | 值班可据此采取的动作 |
|------|----------|----------------------|
| `INTERRUPTED` | 某执行只观察到 `task-revoked` 终态 | 中断有事件证据（仅 F3） |
| `SUCCEEDED` | 只观察到 success 类终态 | 任务跑完 |
| `CONFLICTED` | **不同执行**分别出现 revoked 与 succeeded（重试/晚到同 id） | 不能给单一答案，按 attempt 分别陈述 |
| `AMBIGUOUS_TERMINAL` | **同一执行**收到两个不同终态（乱序/重复） | 显示态不可信，需 worker 权威终态+投递id 仲裁 |
| `CANCEL_REQUESTED_ONLY` | 只有 F1/F2，没有任何终态事件 | 「已受理/已下令」，任务命运未知 |
| `NO_EVIDENCE` | 该 id 无任何观察 | 先补采集 |

判定优先级（见 `model.py` 的 `_verdict`）：
1. 同一执行出现多种终态 → `AMBIGUOUS_TERMINAL`（最高优先，避免被显示态误导）；
2. 不同执行终态不同 → `CONFLICTED`；
3. 仅 revoked → `INTERRUPTED`；仅 success/其它终态 → `SUCCEEDED`；
4. 无终态但有受理/回执 → `CANCEL_REQUESTED_ONLY`；否则 `NO_EVIDENCE`。

### 3.3 不可判定窗口（必须显式标出，而不是隐式吞掉）

- **受理到终态之间**：从首个 `revoke-http`/`revoke-reply` 到首个终态事件的
  时间段，取消已被确认但任务命运尚不可证。
- **全程无终态**：整个观察窗口都不可判定（典型：worker 挂了、事件未开、
  任务卡在执行中）。
- 实验运行器会为每个场景打印这些窗口（`undecidable_windows`）。

## 4. 四个可复跑实验与各观察点结论

运行（仓库根目录，无需 broker / 不绑端口）：

```bash
python -m experiments.cancel_reconciliation.run_experiments
python -m pytest experiments/cancel_reconciliation/test_reconciliation.py -q
```

四个场景（`scenarios.py`）与其观察点、可支持结论、不可判定窗口：

### 场景 A：控制回复缺失，但收到取消状态
- 序列：`task-received` → API revoke 200（reply=False，控制回执丢弃）→
  `task-revoked`。
- 可支持：F1 成立（API）；F3 显示该执行 REVOKED → `INTERRUPTED`。
- 无法判定：F2 无任何证据（worker 是否处理过命令不可知，可能是 expires
  过期等其它原因导致的 revoked）；受理到终态窗口内不可证中断。
- 额外记录：`reply=True` 的控制回执；`task-revoked` 的
  `terminated/expired/signum` 字段以区分「被命令撤销」与「过期」。

### 场景 B：回复先到，另一尝试成功（同一 id 重试）
- 序列：执行0 `task-revoked(terminated=True)` → API 200 → `task-retried` →
  执行1 `task-succeeded`（同一 task_id）。
- 可支持：执行0 被中断、执行1 成功；id 级判定 `CONFLICTED`。
- 无法判定：若只看 id 的当前 `state`，会显示 SUCCESS，误以为「取消没生效」；
  缺少 `attempt_no` 时无法把成功归到第二次执行。
- 额外记录：每个事件与 backend 结果上的执行关联 id（见 §5）。

### 场景 C：成功事件先到、撤销事件后到（次序之一）
- 序列：received → started → API 200 → `task-succeeded` →
  `task-revoked(terminated=True)`。
- 可支持：同一执行出现两个终态 → `AMBIGUOUS_TERMINAL`；由于 precedence，
  界面显示 SUCCESS，且 `revoked` 时间戳仍在。
- 无法判定：因果先后（任务到底是先完成还是先被信号终止），事件到达顺序
  不等于发生顺序；不能凭显示 SUCCESS 断言取消无效。
- 额外记录：worker 权威终态、信号是否实际送达（`terminated` 与 worker pid 级
  记录）、事件/结果投递 id。

### 场景 D：撤销事件先到、成功事件后到（C 的次序互换）
- 序列：received → started → API 200 → `task-revoked` →
  晚到重复 `task-succeeded`。
- 可支持：同样 `AMBIGUOUS_TERMINAL`；晚到 success 把显示态翻成 SUCCESS，但
  `revoked` 时间戳保留。
- 无法判定：与 C 对称——单看 state 会得出相反直觉；重复投递是否被识别
  取决于传输层幂等 id。
- 额外记录：投递/去重 id，使对账能把晚到 success 标记为 duplicate 而非新终态。

> C 与 D 一起证明：**在当前 precedence 规则下，只要 success 被合并，显示态
> 最终都是 SUCCESS，与因果顺序无关**；因此必须用台账+时间戳，而不是 state。

## 5. 需要补齐的额外记录（落地清单）

不新增这些，§3.2 中的 CONFLICTED / AMBIGUOUS 永远无法收敛：

1. **执行级关联 id（最关键）**：在任务消息 header 与每个 `task-*` 事件、
   result backend 条目上携带 `attempt_no`（可基于 celery request 的
   `retries`/root_id 派生），让「同 id 的多次执行」可区分。
2. **控制命令回执落库**：对关键取消走 `control.revoke(..., reply=True,
   timeout=...)`，把 worker 回执（含 worker 名、ok、terminate 结果）写入台账
   的 control 通道；现有无 reply 的 200 行为保留不变，新增一条旁路记录即可。
3. **revoked 原因字段**：保留 `task-revoked` 的 `terminated / expired /
   signum`，区分「控制命令撤销」「过期撤销」「信号终止」。
4. **投递/去重 id**：事件与结果的 delivery id，识别晚到重复，支撑
   `duplicate` 标记。
5. **本地接收时刻与逻辑时钟并存**：`observed_at`（本地单调钟）用于到达顺序，
   `clock`/`timestamp` 用于因果参考；二者都要落，不能只存一个。
6. **终态缺口监控**：对「超过阈值仍停在 `CANCEL_REQUESTED_ONLY`」的 id 告警，
   覆盖 worker 宕机 / 事件未开启 / 任务卡死导致的全程无终态。

## 6. 在 Flower 中的接入点（最小侵入）

- `flower/api/control.py:449`（`TaskRevoke.post`）：保持现有 200 回复不变，
  在 `run_blocking` 前后各追加一条 api 通道台账记录（受理时刻、参数、状态）。
- 可选新增「带回执」的取消旁路（独立端点或 query 开关），用
  `reply=True` 收集 F2 并写入 control 通道，不影响默认行为与既有 API 契约。
- `flower/events.py:136`（`EventsState.event`）：在调用 `super().event(event)`
  处旁路复制一条不可变 event 记录进台账（含 `local_received`、`clock`、
  `terminated/expired`），不改变现有 state 合并与 `/api/task/info` 返回。
- 对账器为纯函数模块（本实验 `model.py` 即原型），可作为离线/定时作业对
  台账重跑，输出 id 级结论与不可判定窗口，供值班排查与告警消费。

## 7. 证据边界速查（贴给值班）

- 看到 API 200「Revoked」→ 只代表 **F1 本地受理**，不代表已中断。
- 看到 worker 控制回执 ok → 代表 **F2 命令被处理**，仍不代表终态。
- 看到 `task-revoked` → 代表该**执行**发出过撤销终态（F3），注意区分
  `terminated` 与 `expired`。
- 看到 state=SUCCESS 但同时有 `revoked` 时间戳 → 大概率是重试/晚到结果或
  乱序，按 `CONFLICTED`/`AMBIGUOUS_TERMINAL` 处理，不要直接判「取消失败」。
- 任何时候 id 级结论与执行级结论冲突，以执行级（带 attempt_no）为准。
