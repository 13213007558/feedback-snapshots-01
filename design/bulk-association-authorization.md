# 批量调整关联的授权设计（评审稿）

## 1. 背景与问题

管理端需要"批量调整关联"（例如把一批 Article 一次性挂到某个 Category 下）。
列表页已经用 `accessible_by` 限定了可见范围，但这只解决了"看得到什么"，
没有解决"能不能整批提交"：

- 列表作用域是**查询时刻的快照**，提交时刻记录状态可能已经变化（属主变更、
  目标关联被归档等 TOCTOU 场景）；
- 对列表里**一条**记录单独 `authorize!` 成功，不能推出**整批**在提交时都能通过；
- 批量操作一旦部分成功部分失败，管理端没有方便的补偿手段，必须整批原子化。

因此需要明确：现有授权入口各自适合承担什么，以及批量提交的证据标准。

## 2. 现有授权入口的职责划分

| 入口 | 语义 | 在批量流程中的定位 |
| --- | --- | --- |
| `Model.accessible_by(ability, action)` | 把规则中**可下推 SQL 的条件**（hash 条件）翻译成作用域 | **准备期**的候选集裁剪与列表展示。是快照，不是提交证据。block 规则无法下推 SQL，依赖它的授权在作用域层面会失真 |
| `ability.can?(action, record)` | 对内存中的单条记录做规则匹配 | **准备期**的预检（dry-run），用于提前拒绝明显不可行的批次、减少无谓事务。检查的是当时加载的对象状态 |
| `ability.authorize!(action, record)` | 同 `can?`，失败时抛 `CanCan::AccessDenied` | **应用期**唯一的提交证据。必须在事务内、对**刷新后**的记录逐条调用 |
| `authorize! action, ModelClass`（类级） | 不评估 hash 条件与 block，只问"这类操作是否被允许发起" | 控制器入口的粗粒度闸门：是否允许该角色发起此类批量操作，同时满足 `check_authorization` 的要求 |
| `load_and_authorize_resource` / `authorize_resource` | 面向单资源 REST 动作的加载+授权 | **不适合**批量端点。批量端点应对该动作 `skip_authorize_resource`，改走显式服务对象 |

要点：**作用域筛选（`accessible_by`/`can?` 预检）与提交证据（事务内 `authorize!`）是两回事。**
前者回答"这批大概率行不行"，后者回答"此刻这一条到底行不行"。只有通过后者的记录才允许落库。

## 3. 两阶段协议

### 3.1 准备期（事务外，可重复、无副作用）

1. 用 `accessible_by(ability, :update)`（或对应动作别名）得到候选作用域，供列表展示与数量预估；
2. 对勾选的记录逐条 `can?` 预检，把明显不可行的批次提前拒掉；
3. 返回给前端的只有**数量**（候选数 / 预计执行数），不返回被剔除记录的 id 清单（见第 5 节）。

准备期的任何结果都允许过期，不作任何持久化决策。

### 3.2 应用期（单个数据库事务）

    Model.transaction do
      Model.where(id: submitted_ids).order(:id).find_each do |record|
        record.reload                       # 或 record.lock!，取提交时刻的新鲜状态
        ability.authorize!(action, record)  # 提交时证据：对新鲜状态重新判定
        apply_change(record)                # 调整关联
      end
    end

- 按固定顺序（主键序）逐条处理，避免并发批量任务之间死锁；
- 每条记录先 `reload`（需要强一致时升级为 `lock!` 悲观锁）再 `authorize!`——
  **陈旧对象上的 `can?` 通过不算证据**；
- 任何一条 `authorize!` 抛出 `CanCan::AccessDenied`，事务整体回滚。

## 4. 全批回滚约定

- **原子性**：整批包裹在一个事务里，不存在"部分提交"。对外语义只有两种：
  全部成功（返回成功条数）或全部未执行（返回失败）。
- **失败后的计数**：对外 `applied_count` 恒为 0——回滚后没有任何记录被修改，
  不得报告"成功了 N 条后失败"。
- **关联状态在操作中变化**：以应用期 `reload` 之后的状态为准。准备期通过、
  应用期失败是**正常路径**而非异常，按整批拒绝处理，客户端可重新拉取列表后重试。
- **幂等重试**：由于要么全做要么全没做，客户端用同一批 id 重试是安全的；
  已满足目标状态的记录应在 `apply_change` 中视为成功（no-op），避免重试被自己的上次成果拒绝。

## 5. 较少披露的错误约定

批量端点比单条端点更容易变成枚举/探测工具，错误信息按下述约定收敛：

- **对外（HTTP 响应）**：统一 `403` + 通用文案
  「批次中包含当前不可操作的记录，整批未执行」。只给数量，不给记录 id；
  「记录不存在」与「存在但无权限」不做区分，统一按不可见处理；
  不得把 `CanCan::AccessDenied#subject` 直接渲染进响应。
- **对内（服务端日志/审计）**：记录批次 id、操作者、动作、被拒记录的 id 与
  `AccessDenied` 的 `action`/`subject`，供安全审计与排障。
- **准备期同样收敛**：预检结果只回数量；前端列表本来就被 `accessible_by`
  限定，批量接口不应成为绕过该限定的旁路。

## 6. 验证

`design/bulk_association_verification_spec.rb` 用内存 SQLite 和两个 Article
对象验证了上述判断：

1. **准备期**：`accessible_by` 作用域是快照，状态变化后同一查询结果随之改变，
   证明它只能做筛选、不能当提交证据；
2. **应用期**：两条记录均在事务内 `reload` + `authorize!` 通过后落库，
   且演示了陈旧内存对象会误判（必须先刷新再授权）；
3. **异常回滚**：第一条记录更新触发的并发变更使第二条在提交时失去授权，
   `authorize!` 抛 `AccessDenied`，整批回滚——第一条的修改也被撤销，
   对外错误不含记录 id。

运行方式：

    sh .feedback/ruby-env.sh rspec -r active_record -Ispec design/bulk_association_verification_spec.rb

## 7. 落地清单（评审用）

- [ ] 批量端点控制器：类级 `authorize! :bulk_adjust, Model` 作为入口闸门；
  对该动作 `skip_authorize_resource`，保留 `check_authorization`。
- [ ] 服务对象实现第 3 节两阶段协议，事务内 `reload`/`lock!` + 逐条 `authorize!`。
- [ ] 统一异常处理：`CanCan::AccessDenied` → 第 5 节的对外文案 + 对内审计日志。
- [ ] 前端：准备期只展示数量；失败后刷新列表再允许重试。
- [ ] 规则审计：批量动作依赖的授权规则尽量用 hash 条件表达；
  必须用 block 的规则要意识到 `accessible_by` 无法下推，准备期筛选会偏宽，
  更依赖应用期的逐条证据兜底。
