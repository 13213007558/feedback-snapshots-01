# CanCanCan 权限规则对照记录（合规）

本记录用于解释“同一动作下可核对的生效依据”，并说明为什么范围（scope）比上周少了几条规则。

- 动作（action）：`:read`
- 主体（subject）：`Article`
- 判定入口：纯 Ruby `Ability#can?`（实例判定）与 `Article.accessible_by(ability, :read)`（SQL 范围）
- 复现脚本：`compliance/ability_audit.rb`（可重跑、自带断言，失败时进程退出码非零）
- 原始输出：`compliance/audit_output.txt`

## 1. 数据边界（哪些内容不进入工单）

本记录与脚本输出刻意只保留可核对的结构性信息：

| 允许出现 | 明确排除 |
| --- | --- |
| 动作、主体类名 | 业务条件的具体取值（值一律不打印） |
| 规则来源模块、声明顺序 token（R1..R5） | 对象/行的内容 |
| 条件的“形状”（catch-all 还是 hash）与字段名 | 行内数据、ID、名称等 |
| 纯 Ruby 的允许/拒绝布尔值（针对占位主体 A/B/C） | 真实用户、真实业务对象 |
| 汇总计数、脱敏后的 SQL 形状（字面量替换为 `?`） | 未脱敏 SQL、绑定参数值 |

字段名仅用于核对规则结构；条件值在脚本里仅用于构造内存数据，从不输出。

## 2. 规则来源与声明顺序（同一动作 `:read`）

多个能力模块向同一个动作注册规则，按声明顺序登记：

| 声明 token | 来源模块 | 动词 | 动作 | 主体 | 条件形状 | 条件字段（仅字段名） |
| --- | --- | --- | --- | --- | --- | --- |
| R1 | WorkflowAbility | can | read | Article | hash conditions | published |
| R2 | OwnershipAbility | can | read | Article | hash conditions | category_id |
| R3 | RestrictionAbility | cannot | read | Article | hash conditions | secret |
| R4 | BaselineAbility | can | read | Article | catch_all（无条件） | — |
| R5 | HoldAbility | cannot | read | Article | hash conditions | flagged |

声明规则总数：`5`（压缩开启与关闭两次运行完全相同）。

## 3. 实际判定顺序（库内部如何取舍）

`can?` 不是按声明顺序，而是按库内部重排后的“相关规则”顺序，采用**首个命中即定（first-match wins）**：

```
R5:cannot -> R4:can -> R3:cannot -> R2:can -> R1:can
```

依据（库源码）：

- `CanCan::Ability::Rules#relevant_rules`：取相关规则后 `reverse!`，再经 `optimize_order!` 把 `:all` 主体规则前置。
- `CanCan::Ability#matching_rule`：对重排后的规则用 `detect` 取第一条同时满足条件与属性的规则，其 `base_behavior` 决定允许/拒绝。

结论性观察（仅结构，不含值）：

- R5（cannot）排在最前，是真正会生效的“显式拒绝”。
- R4 是无条件 `can`（catch-all），其后的 R3/R2/R1 对实例判定被 R4 抢先，R3 因此**从不决定结果**。

## 4. 显式拒绝改变结果的例子（纯 Ruby 判定）

对三个占位主体只输出布尔值，绝不输出其内容。再用一个“去掉 R5 的对照能力”重复判定，证明结果翻转仅由显式拒绝引起：

| 占位主体 | 含 R5 的判定 | 去掉 R5 的对照判定 | 是否被显式拒绝改变 |
| --- | --- | --- | --- |
| A | true | true | false |
| B | true | true | false |
| C | false | true | **true** |

即：主体 C 在没有 R5 时本应允许（R4 catch-all 放行），加入 R5 显式 `cannot` 后被拒绝。这是“因显式拒绝改变结果”的可核对例子。

## 5. 纯 Ruby 判定 vs 真实范围查询

脚本在内存 SQLite（ActiveRecord 7.2，`sqlite3` 适配）中持久化三行占位数据，分别走两条路径并断言集合相等：

| 指标 | 压缩开启 | 压缩关闭 |
| --- | --- | --- |
| 纯 Ruby 允许集合 | [A, B] | [A, B] |
| 纯 Ruby 显式拒绝集合 | [C] | [C] |
| 范围返回行数 | 2 | 2 |
| 范围允许集合 | [A, B] | [A, B] |
| SQL 集合 == Ruby 允许集合 | true | true |

脱敏后的 SQL 形状（两种设置下完全一致，字面量已替换为 `?`）：

```
SELECT "articles".* FROM "articles" WHERE (("articles"."flagged" = ?) IS NOT TRUE)
```

含义（结构层面）：范围只保留“未命中 R5 拒绝字段”的行；R4 catch-all 使其余条件不再出现在 WHERE 中。

## 6. 压缩开启 vs 关闭的证据

压缩器在构造 ActiveRecord 适配器时被调用（`CanCan::ModelAdapters::ActiveRecordAdapter#initialize` → `CanCan::RulesCompressor`）。开关：`CanCan.rules_compressor_enabled`，可全局设置或用 `CanCan.with_rules_compressor_enabled(false) { ... }` 局部切换。

| 证据项 | 压缩开启（默认） | 压缩关闭 |
| --- | --- | --- |
| 适配器看到的相关规则数 | 5 | 5 |
| 实际交给范围查询的规则数 | **2** | **5** |
| 交给查询的规则 token | R5 -> R4 | R5 -> R4 -> R3 -> R2 -> R1 |
| 纯 Ruby 判定结果 | A、B 允许；C 拒绝 | 完全相同 |
| 范围行数 / 脱敏 SQL | 2 / 同上 | 2 / 同上 |

压缩规则（`CanCan::RulesCompressor`，并见 `docs/rules_compression.md`）：

1. `simplify`：去除 (subject, conditions) 完全重复的规则（从后往前保留最新）。
2. 遇到 catch-all 规则时，淘汰它之前的所有规则，以及其后与之同类型（同为 can 或同为 cannot）的规则。
   - R4 是 `can` catch-all：淘汰其之前的 R1/R2/R3，并吸收其后同类的 can；R5 是其后的 `cannot`，类型不同，保留。
   - 因此 5 条声明规则在范围查询路径被压缩为 2 条（R5、R4）。

## 7. 给合规问题的直接结论

- “少了几条”来自库内部的**规则压缩**，不是规则被删除或权限被收紧：声明仍是 5 条，范围查询实际使用从 5 条降为 2 条。
- 被压缩掉的是被 catch-all（R4）取代的冗余授权（R1/R2）与永不决定结果的拒绝（R3）；唯一生效的显式拒绝 R5 被保留。
- 压缩开启与关闭两次运行，纯 Ruby 判定、范围行数与脱敏 SQL **完全一致**，脚本对该等价性做了硬断言（不一致即非零退出）。
- 本记录不含任何业务条件取值或对象内容，可直接用于工单核对。

## 8. 复现方式

需要本机已具备 Ruby 3.3 与 ActiveRecord 7.2 + sqlite3（本环境使用仓库 `.venv` 内的离线 gem，无需联网）：

```sh
ruby compliance/ability_audit.rb
```

末行打印 `result=PASS ...` 且退出码为 0 即表示所有等价性断言通过。
