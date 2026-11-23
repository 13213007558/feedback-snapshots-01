# 局部校验与跨路径权限：可落地判据

本文回答一个设计问题：配置中心里，低权限操作员只能改**部分实例路径**，更新后整份文件仍须通过 schema。能否只对改动附近的一小段做检查，同时保证这次修改不会改变**其他路径的许可含义**？

结论先行：

- **可以局部化的是“语法/局部约束”的快速检查**，作为提交前的低成本门禁。
- **不能局部化的是“权限含义”**。`if`/`then`/`else`、`dependentSchemas`、`$ref` 到共享 `$defs`、`unevaluatedProperties` 等关键字会让某个路径的许可依赖**别处**的取值。因此必须再加一条**全量验证**和一条**跨路径差异检查**。
- **纯局部检查单独使用是不安全的**，本文给出可复核的反例（第 4 节 B 组）。
- 判据分三档：`自动通过` / `需提升审查` / `拒绝`。`需提升审查` 保留一个**带署名和理由**的正式变更通道，但不能绕过结构性错误。

下文所有结论都能用仓库内 `design/scoped_edit_guard.py` 复跑，测试在 `design/test_scoped_edit_guard.py`。

```sh
.venv/bin/python -m pytest design/test_scoped_edit_guard.py -q
.venv/bin/python -m design          # prints the A / B / B' transcripts below
```

---

## 1. 检查依据：schema 的哪些部分让“权限”变成跨路径的

JSON Schema 是**声明式、整体求值**的。判断某路径 `p` 是否被允许，不是只看挂在 `p` 上的那段子 schema，而是要看所有对当前实例生效的关键字。下面这些关键字会让 `p` 的许可依赖 `p` 之外的状态：

| 关键字 | 依赖什么 | 对局部检查的影响 |
|---|---|---|
| `if` / `then` / `else` | 整个实例（至少是 `if` 子 schema 触及的字段） | 改 `if` 触及的字段会切换分支，另一分支下的约束随之整体替换 |
| `dependentSchemas` | 实例中**是否存在**某个属性 | 增删触发键会整体启用/停用一段约束 |
| `dependentRequired` | 同上 | 同上，作用于“必须同时出现哪些键” |
| `$ref` 到同一文档 `$defs` | 被引用的共享定义 | 两条实例路径可能共享同一个约束节点，改一处语义会同时影响另一处 |
| `$dynamicRef` | 动态作用域（运行时锚点） | 目标无法在静态阶段唯一确定 |
| 递归 `$ref` | 自身 | 局部性与终止性都无界 |
| `unevaluatedProperties` / `unevaluatedItems` | 所有兄弟关键字产生的注解 | “哪些键算已求值”取决于同层其它关键字，且错误定位是粗粒度的 |
| `oneOf` / `anyOf` / `not` | 多个子 schema 的联合结果 | 分支选择会随实例值改变 |

对照实现可以看：

- `if_`：先 `evolve(schema=if_schema).is_valid(instance)`，再决定 `then` 还是 `else`（`jsonschema/_keywords.py:384`）。
- `dependentSchemas`：只对“实例中出现了的触发键”调用 `descend`（`jsonschema/_keywords.py:256`）。
- 注解收集：`find_evaluated_property_keys_by_schema` 明确覆盖 `properties`、`additionalProperties`、`unevaluatedProperties`、`patternProperties`、`dependentSchemas`、`allOf`、`oneOf`、`anyOf`、`if`、`then`、`else`（`jsonschema/_utils.py:324`）。

这张表就是“哪些配置可以局部处理”的第一道筛子：**只要改动路径落在上述关键字的依赖范围内，就不能只做局部判断**。

---

## 2. 现有验证 API 能接在哪一步

`jsonschema` 的公共验证入口已经够用，不需要改库：

- `Draft202012Validator(schema)` 构造验证器。
- `validator.check_schema(schema)`：先确认 schema 本身合法（否则后续结论无意义）。
- `validator.is_valid(instance)`：布尔快速判断，适合前置门禁。
- `validator.iter_errors(instance)`：拿到**带位置信息**的错误；错误对象提供 `validator`、`message`、`path`、`absolute_path`、`schema_path`、`absolute_schema_path`、`json_path`、`context`（`jsonschema/exceptions.py:141`、`docs/errors.rst`）。
- `validator.evolve(schema=子schema)`：换 schema 但**保留原 resolver**，因此子 schema 里指向根 `$defs` 的 `$ref` 仍能解析（`jsonschema/validators.py:342`、`jsonschema/protocols.py:216`）。这是“局部检查”能落地的关键 API 依据。

推荐的对接顺序（与 `guard()` 的实现一致）：

1. `check_schema`：schema 非法 → 直接拒绝。
2. 基线文档全量 `is_valid`：基线本身不合法 → 拒绝（不能拿坏基线做比较）。
3. ACL：算 diff，任何改动路径不在可写集合内 → 拒绝。
4. 全量 `iter_errors(new)`：结果不合法 → 拒绝。
5. 局部检查：对每个改动叶子，用 `evolve(schema=local_subschemas(...)).iter_errors(value)` 做快速定位。**这步只用来“更早失败/更好报错”，不能替代第 4 步**。
6. 跨路径检查：分支状态对比 + witness 搜索（第 3、4 节）。
7. 输出三档结论；`需提升审查` 可附正式理由。

`absolute_path` / `json_path` 是 ACL 与报错的连接点：前者定位实例路径，后者适合直接展示给操作员。注意 `$ref` 场景下 `ValidationError.schema` 可能是被引用的子 schema，而 `absolute_schema_path` 仍相对原始 schema（`docs/errors.rst` 有说明）。

---

## 3. 判据

把一次提交记为 `(schema, old, new, writable)`，`changed = diff(old, new)`。判定顺序如下。

### 3.1 拒绝（结构性，不可用理由豁免）

- schema 本身不合法（`check_schema` 失败）。
- 基线 `old` 不合法。
- 任一改动路径不在 `writable` 内。路径按前缀授权：授权 `("limits",)` 覆盖 `("limits","retries")`，但不覆盖 `("limits",)` 的兄弟。
- `new` 全量验证失败。
- 改动叶子的**局部约束**不通过（`local_invalid`）。这是“局部检查的正当用途”：给出更精确的报错，但失败仍然拒绝。

### 3.2 自动通过（局部处理）

同时满足：

- 只有叶子级 `replace`，且每个改动路径都有可解析的**无条件**局部子 schema；
- 没有触发 3.3 中任何一条跨路径信号。

这里的“叶子级”是保守定义：数组长度变化会被当成整体替换（授权改 `items/3` 不等于允许增删数组元素）。

### 3.3 需提升审查（局部不够，必须看全局）

出现任一即升级；**升级不等于拒绝**，而是进入带理由的正式变更流程：

- `branch_flip`：`if/then/else`、`oneOf`、`anyOf`、`not`、`dependentSchemas`、`contains` 的运行时判定在 `old` 与 `new` 之间不同。
- `presence_dependency`：增删了 `dependentSchemas` / `dependentRequired` 的触发键。
- `unevaluated_scope`：改动落在使用 `unevaluatedProperties` / `unevaluatedItems` 的作用域内。
- `dynamic_ref` / `nonlocal_ref` / `recursive_ref`：引用无法在本文档内静态收敛。
- `permission_witness`：在**未改动**的路径上找到一个具体取值，`old` 拒绝而 `new` 接受（或反之）。
- `local_subschema_unavailable`：该路径没有无条件局部子 schema（例如只出现在 `if` 分支里）。

### 3.4 一个重要的诚实声明

**“没有 witness”不等于“没有跨路径影响”。** witness 搜索是在有限候选路径和有限候选值上做的（见第 5 节成本）。因此自动通过的依据不是“搜不到反例”，而是“没有分支翻转 + 引用可静态收敛 + 局部约束成立”。这也是为什么 witness 只作为**升级信号**，不作为**放行证据**。

---

## 4. 两组可复核对照

同一份 schema：`mode ∈ {live, readonly}`；`live` 分支下 `timeoutSeconds ≤ 30` 且 `publish` 必须为 `true`；`readonly` 分支下 `timeoutSeconds ≤ 300` 且 `publish` 必须为 `false`。基线：

```json
{"mode": "live", "limits": {"retries": 1, "timeoutSeconds": 20}, "publish": true}
```

### 4.1 A 组：独立字段修改 → 自动通过

只改 `limits.retries`：`1 → 2`，授权 `{("limits","retries")}`。

- 全量验证：通过。
- 局部检查：`limits.retries` 的局部子 schema 为 `{"type":"integer","minimum":0,"maximum":3}`，`2` 通过。
- 跨路径检查：`if` 判定仍为真、选中分支仍是 `then`、无 witness。
- 结论：`auto-approve`。

这条改动的语义是“同一个分支内把一个独立计数调大”，不触碰任何分支条件，也不改变别的路径的许可。

### 4.2 B 组：改变分支、继而改变另一字段许可 → 需提升审查

把 `mode` 改为 `readonly`、`publish` 改为 `false`，授权 `{("mode",), ("publish",)}`。

看起来“每个被改的叶子都合法”：`mode` 命中 `enum`，`publish` 是布尔，且**整份新文档也合法**。但：

- `if` 判定由 `true → false`，选中分支由 `then → else`；
- 未被改动的 `limits.timeoutSeconds` 的许可上界由 `30` 变成 `300`；
- 具体 witness：`timeoutSeconds = 31` 在旧文档下被拒绝（`maximum: 30`），在新文档下被接受（`maximum: 300`）。

因此结论是 `escalate`，理由里同时给出 `branch_flip` 与 `permission_witness`。这正是“局部检查会误放行”的场景：如果只校验 `mode` 和 `publish` 两个叶子，会得到“全部合法”，从而错误地自动通过。

### 4.3 用测试固化反例

`design/test_scoped_edit_guard.py` 里的 `test_local_only_check_would_have_approved_the_branch_flip` 显式断言了这一点：每个改动叶子在局部子 schema 下都合法、整份新文档也合法，但 guard 仍必须 `escalate`。同一文件的 `test_naive_local_policy_is_demonstrably_unsafe` 进一步量化：`timeoutSeconds = 31` 在改动前被拒、改动后被接受。

`dependentSchemas` 的版本同样可复核：触发键 `a` 存在时 `b ≤ 5`；删除 `a` 后 `b` 的上界消失。guard 报 `presence_dependency` 与 `branch_flip`，并在 `b` 上找到 witness：`6` 在旧文档下被拒（`maximum: 5`），删除 `a` 后被接受。见 `test_dependent_schema_permission_witness`。

---

## 5. 检查依据与代价

`guard()` 的返回里带 `metrics`，实测（本仓库、Draft 2020-12、上述 5 字段 schema）：

| 指标 | A 组（1 处改动） | B 组（2 处改动） | 含义 |
|---|---|---|---|
| `full_validations` | 2 | 2 | 基线与新文档各一次全量验证 |
| `local_validations` | 1 | 2 | 每个改动叶子一次局部验证 |
| `branch_validations` | 2 | 2 | 基线/新文档的分支判定 |
| `witness_candidates` | ~42 | ~39 | 尝试的（未改动路径 × 候选值）组合 |
| `witness_validations` | ~84 | ~78 | 每个候选两次全量验证（旧/新） |

代价要点：

- **局部检查很便宜**：与改动叶子数成正比，适合作为提交时的同步门禁。
- **witness 搜索是主要成本**：候选路径上限 24、候选值上限 48、witness 上限 5，最坏约 `2 × 24 × 48` 次全量验证。适合异步/预审，不适合每个请求都跑。
- **分支状态对比接近一次全量验证的成本**，但只在 schema 含条件关键字时才需要。
- **保守偏差**：`additionalProperties`、`patternProperties`、数组整体替换、以及“只出现在条件分支里的路径”都会被升级处理，宁可多审。

一条工程上可用的策略：提交路径只跑第 1–5 步（schema 合法性、ACL、全量验证、局部定位）；把第 6 步（分支对比与 witness）放到异步预审。这样绝大多数独立字段修改仍能快速通过，而 B 组这类改动会被异步升级。

---

## 6. 正式变更的理由位

`需提升审查` 的价值在于**不把跨路径影响当成错误，而是当成需要人解释的变更**。原型提供 `Justification(reason, approver, acknowledged)`：

- `reason` 与 `approver` 必填；
- `acknowledged` 列出被明确接受的升级类别（如 `branch_flip`、`permission_witness`）；
- `review()` 只有在**没有结构性理由**、且所有非结构性理由都被 `acknowledged` 覆盖时，才返回 `approved-with-justification`，并把理由写进结论。

结构性理由（`acl_violation`、`full_validation_failed`、`schema_invalid`、`baseline_invalid`、`local_invalid`）**永远不能**被理由豁免——它们是“错”，不是“需要解释”。

为了让理由可复核，`change_fingerprint()` 把“改动 + 每个改动路径实际绑定的局部 schema”哈希成一个 `sha256`。审核者记录的是这个指纹：后续如果 `$defs` 被改、导致同样的文字 diff 绑到了不同的约束节点，指纹会不同，旧理由不能复用。

---

## 7. 落地判据速查

| 情况 | 结论 |
|---|---|
| 改动路径越权 | 拒绝 |
| schema / 基线 / 新文档整体不合法 | 拒绝 |
| 改叶子、局部约束失败 | 拒绝（并给出精确路径） |
| 独立叶子修改，无分支/引用/注解风险 | 自动通过 |
| 触发任一跨路径信号 | 需提升审查 |
| 提升后理由覆盖所有非结构性项 | `approved-with-justification` |
| 试图用理由豁免结构性项 | 仍然拒绝 |

---

## 8. 已知边界与后续

- 原型只覆盖 Draft 2020-12 的关键字集合；`$dynamicRef` 的解析只做“检测到就升级”，不做目标求解。
- witness 是**反例搜索**，不是完备证明；它的作用是给审核者一个可读的具体值，而不是给自动通过背书。
- `local_subschemas()` 只沿 `properties` / `patternProperties` / `additionalProperties` / `items` / `prefixItems` / `allOf` / `$ref` 下钻，这是有意的保守裁剪。
- 真正的生产实现还应把 `writable` 的授权模型、指纹的存储/比对、以及 `branch_state()` 对更多关键字（如 `propertyNames`、`contentSchema`）的覆盖补齐。

文档中的 API 依据：`docs/validate.rst`、`docs/errors.rst`、`jsonschema/protocols.py`（`is_valid` / `iter_errors` / `evolve`）、`jsonschema/validators.py:399`（`descend`，供理解内部求值）、`jsonschema/_keywords.py`（`if_`、`dependentSchemas`）、`jsonschema/_utils.py:324`（注解覆盖范围）。
