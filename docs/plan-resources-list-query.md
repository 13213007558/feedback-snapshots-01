# 用 PlanResources 约束列表查询：HTTP/gRPC 计划形态、转换与回退

目标：把 Cerbos 的 `PlanResources` 输出接到列表接口上，并保证**授权约束在分页之前生效**。
配套实现见 `src/cerbos/sdk/plan_filter.py`，等价性测试见 `tests/_plan/`。

## 1. 两种客户端分别拿到什么

| 维度 | HTTP 客户端（`sdk/_sync/_http.py` 等） | gRPC 客户端（`sdk/_sync/_grpc.py` 等） |
| --- | --- | --- |
| 返回类型 | `sdk.model.PlanResourcesResponse`（dataclass） | `response_pb2.PlanResourcesResponse`（原生 protobuf） |
| 过滤器入口 | `response.filter: PlanResourcesFilter` | `response.filter: engine_pb2.PlanResourcesFilter` |
| 条件节点 | `PlanResourcesValue` / `PlanResourcesVariable` / `PlanResourcesExpression` | `filter.condition`（`Expression.Operand`，oneof `node`：`value`/`variable`/`expression`） |
| 变量写法 | `R.attr.department`、`R.id` | `request.resource.attr.department`、`request.resource.id` |
| 字面量 | 原生 Python 值 | `google.protobuf.Value`（需按 `WhichOneof("kind")` 拆箱） |
| 无条件形态 | `KIND_ALWAYS_ALLOWED` / `KIND_ALWAYS_DENIED`，`condition=None` | 同枚举（int），无条件时 `condition` 序列化长度为 0 |
| 失败响应 | `status_code != 200`，可用 `raise_if_failed()` | gRPC status 异常，不返回正常 response |

三种 `kind` 的含义对两种客户端一致：

- `KIND_ALWAYS_ALLOWED`：该 kind 下所有资源都授权，列表查询不需要任何授权谓词；
- `KIND_ALWAYS_DENIED`：全部拒绝，应直接返回空页，**不要**再查库；
- `KIND_CONDITIONAL`：带一棵布尔表达式，必须在 SQL/存储层或内存中求值。

`QueryPlan.from_any(...)` 同时接受两种线格式（也接受裸 `filter`），归一化为同一棵 AST：
`Literal` / `Variable` / `Expression`，并把 gRPC 的 `request.resource.*` 统一改写成 `R.*`。
因此后续转换逻辑只需面对一种结构，测试可以对两种线格式断言出完全相同的 AST。

## 2. 计划里可能出现哪些运算符

Cerbos 查询规划器可能输出的运算符（见 Cerbos 文档 "Filtering"）：

- 逻辑：`and`、`or`、`not`
- 比较：`eq`、`ne`、`lt`、`lte`、`gt`、`gte`、`in`（`in` 的右值是 `list` 结构节点）
- 字符串：`starts_with`、`ends_with`、`contains`
- 集合/不可编译：`intersects`、`intersects_pairs`、`is_set`、`union_sets`、`size`

当策略条件无法完整下推时，规划器不会报错，而是把不可编译的函数原样保留在条件树里
（即“部分不可编译”），其余分支仍然是可下推的比较表达式。

## 3. 可兑现的转换（默认 SQL 方言）

`list_query(plan)` 返回 `ListQuery(decision, sql, params, fallback)`：

| 计划 | `sql` | `fallback` | 列表接口动作 |
| --- | --- | --- | --- |
| `ALWAYS_ALLOWED` | `None` | `None` | 原样分页 |
| `ALWAYS_DENIED` | `"0"` | `None` | 直接空页，不查库 |
| 纯可编译条件 | 参数化片段，如 `(department = ?) OR (geography = ?)` | `None` | 把片段 AND 进 WHERE 后再分页 |
| 部分不可编译（AND 边界） | 可编译分支的片段，如 `department = ?` | 不可编译子树，如 `intersects(...)` | SQL 先过滤候选集，内存对候选行求值 fallback，再分页 |
| 不可编译部分位于 OR 下 | `None` | 完整原树 | 不做拆分，对候选行整体内存求值 |
| 非资源变量（如 `P.attr.*`） | 拆分时视为不可下推 | 保留子树 | 同上；若整棵树都依赖它则全量内存求值 |

默认映射规则：

- `eq/ne/lt/lte/gt/gte` → `= / != / < / <= / > / >=`，全部使用绑定参数；
  `eq null` / `ne null` 特判为 `IS NULL` / `IS NOT NULL`；
- `in` → `column IN (?, ?, ...)`；
- `not` → `NOT (...)`；`and/or` → `AND/OR` 并加括号；
- 变量经 `default_column_resolver` 把 `R.attr.foo` 映射成列 `foo`，
  可传入自定义 resolver 适配 JSON 路径、ORM 字段名等；
- 常量子树折叠：`true AND x` → `x`、`x AND false` → 拒绝全部，避免发出无意义 SQL。

`to_sql(node, handlers=...)` 支持注册自定义运算符处理器，例如把 `starts_with`
映射成 `LIKE ?`（参数 `prefix%`），从而把更多分支留在存储层。

## 4. 不能转换时的处理建议

1. **只在 AND 边界拆分。** `A AND unsupported()` 可以拆成“SQL 跑 A、内存跑 unsupported”，
   两者合取与原树等价；`A OR unsupported()` 不能拆——拆出 A 会漏掉只靠
   `unsupported` 放行的行。实现遇到这种情况会把整棵子树留给 fallback。
2. **默认 fail-closed，不静默放行。** 遇到无法解析的变量（如主体属性 `P.attr.*`）
   或未注册处理器的运算符，抛 `UnsupportedPlanVariable` / `UnsupportedPlanOperator`，
   由 `list_query` 统一转成内存回退；调用方不应 catch 后当作“无条件允许”。
3. **回退路径要限制候选集。** 即使整棵树都不能下推，也应加上资源 kind、租户隔离等
   基础 WHERE，再对候选行内存求值，避免全表扫描后再过滤。
4. **生产环境的内存回退应调用 `check_resources` 批量复核**，而不是信任本地求值器；
   本仓库的 `evaluate(...)` 用于测试与单进程内的数据存储场景，语义与规划器运算符对齐，
   但不替代 PDP 的完整判定（如 derived roles、变量导出）。
5. **分页必须在过滤之后。** 正确顺序是：`plan → WHERE 片段 → 存储查询 → fallback 内存过滤
   → ORDER BY + LIMIT/OFFSET`。先分页再过滤会让被拒行占据页位，导致后续授权行永远取不到。

## 5. 等价性验证（真实小表 + 逐项 check）

`tests/_plan/fixtures.py` 内置 8 行 `docs` 小表，并为每个场景提供一个独立的“逐项 oracle”
函数，模拟对每行单独调用 check 的结论。同一组逻辑计划同时构造 HTTP dataclass 与
gRPC protobuf 两种形态。

| 场景 | 计划形状 | 下推部分 | 回退部分 | 与逐项 check 等价 |
| --- | --- | --- | --- | --- |
| 肯定（ALWAYS_ALLOWED） | 无条件 | 无约束 | 无 | 是（HTTP/gRPC 均测） |
| 拒绝（ALWAYS_DENIED） | 无条件 | `0` | 无 | 是，返回空集 |
| 可编译条件 | `eq(department,'marketing') OR eq(geography,'GB')` | 完整 OR 片段 | 无 | 是，授权 E01/E02/E03/E05/E07 |
| 部分不可编译 | `eq(department,'sales') AND intersects(tags,['red'])` | `department = ?` | `intersects` | 是，SQL 候选 {E03,E04} 经 fallback 后为空 |
| 嵌套 NOT | `NOT(lt(level,3)) AND eq(owner,'alice')` | `NOT (...) AND owner = ?` | 无 | 是 |
| 不可编译运算符在 OR 下 | `eq(...) OR starts_with(...)` | 不拆分 | 整树 | 是，整体内存求值 |
| 完全不可编译 | 单独 `intersects` | 无 | 整树 | 是，命中 E01/E02/E06/E08 |

测试中的关键断言：

- `test_wire_shapes_normalize_identically`：两种线格式归一化后的 `QueryPlan` 完全相等；
- 每个场景都用 SQLite 实际执行 `sql + params`，再对结果跑 `fallback`，
  与逐行 oracle 的 id 集合比对；
- `test_pagination_never_leaks_unauthorized_rows`：对 1/2/3/5/100 等页大小分页，
  校验每一页都只含授权 id，且拼接后恰好等于完整授权集合；
- `test_naive_pagination_after_fetch_hides_authorized_rows`：对照“先取页再过滤”的错误做法，
  展示页缩短、授权行被永久跳过的失败模式；
- `test_custom_handler_extends_sql_capabilities`：注册 `starts_with → LIKE` 后可继续下推。

运行方式（仓库根目录）：

```sh
.venv/bin/python -m pytest tests/_plan -q --noconftest
```

## 6. 集成到列表接口的最小示例

```python
from cerbos.sdk.plan_filter import QueryPlan, list_query

plan = QueryPlan.from_any(cerbos.plan_resources("view", principal, resource_desc))
query = list_query(plan)  # 可传 column_resolver / handlers

if query.denies_all:
    return []

where, params = "", []
if query.sql is not None:
    where, params = f"WHERE {query.sql}", query.params

rows = db.query(
    f"SELECT * FROM docs {where} ORDER BY id LIMIT ? OFFSET ?",
    [*params, page_size, offset],
)
# 仅当计划含不可下推子树时才需要这一步；它发生在 LIMIT 之前
rows = query.filter_rows(rows)
```
