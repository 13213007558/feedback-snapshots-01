# 直接传入业务对象前的调用面核验

结论先行：**Liquid 不执行 Ruby 源码，但这不等于业务对象上的 Ruby 方法不会被调用。** 当前实现（Liquid 5.14.0，Ruby 4.0.7）会在变量解析、输出、条件、过滤和 `render` 参数绑定时，按 Ruby 协议调用宿主对象的方法。把任意业务对象直接作为 assigns 传入，会把对象公开方法的可调用面暴露给模板；`Liquid::Drop` 只约束“按名字查找”的那一条路径，不约束 `to_s`、`to_liquid`、`[]`、`each`、`==`、`include?`、`empty?` 等协议方法。

因此，接入应当限制在**纯值与明确适配器**上，并由适配器代码承担字段选择责任。应用仍需信任自己写的适配器；本库不能、也没有承诺中断适配器内部的任意 Ruby 回调。

## 1. 实际调用链

### 1.1 顶层名字：`to_liquid` 是无条件调用的

`Context#find_variable` 在解析每个顶层名字后，无论值是什么类型，都会执行：

- `variable.context = self if variable.respond_to?(:context=)`
- `liquid_variable = variable.to_liquid`
- `liquid_variable.context = self if variable != liquid_variable && ...`

见 `lib/liquid/context.rb:224-231`。最后一行还意味着每次顶层查找都会调用一次 `==`（除非 `to_liquid` 返回了不同对象）；如果对象自定义了 `==`，它同样是模板可触发的宿主方法。因此普通 Ruby 对象如果没有 `to_liquid`，直接输出、条件判断、字段访问都会抛 `NoMethodError: undefined method 'to_liquid'`；这不是“安全失败”，而是接入错误。`Liquid::Drop#to_liquid` 返回 `self`（`lib/liquid/drop.rb:55-57`），所以 Drop 天然通过这一关。

同样的规则也适用于环境变量（`Context#try_variable_find_in_environments`），以及过滤器返回值：`Context#invoke` 对每个过滤器结果调用 `.to_liquid`（`lib/liquid/context.rb:108-110`）。

### 1.2 字段访问：先问 `key?`，再调用 `[]`

`VariableLookup#evaluate` 只在同时满足以下条件时才把对象当作“可索引对象”：

1. `object.respond_to?(:[])`；
2. `(object.respond_to?(:key?) && object.key?(key))`，或 `object.respond_to?(:fetch) && key.is_a?(Integer)`。

满足后走 `context.lookup_and_evaluate(object, key)`，内部执行 `obj[key]`；随后对结果再执行 `.to_liquid`（`lib/liquid/variable_lookup.rb:59-65`、`lib/liquid/context.rb:234-246`）。因此一个只实现 `[]`、没实现 `key?` 的普通对象，`{{ obj.name }}` 不会触发 `[]`，而是返回 `nil`（严格模式下报 `UndefinedVariable`）。

`size`、`first`、`last` 是 `VariableLookup::COMMAND_METHODS`（`lib/liquid/variable_lookup.rb:5`）：如果前面的键查找失败，且对象 `respond_to?` 该方法，就会直接 `send` 并再 `.to_liquid`（`lib/liquid/variable_lookup.rb:70-71`）。这条命令回退主要影响普通对象和哈希；Drop 因为 `Drop#key?` 永远返回 `true`，会先走 `object[key]` → `invoke_drop`，由 Drop 白名单决定 `size`/`first`/`last`/`count` 是否可调用。

### 1.3 Drop 白名单的真实边界

`Drop.invokable_methods` 通过 `blacklist = Liquid::Drop.public_instance_methods + [:each]`，再减去 `Enumerable` 的公开方法（保留 `sort/count/first/min/max`），最后用 `public_instance_methods - blacklist` 生成允许按名字调用的集合（`lib/liquid/drop.rb:70-81`）。`Drop#[]` 是 `invoke_drop` 的别名（`lib/liquid/drop.rb:63`），而 `invoke_drop` 用 `invokable?` 检查后决定 `send` 还是 `liquid_method_missing`（`lib/liquid/drop.rb:39-45`）。

这条白名单只作用于“`object[key]` 的名字查找”。它不覆盖：

- 直接输出时的 `to_s`；
- `to_liquid`（白名单永远包含它，见 `lib/liquid/drop.rb:79`）；
- 条件比较的 `==`、`include?`、`empty?`、`<`/`>` 等；
- `for` / `tablerow` 的 `each`；
- 过滤器内部的 `[]`、`<=>`、`to_s`、`reduce/sum` 等；
- 容器序列化时的 `inspect`。

例如一个 Drop 同时定义了 `name` 与 `delete_all`，两者都在 `invokable_methods` 里；`{{ drop.delete_all }}` 会直接执行它。若 Drop 没有覆盖 `each`，`{% for x in drop %}` 不迭代（`each` 被显式列入黑名单）；但一旦覆盖了 `each`，`for` 会直接调用它，绕过名字白名单。

### 1.4 输出：`to_s` 与 `inspect`

`Variable#render_obj_to_output` 对非 `nil`、非 `Array` 的值执行 `output << Liquid::Utils.to_s(obj)`（`lib/liquid/variable.rb:117-127`）。`Utils.to_s` 对普通对象直接调用 `#to_s`；对 Hash/Array 走 Liquid 自己的 `hash_inspect`/`array_inspect`（`lib/liquid/utils.rb:165-183`、`203-247`），而这两个函数在遇到叶子对象时又会调用 `#inspect`。

所以：

- `{{ obj }}` → `to_s`；
- `{{ hash_with_obj_value }}`、`{{ array | upcase }}`（数组先被 `to_s`）→ `hash_inspect`/`array_inspect` → 叶子 `inspect`。

`Utils.to_s` 对 Hash 有一个特例：如果 Hash 子类自定义了 `to_s`，则调用自定义 `to_s`（`lib/liquid/utils.rb:169-177`）；这同样是宿主代码。

### 1.5 条件：`==`、`include?`、`empty?`、比较运算符

条件求值的两条路径：

- 单变量条件（`{% if obj %}`）：`Condition#interpret_condition` 在 `op.nil?` 时直接返回 `context.evaluate(left)`，不调用协议方法；随后 `if` 标签对结果调用 `Liquid::Utils.to_liquid_value`（`lib/liquid/tags/if.rb:53-62`）。若对象实现了 `to_liquid_value`，就会被调用（`lib/liquid/utils.rb:157-163`）。
- 带运算符条件：先对左右两侧 `to_liquid_value`，再查运算符表（`lib/liquid/condition.rb:177-197`）。`==`/`!=` 走 `equal_variables` → `left == right`（`lib/liquid/condition.rb:114-124`）；`contains` 调用 `left.include?(right)`（`lib/liquid/condition.rb:20-30`）；`<`/`>`/`<=`/`>=` 在两侧都 `respond_to?` 时 `left.send(operation, right)`（`lib/liquid/condition.rb:190-195`）。`empty`/`blank` 是 `MethodLiteral`，会优先调用值的 `empty?`/`blank?`，否则回退到 Liquid 的语义（`lib/liquid/condition.rb:126-175`）。

这些调用都不查 Drop 白名单。一个 Drop 只要定义 `include?`，`contains` 就会调用它。

### 1.6 迭代：`for`、`tablerow`、`render ... for` 直接调用 `each`

- `For#collection_segment` 先 `context.evaluate` 取集合，再 `Utils.slice_collection_for_iteration`；对普通对象，`Utils.slice_collection_using_each` 在 `respond_to?(:each)` 时直接 `collection.each`（`lib/liquid/tags/for.rb:118-148`、`lib/liquid/utils.rb:36-59`）。
- `TableRow` 同样在 `Utils.slice_collection_for_iteration` 后 `collection.each`（`lib/liquid/tags/table_row.rb:82-99`）。
- `Render#render_tag` 对 `render ... for` 要求 `variable.respond_to?(:each) && variable.respond_to?(:count)`，然后 `variable.count` 和 `variable.each`（`lib/liquid/tags/render.rb:76-82`）。
- `Include` 对 `include ... for` 只在 `variable.is_a?(Array)` 时逐项渲染（`lib/liquid/tags/include.rb:61-69`），但 `include` 默认已在 `Render` 中被禁用（`lib/liquid/tags/render.rb:37`），且不属于推荐的接入面。

### 1.7 过滤器：按属性名索引、比较、转字符串

标准过滤器直接使用宿主协议，而不是 Drop 白名单：

- `map`：`e[property]`（`lib/liquid/standardfilters.rb:557-569`）；
- `where`/`reject`/`has`/`find`/`find_index`：`filter_array` 内部 `item[property]`（`lib/liquid/standardfilters.rb:1006-1023`）；
- `sort`/`sort_natural`：`a[property]` 或 `nil_safe_compare` → `a <=> b`（`lib/liquid/standardfilters.rb:400-446`、`1034-1046`）；
- `uniq`/`compact`/`sum`：`item[property]`（`lib/liquid/standardfilters.rb:519-535`、`579-593`、`979-999`）；
- `join`：逐项 `Liquid::Utils.to_s(item)` → `to_s`（`lib/liquid/standardfilters.rb:1074-1087`）；
- `size`：`input.respond_to?(:size) ? input.size : 0`（`lib/liquid/standardfilters.rb:63-65`）；
- `first`/`last`：`array.first` / `array.last`（`lib/liquid/standardfilters.rb:792-808`）。

`InputIterator#each` 会对每个元素做 `to_liquid`（如果响应）并设置 `context`（`lib/liquid/standardfilters.rb:1113-1119`）。因此过滤器链会反复触发这些协议，且可能对同一元素多次求值。

### 1.8 `render` 参数：先求值，再绑定，未使用也会求值

`Render#render_tag` 在渲染 partial 的函数里对每个属性执行 `context.evaluate(value)` 并写入子上下文（`lib/liquid/tags/render.rb:62-72`），即使 partial 根本不引用该属性。`render 'name' with expr` 也会先 `context.evaluate(@variable_name_expr)`（`lib/liquid/tags/render.rb:76`）；如果表达式是简单变量，这一步会走 `find_variable` → `to_liquid` 和 `==`。`render ... for` 还会额外调用 `count` 与 `each`（`lib/liquid/tags/render.rb:76-82`）。如果 partial 使用绑定的值，还会继续触发字段/输出协议。

`render` 使用 `new_isolated_subcontext`，它继承环境、静态环境、资源限制和寄存器，但**不继承父作用域的局部变量**（`lib/liquid/context.rb:136-161`）。这不是安全边界：它只隔离 Liquid 变量，不限制宿主方法调用面。

### 1.9 预览与正式渲染

本仓库没有独立的“预览渲染器”；预览通常就是同一 `Template#render` 加不同选项（例如 `strict_variables: true`）。两条路径共用：

- `Template#render` → `Context` 建立 → `@root.render_to_output_buffer`（`lib/liquid/template.rb:141-197`）；
- 同样的 `find_variable`、`VariableLookup`、过滤器、标签实现。

区别只在错误呈现：`strict_variables` 会把不存在的键变成 `UndefinedVariable`/`UndefinedDropMethod`（`lib/liquid/context.rb:234-237`、`lib/liquid/drop.rb:33-36`），`strict_filters` 会拒绝未注册过滤器（`lib/liquid/strainer_template.rb:44-51`），`render!` 会重抛错误（`lib/liquid/template.rb:210-213`）。它们不减少宿主方法调用，也不把 `to_s`/`each`/`==` 变成安全操作。预览如果比正式渲染更宽松（例如正式渲染使用更严格的权限过滤），风险反而会漏检；应让两者使用同一套适配器和同一组选项。

### 1.10 错误路径不会回滚已发生的调用

`BlockBody.self.render_node` 会 rescue 渲染异常并交给 `Context#handle_error`（`lib/liquid/block_body.rb:86-108`、`lib/liquid/context.rb:100-106`）。这意味着某个宿主方法已经执行后才抛出的异常，可能只被渲染成错误文本（非 `render!` 时），**不会撤销副作用**。把有副作用的方法暴露给模板，不能依赖“抛错会中止”来防护。

## 2. 调用矩阵

下表中的“对象”指同时实现 `to_liquid`、`to_s`、`[]`/`key?`、`each`、`==`、`include?`、`empty?`、`to_liquid_value` 的内存探针；“Drop”指继承 `Liquid::Drop` 的探针。完整断言见 `test/security/host_method_invocation_test.rb`。

| 模板用法 | 普通对象实际调用 | Drop 实际调用 |
| --- | --- | --- |
| `{{ obj }}` | `to_liquid`、`==`、`to_s` | `==`、`to_s` |
| `{{ obj.name }}` | `to_liquid`、`==`、`key?`、`[]` | `==`、`name`（白名单） |
| `{% if obj %}` | `to_liquid`、`==`、`to_liquid_value` | `==` |
| `{% if obj == "x" %}` | `to_liquid`、`==`（查找期）、`to_liquid_value`、`==`（比较） | `==`（查找期）、`==`（比较） |
| `{% if obj contains "x" %}` | `to_liquid`、`==`、`to_liquid_value`、`include?` | `==`、`include?` |
| `{% if obj == empty %}` | `to_liquid`、`==`、`to_liquid_value`、`empty?` | `==`、`empty?` |
| `{% for x in obj %}` | `to_liquid`、`==`、`each` | `==`、`each`（若定义；否则不迭代） |
| `{% tablerow x in obj %}` | `to_liquid`、`==`、`each` | `==`、`each`（若定义） |
| `{{ obj | size }}` | `to_liquid`、`==`、`size`（若响应） | `==`、`size`（白名单） |
| `{{ obj | map: "name" }}` | `to_liquid`、`==`、`[]` | `==`、`name`（白名单） |
| `{{ obj | join: "," }}` | `to_liquid`、`==`、`to_s` | `==`、`to_s` |
| `{% render 's', x: obj %}`（参数未使用） | `to_liquid`、`==` | `to_liquid`、`==` |
| `{% render 's' with obj %}` | `to_liquid`、`==` | `to_liquid`、`==` |
| `{% render 's' for obj %}` | `to_liquid`、`==`、`count`、`each` | `==`、`count`、`each` |
| `{{ hash_with_obj }}` | 叶子 `inspect` | 叶子 `inspect` |
| `{{ array_with_obj | upcase }}` | 叶子 `inspect` | 叶子 `inspect` |
| 根 Drop `{{ any_method }}` | — | 根 Drop 通过 `Context#environments` 查找，`find_variable` 仍会调用 `to_liquid`/`==`；名字白名单生效 |

注意三点：

1. `==` 首先来自 `find_variable` 的 `variable != liquid_variable`，所以即使只是输出也会出现一次；Drop 覆盖 `==` 时同样会被调用。
2. `{% render 's', x: obj %}` 的“参数未使用”仍会触发 `to_liquid` 和 `==`，因为属性在绑定前被求值；如果 partial 使用 `x.name`，还会再触发 `key?`/`[]`。
3. `where` 对同一元素可能调用两次 `[]`（过滤一次、后续 `map` 再一次）；过滤器链越长，宿主调用越多。

## 3. 接入原型：纯值 + 明确适配器

可运行原型见：

- `test/security/pure_value_adapter_prototype.rb`
- `test/security/pure_value_adapter_test.rb`

设计规则：

1. **默认只传纯值快照**：`PureValue.call` 只接受 `nil`、`true`/`false`、`String`、`Numeric`、`Symbol`（转字符串）、`Time`/`Date`/`DateTime`、由这些值组成的 `Array` 和字符串键 `Hash`。其他类型一律抛 `RejectedValue`。这样模板看到的对象图里没有业务对象，`to_s`/`[]`/`each` 都只作用于 Ruby 内建值。
2. **需要引用对象时只传显式适配器**：`BusinessRefAdapter < Liquid::Drop` 只暴露命名字段（`name`、`status`、`tags`、`updated_at`）和 `to_s`。适配器初始化时自检 `invokable_methods` 是否超出允许集合，超出即失败。
3. **管理方法不进入适配器**：`delete_all`、`secret_token` 不是适配器的方法，也不在快照里；模板按名字、`map`、`[]`、`send`、`instance_eval` 都取不到。
4. **适配器内部只读允许字段**：`BusinessRefAdapter#name` 等只调用业务对象的对应 getter；测试用 singleton 方法埋点证明，渲染期间业务对象只收到 `name`（两次，来自两处 `audit.name` 求值），没有收到 `delete_all`、`secret_token` 或 `to_s`。

测试覆盖的模板形态：

```liquid
{{ view.name }}
{{ view.tags | join: "," }}
{{ view.audit.name }}
{{ view.audit | join: "," }}
{% render 'business' with view %}
{% render 'audit', audit: view.audit %}
{% if view.tags contains "alpha" %}Y{% endif %}
{% for tag in view.tags %}{{ tag }}{% endfor %}
```

以及拒绝形态：

```liquid
{{ view.audit.delete_all }}
{{ view.audit.secret_token }}
{{ view.audit.instance_eval }}
{{ view.audit.send }}
{{ view.audit | map: "delete_all" }}
{{ view.audit | map: "secret_token" }}
```

这些都能得到空输出；在 `strict_variables: true` 下，`{{ view.audit.delete_all }}` 这类缺失名字会得到 `UndefinedDropMethod`，便于预览期发现拼写/越权访问。注意 `instance_eval`/`send` 在 Drop 上属于公共 `Drop` 方法，会被白名单过滤后交给 `liquid_method_missing`；如果应用覆盖了 `liquid_method_missing`（常见于动态字段 Drop），必须保证它只返回已授权的值，不会把名字转成 `send`。默认实现只按 `strict_variables` 抛错。

## 4. 仍需信任的代码

这个原型不是“库级沙箱”。应用仍需信任：

- **`PureValue` 的字段清单与递归逻辑**：它决定哪些字段可以进入快照；如果它把敏感字段复制进去，模板就能读。
- **适配器的 getter**：`BusinessRefAdapter#name` 等是普通 Ruby 方法，内部可以执行任意逻辑、访问数据库、触发副作用。库不会中断这些回调。
- **适配器的 `to_s`/`inspect`/`==` 等覆盖**：`{{ view.audit }}` 会调用 `to_s`，`hash_inspect` 会调用 `inspect`，条件会调用 `==`；适配器若覆盖这些方法，必须自己保证安全。
- **过滤器实现**：自定义过滤器接收的是 Liquid 值，但可以自行调用宿主服务；`register_filter` 的代码始终在信任边界内。
- **标签/文件系统/寄存器**：自定义标签、`read_template_file`、`registers` 都是应用代码，模板可以间接触发它们。
- **业务对象自身的线程安全与副作用**：适配器读 getter 时仍会执行真实代码；如果 getter 有副作用，模板渲染就会触发。

换言之：**Liquid 保证的是模板文本不是 Ruby 源码，不保证模板中对值的协议调用是无副作用的。** 安全边界应划在“适配器暴露了什么”和“应用注册了什么”，而不是“模板没有 eval”。

## 5. 可执行的验证

```sh
bundle exec ruby -Itest test/security/host_method_invocation_test.rb
bundle exec ruby -Itest test/security/pure_value_adapter_test.rb
```

第一条测试固定了上表的调用矩阵，并单独验证预览/正式渲染使用同一调用路径；第二条验证纯值快照、适配器白名单、管理方法不可达、`render` 参数绑定和严格模式错误。
