# REXML 内部 DTD 默认属性导致的授权伪造：复现与读取契约

环境：CRuby 4.0.7，REXML 3.4.4（仓库源码），结论同时适用于当前 gem 3.4.x。
所有结论均由本目录下可运行脚本验证，未修改 REXML 库代码。

## 1. 漏洞模型

导入服务把“`approved` 属性是否存在”当作调用方明确授权的证据，典型写法是：

```ruby
granted = !element["approved"].nil? && element["approved"] == "true"
```

REXML 默认允许 XML 携带内部 DTD 子集（`<!DOCTYPE ... [ ... ]>`），而 DTD 的
`ATTLIST` 可以为元素声明默认属性：

```xml
<!ATTLIST record approved CDATA "true">
```

于是调用方提交的文档正文里完全不写 `approved`，REXML 的 DOM 读取接口仍会返回
`"true"`，把“没有提交授权字段”变成“读取到了授权字段”。注意 REXML 是**非校验
解析器**，它不会去网络拉取外部 DTD（实测 `SYSTEM`/`PUBLIC` 外部子集里的 ATTLIST
不生效），攻击面只需要文档自带的内部子集，因此不依赖任何外联能力。

## 2. 根因：默认值在查询期回退，而不是解析期注入

默认值并没有被写进元素的属性表，整条链路分两层：

1. 解析期：`BaseParser#parse_attributes`
   （`lib/rexml/parsers/baseparser.rb:850`）只收集起始标签上的显式属性；
   ATTLIST 被解析成独立的 `:attlistdecl` 事件，挂在 `DocType` 下。
2. 查询期：`REXML::Attributes#get_attribute`
   （`lib/rexml/element.rb:2328`）先查自身 Hash，未命中再调用
   `attlist_attributes` → `DocType#_attlist_mappings`
   （`lib/rexml/doctype.rb:126`）动态合成一个默认 `Attribute` 对象返回。

因此默认值与显式属性在**事件层和 Hash 层始终是可区分的**，只有走 DTD 回退的
读取访问器会把两者抹平。源码注释也明确写了迭代器“不遍历 DTD 中的属性，这可能
是个 bug”（`lib/rexml/element.rb:2272`、`:2300`），说明这是已知的行为分裂。

## 3. 四个阶段的实测行为

载荷（正文里 `r1` 没有 `approved`，`r2` 显式给了 `approved="false"`）见
`reproduce.rb` 的 `ATTACK_XML`。

### 阶段 A：原始输入

- 字符串层面 `approved` 只出现在 `<!ATTLIST ...>` 声明里，`<record id="r1"/>`
  起始标签上没有该字段。
- 字节证据可以在解析前直接检查；这是最硬的信任边界。

### 阶段 B：DOM 查询（默认值在此阶段“显形”）

在带 DTD 的 `Document` 上查询 `r1`：

| 接口 | r1（无显式 approved） | 是否保留显式/默认差别 |
| --- | --- | --- |
| `element["approved"]` (`Element#[]` → `Attributes#[]`) | `"true"` | 否，回退 DTD |
| `element.attribute("approved")` | `approved='true'` | 否，回退 DTD |
| `attributes.get_attribute("approved")` | `Attribute` 对象 | 否，回退 DTD |
| `attributes.key?/include?/has_key?` | `false` | 是，只认真实 Hash |
| `attributes.fetch(name, nil)` | `nil`（命中时返回 `Attribute` 对象） | 是 |
| `attributes.dig` | `nil` | 是 |
| `attributes.keys / each / each_attribute / size / select` | 只见 `id` | 是 |
| XPath `//record[@approved]`、`@approved` 轴 | 谓词不匹配（轴取到空串） | 是，XPath 不看 DTD 默认 |
| `doc.doctype.attribute_of("record","approved")` | `"true"` | 明确返回“声明的默认值” |

关键反差：`r1["approved"] == "true"` 但 `r1.attributes.key?("approved") == false`。
另外 `#FIXED` 也只是普通回退——REXML 不校验、不强制，显式给别的值会原样保留。

### 阶段 C：复制节点

- `element.clone` / `deep_clone` 出来的节点 `document` 为 `nil`，DTD 回退链断裂：
  副本上 `["approved"]`、`["display"]` 全部变成 `nil`，`key?` 仍为 `false`。
- 把副本挂回**带原 DTD 的文档**后，`[]` 的默认值回退恢复，但 `key?` 依然是
  `false`——显式/默认差别没有丢。
- 把副本放进一个**没有 DTD 的新文档**，默认值永久消失；显式属性随节点一起保留。
- 结论：跨文档/脱离文档的拷贝天然“净化”了默认值，但不能依赖这种隐式净化做安全
  判断，必须在原树上就用 Hash 层判存在性。

### 阶段 D：序列化再解析

- `Element#to_s` / `Formatter` 只序列化真实 Hash 里的显式属性：`r1` 输出
  `<record id='r1'/>`，默认属性不会被物化进标签。
- 整文档序列化会原样带出 DOCTYPE/ATTLIST；再解析后 `r1` 依旧 `key? == false`
  而 `[] == "true"`，行为完整重现。
- 即“序列化—再解析”不会让默认值变成显式值，但只要 DTD 跟着走，回退就一直在。

### 事件解析路径（SAX/Stream/Pull/Base）

`BaseParser`、`SAX2Parser`、`StreamParser`、`PullParser` 的 `start_element`
事件只携带显式属性（r1 只有 `{"id"=>"r1"}`）。基于事件的导入管道天然免疫该
问题；风险只存在于构建完整 DOM 后再用值访问器判存在性的写法。

## 4. 可运行案例

- `reproduce.rb`：四阶段完整复现，逐接口打印并对照显式/默认差别。
  `ruby security/dtd-default-attributes/reproduce.rb`
- `demo_service.rb`：同一载荷下“脆弱服务 vs 加固服务”的端到端对比。
  `ruby -Ilib security/dtd-default-attributes/demo_service.rb`
- `safe_import_contract.rb`：可落地的读取契约（见下）。
- `test_safe_import_contract.rb`：11 个用例、42 条断言，覆盖攻击载荷、显式值、
  空串、`#FIXED`、克隆、序列化往返、DTD 剥离。
  `ruby -Ilib -Itest security/dtd-default-attributes/test_safe_import_contract.rb`

脆弱写法的最小复现（输出见 `reproduce.rb` 末尾）：

```ruby
doc = REXML::Document.new(attack_xml)
r1 = REXML::XPath.first(doc, "//record[@id='r1']")
r1["approved"]                # => "true"   （实际未提交该字段）
!r1["approved"].nil?          # => true     错误授权
r1.attributes.key?("approved") # => false   正确的存在性判断
```

## 5. 可落地的读取契约

`SafeImportContract` 把两个问题彻底分开：

- **授权判断只接受原始输入中明确提供的值**
  - `explicit_attr?(element, name)`：用 `attributes.key?` 判存在性，DTD 默认值
    永远进不了这个 Hash，空串提交与字段缺失也能区分。
  - `explicit_attr(element, name)`：用 `fetch` 取显式原始值并读出字符串，绝不
    经过 `get_attribute` 的 DTD 回退。
  - `authorized?`：存在且值精确等于约定令牌才放行，其余（缺失、空串、默认值、
    未知值）一律拒绝。
- **合法默认展示值继续保留**
  - `display_value(element, name, fallback)` 仍允许走 `Element#[]` 读取 DTD
    默认值（如 `display="guest"`），但返回值禁止进入授权决策。
- **纵深防御：解析前剥离 DOCTYPE**
  - `parse(xml)` 用 `DOCTYPE_RE` 移除内部/外部 DTD 声明后再建 DOM，默认值与
    内部实体攻击面一起消失；显式属性和正文不受影响。正则对无子集、`SYSTEM`、
    `PUBLIC`、多行内部子集等形态均验证通过。
- 若业务确实需要保留 DTD（展示默认值、实体），可以解析完整文档，但授权路径
  必须且只能走 `explicit_attr?/explicit_attr`；`demo_service.rb` 第三种场景
  证明这种模式下 `display` 默认值照常可读，而 mallory 仍被拒绝。

契约有效性（测试实测）：

| 记录 | 提交情况 | 脆弱 `Element#[]` 判断 | `authorized?` | 展示值 `display` |
| --- | --- | --- | --- | --- |
| r1 / mallory | 未提交 approved，DTD 默认 true | 误授权 | 拒绝 | `guest`（默认保留） |
| r2 | 显式 `approved="false"` | 拒绝 | 拒绝 | `guest` |
| r3 / alice | 显式 `approved="true"` | 授权 | 授权 | `guest` |
| r4 | 显式 `approved=""` | 视实现而定 | 拒绝（空串非令牌） | `guest` |

## 6. 接入建议与边界

- 代码审计规则：授权/角色/开关类字段禁止用 `Element#[]`、`Element#attribute`、
  `Attributes#[]`、`get_attribute` 的返回值做**存在性**判断；统一替换为
  `attributes.key?(name)` 或本契约。
- 新代码优先采用事件式解析（SAX/Stream/Pull），事件里根本没有默认值回退。
- 解析前剥离 DOCTYPE 是纵深防御，不要把它当作唯一措施——保留 DTD 的合法文档
  仍需依赖显式属性契约。
- REXML 不抓取外部 DTD、不解析外部实体；内部通用实体仍会展开（受
  `Security.entity_expansion_limit` 约束），剥离内部子集同时缓解了实体膨胀面。
- REXML 非校验：`#REQUIRED` 缺失不报错、`#FIXED` 不强制，任何依赖 DTD 做
  约束的假设都不成立。
