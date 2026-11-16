# 安全消息接收服务：ASN.1 约束执行清单与严格接入

asn1tools 不会因为 ASN.1 里写了约束就在所有解码入口自动执行。本目录用一个包含
**受限整数、SIZE、字符集合（FROM）、嵌套可选字段、引用类型与扩展区**的小协议，
把“声明了什么”和“实际在哪一层执行”逐项对齐，并提供一个 fail-close 的严格接入网关。

## 文件

- `protocol.asn1` — 示例协议（BER/DER/UPER/OER 均可编译）。
- `build_inventory.py` — 从解析器 AST 与 `constraints_checker` 编译树交叉生成机器可读清单。
- `constraint_inventory.json` — 生成产物，准入判断的唯一事实来源。
- `strict_gateway.py` — 严格接入网关：强制 `check_constraints=True`，缺口无验证器即拒绝启动。
- `validators.py` — 针对“无法保证”的声明编写的显式策略验证器（非通用表达式求值）。
- `demo_verification.py` — 默认入口 vs 严格网关的实证对比，输出 `verification_report.json`。
- `test_secure_message.py` — 17 个 pytest 用例。

## 三层执行模型（清单里的 L1–L4）

| 层 | 机制 | 何时生效 |
|----|------|----------|
| L1 编码布局 | PER/OER 定长字段、长度指示符、字母表索引 | 仅 UPER/OER；BER/DER 的 TLV 不提供任何约束保证 |
| L2 `check_types` | Python 类型检查（INTEGER 同时接受 `int` 和 `str`），**不查取值范围** | 仅 encode，默认开 |
| L3 `check_constraints` | 整数范围、SIZE、FROM 字母表、递归到引用/嵌套/SEQUENCE OF 元素 | **所有编码、所有入口默认关闭**，须显式传 `check_constraints=True` |
| L4 无机制 | 扩展标记、WITH COMPONENTS 等被静默跳过 | 永远不执行，必须用应用验证器接管 |

默认入口的真实默认值（见 `asn1tools/compiler.py`）：

```text
encode(name, data, check_types=True,  check_constraints=False)
decode(name, data,                     check_constraints=False)
```

## 实证结论（均由 demo 与测试复现）

1. **BER/DER 默认解码放行一切语义越界**：severity=99、token=`abc2`、recipients 长度 4、
   嵌套 `envelope.traceId=50` 全部解码成功；只有 L3 抛 `ConstraintsError`。
2. **UPER 的 L1 只覆盖布局能表达的约束**，且存在两类盲区：
   - 带扩展标记的整数 `INTEGER (1..10, ...)`：越界值 77 走扩展分支，L1 与 L3 都放行；
   - 结构上仍可解码的恶意线格式（bit 翻转使 `recipients` 元素变成 256、traceId 越界）：
     默认解码静默放行，只有 L3 拒绝。
3. **扩展标记使约束检查器整体丢弃该约束**：`constraints_checker.Type.set_range` 在
   `has_extension_marker=True` 时直接返回，检查树中 MsgId 的范围是 `MIN..MAX`。
4. **SEQUENCE 扩展区（`...`）对旧版 schema 不可见**：BER 未知扩展成员被静默剥离；
   网关通过遍历外层 TLV 元素个数识别并拒绝。
5. **能编译不等于会执行**：`WITH COMPONENTS` 被解析进 AST 但无任何编译器消费；
   多重约束 `INTEGER (0..10) (5..8)` 只执行第一段，值 9 在严格模式下仍放行；
   `BIT STRING (SIZE(...,...))` 在 UPER 越界时抛 `NotImplementedError`；
   时间区间约束在解析期即 `ParseError`。这些都列在清单的
   `compiler_capability_probes` 与 `unsupported_or_ignored` 中，状态绝不标成 enforced。
6. **PER 字母表回退与静默截断**：非 2 的幂大小的自定义 FROM 子集在 PER 编译器中回退到
   内置全字母表；带扩展标记 SIZE 的字符串扩展分支解码时可能截断（9 字符解出 1 字符）。

## 严格接入如何堵住缺口

`StrictGateway` 在构造时读取清单，对所选 codec 的 `strict_gateway` 平面逐条核对：

- 有保证的条目（PER 的 L1，或网关强制的 L3）直接依赖；
- 无保证的条目（如 MsgId 的扩展标记、SEQUENCE 扩展区）**必须**在 `validators` 中注册
  同名路径的显式验证器，否则抛 `PolicyError` 拒绝启动——无法保证的声明不能被当成准入政策。
- `receive()` 始终以 `check_constraints=True` 解码，再运行注册验证器；
  `send()` 同时打开 `check_types` 与 `check_constraints`。

验证器是按清单路径手写的具名函数，不存在“把 ASN.1 约束当 Python 比较表达式通用求值”的路径。

## 运行

```bash
# 重新生成机器可读清单
../.venv/bin/python build_inventory.py

# 默认入口 vs 严格网关实证（含线格式 bit 翻转与扩展区攻击）
../.venv/bin/python demo_verification.py

# 测试
../.venv/bin/python -m pytest test_secure_message.py -v
```

## 清单字段读法

每个 `constraints[]` 条目包含：

- `path`：约束所在字段（含 `[]` 表示 SEQUENCE OF 元素、点号表示嵌套/引用递归）；
- `constraint.extension_marker`：是否带扩展标记；
- `enforcement[]`：按 codec 列出实际拒绝层与状态（enforced / optional /
  conditional / not-enforced-silent / not-enforced-unsupported）；
- `admission_guarantee.<codec>.default_entry` 与 `.strict_gateway`：
  两个平面各自能否作为准入保证，`guaranteed=false` 的原因与所需补救措施。
