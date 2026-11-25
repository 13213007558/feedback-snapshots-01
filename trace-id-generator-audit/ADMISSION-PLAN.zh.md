# 替换 OpenTelemetry Python Trace ID 生成器 —— 可审计准入方案

适用版本：`opentelemetry-sdk` / `opentelemetry-api` 1.46.0.dev（本仓库源码核对）。
配套演示：`trace-id-generator-audit/demo_id_generator_audit.py`，结构化证据：`trace-id-generator-audit/audit-evidence.jsonl`。

## 1. 审计边界与三个必答问题

审批需要确认的三个接入面，以及 SDK 中的唯一事实来源：

1. **SDK 从哪里接受本地新链路的随机性声明**
   - 插件入口只有一个：`TracerProvider(id_generator=...)`，不传时默认 `RandomIdGenerator()`。
     见 `opentelemetry-sdk/src/opentelemetry/sdk/trace/__init__.py:1340` 与 `:1347`。
   - 抽象基类 `IdGenerator` 要求实现 `generate_span_id()` / `generate_trace_id()`，并提供可选的
     `is_trace_id_random()`，默认返回 `False`（向后兼容）。见
     `opentelemetry-sdk/src/opentelemetry/sdk/trace/id_generator.py:10`、`:37`、`:50`。
   - 只有新根 span 会调用生成器：父上下文缺失或无效时执行
     `trace_id = self.id_generator.generate_trace_id()`，随后
     `random_trace_id = self.id_generator.is_trace_id_random()` 决定是否置位 W3C
     `RANDOM_TRACE_ID`（0x02）。见 `opentelemetry-sdk/src/opentelemetry/sdk/trace/__init__.py:1240`、`:1242`、`:1260`、`:1265`。
   - 标志位定义：`SAMPLED=0x01`、`RANDOM_TRACE_ID=0x02`。见
     `opentelemetry-api/src/opentelemetry/trace/span.py:214`。

2. **已有远端父链路怎样继承标志**
   - 父上下文有效时，trace_id 直接取 `parent_span_context.trace_id`，**不调用**
     `generate_trace_id()`。见 `opentelemetry-sdk/src/opentelemetry/sdk/trace/__init__.py:1243`。
   - 随机性声明改从父标志继承：`random_trace_id = parent_span_context.trace_flags.random_trace_id`，
     插件的 `is_trace_id_random()` 在该路径上完全不参与。见同文件 `:1262`。
   - 采样位（0x01）由采样器决策重算，但默认 `ParentBased` 采样器按父 `is_remote` 与
     `trace_flags.sampled` 选择委托采样器，生产默认配置下子 span 跟随父决策。见
     `opentelemetry-sdk/src/opentelemetry/sdk/trace/sampling.py:342`-`:356`。

3. **采样端实际得到哪些输入**
   `Sampler.should_sample(parent_context, trace_id, name, kind, attributes, links, trace_state)`
   共 7 个参数（SDK 调用点传前 6 个，见
   `opentelemetry-sdk/src/opentelemetry/sdk/trace/__init__.py:1252`；签名见
   `opentelemetry-sdk/src/opentelemetry/sdk/trace/sampling.py:193`）。
   采样器**拿不到 IdGenerator 实例**，无法自行判断随机性；它只能通过 `parent_context` 读取父
   SpanContext（含 `trace_flags`），以及收到已确定的 `trace_id`。返回 `SamplingResult(decision, attributes, trace_state)`，
   `decision` 仅 `DROP / RECORD_ONLY / RECORD_AND_SAMPLE` 三态（`sampling.py:148`）。
   最终输出标志由决策映射：采样→0x01，再按随机声明或上 0x02（`__init__.py:1254`-`:1266`）。

## 2. 演示矩阵（两个合法替身 × 两条路径）

两个替身均满足接口契约（128/64 bit、永不返回非法 ID），差异仅在熵来源与诚实的随机声明：

| 替身 | 熵来源 | `is_trace_id_random()` | 准入定位 |
| --- | --- | --- | --- |
| `ApprovedSecretsIdGenerator` | `os.urandom`（低 112 bit 随机，高 16 bit 固定前缀 `0x7a1d` 供识别） | `True` | 批准候选，可声明 W3C random-trace-id |
| `DeterministicCounterIdGenerator` | 进程内单调计数器（前缀 `0x0bad`） | `False` | 合法对照/压测替身，禁止声明随机 |

父上下文（手工构造，等价于传播器 extract 结果，`is_remote=True`）：

- P1：trace_id `abcdef0123456789abcdef0123456789`，flags `0x03`（sampled=1, random=1）
- P2：trace_id `99887766554433229988776655443322`，flags `0x00`（sampled=0, random=0）

| 用例 | 路径 | 生成器 | 父 | 生成器 trace_id 调用 | 决策来源 | 输出 flags | trace_id 归属 | 记录 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A1 | 新根 | ApprovedSecrets | 无 | 1 | ParentBased root=AlwaysOn | 0x03 | 生成器（`7a1d…`） | 是 |
| A2 | 新根 | DeterministicCounter | 无 | 1 | 同上 | 0x01 | 生成器（`0bad…`），无随机位 | 是 |
| B1 | 继承 | ApprovedSecrets | P1 | **0** | 父 sampled→AlwaysOn | 0x03 | **父 trace_id** | 是 |
| B2 | 继承 | DeterministicCounter | P1 | **0** | 同上 | 0x03 | **父 trace_id** | 是 |
| B2b | 继承 | DeterministicCounter | P2 | **0** | 父 not sampled→AlwaysOff | 0x00 | **父 trace_id** | 否（DROP） |

**“替换生成器后仍由旧父上下文决定”的路径即 B2**：即便换成确定性计数器生成器，
`generate_trace_id()` 调用次数为 0，输出 trace_id 与 P1 完全相同，flags 仍为 0x03。
B2b 从反方向证明 P2 的 0x00 同样被原样继承（含 DROP 导致不记录）。

## 3. 采样端输入的固化证据

演示中的 `RecordingSampler` 不改变任何决策，只把每次 `should_sample` 的输入落盘。
B1 记录证明采样器实际收到：父上下文（remote、父 trace_id、父 flags=3、两个布尔标志）、
已确定的 trace_id（此时已等于父 ID）、span 名、kind、attributes、links、trace_state。
即：**采样器在生成器之后运行，且对继承路径完全看不到生成器**。

## 4. 生产约定 vs 必须独立观测的判断

**可由代码/短样本记录直接审计（生产约定，准入时静态确认）**

- 接入点唯一：仅 `TracerProvider(id_generator=...)`；可在启动日志/配置留 `get_description()` 类标识。
- 接口契约：位宽、非法 ID 重试、`is_trace_id_random()` 必须与真实熵来源一致（诚实声明）。
- 继承不变量：有效父上下文存在时生成器不产出 trace_id；两个标志位的来源分别是父 flags 与采样器决策。
- 采样器输入面固定为上述 7 参数，不含生成器句柄。
- 默认采样器为 `parentbased_always_on`（`sampling.py:466`），可用
  `OTEL_TRACES_SAMPLER` / `OTEL_TRACES_SAMPLER_ARG` 覆盖。

**短样本无法证明、只能保留待观察的准入判断**

- **随机分布质量（唯一必须挂起的一项）**：`IdGenerator` 文档明确要求至少低 56 bit 均匀随机
  （`id_generator.py:23`-`:30`）。前缀识别、调用计数、单次输出都无法证明均匀性；
  需要对生产规模样本做独立统计检验（字节/位频率、卡方或 NIST 项、碰撞率、跨实例前缀冲突）。
  `is_trace_id_random()=True` 只是**声明**，不是证据。
- **比例采样的实际命中率**：`TraceIdRatioBased` 仅比较 trace_id 低 64 bit 与
  `bound=round(rate·2^64)`（`sampling.py:263`-`:289`）。其正确性隐含依赖 trace_id 均匀分布——
  演示中确定性生成器 20 次 probe 全部落在 bound 同侧（观测命中率 1.00 vs 批准生成器 0.55），
  说明有偏生成器会直接扭曲比例采样。生产实际命中率须由后端按采样标记独立统计，
  不能在准入环节以短样本签收。
- 前置依赖：`RANDOM_TRACE_ID` 的跨系统语义要求上下游 W3C 传播器支持 Trace Context level 2；
  本仓库未检出 `opentelemetry-propagator-w3c`，该链路需在部署环境另行验证。

## 5. 准入检查清单

- [ ] 生成器类实现两个抽象方法，位宽与非法 ID 处理合规；`is_trace_id_random()` 与熵来源一致。
- [ ] 仅通过 `TracerProvider(id_generator=...)` 注入，启动配置与构建产物哈希留档。
- [ ] 复跑 `demo_id_generator_audit.py`，5 个用例与 `audit-evidence.jsonl` 归档（含 A1/A2/B1/B2/B2b）。
- [ ] B2/B2b 断言通过：继承路径生成器零调用、trace_id 与 flags 由父上下文决定。
- [ ] 比例采样部署登记实际 `rate`，并在观测平台建立命中率与 trace_id 分布的长期看板（挂起项）。
- [ ] 随机分布质量以独立大样本统计报告签收，不以短样本或 `is_trace_id_random()` 声明替代。

## 6. 复现方式

```sh
.venv/bin/python trace-id-generator-audit/demo_id_generator_audit.py
```

输出：控制台汇总表 + B1 采样器输入 + 比例采样对照；证据写入
`trace-id-generator-audit/audit-evidence.jsonl`（5 条 span 证据 + 2 条比例采样记录）。
