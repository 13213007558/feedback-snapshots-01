# IGMPv3 离线成员关系证据模型（有限、可证伪）

本目录是一个独立于 Scapy 核心树的可运行示例：用 Scapy 构造 IGMPv3
成员报告（Membership Report，类型 `0x22`），序列化为以太网帧字节转录，
再从字节离线解析，依据**可信配置**判断某入口端口是否能被证明订阅了
受保护的组播源。

它刻意不实现交换机转发表，也不声称被动报告能完整还原转发状态。

## 运行方法

```bash
# 仓库根目录
python3 -m igmpv3_evidence_demo.run_demo        # 端到端演示，打印各检查点结论
python3 -m igmpv3_evidence_demo.test_evidence_model  # 9 条断言测试
```

产物写入 `artifacts/`：

- `transcript.jsonl`：带可信采集元数据（时间、入口端口、gap 标记）的字节转录。
- `transcript.pcap`：同一批帧的 pcap，可用 Wireshark/tshark 复核。

## 模块划分

- `config.py`：可信配置（端口、允许的组/源范围、固定成员计时 GMI）。
- `transcript_build.py`：用 `IGMPv3_MR` / `IGMPv3_MR_Group` 构造全部帧并落盘。
- `analyze.py`：用 Scapy 从存储字节还原组记录，喂给证据引擎。
- `evidence_model.py`：有限证据状态机、固定时钟、裁决与边界定义。
- `run_demo.py`：固定时钟检查点编排与结论/前提打印。
- `test_evidence_model.py`：语义断言。

## 记录类型：当前状态报告 vs 状态变化记录

RFC 3376 把组记录分为两类，模型严格区分，二者不可互换：

| rtype | 名称 | 类别 | 语义 |
| --- | --- | --- | --- |
| 1 | `MODE_IS_INCLUDE` | 当前状态记录 CSR | 接收者接口当前过滤模式的**完整快照**，源集合即 INCLUDE 集合 |
| 2 | `MODE_IS_EXCLUDE` | 当前状态记录 CSR | 完整快照，源集合是**排除集合**，不是发送者枚举 |
| 3 | `CHANGE_TO_INCLUDE_MODE` | 状态变化记录 SCR | 用给定模式+源集合整体替换当前状态 |
| 4 | `CHANGE_TO_EXCLUDE_MODE` | 状态变化记录 SCR | 同上，切到 EXCLUDE |
| 5 | `ALLOW_NEW_SOURCES` | 状态变化记录 SCR | 向**当前**源集合增量加入源 |
| 6 | `BLOCK_OLD_SOURCES` | 状态变化记录 SCR | 从**当前**源集合增量移除源 |

要点：

- **CSR 是锚点**。只有 CSR 能建立/重置可证明的接口状态；SCR 只是相对
  当前状态的增量。从未出现 CSR 时，单独的 SCR 无法描述它所编辑的基状态，
  结论为 `NOT_PROVABLE / NO_CURRENT_STATE_ANCHOR`。
- **ALLOW/BLOCK 不是新模式**。`ALLOW_NEW_SOURCES` 做集合并、
  `BLOCK_OLD_SOURCES` 做集合差，作用对象是当前模式下的源集合；
  `CHANGE_TO_*` 才整体替换模式与集合。
- **SCR 重传幂等**。接收者按健壮性变量重传同一变化，迟到的重复 SCR
  （同组、同 rtype、同源集合签名）只记录、不二次应用。
- CSR 的周期性重述是新的快照锚点，不是重复增量。

## 授权来源：可信配置，而非自报地址

- 端口身份、端口允许加入的组、每组允许的源范围、GMI 都来自带外可信配置
  （`config.py`），不来自报文。
- 报文里的发送者 IP 仅作取证展示，不参与授权。
- 接收者自报的组/源地址**本身不构成许可**。配置里不存在的
  `(port, group, source)` 一律 `DENY`，即使报告明确“想要”该源
  （演示中的 `198.51.100.99`，原因码 `SOURCE_NOT_PERMITTED`）。
- 策略判定先于证据判定：未配置项的结论与计时/gap 无关，始终显式拒绝。

## 可证明与未知的边界

对一个已配置三元组 `(port, group, source)`，在固定时钟时刻 `t`：

- `ALLOW`（可证明）：存在 CSR 锚点、无未修复采集 gap、成员计时器未到期，
  且 INCLUDE 集合包含该源，或 EXCLUDE 排除集合不含该源。
- `DENY`（显式拒绝）：配置不允许，或当前可证明状态排除了该源
  （`SOURCE_NOT_IN_INCLUDE_SET` / `SOURCE_IN_EXCLUDE_SET`）。
- `NOT_PROVABLE`（未知，失败关闭）：
  - `NO_CURRENT_STATE_ANCHOR`：从无 CSR 锚点；
  - `CAPTURE_GAP_UNREPAIRED`：可信采集面标记了端口级丢帧且尚无新 CSR 修复；
  - `MEMBERSHIP_TIMER_EXPIRED`：自最近报告起经过固定 GMI 仍无刷新。

边界说明（务必区分“不可证明”与“证伪”）：

- 计时器到期只表示**无法继续证明**成员关系，不等于证明接收者已离开。
- 查询（Membership Query）只被记录，不授予任何成员关系；没有查询也不
  反推任何状态。
- gap 之后、下一个 CSR 之前的 SCR 被挂起（pending），不能跨缺口拼接。
- EXCLUDE 的源集合是排除清单，**枚举不出实际发送者**；因此 EXCLUDE 下
  的 `ALLOW` 仅表示“该源不在排除集合”，不是对发送者存在性的断言。
- IGMPv3 报告无认证。模型假设采集面与配置可信；伪造/篡改报文不在模型内。
- 被动报告无法还原其他接收者、querier 行为、二层 snooping 内部表或数据面，
  因此本模型**不是**交换机转发表的完整复刻。

## 固定时钟与计时

- 时钟只能通过 `advance()` 单调向前，结论可复现，不依赖墙钟。
- GMI 固定为 260 s（RFC 3376 默认：健壮性 2 × 查询间隔 125 s + 响应码 10 s）。
- 任一针对该 `(port, group)` 的有效报告都会把到期时间刷新为
  `last_report + GMI`；到期判断在读取时惰性计算。

## 演示场景（两端口、两组源）

配置：`p1` 仅允许 G1 的 S1/S2；`p2` 仅允许 G2 的 S21/S22。
时间线（节录，完整见 `transcript.jsonl` 与演示输出）：

- F1–F4：INCLUDE 建锚、ALLOW 增量、CSR 周期重述。
- F5：F3 ALLOW 增量的迟到重复 → 只应用一次。
- F6：`CHANGE_TO_EXCLUDE_MODE`，S1/S2 结论随之反转。
- F7–F8：BLOCK 后被新 CSR 快照整体覆盖（快照优先于增量历史）。
- F9：通用查询，无授权效果。
- F10：报告未配置源 S99 → 始终 `DENY`。
- GAP-p1/GAP-p2：可信采集面标记 60 s 缺口 → 修复前全部 `NOT_PROVABLE`。
- F11：gap 后的 BLOCK 被挂起；F12/F13 的 CSR 重新锚定并修复 gap。
- F14：BLOCK 使 p1/G1 变为 EXCLUDE 空集合。
- t=480/580：固定时钟推进越过到期点 → `MEMBERSHIP_TIMER_EXPIRED`。

每条结论在演示第 5 节都列出引用的原始帧 ID（如 `F1, F3, F4`）与适用前提；
未配置源即使被报告订阅，也不会成为授权通过。
