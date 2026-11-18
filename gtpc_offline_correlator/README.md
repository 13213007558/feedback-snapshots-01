# GTP-C 离线请求/响应关联原型

安全告警场景：把 GTPv2-C 请求与响应一一对应。仅看序号（SeqNum）会把不同
对端、或同一对端重启后的消息混在一起，因此关联身份由多字段共同决定。
完全离线：报文由 pycrate 编码器本地合成，不连接真实移动网络。

## 运行

    python3 build_transcript.py   # 生成 transcript.json（合成转录）
    python3 correlate.py          # 解析 + 关联，输出报告

## 关联身份（绝不单用序号）

1. 端点对（源/目的 IP:port，区分方向）；
2. 消息对（29.274 的 GTPCReqResp：请求类型 → 响应类型）；
3. TEID 上下文：头部 TEID；初始请求头部 TEID 为 0 时，用请求内
   sender F-TEID IE —— 响应的头部 TEID 必须回指它；
4. 序号，仅在前三项确定的上下文内有效。

## 规则

- 重传：端点/类型/序号/TEID 上下文/IE 内容哈希全同 → 归入同一事务，保留为证据；
- 序号重用：序号相同但 TEID 上下文或 IE 哈希不同 → 新事务，绝不自动接上旧事务；
  同一端点 Recovery（重启计数器）上升时标注疑似重启；
- 迟到响应：只匹配到已关闭事务 → 保留为迟到重复证据，不改变状态，也绝不
  归到重用同一序号的新事务上；
- 乱序：响应先于请求被记录时挂起，末尾按字段回溯匹配并标注；
- 只有请求：保持 REQUEST ONLY，只有片段证据时不补造成功建隧道；
- 隧道内请求（头部 TEID ≠ 0）的响应 TEID 从已观测会话上下文解析；
  没有上下文时标记为未核实，而不是臆造。

## 转录场景（transcript.json）

| 帧 | 内容 | 预期关联 |
|----|------|----------|
| 1/3 | 对端 A 的 CreateSessionReq seq=700（含一次字节级重传） | 同一事务 TXN#1 |
| 2 | 对端 B 的 CreateSessionReq seq=700 | 独立事务 TXN#2，永无响应 → REQUEST ONLY |
| 4 | A 的 CreateSessionResp seq=700 | 确认 TXN#1 |
| 5 | A 重启后 CreateSessionReq seq=700（新 F-TEID、recovery 7→8） | 新事务 TXN#3，不接 TXN#1 |
| 6 | 迟到的 TXN#1 响应副本 | 挂在 TXN#1 作证据，不归 TXN#3 |
| 7/8 | DeleteSession 响应先于请求被记录 | 乱序回溯匹配为 TXN#4 |

## 输出

报告对每个事务列出：身份字段、状态（CONFIRMED / OPEN）、每条帧的原始
字段（端点、类型、hdr_teid、seq、sender_fteid、imsi、recovery、cause、
IE 哈希）以及每次关联决策所依据的字段；末尾给出会话建立判定——哪次只有
请求、哪次有对应确认。
