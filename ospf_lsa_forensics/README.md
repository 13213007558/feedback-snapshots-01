# OSPFv2 LSA 离线复核（取证判据）

针对"后端用序号数字更大判断 LSA 更新"的缺陷，本目录提供基于 Scapy
OSPFv2 解码的离线复核样例与可执行判据。只做取证判定：不实现路由器、
不构造或发送任何报文（样例帧由 Scapy 组包后仅保留字节）。

## 数据分层

- **原始字段**：`CapturedLsa.raw`（十六进制原样保留）与解码出的头部字段；
- **抓包时间**：`capture_time`，独立于原始字节记录；
- **推导结论**：每个 `Decision` 都附带 `reason`，注明所依据的 RFC 2328 条款。
- OSPF 头部的认证字段（authtype/authdata）只记录、不验证，永远不作为
  可信来源（`AUTH_NOTE`）。

## 判据（RFC 2328）

1. **先验证后比较**（`decode_lsa`）：
   - LSA `len` ≥ 20 且为 4 的倍数，且不超过实际捕获字节（完整长度检查）；
   - Fletcher-16 校验和（附录 C，age 字段除外、校验和字段置零重算）；
   - 序号 0x80000000 为保留值，出现即判无效。
2. **LSA 身份**：(area, type, LS ID, advertising router)，area 取自
   外层 OSPF 头部，必须先明确身份再比较版本。
3. **版本比较**（`compare_instances`，§13.1 顺序）：
   1. 序号按**有符号** 32 位空间比较（§12.1.6：
      InitialSequenceNumber=0x80000001，MaxSequenceNumber=0x7FFFFFFF）；
   2. 序号相同，校验和大者新；
   3. 序号与校验和都相同，age 为 MaxAge(3600) 者新；
   4. 否则年龄差超过 MaxAgeDiff(900s) 时年轻者新，否则视为等价。
4. **序号耗尽**（§12.1.6）：只有观察到同一身份的 MaxSequenceNumber
   实例被 MaxAge 清除后，InitialSequenceNumber 的新起点才被接受为新一代
   （`WRAP_RESTART`）；清除与新起点作为一对事件显式跟踪，普通整数排序
   （无论有符号还是无符号）都不能把它们吞掉。wrap 确认后，属于上一代
   的迟到实例（抓包时间早于清除时刻，或序号在已见上一代集合中）判
   `UNCERTAIN`，不得按整数序复活为拓扑变化。

## 运行

```console
python3 -m ospf_lsa_forensics.replay        # 两种到达顺序重放 + 反例
python3 -m unittest ospf_lsa_forensics.test_lsa_forensics -v
```

## 样例与反例

- `samples.py`：同一身份的更新序列（序号 5→7、乱序到达的 6、同序号
  不同校验和、MaxAge 清除、序号耗尽 0x7FFFFFFF→清除→0x80000001 重启）、
  校验和损坏、截断捕获、保留序号，以及用于 MaxAgeDiff 规则的第二身份。
- `replay.py`：按两种到达顺序重放同一组原始 LS Update，逐条输出
  OVERRIDE / FLUSH / RETAIN / DUPLICATE / REJECT_INVALID / UNCERTAIN /
  WRAP_RESTART 及依据；反例区用同序号不同校验和、MaxAge、MaxAgeDiff、
  序号空间端点验证比较逻辑，并标出无符号"序号大者新"与 RFC 判据的
  分歧点（CE5）。两种顺序最终保留状态一致；中间判定不同的条目在汇总
  中标为顺序相关证据，不得直接当作拓扑变化。
