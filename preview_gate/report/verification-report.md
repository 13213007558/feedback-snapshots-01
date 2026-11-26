# 工单外部预览缓存：版本检查与处理规则验证

- 运行时间：2026-11-26 18:42:19
- 出口方式：`real-wsgi-outlet`（与 `ticket_preview/serve.py` 托管同一 WSGI application）
- Python：`3.12.11` · Bleach：`6.4.0` · 当前规则版本：`v2`
- 结果：**58/58 通过**

## 三种判定

| 缓存 | 缓存版本 | 原文/证明 | 出口判定 | HTTP | 是否下发内容 |
|---|---|---|---|---|---|
| 1 有原文 | v1 | 有，SHA-256 校验通过 | `recleaned` 重新清洗 | 200 | 是（新规则） |
| 2 缺原文 | v1 | 无 | `unverifiable` 暂时无法确认 | 422 | 否（fail-closed） |
| 3 新规则 | v2 | 不需要 | `current` 沿用 | 200 | 是（逐字沿用） |
| 探针：v2 命中但含事后撤回字段 | v2 | — | `current` + 出口撤回过滤 | 200 | 是（剔除该字段） |

## 敏感标记暴露矩阵

“旧成品 html”是直接读取缓存文件里的 Bleach 成品；其余列为真实出口/内部接口响应。

| 标记 | 旧成品 html | 内部接口 | 缓存1出口 | 缓存2出口 | 缓存3出口 | 探针出口 |
|---|---|---|---|---|---|---|
| 内部底价标签 `SECRET-BID-9001` | 有 | 有 | 无 | 无 | 无 | 无 |
| 风控内部备注 `RISK-SECRET-5566` | 有 | 有 | 无 | 无 | 无 | 无 |
| 自定义内部节点 `INTERNAL-CUSTOM-3133` | 有 | 有 | 无 | 无 | 无 | 无 |
| 已撤回值班直线 `WITHDRAWN-HOTLINE-4242` | 有 | 有 | 无 | 无 | 无 | 无 |
| 内部定级资料 `INTERNAL-TRIAGE-6677` | 无 | 有 | 无 | 无 | 无 | 无 |
| XSS 事件载荷 `XSSCANARY7731` | 无 | 有 | 无 | 无 | 无 | 无 |

> 内部接口 `GET /internal/tickets/WO-2026-224`（带 `X-Staff-Role: staff`）始终包含全部标记对应的完整原始资料；无该头返回 403。

## 恢复旧缓存对照

```json
{
  "rule_version_1": true,
  "has_internal_label_markup": true,
  "has_withdrawn_value": true,
  "has_bid": true
}
```
恢复后再过真实出口仍为 `recleaned`，响应中敏感标记为“无”；而磁盘旧文件依旧保留 `internal-tag` 与已撤回号码，证明安全结论来自出口规则而非改写证据。

## 三份回执（receipt）

### `case1_recleaned`
```json
{
  "ticket_id": "WO-2026-224",
  "rule_version_current": 2,
  "rule_version_cached": 1,
  "policy_current": "v2-tightened-internal-scope",
  "bleach_version": "6.4.0",
  "cache_present": true,
  "load_error": null,
  "withdrawn_fields": [
    "agent_direct_line"
  ],
  "redacted_withdrawn": [
    "agent_direct_line"
  ],
  "source_present": true,
  "source_verified": true,
  "excluded_out_of_scope": [],
  "reason": "stale-version-rebuilt-from-attested-original",
  "decision": "recleaned",
  "decision_zh": "依现行规则重新清洗",
  "served": true
}
```

### `case2_unverifiable`
```json
{
  "ticket_id": "WO-2026-224",
  "rule_version_current": 2,
  "rule_version_cached": 1,
  "policy_current": "v2-tightened-internal-scope",
  "bleach_version": "6.4.0",
  "cache_present": true,
  "load_error": null,
  "withdrawn_fields": [
    "agent_direct_line"
  ],
  "redacted_withdrawn": [],
  "source_present": false,
  "source_verified": false,
  "reason": "stale-version-missing-original",
  "decision": "unverifiable",
  "decision_zh": "暂时无法确认，已暂缓外部预览",
  "served": false
}
```

### `case3_current`
```json
{
  "ticket_id": "WO-2026-224",
  "rule_version_current": 2,
  "rule_version_cached": 2,
  "policy_current": "v2-tightened-internal-scope",
  "bleach_version": "6.4.0",
  "cache_present": true,
  "load_error": null,
  "withdrawn_fields": [
    "agent_direct_line"
  ],
  "redacted_withdrawn": [],
  "source_present": false,
  "source_verified": false,
  "reason": "cache-current-reuse",
  "decision": "current",
  "decision_zh": "沿用现行规则缓存",
  "served": true
}
```

### `probe_withdrawn_hit`
```json
{
  "ticket_id": "WO-2026-224",
  "rule_version_current": 2,
  "rule_version_cached": 2,
  "policy_current": "v2-tightened-internal-scope",
  "bleach_version": "6.4.0",
  "cache_present": true,
  "load_error": null,
  "withdrawn_fields": [
    "agent_direct_line"
  ],
  "redacted_withdrawn": [
    "agent_direct_line"
  ],
  "source_present": false,
  "source_verified": false,
  "reason": "cache-current-reuse-with-withdrawal-filter",
  "decision": "current",
  "decision_zh": "沿用现行规则缓存",
  "served": true
}
```

## 检查清单


### internal

- ✅ 无 staff 头访问内部接口被拒 (403)
- ✅ 内部接口 200 且返回完整工单
- ✅ 内部资料保留全部字段（含内部/撤回原文）
- ✅ 三次预览判定均不改动原始工单（摘要一致）

### case1

- ✅ 激活的是 rule_version=1 旧缓存
- ✅ 对照：旧成品 html 直接读取时确实含内部/撤回内容
- ✅ HTTP 200
- ✅ 回执 decision=recleaned（重新清洗）
- ✅ 响应头 X-Preview-Decision=recleaned
- ✅ 回执记录原文存在且校验通过
- ✅ 回执登记被剔除的已撤回字段 agent_direct_line
- ✅ 保留允许的普通排版（strong/em/blockquote/ul/链接）
- ✅ 新规则移除内部 class 标签钩子
- ✅ 无可执行事件属性 onerror
- ✅ 无 javascript: 协议
- ✅ 重新清洗后：全部内部/撤回敏感标记均不可见
- ✅ HTML 出口 200
- ✅ HTML 标注 data-preview-decision=recleaned

### case1-html

- ✅ 所见页面：全部内部/撤回敏感标记均不可见

### case1

- ✅ 重建结果已写回本地缓存（rule_version 升级为 2）
- ✅ 重建后的下一次读取转为 current（沿用新缓存）
- ✅ 原始工单：内部出口 200 且完整资料（含内部/撤回字段）仍在
- ✅ 原始工单：内容与权威工单一致，未被缓存流程改写

### case2

- ✅ 激活的是 rule_version=1 旧缓存
- ✅ HTTP 422（明确的无法确认状态，fail-closed）
- ✅ 回执 decision=unverifiable
- ✅ served=false 且不回传任何缓存 html
- ✅ 原因码 stale-version-missing-original
- ✅ 响应头 X-Preview-Served=0 且 decision=unverifiable
- ✅ 暂缓返回的回执：全部内部/撤回敏感标记均不可见
- ✅ HTML 出口同样 422
- ✅ 页面给出明确中文状态与 withheld 区域

### case2-html

- ✅ 所见 withheld 页面：全部内部/撤回敏感标记均不可见

### case2

- ✅ unverifiable 不覆盖旧缓存（磁盘上仍是 v1）
- ✅ 原始工单：内部出口 200 且完整资料（含内部/撤回字段）仍在
- ✅ 原始工单：内容与权威工单一致，未被缓存流程改写
- ✅ 值班显式重建返回 200 且升到 v2
- ✅ 重建后再读 -> decision=current 且可安全预览

### case2-fixed

- ✅ 显式重建后：全部内部/撤回敏感标记均不可见

### case3

- ✅ HTTP 200
- ✅ 回执 decision=current（沿用）
- ✅ 响应头 X-Preview-Decision=current
- ✅ 直接沿用缓存成品（public_html 与缓存 html 逐字一致）
- ✅ 公开页面保留允许的普通排版
- ✅ 沿用的新缓存：全部内部/撤回敏感标记均不可见
- ✅ 原始工单：内部出口 200 且完整资料（含内部/撤回字段）仍在
- ✅ 原始工单：内容与权威工单一致，未被缓存流程改写

### probe

- ✅ 探针缓存文件本身确实含已撤回号码（证明是一次真实命中）
- ✅ 命中仍判 current（沿用缓存）
- ✅ 出口拦截并登记撤回字段
- ✅ 响应头 X-Preview-Redacted 标出字段
- ✅ 其余缓存内容仍正常沿用
- ✅ 撤回过滤后：全部内部/撤回敏感标记均不可见

### restore

- ✅ 已恢复的旧缓存文件在磁盘上仍是 v1 且保留旧标记/撤回值
- ✅ 恢复后过真实出口仍判 recleaned 而非直接命中旧成品
- ✅ 对照出口：全部内部/撤回敏感标记均不可见
- ✅ 对照：旧文件含敏感值=True 而出口响应含敏感值=False
- ✅ 结束时原始工单依旧完整未被缓存流程改写
