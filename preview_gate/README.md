# 工单外部预览：缓存版本检查与处理规则

外部预览曾经放行一部分内部标签（如 `<span class="internal-tag">`、
`[data-internal]`、`<internal-note>`）。新权限收紧范围后，磁盘上仍有大量
**已经过 Bleach 清洗的旧成品缓存**。本模块在“读取预览”这一真实出口上加入
版本检查与固定处理规则，区分 **沿用 / 重新清洗 / 暂时无法确认** 三种结果，
同时保证同一工单的内部接口仍拿到完整资料，且已撤回字段不会因任何缓存命中
（包括旧缓存）重新出现。

## 三种判定（核心规则）

| 缓存情况 | 判定 `decision` | HTTP | 处理 |
|---|---|---|---|
| `rule_version = 2`（新规则） | `current` 沿用 | 200 | 直接复用缓存的清洗片段/成品；仍执行撤回字段过滤 |
| 旧版本（`rule_version < 2` 或无版本号）**且**带有可校验原文 `original` | `recleaned` 重新清洗 | 200 | 用当前 Bleach 策略 + 当前字段范围/撤回状态重建，并写回 v2 缓存 |
| 旧版本成品 **但没有原文**（或原文摘要校验失败） | `unverifiable` 暂时无法确认 | **422** | **fail-closed**，不下发旧成品，只给明确状态与回执 |
| 缓存文件不存在（干净 miss） | `built` | 200 | 直接依据权威工单按当前规则生成并缓存 |

判定逻辑集中在 `ticket_preview/gate.py` 的 `evaluate_preview`，每条响应都带
结构化“回执” `receipt`（版本、原因码、原文校验、被剔除的撤回字段等）和响应头
`X-Preview-Decision` / `X-Preview-Served` / `X-Preview-Redacted`。

### 为什么缺原文的旧成品不能“再洗一遍”了事

Bleach 对不允许的标签默认是“去标签、保留文本”。旧策略已经把内部节点清洗过
一次：内部 `class` 钩子可能还在，但 `data-internal` 等属性早已被删，敏感文本
被拍平成普通文本；已撤回号码在旧成品里只是一个无法与正常加粗区分的
`<strong>`。对“成品”二次清洗既不能恢复“这是内部内容”的上下文，也不能按字段
撤回。因此规则明确：**只有旧成品 = 无法证明现行许可 → `unverifiable`，整份
暂缓**，而不是猜测后放行。有原文时，会先按内部标记做“整子树（含文本）剪除”，
再跑 Bleach，并按当前字段范围与撤回集合重建。

## 撤回字段保证

- 权威工单 `data/tickets.json` 维护 `withdrawn_fields`（如
  `agent_direct_line`）。
- 出口在任何“沿用缓存”路径上都用权威撤回集合与缓存的字段化片段 `parts` 求交：
  命中撤回字段就从输出中剔除并在回执 `redacted_withdrawn` 与响应头
  `X-Preview-Redacted` 登记。
- 旧缓存没有字段化 `parts`，因此根本不会被“直接命中下发”：有原文走重建（按
  字段丢弃），无原文整体暂缓。
- 额外探针 `fixtures/probe_current_hit_withdrawn.json` 专门验证：一个合法 v2
  缓存即使含“缓存之后才撤回”的字段，`decision` 仍是 `current`，但该字段不会
  出现在出口内容里。

## 内部完整资料

`GET /internal/tickets/WO-2026-224`（需请求头 `X-Staff-Role: staff`，否则
403；响应 `Cache-Control: no-store`）始终返回权威工单的完整 JSON：公开字段、
`internal_triage` 等内部字段、以及撤回字段的原始值。缓存的任何判定都不会改写
权威工单（校验脚本对其规范化摘要做前后比对）。

`POST /internal/tickets/WO-2026-224/rebuild-preview`（同样需 staff）允许值班
凭权威工单对 `unverifiable` 缓存做**显式**重建修复；公开读取路径不会擅自把
“缺原文的旧成品”替换掉，以保留可观测的第三态与审计边界。

## 三份本地缓存

由 `ticket_preview/seed.py` 生成到 `data/fixtures/`（均为真实 Bleach 产物）：

1. `cache_1_old_with_original.json` — v1 旧成品 + 带 SHA-256 的原文。
2. `cache_2_old_missing_original.json` — v1 旧成品，无原文。
3. `cache_3_current_rules.json` — 已是 v2 新规则缓存。
4. `probe_current_hit_withdrawn.json` — 撤回字段命中探针（附加回归用）。

活动缓存路径固定为 `data/live/WO-2026-224.json`，验证脚本会逐个把夹具激活为该
文件、跑完出口，最后再把第 1 份旧缓存恢复回去作对照。

## 运行与验证

```sh
# 一键：造三份缓存 → 逐个过真实出口 → 检查内容/回执/原始工单 → 恢复旧缓存对照
.venv/bin/python preview_gate/verify.py
# 或
preview_gate/run_checks.sh

# 单元/集成测试（12 项，hermetic）
.venv/bin/python -m pytest preview_gate/tests -q

# 起真实 HTTP 服务后用浏览器/curl 查看（需要允许本地 bind；本沙箱禁止 bind(2)）
preview_gate/run_preview.sh
#   http://127.0.0.1:8077/tickets/WO-2026-224/preview
#   curl -H 'X-Staff-Role: staff' \
#        http://127.0.0.1:8077/internal/tickets/WO-2026-224
```

在禁止绑定端口的沙箱里，`verify.py` 自动改用 WSGI transport 调用
`ticket_preview/wsgi_app.py` 中**同一个 application**（`serve.py` 也托管它），
完整经过路由、状态码、响应头、HTML/JSON 序列化；在允许 bind 的环境会优先起
真实 loopback HTTP（`wsgiref` + 后台线程 + `urllib`）发真实请求。

最近一次运行的完整证据（含敏感标记暴露矩阵与三份回执）写入
`report/verification-report.md`。

## 代码地图

- `ticket_preview/policy.py` — 规则版本、v2 标签/属性/协议白名单、内部节点整子树剪除、v1 旧策略（仅造夹具）、原文摘要。
- `ticket_preview/gate.py:evaluate_preview` — 版本检查 + 三/四态判定与撤回过滤。
- `ticket_preview/wsgi_app.py` — 真实预览/内部出口、HTML 页面与 JSON 回执。
- `ticket_preview/cache_store.py` / `ticket_store.py` — 本地 JSON 缓存与权威工单。
- `ticket_preview/seed.py` — 工单内容、金丝雀标记、三份缓存与探针。
- `verify.py` — 端到端核验与报告生成。
