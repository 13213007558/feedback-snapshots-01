# CSP 变更检查器原型（`SecureHeaders::CspChangeChecker`）

目标：在发布时阻止 Content-Security-Policy 被意外放宽。检查器**不做字符串相等判断**，
而是把两侧配置都通过生产生成器 `SecureHeaders::ContentSecurityPolicy` 渲染成浏览器实际收到的
**最终有效头值**，再对有效来源集合做子集（subset）推理，返回三态结论：

- `provably_tightened`（可证明收紧，含“等价/无变化”）
- `loosened`（发现放宽，并给出一个现在被允许的具体资源作为见证 witness）
- `cannot_determine`（无法判断；遇到不支持语法时绝不给绿色结论）

## 为什么比较“最终有效配置”而不是增量

用户传入的增量与浏览器实际生效的策略之间隔着多层生成逻辑，只 diff 增量会漏判：

- `combine_policies` / append 会在某 fetch 指令缺失时把 `default-src` 拷贝过去再并集；
- 生成器在存在其他来源时会丢弃 `'none'`（`reject_all_values_if_none`）；
- 默认会从 host 来源剥离 `http(s)://` scheme（`strip_source_schemes`）；
- nonce 会被注入 `script-src`/`style-src`，并按兼容性追加 `'unsafe-inline'`；
- `*` 存在时其他 host 来源会被裁剪；路径末尾 `/` 会被归一化。

因此检查器的输入是两个完整配置 hash，输出比较的是 `ContentSecurityPolicy#value`。

## 可靠处理的范围（超出范围即 `cannot_determine`）

支持的指令：fetch 类 source-list 指令（`default-src`、`script-src`、`img-src`、
`connect-src`、`frame-src`、`child-src`、`font-src`、`media-src`、`worker-src`、
`manifest-src`、`prefetch-src`、`navigate-to` 等），以及不回退 `default-src` 的
`base-uri`、`form-action`、`frame-ancestors`。

支持的来源语法（见 `EffectivePolicyParser`）：

- 关键字 `'none'`、`'self'`、`'unsafe-inline'`、`'unsafe-eval'`（离散 token，按相等比较）；
- scheme 来源，如 `https:`、`http:`、`data:`、`blob:`；
- host 来源，含精确 host、`*.wildcard` 子域通配；
- 端口约束，含固定端口与 `:**` 通配端口；
- 裸 `*`。

明确不支持、遇到即 `cannot_determine` 的情况：

- **nonce**：值是每请求随机的，且会触发 `'unsafe-inline'` 兼容注入，无法静态比较；
- **hash-source**（`'sha256-…'` 等）：与 inline 回退的交互未建模；
- **`'strict-dynamic'`**：会改变 host/scheme 的传递语义，未建模；
- 带路径的 host 来源（`cdn.example.com/assets/`）；
- `sandbox`、`plugin-types`、`require-sri-for`、`trusted-types`、
  `require-trusted-types-for`、`upgrade-insecure-requests` 等非 URL allow-list 指令；
- 任何无法落入上述文法的表达式。

`report-uri` / `report-to` 只负责上报，不参与资源 allow-list，比较时被忽略但会在报告中注明。

## default-src 回退与 `'none'`

- fetch 指令在有效头中缺失时，按浏览器解析规则回退到 `default-src` 的有效集合；
  `base-uri`/`form-action`/`frame-ancestors` 不回退，缺失即视为无该指令。
- 单独的 `'none'` 归一化为空 allow-set（全部拒绝）；当它与其他来源共存时，
  生成器已将其删除，因此“往 `'none'` 里加一个 host”会被正确识别为从全拒绝放宽到该 host。

## 子集推理方向（宁可保守，不可误绿）

`SourceSetSemantics.covers?(old, new)` 判断 old 授予的能力是否覆盖 new。不能证明覆盖时，
一律把 new 视为新增能力。关键保守点：

- 裸 host（无 scheme）匹配任意 scheme，因此 scheme 来源、带 scheme 的 host 都不能证明覆盖裸 host；
- 精确域不覆盖 `*.域`；`*.example.com` 覆盖子域但不覆盖注册域 `example.com` 自身；
- 无端口 host 与带端口 host 互不能证明覆盖（缺少“页面源默认端口”这一外部事实），
  端口收窄因此通常落在 `loosened`/`cannot_determine`，而不是错误地给绿色；
- `*` 不覆盖 `data:`/`blob:` 与关键字；具体 host 永不覆盖裸 `*`。

指令级结论：有效集合有“未被旧集合覆盖的新来源”即 `loosened`，并由 `witness_for`
生成一个现在被允许的资源 URL 作为证据；只有纯移除/等价才是 `provably_tightened`；
任一 token 不支持即 `cannot_determine`。

## 强制头与 Report-Only 严格分离

- `content-security-policy`（强制）与 `content-security-policy-report-only` 分别渲染、分别判定。
- 顶层结论以**强制头**为准。仅 report-only 收紧时，顶层是 `cannot_determine`，
  并附 note 说明“这不构成强制策略收紧”；report-only 的变化不会冒充强制收紧。
- 强制头被 `OPT_OUT` 移除、或无基线可比时，返回 `cannot_determine`，不允许绿色结论。

## 入口

```ruby
report = SecureHeaders::CspChangeChecker.compare(old_config_hash, new_config_hash)
report.verdict            # => provably_tightened | loosened | cannot_determine
report.enforced.findings  # 每条指令的 verdict/evidence/witness
```

可运行示例：`bundle exec ruby examples/csp_change_checker_demo.rb`。

## 接入发布流程仍缺的证明（本原型不声称能完整模拟浏览器）

1. **请求期配置未覆盖**：检查器只分析静态配置 hash，未执行 per-request override/append、
   named append、nonce 生成等运行时路径；要在发布门禁使用，需要能枚举所有请求期分支
   或对其单独建模。
2. **来源匹配的外部事实缺失**：`'self'` 的实际 origin、页面 URL scheme/默认端口、重定向、
   同站/同源关系、IDN/Punycode、大小写与尾点等归一化，均未引入，因此端口/scheme 收窄
   多按保守处理。
3. **指令交互未建模**：`'strict-dynamic'` 对 host/scheme 的忽略、nonce/hash 与
   `'unsafe-inline'` 的 CSP1/2/3 兼容差异、`upgrade-insecure-requests` 的实际升级效果、
   `sandbox`、trusted-types、SRI 等都在可靠范围外。
4. **路径与查询匹配未实现**：带路径来源的 path 前缀匹配、URL 编码/解码差异未建模。
5. **浏览器差异与版本矩阵**：各引擎对非标准指令、废弃值、`frame-src`/`child-src` 回退、
   report 端点支持不同；原型未消费 User-Agent 变体（`ua_to_variation` 也未纳入）。
6. **多源/多响应头合并语义**：同一响应出现多个 CSP 头时浏览器取交集，原型按单头比较，
   需在接入层证明实际只会输出一个强制头。
7. **生成器版本一致性证明**：门禁使用的 `secure_headers` 版本必须与生产运行版本一致，
   否则渲染结果可能不同；需要在 CI 中锁定并校验版本。
8. **策略完整性而非单指令**：原型证明的是“各指令 allow-set 未放宽”，不等于整体安全
   （例如 DOM XSS、注入面、report-only 长期不转强制等仍需其他控制）。

结论应作为发布门禁的**必要非充分**条件：`loosened` 阻断、`cannot_determine` 转人工评审，
只有 `provably_tightened` 可自动放行，且放行范围严格限定在上述已建模文法内。
