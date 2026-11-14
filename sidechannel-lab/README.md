# Rack::Deflater 压缩长度侧信道实测评估

完全本地、纯进程内的复现实验：示例应用把一个**固定假令牌**和**攻击者可控的反射文本**放进同一个
HTML 响应，用真实的 `Rack::Deflater`（Rack 3.2.8 + Ruby 4.0.7，Zlib gzip）压缩，
通过 `Rack::MockRequest` 测量实际压缩后的线上字节数，不引用任何外部服务，也不监听端口。

> 目标是评估侧信道是否**可用**并验证缓解，不实现通用令牌窃取器。

## 运行方式

```sh
ruby experiments.rb   # 全量实验矩阵，输出到 results/
ruby verify.rb        # 7 项行为断言（应全部 PASS）
```

产物：`results/console.txt`（表格输出）、`results/results.json`（机器可读）、
`results/summary.tsv`、`results/verify.txt`。固定 `Last-Modified` 使 gzip 头的 mtime
确定，两次完整运行的字节数逐行一致（已用 diff 验证）。

## 实验应用

- 假令牌（恒定，出现在每个敏感页面）：`AKIA-FAKE-9XQZ-TKN-2026-k7v2m9p4`（32 字符）。
- `/reflection`：隐藏域中的令牌与查询参数 `echo` 的反射文本位于**同一可压缩响应**，
  反射内容可重复 `repeats` 次（模拟攻击者放大信号）。
- `/separate`：令牌与反射之间插入 `pad` 字节填充，`mode=fixed|random`。
- `/stream`：同一文档由自定义 body 对象按 `chunks` 块流式产出。
- `/token-only`、`/echo-only`：分别移除反射、移除令牌的对照。
- `/public/app.js`：不含秘密、可缓存的公开可压缩资源。

所有猜测候选都做**等长处理**，因此任何线上体积差异只来自压缩，不来自输入长度。

## 实测结果（gzip 线上字节数）

### A. 基线（`sync=true`，`Accept-Encoding: gzip`）

| 场景 | 编码 | 线上字节 | 解码字节 |
|---|---|---|---|
| 仅令牌 `/token-only` | gzip | 397 | 1733 |
| 同页反射（错误猜测） | gzip | 582 | 4001 |
| 仅反射 `/echo-only` | gzip | 371 | 2290 |

压缩确实生效；长度信号只在“秘密 + 可控反射同页”时才有意义。

### B. 等长预言机：正确前缀 vs 错误前缀

| repeats | 猜测长度 | 错误猜测 | 正确前缀 | 差值（错误−正确） |
|---|---|---|---|---|
| 8 | 1 | 566 | 565 | **1** |
| 8 | 8 | 572 | 570 | **2** |
| 8 | 16 | 575 | 572 | **3** |
| 32 | 1 | 570 | 568 | **2** |
| 32 | 8 | 575 | 573 | **2** |
| 32 | 16 | 582 | 579 | **3** |

正确前缀让反射区命中令牌已建立的字典，输出**稳定地小 1–3 字节**；差值随猜测长度增大。

### C. 全前缀扫描（repeats=16，长度 0..32）

32 个位置上 `delta_wire` **全部为正（1–4 字节），没有一个位置反转**。说明每个字符位置都能
用“同长度候选中体积最小”做判定，预言机对整串令牌逐字符可用（本实验只验证可行性，不做穷举窃取）。
`verify.rb` 进一步对首字符跑 38 字符字母表：真实首字符 `A` 在线上体积中并列最小（rank 1/38）。

### D. 秘密与输入分离

| 填充模式 | 填充字节 | 错误 | 正确 | 差值 |
|---|---|---|---|---|
| fixed | 0 | 447 | 446 | 1 |
| fixed | 1024 | 459 | 459 | 0 |
| fixed | 4096 | 471 | 470 | 1 |
| random | 1024 | 1261 | 1263 | −2 |
| random | 4096 | 3429 | 3437 | **−8（反转）** |

- 固定填充下信号被压到 0–1 字节，基本不可区分。
- **每请求随机填充**使差值在不同请求间翻转（D2：两组 8 次采样的区间互相重叠，
  如 prefix `[3424..3435]`、wrong `[3424..3433]`），单请求判定不再可靠——这正是 BREACH
  缓解中随机化填充的作用，但需要足够多的噪声字节和统计处理。

### E. 流式分块（`/stream`，32 次反射，猜测长度 8）

| chunks | sync | 错误 | 正确 | 差值 |
|---|---|---|---|---|
| 1 | true | 575 | 573 | 2 |
| 1 | false | 568 | 566 | 2 |
| 2 | true | 590 | 588 | 2 |
| 8 | true | 655 | 653 | 2 |
| 32 | true | 911 | 909 | 2 |
| 32 | false | 568 | 566 | 2 |

- **分块不重置 gzip 字典**：无论切成多少块，正确猜测始终小 2 字节。流式不是缓解。
- `sync=true`（Deflater 默认）每块 `gzip.flush`，每块带来固定额外字节（32 块时总体积
  568→911），但它只加噪声常量，不破坏跨块字典；`sync=false` 体积更小且差值依旧。

### F. 缓存 / 转换头

| 情形 | 编码 | 线上字节 | Vary | Cache-Control |
|---|---|---|---|---|
| 响应带 `no-transform` | identity | 1733 | — | private, no-store, no-transform |
| 敏感 `/reflection` | gzip | 566 | Accept-Encoding | private, no-store |
| 公开 JS | gzip | 367 | Accept-Encoding | public, max-age=3600 |
| 客户端只接受 identity | identity | 2881 | Accept-Encoding | private, no-store |

`Rack::Deflater` 内置规则：`Cache-Control` 含 `no-transform` 时**直接跳过压缩**
（见 `rack/deflater.rb` 的 `should_deflate?`）。`no-store` 本身不阻止压缩，只影响缓存。

### G. 缓解栈验证（见下节配置）

| 路径 | 编码 | 线上/解码字节 | Cache-Control |
|---|---|---|---|
| `/reflection` `/separate` `/stream` `/token-only` | **identity** | 原样 | private, no-store, **no-transform** |
| `/public/app.js` | **gzip** | 367 / 6168 | public, max-age=3600 |

敏感响应完全不压缩、并显式标注 `no-transform`；公开资源仍享受 6168→367（约 94%）的压缩收益。

## 哪些观察支持“风险可用”

1. 同页同响应中，等长的正确令牌前缀让 gzip 输出**确定性地少 1–3 字节**（B 节），32 个字符
   位置无一反转（C 节），首字符在 38 候选中可判到并列第一。
2. 信号在零噪声、确定性响应里标准差为 0（H2：15 次采样完全相同），单次请求即可区分。
3. 应用层流式分块、`sync` 开关都不消除信号（E 节），因为 gzip 字典在整个响应内持续有效。
4. 攻击面只需要两个普通能力：能在页面里注入反射文本、能读到响应的线上长度（gzip 时
   `content-length` 被删除，需读到完整响应或分块传输的累计长度）。

## 哪些前提仍依赖部署（本实验无法证明的部分）

1. **网络长度可观测性与噪声**：真实链路有 TLS 记录、TCP 分段、HTTP/2 帧、代理缓冲与填充，
   1–3 字节的差值可能被淹没；需要统计采样、多次请求，或像 BREACH 那样放大反射。本实验在
   进程内测的是“压缩器确实泄露了长度”，不是“任意网络位置都能稳定读到”。
2. **反射与秘密必须同处一个压缩上下文**：距离拉远到接近 gzip 32 KiB 窗口后信号反转/消失
   （H3：32768 字节填充时差值 −4）。部署中若反射点与令牌相隔很远或位于不同响应/不同源，
   本信道不成立。
3. **令牌需稳定且可被逐字符猜测**：每请求轮换、每请求随机填充（D 节 random 模式）会把信号
   压进噪声；CSRF 令牌若与会话绑定且长期不变才满足前提。
4. **请求必须被 gzip 处理**：攻击者只能发 `Accept-Encoding: gzip`，无法强迫服务器压缩；
   前置 CDN/WAF 的压缩策略、是否尊重 `no-transform`、是否重新压缩，都会改变结论。
5. **缓存语义**：`no-store` 不防压缩，只防缓存；若敏感页被错误地标为 `public` 且可共享缓存，
   风险模型还会叠加缓存投毒问题——这是独立的部署缺陷。
6. **长度反馈粒度**：某些客户端场景（跨域 fetch 无 CORB 读取、计时替代长度）只能拿到更粗的
   信号，可用性进一步下降。

## 可落地的缓解配置

### 方案 A（推荐）：路径/敏感门 + 公开路径继续压缩

`mitigation.rb` 的 `SelectiveDeflation` 在 Deflater 之前决策，不读取也不回滚 body，
因此流式响应保持流式；敏感路径绕过压缩并加 `no-transform`，公开路径照常 gzip。

```ruby
# config.ru / application bootstrap
app = MyApp.new
deflater = Rack::Deflater.new(app)                       # 只处理公开响应
use SidechannelLab::SelectiveDeflation,
    sensitive: %r{\A/(account|settings|csrf|admin)(\z|/)} do |env|
  deflater.call(env)                                     # 非敏感请求才进入压缩器
end
run app
```

要点：
- 敏感集合按**路由**维护（含任何带令牌/个人数据的反射页、SSE/流式端点），默认拒绝、显式放行公开路径更安全。
- 门控同时写入 `Cache-Control: no-transform`，让遵守 RFC 的中间代理也不压缩（纵深防御）。
- 公开资源（JS/CSS/静态 HTML）仍走 `Rack::Deflater`，保留压缩收益。

### 方案 B：应用打 env 标记 + Deflater 原生 `:if`

`Rack::Deflater` 的 `:if` 条件在下游 `app.call` **之后**求值，所以下游写入的 env 标记可见
（`mitigation.rb` 的 `SensitiveMarker` 与 `DEFLATE_UNLESS_MARKED`）：

```ruby
marker = ->(env) {
  status, headers, body = app.call(env)
  env["sidechannel.sensitive"] = true if headers["x-sensitive"] == "1"
  [status, headers, body]
}
use Rack::Deflater, if: ->(env, _status, _headers, _body) {
  !env["sidechannel.sensitive"]
}
run marker
```

路由知识留在应用内，适合敏感判定不能简单用路径表达的场景。

### 配套措施（任一栈都建议）

- 敏感响应固定带上 `Cache-Control: private, no-store, no-transform`（实测 `no-transform`
  会让原版 Deflater 直接跳过，无需补丁）。
- 对无法关闭压缩的遗留路由，启用每请求随机填充（参考 D 节 random 模式）与令牌轮换，
  把信号压进噪声并缩小窗口；这是补偿控制，不如直接不压缩可靠。
- 保持 `Vary: Accept-Encoding`（Deflater 自动添加），避免缓存把 gzip/identity 版本串用。
- 前置 CDN 需配置为尊重源站 `no-transform` 且不对敏感内容二次压缩。

## 验证结论

`ruby verify.rb` 的 7 项断言全部 PASS：字母表预言机可区分真实首字符、门控栈下所有敏感路由
identity + no-transform、公开 JS 仍 gzip、标记栈行为一致、`no-transform` 能关闭原版
Deflater、固定 mtime 下结果可复现、所有分块数下预言差值均存在（即分块无效、必须在压缩前阻断）。
