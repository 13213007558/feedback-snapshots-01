# flask-limiter 路由限额上线前检查方法

目标：在不消耗真实配额的前提下，确认某条 Flask 路由最终会被评估哪些限额；
并明确哪些信息可以离线确定、哪些必须在真实请求内观察。

配套演示：`limit-inspection/demo.py`（运行 `.venv/bin/python limit-inspection/demo.py`，
末尾 `ALL CHECKS PASSED` 即验证通过）。

## 1. 真实请求调用链（配额在哪里被扣）

1. `init_app` 把 `Limiter._check_request_limit` 挂到 `app.before_request`，
   把 `__inject_headers` 挂到 `app.after_request`（`flask_limiter/_extension.py:492`）。
2. `_check_request_limit`（`flask_limiter/_extension.py:1142`）
   → `__filter_limits`（同文件 `:963`）检查路由/蓝图级豁免后，调用
   `LimitManager.resolve_limits`（`flask_limiter/_manager.py:75`）汇总
   application / default / blueprint / 装饰器限额。
3. `__evaluate_limits`（`flask_limiter/_extension.py:1011`）逐条：
   - `lim.is_exempt`（此时才调用 `exempt_when()`）和 `lim.method_exempt`
     （读 `request.method`）决定是否跳过；
   - `lim.key_func()` 此时才求值 —— 动态 key 在这里变成具体值；
   - `lim.scope_for(endpoint, request.method)` 推出存储桶 scope；
   - 默认调 `limiter.hit()` —— **这一步扣配额**；若配了 `deduct_when`，
     先 `test()`，到 after_request 的 `__check_conditional_deductions`
     （`:884`）按响应决定是否补扣。
4. 评估结果写入 `LimiterContext`，请求内可读 `Limiter.current_limit` /
   `Limiter.current_limits`（`:854`）；after_request 据此写
   `X-RateLimit-*` 响应头。

## 2. 呈现 / 检查入口

- **CLI（需 `pip install flask-limiter[cli]`，本仓库 pyproject.toml:39 注册）**
  - `flask limiter config`：静态配置全景（key_func、storage、strategy、
    default/application limits、headers 等），见 `flask_limiter/commands.py:50`。
  - `flask limiter limits --path /api/report --method GET --key acme`：
    逐路由列出解析到的限额及来源（route/blueprint/default），并用
    `limiter.test()` + `get_window_stats()` 探测该 key 的剩余配额
    （`flask_limiter/_cli.py:58` `render_limit_state`）—— **test 不扣配额**。
- **编程式（与 CLI 同源，demo.py 的 `inspect_route()` 即此法）**
  - `limiter.limit_manager.resolve_limits(app, endpoint, blueprint)`
  - `limiter.limit_manager.exemption_scope(app, endpoint, blueprint)`
  - `limiter.limiter.test(limit, *args)` / `limiter.limiter.get_window_stats(...)`
- **请求内**：`limiter.current_limit` / `limiter.current_limits`
  （只能在 before/after request 钩子里读到，teardown 时清空）。

## 3. 能离线确定 vs 必须请求内观察

| 信息 | 离线可确定？ | 说明 |
| --- | --- | --- |
| 静态限额字符串（`"3/minute"`、`default_limits`） | ✅ | `resolve_limits` 直接列出 |
| 限额来源（route / blueprint / default / application） | ✅ | CLI 输出带 `[route]` 等标签 |
| `override_defaults`、`methods`、`per_method`、`scope` 规则 | ✅ | 静态声明 |
| 路由/蓝图豁免（`@limiter.exempt`） | ✅ | `exemption_scope()` 返回 `ExemptionScope` |
| storage / strategy / headers 配置 | ✅ | `flask limiter config` |
| 动态 `key_func` 的**取值** | ❌ 只能看到函数名 | 请求内才调用；离线可用探针 header 模拟 |
| 动态限额字符串（callable `limit_value`） | ❌ | resolve 时才求值，可能依赖请求上下文 |
| `exempt_when()` 的判定 | ❌ | 依赖真实请求；探针上下文只能模拟 |
| `method_exempt` | ❌ | 依赖 `request.method` |
| `cost` callable、`deduct_when(response)` | ❌ | 后者甚至依赖响应 |
| 实际 remaining / reset_at | ❌ | 存储状态随时在变 |

边界提醒：CLI 和 `inspect_route()` 都跑在 `test_request_context()` 里
（`commands.py:208`），动态 key / `exempt_when` 读到的是**探针请求**的值，
不是未来真实请求的值。要确认真实判定，只能在请求链里观察：
after_request 打 `current_limits`，或看响应的 `X-RateLimit-*` / 429。

## 4. 检查不耗配额的纪律

- 只用 `limiter.test()` 和 `get_window_stats()`，**绝不调 `hit()`**；
  CLI `--key` 内部就是 `test()`。
- 验证方法：连续检查两次，remaining 必须不变（demo.py 第 1 段断言）。
- 反向验证：真实请求之间夹一次检查，remaining 只被请求扣 1
  （demo.py 第 2 段断言）。

## 5. demo.py 演示要点（已验证输出）

- `/api/report`：两条装饰器限额（动态租户 key + `exempt_when`），
  装饰器限额默认 `override_defaults=True`，故不继承 `100/minute` 默认限额。
- `/api/echo`：未装饰，离线可见继承静态 `default_limits`。
- `/api/health`：`@limiter.exempt`，离线可见 `ExemptionScope.APPLICATION|META|DEFAULT`。
- 真实请求 4 连发：200/200/200/429；第 4 次里 `3/minute` breached，
  但 `20/hour` 仍被评估并扣减（默认 `fail_on_first_breach=False`）——
  这类交互只有请求内观察才能发现。
- 配额用光后带 `X-Internal: yes` 的请求仍 200：运行时豁免只能请求内确认。
