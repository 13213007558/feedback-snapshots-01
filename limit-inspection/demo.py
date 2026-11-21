"""
极小演示：上线前检查某条 Flask 路由会被 flask-limiter 执行哪些限额。

运行（仓库根目录）:
    .venv/bin/python limit-inspection/demo.py

对比两条路径：
  1. inspect_route() —— 离线检查入口：只解析 + test()/get_window_stats()，不扣配额；
  2. client.get()    —— 真实请求调用链：before_request 里 hit()，扣配额。
"""

from flask import Flask, request

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# ---- 静态配置：构造期写死，离线可读 ----------------------------------------
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100/minute"],  # 静态默认限额：未被装饰的路由继承
    headers_enabled=True,
)


def tenant_key():
    """动态 key：取到哪个租户，只有请求进来才知道。"""
    return request.headers.get("X-Tenant", get_remote_address())


def skip_internal():
    """运行时例外：是否豁免，只有请求进来才知道。"""
    return request.headers.get("X-Internal") == "yes"


@app.route("/api/report")
@limiter.limit("3/minute", key_func=tenant_key, exempt_when=skip_internal)
@limiter.limit("20/hour", key_func=tenant_key)
def report():
    return "report"


@app.route("/api/echo")
def echo():  # 未装饰：继承静态 default_limits
    return "echo"


@app.route("/api/health")
@limiter.exempt
def health():
    return "ok"


# ---- 请求内观察入口：只有在真实请求链里才有值 -------------------------------
@app.after_request
def show_evaluated_limits(response):
    # Limiter.current_limits 由 __evaluate_limits 在 before_request 阶段填充，
    # 记录本次请求实际评估过的每一条限额（含动态 key 的实际求值结果）。
    for rl in limiter.current_limits:
        print(
            f"    [in-request] evaluated {rl.limit} key={rl.key!r} "
            f"breached={rl.breached} remaining={rl.remaining}"
        )
    return response


# ---- 离线检查入口：与 CLI `flask limiter limits --key` 同源 -----------------
def inspect_route(path, method="GET", probe_headers=None):
    """解析 path 对应路由会被评估的限额，并用 test() 探测配额（只测不扣）。

    与真实调用链共用 limit_manager.resolve_limits()；与 CLI 一样包在
    test_request_context 里 —— 动态 key / exempt_when 读到的是
    probe_headers 构造出来的“探针请求”，不是未来的真实请求。
    """
    with app.test_request_context(path, method=method, headers=probe_headers or {}):
        endpoint = request.endpoint
        manager = limiter.limit_manager
        exemption = manager.exemption_scope(app, endpoint, request.blueprint)
        defaults, decorated = manager.resolve_limits(app, endpoint, request.blueprint)
        print(f"[inspect] {method} {path} -> endpoint={endpoint!r} exemption={exemption}")
        snapshot = {}
        if not defaults and not decorated:
            print("    (no limits apply)")
        for lim in defaults + decorated:
            key = lim.key_func()  # 动态 key 在此探针上下文里求值
            scope = lim.scope_for(endpoint, method)  # 与 __evaluate_limits 相同的 args 推导
            args = [key, scope]
            would_pass = limiter.limiter.test(
                lim.limit, *args, cost=lim.deduction_amount
            )  # 只测不扣
            _, remaining = limiter.limiter.get_window_stats(lim.limit, *args)
            print(
                f"    limit={lim.limit} key={key!r} scope={scope!r} "
                f"exempt={lim.is_exempt} remaining={remaining}/{lim.limit.amount} "
                f"would_pass={would_pass}"
            )
            snapshot[str(lim.limit)] = remaining
        return snapshot


if __name__ == "__main__":
    tenant = {"X-Tenant": "acme"}

    print("== 1. 离线检查：不消耗配额 ==")
    snap1 = inspect_route("/api/report", probe_headers=tenant)
    snap2 = inspect_route("/api/report", probe_headers=tenant)
    assert snap1 == snap2, "检查动作本身消耗了配额！"
    print(f"    -> 连续两次检查结果一致 {snap1}，检查未消耗配额\n")
    inspect_route("/api/report", probe_headers={**tenant, "X-Internal": "yes"})
    inspect_route("/api/echo", probe_headers=tenant)
    inspect_route("/api/health")

    print("\n== 2. 真实请求：before_request -> hit()，消耗配额 ==")
    client = app.test_client()
    resp = client.get("/api/report", headers=tenant)
    print(f"  request #1: {resp.status_code}")
    snap = inspect_route("/api/report", probe_headers=tenant)
    assert resp.status_code == 200 and snap["3 per 1 minute"] == 2
    print("    -> 真实请求扣了 1；夹在中间的检查没有再扣")

    for i in (2, 3, 4):
        resp = client.get("/api/report", headers=tenant)
        retry = resp.headers.get("Retry-After", "")
        print(f"  request #{i}: {resp.status_code} {f'Retry-After={retry}' if retry else ''}")
    assert resp.status_code == 429

    resp = client.get("/api/report", headers={**tenant, "X-Internal": "yes"})
    print(f"  internal request: {resp.status_code}  (运行时豁免，只有请求内才能确认)")
    assert resp.status_code == 200

    print("\n== 3. 响应头里的请求内证据 ==")
    resp = client.get("/api/echo")
    print(f"  GET /api/echo -> {resp.status_code}, "
          f"X-RateLimit-Remaining={resp.headers.get('X-RateLimit-Remaining')}")

    print("\nALL CHECKS PASSED")
