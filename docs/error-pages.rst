.. _error-pages-chapter:

============================================
错误页接入 CSP：404、500 与重定向对照指南
============================================
本文面向把 ``Content-Security-Policy`` 覆盖到生产环境 HTML 错误页、同时保留本地
``DEBUG=True`` 诊断页可用性的团队。结论基于 django-csp 4.0 的 ``csp/middleware.py``
和 Django 5.x 的错误处理链路（``django/core/handlers/``），文中所有行为均可用
Django 测试客户端复现，对应测试见 ``csp/tests/test_error_pages.py``。

.. note::

   下文的“强制头”指 ``Content-Security-Policy``（常量 ``csp.constants.HEADER``），
   “报告头”指 ``Content-Security-Policy-Report-Only``（``HEADER_REPORT_ONLY``）。
   两条头在中间件里走完全对称的分支，区别只在配置项与豁免属性名。

响应是在哪一层生成的
====================

django-csp 本身不产生错误响应，它只在出口处统一加工响应。理解三类响应的生成位置，
才能判断头由谁加上、nonce 还来不来得及。

Django 启动时，每一层中间件都会被
``django.core.handlers.exception.convert_exception_to_response`` 包一层
``try/except``（见 ``exception.py``）。因此任何内层（视图、更靠内的中间件）抛出的
异常，都会在某一层被转成 ``HttpResponse``，再逐层向外返回；外层中间件的
``process_response`` 拿到的始终是一个响应对象而不是异常。

三类对照
--------

* **404**：URL 解析失败或视图抛出 ``django.http.Http404`` 后，由
  ``django.core.handlers.exception.response_for_exception`` 接住。
  ``DEBUG=False`` 时调用 ``django.views.defaults.page_not_found``（即
  ``handler404``），渲染 ``404.html``；``DEBUG=True`` 时改用
  ``django.views.debug.technical_404_response`` 输出技术诊断页。
* **异常转 500**：未被 ``process_exception`` 中间件处理的异常进入
  ``handle_uncaught_exception``。``DEBUG=False`` 时调用
  ``django.views.defaults.server_error``（即 ``handler500``）渲染 ``500.html``；
  ``DEBUG=True`` 时由 ``debug.technical_500_response`` 输出带堆栈的技术页。
  无论哪条分支，转换出的 500 响应仍会向上穿过 ``CSPMiddleware.process_response``。
* **普通重定向**：视图正常返回 ``HttpResponseRedirect``/``HttpResponsePermanentRedirect``，
  状态码 3xx，不经过任何错误处理分支。它和 200 响应走的是同一条出口路径。

关键结论：**头永远由 ``CSPMiddleware.process_response`` 在出口统一生成**，错误视图
只负责产生响应体。中间件并不关心响应来自正常视图还是错误处理器，它只看状态码、
``DEBUG`` 标志以及响应上的几个属性。

DEBUG 诊断页的豁免分支
======================

``CSPMiddleware.process_response`` 的第一件事就是诊断页豁免（``middleware.py``）：

.. code-block:: python

    exempted_debug_codes = (
        http_client.INTERNAL_SERVER_ERROR,  # 500
        http_client.NOT_FOUND,              # 404
    )
    if response.status_code in exempted_debug_codes and settings.DEBUG:
        return response

含义与边界：

* 仅当 **状态码属于 {404, 500} 且 ``settings.DEBUG`` 为真** 时直接返回，整条 CSP
  逻辑（含报告头）都跳过，技术诊断页里的内联脚本、样式不受 CSP 约束，本地调试保持可用。
* 这是基于状态码的判断，不关心响应是不是 ``debug.technical_*`` 生成的。因此
  ``DEBUG=True`` 下你自定义的 404/500 视图同样不会拿到头——本地开发不要靠自定义
  错误页来验证 CSP。
* 豁免名单只有 404 和 500。``DEBUG=True`` 下的 400、403 页面（技术页或自定义页）
  仍会正常加上 CSP 头。
* 3xx 重定向不在名单内，任何环境都会加头。
* 生产环境 ``DEBUG=False`` 时该分支永不命中，404/500 与其他响应一样进入策略构建，
  这正是“把 CSP 覆盖到生产错误页”不需要额外开关的原因——默认行为已经覆盖。

nonce 什么时候已经来不及
========================

nonce 是惰性的，时机由“谁在响应处理前读取了 ``request.csp_nonce``”决定。

生命周期
--------

1. ``process_request`` 给每个请求挂上 ``CheckableLazyObject``（惰性 nonce），此时
   并未生成随机值，``bool(request.csp_nonce)`` 为 ``False``。
2. 视图/模板/内层中间件执行 ``str(request.csp_nonce)`` 时才调用 ``_make_nonce``
   生成 16 字节随机值并缓存到 ``request._csp_nonce``。
3. ``process_response`` 调用 ``get_policy_parts`` 读取 ``request._csp_nonce``：
   有值则把策略里的 ``csp.constants.NONCE`` 哨兵替换成 ``'nonce-<值>'``；没值则
   在 ``build_policy`` 里把 ``NONCE`` 哨兵静默剔除（见 ``utils.py``），策略其余部分
   照常输出。
4. 头写完之后，如果此前从未生成过 nonce，中间件会把 ``request.csp_nonce`` 替换成
   一个访问即抛 ``csp.exceptions.CSPNonceError`` 的惰性对象，防止有人在头已固化后
   才试图补 nonce（这在安全上没有意义，因为头已经发出去了）。若 nonce 早已生成，
   之后继续读取是安全的，返回同一个值。

因此“来不及”的判定点就是 ``CSPMiddleware.process_response``：在它之后才读取
nonce，要么拿到 ``CSPNonceError``（之前没读过），要么为时已晚（头已写死）。

三类响应的 nonce 可达性
-----------------------

* **重定向**：响应没有 HTML 体，通常不需要 nonce；不读取就不带 nonce，头仍正常生成。
  若内层逻辑读取过，nonce 一样会进头。
* **404（生产）**：响应在错误处理器中生成，但生成动作发生在中间件链内部、
  ``process_response`` 之前，所以自定义 ``404.html`` 里读取
  ``{{ request.csp_nonce }}`` 完全来得及。
* **异常转 500（生产）**：原视图在渲染前就抛异常了，但 ``handler500`` 是在异常
  转换阶段、同样早于出口中间件被调用的。只要自定义 500 视图在渲染时读取了
  ``request.csp_nonce``，nonce 就会进入响应头。

两个必须避开的坑
~~~~~~~~~~~~~~~~

* **Django 默认 ``server_error`` 不给模板传 request**。
  ``django/views/defaults.py`` 里 500 视图调用的是 ``template.render()``（无参数），
  模板上下文里没有 ``request`` 变量，``{{ request.csp_nonce }}`` 会被 Django 模板
  系统解析为空字符串（``string_if_invalid`` 默认为空），表现为
  ``<script nonce="">``，且 nonce 从未生成、头里也没有 nonce。对比之下默认 404 视图
  调用的是 ``template.render(context, request)``。需要 nonce 的 500 页应自定义
  ``handler500`` 并显式把 request 传进上下文：

  .. code-block:: python

      # views.py
      from django.http import HttpResponseServerError
      from django.template import loader


      def server_error(request):
          template = loader.get_template("500.html")
          return HttpResponseServerError(
              template.render({"request": request}, request)
          )

  .. code-block:: python

      # urls.py（或项目 ROOT_URLCONF）
      handler500 = "myapp.views.server_error"

* **``render(request=request)`` 不等于模板里有 ``request`` 变量**。给
  ``Template.render`` 传第二个位置参数只是为上下文处理器绑定 request；普通模板变量
  仍需通过 context 字典传入（``render({"request": request}, request)``），或使用
  ``django.template.loader.render_to_string`` 配合 ``RequestContext``。用
  ``django.shortcuts.render(request, "x.html", {...})`` 则没有这个问题，它内部使用
  ``RequestContext``，配合 ``django.template.context_processors.request`` 即可在模板
  中直接访问 ``request``。

错误页策略建议
--------------

* 错误页尽量不依赖内联脚本，从源头免去 nonce 依赖；需要内联脚本时再走上面的自定义
  ``handler500``/``handler404`` 方案。
* 不要为了让错误页“宽松”而在生产关闭头或加 ``'unsafe-inline'``；默认分支已经会给
  错误页加与全站一致的策略。
* 若错误页本身渲染失败（例如自定义 ``handler500`` 又抛异常），Django 会退回到内置
  兜底错误页，该响应仍会经过出口中间件并带上 CSP 头。

应用/视图预设头的处理
=====================

中间件对已存在的头采取“不覆盖”策略，强制头与报告头各自独立判断：

.. code-block:: python

    no_header = HEADER not in response
    is_not_exempt = getattr(response, "_csp_exempt", False) is False
    policy = getattr(settings, "CONTENT_SECURITY_POLICY", None) or {}
    prefixes = policy.get("EXCLUDE_URL_PREFIXES", None) or ()
    is_not_excluded = not request.path_info.startswith(tuple(prefixes))
    if no_header and is_not_exempt and is_not_excluded:
        response[HEADER] = csp

要点：

* **响应已自带同名头时，中间件原样保留，不追加、不合并非覆盖**（测试
  ``test_dont_replace`` 锁定了该行为）。视图、装饰器、更外层的代理都可以用
  ``response["Content-Security-Policy"] = ...`` 预设策略，中间件不会改写它。
* 报告头独立判断：响应预设了强制头，只影响强制头分支；报告头仍按
  ``CONTENT_SECURITY_POLICY_REPORT_ONLY`` 的配置决定是否写入，反之亦然。
* 另外两个跳过条件：响应带 ``_csp_exempt = True``（由 ``@csp_exempt()`` 设置，
  报告头对应 ``_csp_exempt_ro``）；请求路径命中配置里的
  ``EXCLUDE_URL_PREFIXES``（注意必须是 list/tuple，字符串会触发 ``csp.E002`` 检查，
  因为字符串会被拆成字符导致全站漏加头）。
* 装饰器 ``@csp``/``@csp_update``/``@csp_replace`` 并不直接写头，而是在响应上挂
  ``_csp_config``/``_csp_update``/``_csp_replace`` 属性，由中间件在出口读取后合并
  生成头。异常发生在装饰视图内部时，这些属性挂在的那个响应根本不会返回，因此错误页
  拿到的是 ``handler500`` 新生成的响应——它不带任何视图级装饰属性，只适用全局配置。
  要给错误页定制策略，应在自定义错误视图内部设置这些属性，或子类化中间件重写
  ``get_policy_parts``。

中间件顺序的依据
================

``MIDDLEWARE`` 是洋葱模型：列表越靠外的中间件，``process_request`` 越早执行、
``process_response`` 越晚执行。django-csp 的顺序要求全部来自这两个钩子的职责：

1. **nonce 读取方必须排在 ``CSPMiddleware`` 之内侧（列表中位于其后）**。
   内侧中间件、视图、模板的执行窗口位于 CSP 的 ``process_request`` 之后、
   ``process_response`` 之前，这是 nonce 唯一有效的生命周期。若某中间件需要在自己的
   ``process_response`` 里读取 ``request.csp_nonce``，它必须排在 CSP 外侧（列表中位于
   其前），这样它的响应处理晚于 CSP 写头——但此时若 nonce 尚未生成会直接抛
   ``CSPNonceError``；官方推荐做法是再加一层内侧中间件提前
   ``str(request.csp_nonce)`` 把 nonce 生成出来（参见 ``docs/nonce.rst``）。
2. **修改 CSP 头的中间件要与 CSP 明确排序**。由于中间件不覆盖已存在的头，若外侧
   中间件想统一改写头，它会先看到 CSP 已写好的头；若内侧中间件预设了头，CSP 会让其
   生效。谁先谁后决定最终值，需要按“预设优先还是统一策略优先”显式排好。
3. **错误处理不依赖 CSP 的位置，但依赖洋葱包装**。Django 给每层中间件都包了
   异常转换，因此只要 CSP 在 ``MIDDLEWARE`` 中正常注册，内层任何位置抛出的异常转成
   的 404/500 都会流经它的 ``process_response``。唯一例外是 CSP 自身的
   ``process_request`` 抛错——这种情况下它自己的 ``process_response`` 不会执行，
   应保持该钩子无副作用、不依赖下游资源。
4. 与 Django 内置中间件协作时，把 CSP 放在常规业务中间件附近即可，例如：

   .. code-block:: python

       MIDDLEWARE = [
           "django.middleware.security.SecurityMiddleware",
           "django.contrib.sessions.middleware.SessionMiddleware",
           "django.middleware.common.CommonMiddleware",
           "django.middleware.csrf.CsrfViewMiddleware",
           "django.contrib.auth.middleware.AuthenticationMiddleware",
           "csp.middleware.CSPMiddleware",
           # 需要读取 csp_nonce 的自定义中间件放在这之后（内侧）
       ]

   ``installation.rst`` 同时说明：没有其他中间件触碰 CSP 头或 nonce 时，顺序不影响
   基础加头功能。

用 Django 测试客户端核对的验证矩阵
==================================

``csp/tests/test_error_pages.py`` 用 ``django.test.Client`` 走完整中间件链复现以下
矩阵（构造 500 时注意 ``Client(raise_request_exception=False)``，否则测试客户端会
直接把视图异常抛出来而不是返回转换后的 500 响应）。预设策略沿用测试配置
``CONTENT_SECURITY_POLICY = {"DIRECTIVES": {"default-src": [SELF, NONCE]}}``。

.. list-table::
   :header-rows: 1
   :widths: 18 14 22 26 20

   * - 场景
     - 状态码
     - 响应生成层
     - 预期 ``Content-Security-Policy``
     - nonce 行为
   * - 生产访问不存在的 URL
     - 404
     - ``handler404`` / ``page_not_found``
     - 有头，``default-src 'self'``（模板未读 nonce）
     - 未读取则哨兵被剔除；自定义模板读取后带 nonce
   * - 生产视图抛未捕获异常
     - 500
     - 异常转换 → ``handler500``
     - 有头，``default-src 'self'``
     - 自定义 ``handler500`` 显式传 request 后可带 nonce；默认 500 视图拿不到 request
   * - 生产普通重定向
     - 302
     - 视图直接返回
     - 有头，``default-src 'self'``
     - 通常不读取，无头内 nonce
   * - 视图预设同名 CSP 头
     - 任意
     - 视图
     - 保留预设值，中间件不覆盖
     - 与预设头内容无关
   * - ``DEBUG=True`` 触发异常
     - 500
     - ``debug.technical_500_response``
     - **无头**（诊断页豁免）
     - 整条 CSP 分支跳过
   * - ``DEBUG=True`` 访问不存在的 URL
     - 404
     - ``debug.technical_404_response``
     - **无头**（诊断页豁免）
     - 整条 CSP 分支跳过
   * - ``DEBUG=True`` 普通重定向
     - 302
     - 视图直接返回
     - 有头，``default-src 'self'``
     - 不受豁免影响
   * - 头写完后才访问 ``request.csp_nonce``
     - 任意
     - —
     - 头已固化
     - 此前未生成则抛 ``CSPNonceError``

在自己项目里写最小核对测试
--------------------------

.. code-block:: python

    from django.test import Client, override_settings


    def test_production_error_pages_carry_csp(settings):
        settings.DEBUG = False
        client = Client(raise_request_exception=False)

        not_found = client.get("/definitely-not-a-route/")
        assert not_found.status_code == 404
        assert "Content-Security-Policy" in not_found

        server_error = client.get("/view-that-raises/")
        assert server_error.status_code == 500
        assert "Content-Security-Policy" in server_error


    @override_settings(DEBUG=True)
    def test_debug_technical_pages_are_exempt():
        client = Client(raise_request_exception=False)
        response = client.get("/view-that-raises/")
        assert response.status_code == 500
        assert "Content-Security-Policy" not in response

运行仓库内的矩阵测试：

.. code-block:: bash

    .venv/bin/python -m pytest -o addopts= csp/tests/test_error_pages.py -v

排查清单
========

* 生产错误页没有头：确认 ``DEBUG=False``、路径未命中 ``EXCLUDE_URL_PREFIXES``、
  响应没有被设置 ``_csp_exempt``，以及没有更内侧的中间件预设同名头。
* 头里没有 nonce：确认模板中的 ``request`` 变量真实存在（500 默认视图不传 request），
  且读取发生在响应进入 ``CSPMiddleware.process_response`` 之前。
* 测试里拿不到 500 响应而是直接异常：测试客户端加
  ``raise_request_exception=False``。
* 本地调试页样式/脚本被 CSP 拦截：确认 ``DEBUG=True`` 且响应状态码确为 404 或 500；
  400/403 不在豁免名单内。
* 自定义了 ``handler500`` 但策略没变：视图装饰器作用于原视图，异常后返回的是错误
  视图的新响应；请在错误视图内设置 ``_csp_*`` 属性或在中间件子类中按状态码定制。
