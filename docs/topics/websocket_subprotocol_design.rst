.. _websocket_subprotocol_design:

==========================================
WebSocket 子协议分层与握手设计（只读 / 可写）
==========================================

目标
====

前端通过 ``Sec-WebSocket-Protocol`` 声明本次连接想要的能力：

* ``v1.readonly``：只接收服务端推送，不允许提交命令；
* ``v1.commands``：可提交命令，需要已认证且具备相应权限。

同一路由同时承载两类连接，能力差异由握手阶段协商出的子协议决定，而不是
新开路由或在每条消息里做判断。本文说明三件事各应在哪一层决策、拒绝时调用方
实际收到什么，以及如何用 ``WebsocketCommunicator`` 验证完整的 accept / close
序列。

现状依据（本仓库）
==================

* ``OriginValidator``（``channels/security/websocket.py``）是一个 ASGI 中间件式
  应用：在 ``__call__(scope, receive, send)`` 里检查 ``scope["headers"]``，
  通过则 ``await self.application(scope, receive, send)``，失败则把请求交给
  ``WebsocketDenier``，其 ``connect()`` 只调用 ``self.close()``。
* 客户端在 HTTP 握手里通过 ``Sec-WebSocket-Protocol`` 上报的候选列表，ASGI
  服务器已解析进 ``scope["subprotocols"]``（一个 ``list[str]``，保持客户端
  给出的优先级顺序）。
* 服务端选中的子协议通过 ``websocket.accept`` 消息的 ``subprotocol`` 字段
  回传；``AsyncWebsocketConsumer.accept(subprotocol=None, headers=None)``
  已经支持该参数。
* ``AuthMiddlewareStack`` 在进入 consumer 之前就把 ``scope["user"]``
  解析完成，因此握手阶段可以直接读取认证结果。

分层决策：来源、认证、协商各放哪一层
====================================

原则：**传输层事实在中间件判定，应用层语义在 consumer 判定**。三层各自只看
自己负责的输入，拒绝方式统一为“不 accept，直接发 websocket.close”。

1. 来源（Origin）——安全中间件层
--------------------------------

沿用现有 ``AllowedHostsOriginValidator`` / ``OriginValidator``，放在协议栈最
外层。它只回答“这个 Origin 能不能与本服务建 WS”，与子协议、登录态无关。
失败时短路到 ``WebsocketDenier``，请求根本不会进入内层应用。

2. 认证（AuthN / AuthZ）——认证中间件 + consumer 握手
----------------------------------------------------

* “你是谁”由 ``AuthMiddlewareStack`` 完成，产物是 ``scope["user"]``，这是
  现成能力，不需要新代码。
* “这个身份能不能用可写子协议”是业务授权，放在 consumer 的 ``connect()``
  里、在调用 ``accept()`` 之前判断。原因：授权规则依赖具体业务（哪些权限、
  哪个模型），不属于可复用的传输中间件；且此时 ``scope["user"]`` 已就绪。
* 若团队希望“可写必须认证”成为跨 consumer 的统一硬约束，可加一个薄的
  ASGI 中间件（见下文 ``SubprotocolGuardMiddleware``），但它只做
  “子协议 → 最低认证要求”的机械映射，具体权限仍下沉到 consumer。

3. 子协议协商——consumer 握手（主），可选统一中间件（辅）
--------------------------------------------------------

协商的输入是 ``scope["subprotocols"]``，输出是 accept 时回传的那一个
子协议（或 close）。选择逻辑天然属于连接所属应用，默认放在
``connect()``：

* 计算交集并按**客户端优先级**选定（``next`` 取第一个命中即可，因为
  ``scope["subprotocols"]`` 已按客户端顺序排列）；
* 只读子协议可放行匿名连接；
* 命令子协议要求 ``scope["user"].is_authenticated`` 且通过权限检查，否则
  按“拒绝”处理而不是降级成只读（静默降级会让前端误以为自己可写）。

推荐的协议栈顺序（外 → 内）::

    AllowedHostsOriginValidator(
        AuthMiddlewareStack(
            SubprotocolGuardMiddleware(  # 可选，统一硬约束
                CommandConsumer.as_asgi(),
            )
        )
    )

参考实现
========

consumer 内协商（核心，必做）
-----------------------------

.. code-block:: python

    READONLY = "v1.readonly"
    COMMANDS = "v1.commands"
    SUPPORTED = (READONLY, COMMANDS)

    class CommandConsumer(AsyncWebsocketConsumer):
        async def connect(self):
            offered = self.scope.get("subprotocols", [])
            chosen = next((p for p in offered if p in SUPPORTED), None)

            if chosen is None:
                # 没有共同子协议：见下文“情形 C”
                await self.close(code=1002)
                return

            if chosen == COMMANDS:
                user = self.scope["user"]
                if not user.is_authenticated or not await self._can_issue_commands(user):
                    # 已认证但无权 / 匿名请求可写：拒绝，不降级
                    await self.close(code=4403)
                    return

            self.scope["negotiated_protocol"] = chosen
            await self.accept(subprotocol=chosen)

        async def receive(self, text_data=None, bytes_data=None):
            if self.scope.get("negotiated_protocol") != COMMANDS:
                # 纵深防御：只读连接上收到命令，直接关闭
                await self.close(code=4403)
                return
            ...  # 正常命令处理

        @database_sync_to_async
        def _can_issue_commands(self, user):
            return user.has_perm("someapp.issue_commands")

可选的统一守卫中间件
--------------------

当多个 consumer 都需要“可写必须认证”时，把机械约束抽成与
``OriginValidator`` 同形的 ASGI 包装器；它不挑业务权限，只在匿名请求
``v1.commands`` 时拒绝，其余请求原样下传：

.. code-block:: python

    class SubprotocolGuardMiddleware:
        def __init__(self, inner, commands_protocol=COMMANDS):
            self.inner = inner
            self.commands_protocol = commands_protocol

        async def __call__(self, scope, receive, send):
            if scope["type"] != "websocket":
                raise ValueError("SubprotocolGuardMiddleware 只能用于 WebSocket")
            if self.commands_protocol in scope.get("subprotocols", []):
                user = scope.get("user")
                if user is None or not user.is_authenticated:
                    # 与 WebsocketDenier 同形，但带上自定义关闭码
                    denier = _Denier(code=4401)
                    return await denier(scope, receive, send)
            return await self.inner(scope, receive, send)

    class _Denier(AsyncWebsocketConsumer):
        def __init__(self, code):
            super().__init__()
            self._code = code

        async def connect(self):
            await self.close(code=self._code)

注意该中间件必须位于 ``AuthMiddleware`` **内层**，否则 ``scope["user"]``
尚未填充。

拒绝时调用方收到什么
====================

握手阶段服务端**不发送 ``websocket.accept``**，而是发送一条
``websocket.close``。ASGI 服务器（如 Daphne）据此让 HTTP 升级失败：
浏览器端 ``new WebSocket(url, protocols)`` 不会触发 ``open``，而是触发
``error`` 随后 ``close``，``CloseEvent.code`` 取服务器给的关闭码（握手未
完成时，部分服务器会以 HTTP 403 拒绝升级，此时浏览器只报连接失败、拿不到
自定义码，因此**关闭码不能作为唯一信号，前端还要准备处理“直接打不开”**）。

约定的关闭码（均在 4000–4999 应用私有区间，避免与标准码冲突）：

* ``4401``：请求了 ``v1.commands`` 但未认证；
* ``4403``：已认证但无命令权限，或在只读连接上提交命令；
* ``1002``（标准码，协议错误）：没有共同子协议。

三种握手的 ASGI 消息过程
========================

下面用原生 ASGI 消息表示。输入事件由服务器/测试器经 ``receive`` 通道送入，
输出事件由应用经 ``send`` 通道发出。``scope`` 固定为
``{"type": "websocket", "subprotocols": [...], "headers": [...], ...}``，
三种情形 scope 结构相同，差别只在 ``subprotocols`` 与认证态。

情形 A：允许（命中只读或可写，且授权通过）
------------------------------------------

::

    # scope["subprotocols"] == ["v1.readonly"]（或 commands 且权限通过）
    receive  -> {"type": "websocket.connect"}
    send     <- {"type": "websocket.accept", "subprotocol": "v1.readonly"}
    # 连接进入开放状态，之后才允许收发数据帧：
    receive  -> {"type": "websocket.receive", "text": "..."}
    send     <- {"type": "websocket.send",   "text": "..."}
    # 任一端结束：
    receive  -> {"type": "websocket.disconnect", "code": 1000}

要点：``accept`` 的 ``subprotocol`` 必须是客户端候选列表里确实出现过的那一个，
否则属于协议违规。

情形 B：拒绝（请求了 commands 但未认证 / 无权限）
------------------------------------------------

::

    # scope["subprotocols"] == ["v1.commands"]，scope["user"] 为 AnonymousUser
    receive  -> {"type": "websocket.connect"}
    send     <- {"type": "websocket.close", "code": 4401}   # 未认证
    # 若已认证但无权限，则 code=4403
    # 不会出现 websocket.accept；服务器随后补一条 disconnect 语义：
    receive  -> {"type": "websocket.disconnect", "code": 4401}

要点：先发 close、永不 accept。``WebsocketCommunicator.connect()`` 读到第一条
``websocket.close`` 即返回 ``(False, 4401)``。

情形 C：没有共同子协议（客户端报的协议服务端一个都不支持）
---------------------------------------------------------

两种合法策略，本设计选策略 1（显式拒绝，语义最清晰）：

策略 1：直接拒绝（推荐）::

    # scope["subprotocols"] == ["v1.legacy-foo", "something-else"]
    # 与 SUPPORTED 交集为空
    receive  -> {"type": "websocket.connect"}
    send     <- {"type": "websocket.close", "code": 1002}
    receive  -> {"type": "websocket.disconnect", "code": 1002}

策略 2：不带子协议接受（仅当要兼容“完全不带 Sec-WebSocket-Protocol 的旧客户端”
时使用，见下节）::

    receive  -> {"type": "websocket.connect"}
    send     <- {"type": "websocket.accept", "subprotocol": None}

注意按 RFC 6455，客户端若上报了一个或多个子协议，服务端要么回传其中一个，
要么不建立连接；因此对“上报了但无交集”的请求不能用策略 2，只能策略 1。
``subprotocol=None`` 的 accept 只适用于客户端**根本没报**子协议的情况。

同一路由上默认旧客户端的迁移
============================

旧客户端不发送 ``Sec-WebSocket-Protocol``，即
``scope["subprotocols"] == []``。为平滑迁移，把“空列表”当作隐式只读：

.. code-block:: python

    async def connect(self):
        offered = self.scope.get("subprotocols", [])
        if not offered:
            # 旧客户端：不带子协议，按只读放行，行为与今天完全一致
            self.scope["negotiated_protocol"] = READONLY
            await self.accept()                 # subprotocol=None
            return
        chosen = next((p for p in offered if p in SUPPORTED), None)
        ...  # 同上：None -> close(1002)，commands -> 授权，readonly -> 放行

迁移分三步走，保持路由 URL 不变：

1. **阶段一（兼容）**：上线上述逻辑。旧客户端空列表 → 无 subprotocol 的
   accept，行为不变；新客户端带 ``v1.readonly``/``v1.commands`` 走新协商。
2. **阶段二（推动升级）**：前端逐步在握手时显式带上子协议；可在响应头或
   推送的第一帧里加一个 deprecation 提示，鼓励旧客户端升级，但不拒绝它们。
3. **阶段三（收口，可选）**：等旧客户端流量清零后，去掉空列表分支，让
   ``offered == []`` 也走 ``close(1002)``，强制所有连接显式协商。

关键约束：``accept(subprotocol=None)`` 只在客户端没发子协议头时合法；
一旦客户端发了候选，回包就必须是其中之一或直接 close。

用 WebsocketCommunicator 验证完整序列
=====================================

``WebsocketCommunicator(application, path, subprotocols=[...], headers=[...])``
会把候选写进 ``scope["subprotocols"]``；``connect()`` 消费**第一条**输出消息，
accept 返回 ``(True, chosen_subprotocol)``，close 返回
``(False, close_code)``。因此三种握手各对应一个明确断言，再用
``disconnect()`` 排空，确认没有多余输出（完整 accept/close 序列）。

.. code-block:: python

    import pytest
    from channels.testing import WebsocketCommunicator

    @pytest.mark.asyncio
    async def test_allowed_readonly():
        communicator = WebsocketCommunicator(
            app, "/ws/cmd/", subprotocols=["v1.readonly"]
        )
        connected, subprotocol = await communicator.connect()
        assert connected is True
        assert subprotocol == "v1.readonly"          # accept 回传协商结果
        await communicator.disconnect()

    @pytest.mark.django_db(transaction=True)
    @pytest.mark.asyncio
    async def test_denied_anonymous_commands():
        communicator = WebsocketCommunicator(
            app, "/ws/cmd/", subprotocols=["v1.commands"]
        )
        connected, code = await communicator.connect()
        assert connected is False
        assert code == 4401                          # 第一条输出即 close
        await communicator.disconnect()

    @pytest.mark.asyncio
    async def test_no_common_subprotocol():
        communicator = WebsocketCommunicator(
            app, "/ws/cmd/", subprotocols=["v1.legacy-foo"]
        )
        connected, code = await communicator.connect()
        assert connected is False
        assert code == 1002
        await communicator.disconnect()

    @pytest.mark.asyncio
    async def test_legacy_client_no_subprotocol():
        communicator = WebsocketCommunicator(app, "/ws/cmd/")  # 不带 subprotocols
        connected, subprotocol = await communicator.connect()
        assert connected is True
        assert subprotocol is None                   # 旧客户端：无 subprotocol accept
        await communicator.disconnect()

验证“完整序列”的两个要点：

* ``connect()`` 本身就断言了首条输出只能是 ``websocket.accept`` 或
  ``websocket.close``（见 ``channels/testing/websocket.py``），拒绝路径若误发
  了 accept 会在这里直接失败。
* 对只读连接的纵深防御（收到命令帧应被关闭），可在 accept 后
  ``send_to(...)`` 再用 ``communicator.receive_output()`` 断言收到
  ``{"type": "websocket.close", "code": 4403}``，而不是普通数据帧。
* 若要绕过 ``connect()`` 的便捷封装、逐条核对原始 ASGI 消息，可直接调用
  ``communicator.send_input({"type": "websocket.connect"})`` 后
  ``await communicator.receive_output()``，对返回字典逐字段断言。
