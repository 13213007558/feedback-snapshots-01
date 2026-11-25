# scope_gate — 单一 pynetdicom 服务上的按范围授权网关

一个 SCP 进程同时服务多个归档路由（`ARCHIVE_A` / `ARCHIVE_B`，由 Called AE
Title 选择），授权分两个阶段执行，所有结论以网关的 handler 触达日志为准。

## 两个阶段

1. **关联协商阶段**（`EVT_REQUESTED`）
   - 按 Calling AE Title 在 `ScopeRegistry` 中查出批准的 scope；
   - 把**批准的角色**（`assoc.approved_role`）和 **scope 快照**
     （`assoc.granted_scopes`）挂在关联对象上，随关联携带；
   - 把该关联自身的 supported contexts 收窄到 scope 覆盖的范围，越权的
     presentation context 在 A-ASSOCIATE-AC 中被拒（结果 0x03）；
   - 未登记的调用方 / 未知路由直接 A-ASSOCIATE-RJ。
2. **DIMSE 请求阶段**（`EVT_C_FIND` / `EVT_C_STORE`）
   - 每个请求**重新查询实时 registry**，因此在已建立的连接上，scope 被
     撤回后，后续请求仍会被挡下，返回失败状态 0x0122。

## 撤回后的定位

`ScopedArchiveServer.handler_log` 记录每个真正触达的 handler；
`block_report()` 输出每条被挡消息停在哪个阶段：

- `association-negotiation` — 协商阶段（context 被拒 / 关联被拒），
  对应的 DIMSE handler 从未触达；
- `dimse-handler` — 请求阶段，handler 触达后按当时仍允许的范围拒绝。

## 运行

```sh
.venv/bin/python -m scope_gate.demo                 # 端到端演示
.venv/bin/python -m pytest scope_gate/tests -q      # 测试
```

注意：`tests/test_scope_gate.py` 需要绑定本地端口；沙箱禁止 bind 时会
自动 skip，`tests/test_gate_logic.py`（无 socket 的逻辑测试）始终可跑。
