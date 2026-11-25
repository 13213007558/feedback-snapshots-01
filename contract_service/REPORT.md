# 合同合并服务交付说明

严格模式把三件事分开判定，全部授权通过后才产生任何输出文件。

## 三道独立闸门

1. **查看（VIEW）** — 密码能解密打开文档即可。能打开 ≠ 获准合并。
2. **合并（MERGE）** — 会话实际获得的权限必须包含 `EXTRACT` 和
   `ASSEMBLE_DOC`。所有者密码打开视为全权；用户密码打开则按文档
   `/P` 权限位判定，且 AES-256 文档若 `/Perms` 完整性校验失败，
   权限位一律不可信、直接拒绝。
3. **导出（EXPORT）** — 合并结果按自己的加密策略落盘，与任何输入的
   密码和权限无关。

## 本次实际合并的内容

- `contract_a.pdf`（2 页，用户密码 `view-a-pass` 打开，权限位本身允许合并）
- `contract_b.pdf`（3 页，用户密码仅可查看，改用所有者密码 `owner-b-pass` 获准）
- 合计 5 页 → `merged_contract.pdf`

## 输出按哪套密码和权限打开

- 用户密码（打开用）：`merged-view-pass`；所有者密码：`merged-owner-pass`
- 算法 AES-256，权限仅授予 `PRINT` + `EXTRACT`（不含 `MODIFY` 等）
- 任何输入的密码都打不开输出（测试已断言 `view-a-pass` 解密失败）

## 权限不足时在写出前停住的证据

- 授权全部在内存中完成，输出文件在最后一行才写入；
  `test_denied_merge_writes_nothing` 断言失败后目标文件不存在。
- 演示运行实录（`demo.py` 场景二）：
  `stopped BEFORE writing: contract_b.pdf: opens fine, but merging is not
  granted (missing: EXTRACT|ASSEMBLE_DOC)`，随后 `output file exists
  afterwards: False`。

## 同一份加密空白模板的两种角色

`blank_template.pdf`（用户密码 `template-view-pass`，所有者密码
`template-owner-pass`，权限位仅 PRINT）：

- 用户密码 → **查看获准**（密码能打开即可）
- 用户密码 → **正式导出（合并）拒绝**（缺 EXTRACT/ASSEMBLE_DOC）
- 所有者密码 → **正式导出获准**（所有者密码视为全权）

## 复现

```sh
.venv/bin/python contract_service/demo.py                      # 演示三场景
.venv/bin/python -m pytest -q --disable-socket contract_service/tests/   # 5 passed
```
