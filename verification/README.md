# 单次工作预算验证

这个目录用两份普通本地文档验证 `bleach.budget.Budget`：解析（parse）、
清洗（clean）和可选的链接处理（linkify）共享同一个单次预算。

## 文件

- `comment_long_text.txt` — 文档 A：约 1700 字的普通长评论，没有 URL/email，
  因此不触发链接转换。
- `comment_with_links.html` — 文档 B：约 40 个普通 `<li>` 节点加一段裸链接。
  解析与清洗在降低后的额度内可以通过，计入链接转换后才在 `linkify` 环节超额。
- `comment_short.txt` — 文档 C：失败后用同一个 `Cleaner` 实例/配置处理的普通短文。
- `verify_budget.py` — 可重复运行的核对脚本（自带断言，全部通过时退出码为 0）。
- `verification_record.md` / `verification_run.log` — 最近一次运行的完整记录。
- `outputs/` — 成功调用的最终输出；文档 B 只写 `doc_b_BLOCKED.txt` 失败快照，
  不产生任何“完整结果”文件。

## 运行

```sh
.venv/bin/python verification/verify_budget.py
```

脚本使用人工降低的固定额度 `LOWERED_QUOTA = 4400`（默认建议上限为
`Budget.DEFAULT_LIMIT = 500000`）。它先跑一次 `limit=None` 的纯计量基线，
记录每个阶段的工作量，再通过同一个 `Cleaner` 依次处理 A、B、C。
