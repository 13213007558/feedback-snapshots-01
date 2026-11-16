# ASN.1 授权字段升级评审（asn1tools）

运行：

    python3 run_review.py

产物：

- `artifacts/review_table.txt`：逐“用例 × 编码 × 方向”的 DECODE / MEANING / 再编码字节判定与线型 hex。
- `artifacts/results.json`：同样数据的机器可读版本。
- `REPORT.md`：决策矩阵、线型字节↔字段对照、反例与换版本/重签结论。
- `schemas/`：每个变更成对显式提供的旧/新 ASN.1 schema，字段同一性由 `run_review.py` 的 `shared_fields` 显式声明，不做类型名推断。

判定口径见 `REPORT.md` 第 0 节。编码覆盖 BER、PER（aligned）、UPER（unaligned）。
