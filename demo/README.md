# 显式去标识导出（fail-closed de-identification export）

采集端只读取部分 DICOM 信息（`dcmread(..., defer_size=...)` 产生延迟元素），
之后才拷贝并导出给外部审阅。本示例用一个**显式批准的去标识策略**和**两阶段
准备/提交**流程保证写出结果确定、可核对，且在来源缺失时明确失败。

## 设计要点

- `deid_export/core.py`
  - `DeidentificationStrategy`：显式的**允许清单（allow-list）**。同一次批准
    同时作用于尚未展开的延迟元素、已经访问而转成原生值的元素，以及深拷贝得到
    的数据集——过滤发生在所有元素物化之后，因此不存在“读过就漏过”的差异。
  - 阻断标签（姓名、ID、出生日期、机构、自由文本等）即使被误加入允许清单也一定
    被移除；所有奇数组（私有）元素一律不导出；UID 按本次导出稳定重映射；像素数据
    默认原样保留。
  - `prepare_deidentified()`：先 `deepcopy`（不改动调用方数据集），再递归物化
    全部延迟元素。源文件被移走/缺失时抛 `SourceUnavailableError`，**不回退到未经
    核对的内存属性**，且此时尚未打开任何输出文件。
  - `PreparedDataset.commit()` / `export_deidentified()`：先写同目录临时文件，
    重新打开确认可读后用 `os.replace` 原子替换。失败时清理临时文件，绝不会留下能
    被当成正式成品的文件。准备完成后数据集与源文件脱钩，源被移走仍可提交。

## 目录

- `deid_export/`：可复用的去标识导出包。
- `demo/build_samples.py`：生成两个仅含虚构身份信息的小型 DICOM 档案（含私有
  标识元素与带嵌套姓名的序列）。
- `demo/run_verification.py`：端到端核对脚本，见下。

## 运行

在仓库根目录（沙箱中需把 `HOME` 指到可写目录，供 pydicom 建立配置目录）：

```sh
HOME="$TMPDIR/fakehome" PYTHONPATH="$PWD" \
  .venv/bin/python demo/run_verification.py
```

## 验证场景

1. 样本 A：延迟读取后先访问 `PatientName`（转为原生元素），再深拷贝导出，验证
   “先读取再复制”。
2. 样本 B：完全延迟、不访问任何值直接深拷贝导出，验证“直接复制”。
3. 样本 A 副本：完整准备后再移走源文件，提交仍成功（已自包含）。
4. 样本 B：保持延迟、先移走源再导出，断言抛 `SourceUnavailableError`，且无正式
   输出、无 `.part` 临时残留；受控侧仍可读取自己已物化的属性。
5. 重新打开每个实际成品核对：只剩允许标签、无私有/身份/嵌套 PHI、UID 已重映射且
   文件元信息一致、像素逐字节保留、去标识模块字段已写入。
6. 失败尝试的结果（异常类型、是否产生正式文件、临时文件清单）写入
   `verification_report.json`。
