# Double Ratchet 存档分叉风险演示

- `fork_demo.py`：可运行演示。固定同一初始状态，两个进程从同一存档恢复后各发不同内容，
  交给正常对端，展示公开头重叠、消息编号冲突、`DuplicateMessageException`、确定性 IV 复用，
  以及用代次 CAS（fencing）阻止陈旧发送状态。
- `ANALYSIS.zh.md`：完整中文分析（分叉机理、三种部署形态、库无法证明的持久化事实、部署约束）。

## 运行

```sh
.venv/bin/python demo/fork_demo.py
```

仅依赖仓库已安装的 `doubleratchet` 1.3.0 与 `cryptography`。脚本只打印 SHA-256 短指纹、
公开头编号和异常类型，不输出完整私钥、消息密钥、IV 或明文。
