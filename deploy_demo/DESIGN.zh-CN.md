# 多写入目标的安全发布：可落地方案与可兑现范围

本目录是基于本仓库**真实扩展合同**的可运行参考实现，不改 `src/installer` 一行。
所有场景都有 pytest 覆盖，也有端到端演示。

```sh
.venv/bin/python -m deploy_demo --big-mb 8          # 完整叙事演示
.venv/bin/python -m pytest -q tests/test_deploy_demo.py
```

## 1. 依据的真实合同

- `installer/sources.py:30` 的 `WheelSource`：`dist_info_filenames`、
  `read_dist_info()`、`validate_record()`、`get_contents()`。
  `get_contents()` 顺序产出 `(record 三元组, BinaryIO, is_executable)`，
  且合同明确“可多次调用，每次对同一文件应给出相同内容”——这是重试能重新
  开流的依据。
- `installer/destinations.py:29` 的 `WheelDestination` 三方法：
  `write_file(scheme, path, stream, is_executable) -> RecordEntry`、
  `write_script(...) -> RecordEntry`、
  `finalize_installation(scheme, record_file_path, records)`。
  注意 `write_file` 返回的 `RecordEntry` 应描述**实际写入字节**的 hash/size，
  供最终 `RECORD` 使用；stream 由调用方在调用结束后关闭。
- `installer/_core.py:65` 的 `install()` 真实顺序：读 `WHEEL` 定 `root_scheme`
  → entry points 生成脚本 → 逐个 `get_contents()`，用 `_determine_scheme()`
  映射 scheme/目标路径（含跳过 `RECORD`、安全跳过 `__pycache__`）→
  `additional_metadata` → 最后写 `RECORD`。
- `installer/utils.py:112` 的 `copyfileobj_with_hashing()` 用固定 64 KiB
  缓冲边拷边算 sha256/size，是“大 wheel 不爆内存”的现成支点。
- 路径越界防护参考
  `SchemeDictionaryDestination._path_with_destdir()` 的 `abspath + is_relative_to`
  检查，本实现抽到 `deploy_demo/paths.py:safe_resolve()` 复用同一口径。

## 2. 组件

| 文件 | 职责 |
| --- | --- |
| `deploy_demo/plan.py` | 动目标前的审查计划，逐步对齐 `install()`（直接复用 `installer._core` 的 scheme 映射），输出可存档 JSON |
| `deploy_demo/flaky.py` | 中途读失败的源包装 `FlakyWheelSource`、失败策略、读字节统计，以及常量内存的 `preflight_read_all()` |
| `deploy_demo/staging.py` | 可暂存目标：generation 暂存目录 + `commit()`（逐文件 `os.replace`）+ 失败自动回滚 + `abort()` |
| `deploy_demo/worm.py` | “只能写一次”的替身：`WormStore`（key 只能 `xb` 一次、`ledger.jsonl` 审计/重启记忆、可选整目标砖化）+ `WriteOnceDestination` |
| `deploy_demo/verify.py` | 从**实际落点**回读、按已安装 `RECORD` 重算 hash 的独立验证器（文件系统与 WORM 两套） |
| `deploy_demo/fanout.py` | 多目标扇出，按目标隔离成败，只重试失败目标 |
| `deploy_demo/deploy.py` | 恢复编排：staging 中止重试、write-once 换新 generation |
| `deploy_demo/demo.py` / `__main__.py` | 端到端叙事，产出真实文件、账本、计划 JSON |
| `tests/test_deploy_demo.py` | 13 个测试覆盖下述全部承诺 |

## 3. 事前能保证哪些事实（分级，不夸大）

`build_plan()` **只遍历 `get_contents()` 的元组、不读成员字节**（有测试断言
被投毒的流 `delivered == 0` 也能出计划），因此即使 wheel 很大也很快。在触碰
任何目标前，可向安全审查提供：

1. **恒可提供（纯元数据）**
   - 完整逻辑写入集：类型（wheel 文件/生成脚本/额外元数据/RECORD）、scheme、
     scheme 内路径、entry point 脚本名；
   - 经真实 `_determine_scheme()` 得到的 scheme 归属，以及
     `safe_resolve()` 解析出的最终绝对落点和暂存落点；路径穿越会直接拒绝；
   - wheel `RECORD` **声明**的 sha256/size（`hash_basis=declared-in-RECORD`）；
   - entry point 脚本与 `additional_metadata` 的**实际预算 hash/size**
     （字节在本地确定性生成，`Script.generate()` 与安装时完全一致）；
   - `RECORD` 自身按 PEP 376 无 hash/size，且一定最后写。
2. **若先做完整性预检，可升级为“当前已验证事实”**
   - 先调用 `WheelFile.validate_record(validate_contents=True)`，或本目录的
     `preflight_read_all()`（走与安装相同的 `get_contents()` 路径，常量内存），
     可保证：此刻每个成员都能完整读出，且字节与 `RECORD` 一致。
3. **事前不能诚实保证的**
   - 预检之后、真正读取之时源不会再次失败或被改动（TOCTOU/网络抖动）；
   - 目标写调用会成功、目标介质不会事后损坏；
   - 多个独立目标能原子一起提交；
   - `scripts` scheme 下 shebang 可能被 `fix_shebang()` 改写，其落盘 hash
     不等于 wheel 内原始 hash（生成脚本同理，本就不在 wheel RECORD 中）。

第 3 类靠“写入时边拷边 hash + 落盘后按**已安装 RECORD**独立回读”在事后闭环，
而不是事前承诺。

## 4. 大 wheel 如何处理

- 成员字节只经过 64 KiB 缓冲：`copyfileobj_with_hashing()` 同时完成拷贝与摘要；
  暂存目标落临时文件，WORM 替身直接流式写对象，均不把整个 wheel/成员读进内存。
- 测试 `test_large_member_is_streamed_in_fixed_chunks` 用 2 MiB 成员断言
  实际 `read(n)` 的 `n <= 64 KiB` 且总字节数正确；演示默认 8 MiB，可
  `--big-mb` 调大。
- 计划阶段不读成员；预检/安装/校验各做一次顺序全读，读放大是顺序 I/O，
  内存占用恒定。

## 5. 两类目标各自如何恢复

### 5.1 可暂存目标 `StagingWheelDestination`

所有写入都落在 `<stage_root>/<generation>/<scheme>/...`，generation 全新且
`overwrite_existing=False`，因此安装期不可能撞到线上文件。

| 失败点 | 现场 | 恢复 |
| --- | --- | --- |
| 读源中途失败 / 写暂存失败 | 暂存 generation 内有半成品，线上目录未改 | 捕获后 `abort()` 整个 generation；用**新 generation** 重试（测试验证旧目录已删、预置哨兵字节不变） |
| 进程在暂存期崩溃 | 留下孤儿 generation 目录 | 重启后由 janitor 清理 `stage/gen-*`；线上仍未动 |
| `commit()` 中途失败 | 已做若干 `os.replace`，被覆盖文件先移到 `_transactions/<gen>/backup/` | `commit()` 自动逆序回滚：有备份则 `replace` 还原，无备份则删除新文件；测试用注入故障断言整棵树与提交前逐字节相同 |
| 进程在 commit 期崩溃 | 已写 `journal.json`（staged/live/backup 清单） | 协调器按 journal 完成或回滚该事务 |

边界：`os.replace` 只保证**单文件**原子；要求 `stage_root` 与各 scheme 根在
同一文件系统，代码会用 `st_dev` 检查并给出可操作报错。跨 scheme、跨目标没有
全局原子性。

### 5.2 只能写一次的替身 `WormStore` + `WriteOnceDestination`

语义：每个 key 只能 `open_write` 一次（内存状态 + 账本 + `open("xb")` 三重保证，
重启后重放 `ledger.jsonl` 仍记得用过的 key）。key 按 generation 隔离：
`generations/<gen>/<scheme>/<path>`。

- **中途读失败**：部分字节已经离开平台、落到当前 key。该 key 被记为 `failed`
  （保留半写对象用于取证），当前顺序会话立即“毒化”（`dead=True`），随后任何
  写入都抛 `WriteOnceViolation`。
- **不能做的恢复**：重写同一 key、复用同一个 destination 会话——测试均断言被拒。
- **正确恢复**：新建一个 generation（全新 key 命名空间），重新开源、重跑
  `install()`，成功后写 write-once 的 `generations/<gen>/_manifest.json`
  作为该代的线性提交点；流量指针/别名由控制面切到该 generation。旧的失败
  generation 保留待 GC/审计，绝不被新 manifest 引用。
- **最严格形态** `WormStore(brick_on_failure=True)`：模拟单条顺序通道/单次
  PUT/磁带——一次中途失败后整个目标永久砖化，同实例新 generation 也被拒；
  唯一恢复是**更换目标实例/端点**（演示里用新的 store 根表示），再部署。
- **进程崩溃**：账本里停在 `open` 的 key 视为不可复用；按失败 key 同代处理，
  另开新 generation；对账器可清理无 `seal` 事件的孤儿对象。

### 5.3 多目标

`fanout()` 让每个目标独立成败（测试：staging 成功并校验通过，WORM 永久故障只
标记自己失败）。发布语义应是“所有必需目标都有已验证 manifest 后，控制面再切
流量指针”；某目标失败时，只按该目标的上表恢复，不影响已成功目标。不承诺
跨目标事务。

## 6. 怎样验证“实际落点”

不要信安装过程内存里的记录，验证器从真实落点回读：

- 文件系统：`verify_filesystem_installation()` 找到
  `<root_scheme>/<dist-info>/RECORD`，解析每一行，按 `../scripts/` 等前缀映射回
  scheme，打开**最终绝对路径**重算 hash/size（复用
  `RecordEntry.validate_stream`），再把 `(scheme, path)` 集合与计划比对；
  每个落点的绝对路径留在 `LandingCheck.landing`。`strict_extra=True` 还会报告
  RECORD 之外的多余文件。
- WORM：`verify_worm_generation()` 从 `store.open_read(key)`（底层就是
  `store/objects/<key>` 真实文件）回读校验 RECORD 每行；再交叉核对
  `_manifest.json` 的 key 集 == RECORD key 集 == 计划集，并找孤儿 sealed 对象。
- 测试 `test_worm_verification_detects_tampered_landing` /
  `test_filesystem_verification_detects_wrong_bytes` 会故意翻转一个字节，
  证明篡改/截断/落错位置会变成失败检查并可抛 `VerificationFailure`。
- 带外也可直接用系统工具审计，例如对 `RECORD` 中某行的 urlsafe-base64 sha256：
  `shasum -a 256 <landing>` 得十六进制，`python -c` 做 base64→hex 比对即可；
  WORM 的审计轨迹是目标根下的 `ledger.jsonl`。

## 7. 可兑现范围（诚实边界）

**仓库内已交付并被 13 个测试 + 端到端演示证明：**

- 事前计划 JSON（路径/scheme/绝对落点/声明与预算 hash），计划零成员读取；
- 可选的全量事前可读性/摘要预检；
- 常量内存的大 wheel 流式路径与分块证据；
- 可暂存目标的 abort / commit / 自动回滚 / 事务日志；
- write-once 替身的 key 不可重写、会话毒化、账本重启记忆、新 generation 恢复、
  manifest 提交点、整目标砖化与替换；
- 多目标 fanout 故障隔离；
- 基于实际回读 + RECORD + 计划三方比对的落点验证（含篡改检测）。

**`WormStore` 是“合同替身”，不是生产远程适配器。** 接真实 S3/GCS/Blob/
分片 PUT/裸设备时，需要写一个同样实现 `WheelDestination` 三方法的适配器，并补齐：

- 流式 multipart/chunked 上传（禁止整文件缓冲），把 `copyfileobj_with_hashing`
  的 hash 作为校验尾/对象 checksum；
- 服务端 no-overwrite / Object Lock / 条件写（如 `If-None-Match: *`）与唯一
  generation key；
- 写后读或服务端 checksum 对账、write-once manifest、控制面指针切换与旧代 GC；
- 多进程/多机互斥（本替身的锁仅进程内，跨进程靠账本重放 + 条件写）。

**明确不承诺：** 源在预检与安装之间不可变（应固定制品 fd/内容寻址地址并以
安装时 hash + 落盘复核兜底）；跨目标原子提交；RECORD 数字签名
（`RECORD.jws/p7s`）验签；Windows 启动器与字节码编译的演示覆盖
（演示固定 `script_kind="posix"`、bytecode 级别为空；staging 继承的
`SchemeDictionaryDestination` 本身支持这些配置）。
