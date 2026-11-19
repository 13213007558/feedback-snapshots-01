# 排查示例：同一内存转储为何得到不同 WinAPI 名称

同一台分析机器、同一份转储字节，SMDA 报出的 API 名称却不同——这不是反汇编不稳定，
而是 **API 名称本身就是"目标环境假设"的产物**：它完全由 `SmdaConfig.API_COLLECTION_FILES`
配置的 ApiScout 数据库决定，而数据库描述的是*另一台机器*（目标系统）的 DLL 布局。
本目录给出一个可重跑的最小示例，把这条假设链逐层拆开。

## 重跑

```bash
source .venv/bin/activate
python3 investigations/winapi-env-assumption/reproduce.py
```

脚本自带断言，任何一层行为漂移都会以退出码 1 失败；每次运行重写
`last_run_report.json`（同一调用位置的原始地址、各配置来源、候选名字全集）。

## 实验设计

`reproduce.py` 现场构造一份 32 位内存转储（base `0x10000`），其中同一个函数里有三条
`call <绝对地址>`，目标是仓库自带两个 ApiScout 数据库里的真实地址：

| 调用点 | 原始地址 | 设计目的 |
| --- | --- | --- |
| `conflict` | `0x78180090` | 两个数据库给出**不同名字**（msvcr80 32/64 位 DLL 同基址碰撞） |
| `xp_only` | `0x7c801a28` | 只在 WinXP 库里有（`kernel32!CreateFileA`），Win7 库基址不同→**名字丢失** |
| `control` | `0x78150000` | 两个库一致（`msvcr80!strrchr`），对照组 |

同一份字节在五种配置下各跑一次 `Disassembler.disassembleBuffer`：

| 配置 | `API_COLLECTION_FILES` | 模拟的部署情形 |
| --- | --- | --- |
| `unconfigured` | `{}`（默认值） | 部署时没挂数据库 |
| `target_matched_winxp_sp3` | winxp SP3 库 | 数据库与转储来源系统一致 |
| `near_version_win7_sp1` | win7 SP1 库 | 拿了"相近版本"/分析机自己的系统库 |
| `both_unpinned_win7_first` | 两个库，win7 在前 | 多库且未指定 os_name |
| `both_unpinned_winxp_first` | 两个库，winxp 在前 | 同上，仅调换配置顺序 |

## 结果（每次运行的实际输出）

| 调用点 | 原始地址 | unconfigured | winxp_sp3（正确） | win7_sp1（相近） | 双库 win7 在前 | 双库 winxp 在前 |
| --- | --- | --- | --- | --- | --- | --- |
| conflict | `0x78180090` | (no name) | `msvcr80!strncat` | `msvcr80!_execle` | `_execle` | `strncat` |
| xp_only | `0x7c801a28` | (no name) | `kernel32!CreateFileA` | (no name) | `CreateFileA` | `CreateFileA` |
| control | `0x78150000` | (no name) | `msvcr80!strrchr` | `msvcr80!strrchr` | `strrchr` | `strrchr` |

调用边（`0x10003 -> 0x78180090` 等）在**所有**配置下都存在于报告中，包括完全没配
数据库时——只是没有名字可挂。

## 哪些名字是目标环境假设带来的

逐层对应到代码（`src/smda/common/labelprovider/WinApiResolver.py`）：

1. **没配数据库 → 名字整体缺失，但调用关系仍在。**
   `API_COLLECTION_FILES` 默认为空（`src/smda/SmdaConfig.py:20`），`getApi` 只能返回
   `(None, None)`。注意此时报告里的 `call 0x78180090` 指令和调用边依然存在，
   **不能凭名称缺失认定样本没有使用 API**——只能认定"没有可用于命名的数据库"。

2. **相近版本数据库 → 名字被替换或丢失。**
   `xp_only` 在 Win7 库里消失，是因为两个系统里 kernel32 的加载基址不同，绝对地址
   对不上；`conflict` 被改名，是因为 Win7 库同时含 32 位和 64 位的
   `msvcr80.dll_0x78130000`，`0x78180090` 在两者中分别是 `strncat` 和 `_execle`，
   而 `_loadDbFile`（`WinApiResolver.py:109`）把它们压进同一张以绝对地址为键的表，
   **后写覆盖先写**，64 位条目在 JSON 中靠后于是胜出。转储是 32 位的，正确答案
   应是 `strncat`——解析器从地址本身无法得知这一点，这就是纯粹的配置假设。

3. **多个数据库且未钉住 os_name → 结果由配置顺序决定。**
   `getApi`（`WinApiResolver.py:133-138`）按字典插入顺序遍历，**返回第一个命中**，
   歧义被静默吞掉。同一份转储，仅调换 `API_COLLECTION_FILES` 的键顺序，
   `conflict` 的名字就在 `strncat`/`_execle` 之间翻转。

4. **只配一个数据库 → os_name 被配置反推钉死。**
   `_resolveOsName`（`WinApiResolver.py:46-53`）在恰好加载一个库时把它设为
   `_os_name`。这个"目标系统版本"来自部署配置，不是从样本里分析出来的事实；
   如果运维顺手挂了分析机自己的系统版本（情形 2），报告就会一本正经地给出错误名字。

结论：**报告里每一个 API 名字都隐含"目标机器运行的是数据库所描述的系统版本与
位数"这一假设。原始地址才是事实，名字只是该地址在某个环境假设下的投影。**

## 服务端应保存的最小分析上下文

要能让第三方事后判断"这个名字可不可信、在什么假设下得出"，服务端至少应持久化
（脚本每次运行都会生成一份样例 `last_run_report.json`）：

- **样本事实**：转储 SHA-256、base 地址、位数/架构、SMDA 版本。
- **解析配置**：`API_COLLECTION_FILES` 每个条目的标签、文件路径、文件 SHA-256、
  库内自述的 `os_name`/`os_version`；若显式 `setOsName` 过，记录该值及其来源。
- **调用位置**：函数偏移、指令偏移、**原始目标地址**（必存，与命名解耦）。
- **候选名字全集**：该地址在每个已加载数据库里的所有候选（含同库 32/64 位碰撞），
  以及最终采用的名字和选择规则（单库钉死 / 首个命中 / 无命中原因：
  `no_db_configured` 还是 `addr_not_in_db`）。
- **调用边**：`from -> to` 的原始地址边，独立于命名结果存储。

## 对消费方的两条硬要求

- **保留歧义**：一个地址对应多个候选时全部下发，让下游按自己掌握的目标环境信息
  抉择；不要把分析机器（或部署配置）的系统版本当作目标事实写进结论。
- **名字缺失 ≠ 未使用 API**：没有数据库时调用边和原始地址仍在，统计"API 使用情况"
  必须基于调用边，名字只是可选的标注层。
