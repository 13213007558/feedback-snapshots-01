# pdfminer.six 阅读顺序的取证审查报告

目的：当取证人员依据 PDF 提取文字判断两段内容的先后关系时，必须能说清
这个"先后"究竟来自**文件本身**还是**布局推断**。本报告审查 pdfminer.six
阅读顺序的生成过程，给出可实施的证据输出方案，并用三份极小 PDF 实测
参数变化前后的差异。所有结论均可通过 `out/` 下的 JSON 证据回查到具体
字符与页面区域。

## 1. 阅读顺序的生成管线：哪些是文件事实，哪些是推断

pdfminer.six 的最终文本顺序经过四个阶段，只有前两个阶段是文件事实：

| 阶段 | 代码位置 | 性质 |
|---|---|---|
| 1. 内容流绘制顺序 | `pdfminer/converter.py:233` `render_char`，解释器按 content stream 中操作符顺序逐字生成 `LTChar` | **文件事实** |
| 2. 字符几何 | `pdfminer/layout.py:347` `LTChar`：bbox、matrix、upright 由 Tm/Td/Tj 操作数直接计算 | **文件事实** |
| 3. 行/盒/组分组 | `group_objects`（layout.py:703）、`group_textlines`（layout.py:780）、`group_textboxes`（layout.py:814） | **推断**，受 LAParams 控制 |
| 4. 输出排序 | `LTTextBoxHorizontal.analyze`（layout.py:647，按 `-y1` 排行）、`LTTextGroupLRTB/TBRL`（layout.py:673/685，按 boxes_flow 加权键排盒）、`analyze`（layout.py:907） | **推断** |

关键机制（决定取证结论的边界）：

- **行内不重排**：`LTTextLineHorizontal.add`（layout.py:505）只追加不排序，
  同一文本行内的字符顺序 = 内容流顺序。因此"行内先后"可溯源为文件事实。
- **行间、盒间全部重排**：行在盒内按 y 坐标排序；盒在组内按
  `(1-boxes_flow)*x0 - (1+boxes_flow)*(y0+y1)` 加权键排序（layout.py:679）。
  `boxes_flow=None` 时退化为按 `(-y0, x0)` 几何排序（layout.py:924）。
  这些顺序在文件里不存在，是参数化的几何推断。
- **分组本身是推断**：`char_margin` 决定多大间隙算同一行，`line_margin`
  决定哪些行邻居成盒，`detect_vertical` 决定旋转/竖排字符是否聚类。
  分组一变，排序的输入就变，最终顺序随之改变。
- **合成字符**：输出中的空格与换行是 `LTAnno`（layout.py:509、485），
  由 `word_margin` 等阈值触发，文件里并不存在对应内容。

## 2. 三份极小样本的实测结果

样本由 `make_samples.py` 手写生成（无第三方依赖），每份一页、内容流
绘制顺序与视觉阅读顺序刻意不一致。实验由 `run_experiments.py` 驱动，
完整数据见 `out/comparison.md` 与 `out/*.json`。

### 样本一：双栏（sample1_twocol.pdf）

内容流先画右栏（R1-gamma、R2-delta），再画左栏（L1-alpha、L2-beta）。

| 运行 | 参数 | 输出顺序 |
|---|---|---|
| default | boxes_flow=0.5 | `L1-alpha L2-beta R1-gamma R2-delta`（先左栏） |
| noflow | boxes_flow=None | `R1-gamma L1-alpha R2-delta L2-beta`（按行交错） |
| flow_neg | boxes_flow=-0.5 | 与 default 相同 |

- 内容流顺序（文件事实）始终是 `R1 R2 L1 L2`，三次运行完全一致。
- `default` 与 `noflow` 之间有 **176 对字符关系翻转**（两栏全部跨栏对），
  全部标记为 `inferred_layout`。这证明栏间先后纯属推断：同一份文件，
  仅改一个参数，"谁先谁后"就整体颠倒，而文件内容没有任何变化。

### 样本二：旋转文字（sample2_rotated.pdf）

内容流顺序：横排 `TOP` → 旋转 90° 的 `VERT`（Tm 矩阵 `[0 1 -1 0]`，
字符 `upright=False`）→ 横排 `END`。

| 运行 | 参数 | 输出顺序 |
|---|---|---|
| default | detect_vertical=False | `TOP END T R E V`（旋转字被拆成 4 个单字盒且倒序） |
| vertical | detect_vertical=True | `VERT TOP END`（聚成竖排盒，整体提前） |

- 默认参数下旋转字符各自成盒，输出 `TREV` 既非流顺序（`VERT`）也非
  视觉顺序，是几何排序的副产物；30 对关系在两次运行间翻转。
- 取证含义：涉及旋转文字的先后关系，必须同时记录 `detect_vertical`
  取值与字符的 `matrix`/`upright`，否则结论不可复现。

### 样本三：重叠文本与字符间距（sample3_overlap.pdf）

`AAAA`（x=100..132）与 `BB`（x=112..128）同基线重叠绘制；`Q`（x=430）
先于 `P`（x=400）绘制，间隙约 22pt。

| 运行 | 参数 | 输出顺序 |
|---|---|---|
| default | char_margin=2.0 | `AAAABB P Q`（P、Q 分盒，按 x 几何排序） |
| wide_margin | char_margin=3.0 | `AAAABB Q P`（P、Q 并为一行，行内保持流顺序） |

- 重叠的 A/B 对（4 对）被标记为 `ambiguous_overlap`：几何上不存在唯一
  阅读顺序，唯一可陈述的文件事实是流顺序（A 先于 B 绘制）。
- P/Q 对是唯一的翻转对，其依据从 `inferred_layout` 变为 `file_stream`：
  char_margin 从 2.0 调到 3.0，输出从 `PQ` 变为 `QP`。**报告若只写
  "提取结果为 PQ"，就把一次参数选择伪装成了文件事实。**

## 3. 可实施的证据输出方案

原型 `trace_order.py` 对每页输出一份 JSON（见 `out/*.json`），字段设计
即证据方案：

**字符级（可回查原字符与页面区域）**
- `render_index`：内容流绘制序号（文件事实）；
- `text`、`bbox`、`matrix`、`upright`：几何与变换（文件事实）；
- 所属 `line_id` / `box_id` 及盒的 `index`：分组结果（推断，附当时
  完整的 `laparams` 快照，保证可复现）。

**关系级（成对记录，不强排）**
- `stream_relation`：流顺序先后（文件事实）；
- `output_relation`：本次运行的输出先后（推断）；
- `basis`：关系依据，三值——
  - `file_stream`：同一文本行内，输出顺序即流顺序，可作文件事实陈述；
  - `inferred_layout`：跨行/跨盒，顺序来自参数化推断，报告中必须
    注明参数与算法版本；
  - `ambiguous_overlap`：bbox 有正面积重叠，几何上无唯一顺序，
    **不得**强排为唯一时间或逻辑顺序，只能陈述流顺序。

**参数敏感性（防止"内容变了"的假象）**
- 对同一文件用两套（或多套）参数运行，以 `render_index` 为稳定身份
  比对全部字符对；翻转对写入对比报告（`out/comparison.md`）。
- 翻转即证明该关系是推断：报告措辞必须是"在不同 LAParams 下顺序
  不同"，而不是"原文内容不同"。参数变化只改变推断层，流顺序证据
  在三次运行中逐字一致（见第 2 节各表）。

**报告措辞要求**
1. 凡 `inferred_layout` 关系：写"在 LAParams(boxes_flow=…, char_margin=…)
   下，A 排在 B 之前"，并附证据 JSON 路径。
2. 凡 `ambiguous_overlap` 或参数敏感翻转对：写"先后顺序无法由文件
   确定；内容流中绘制顺序为 …（render_index …）"。
3. 凡 `file_stream` 关系：可写"内容流中 A 先于 B 绘制"，但仍需说明
   这不等同于视觉阅读顺序或逻辑顺序。

## 4. 原型使用

```bash
.venv/bin/python forensic_reading_order/make_samples.py       # 生成三份样本
.venv/bin/python forensic_reading_order/run_experiments.py    # 跑参数矩阵+对比
# 单文件任意参数：
.venv/bin/python forensic_reading_order/trace_order.py some.pdf \
    --set boxes_flow=None --set char_margin=3.0 -o evidence.json
```

文件清单：
- `make_samples.py` / `sample{1,2,3}_*.pdf`：三份极小样本；
- `trace_order.py`：插桩提取器（`TracingAggregator` 给每个 LTChar 打
  绘制序号，证据 JSON 含字符、行、盒、成对关系四层）；
- `run_experiments.py`：参数矩阵与跨运行关系翻转对比；
- `out/`：8 份证据 JSON + `comparison.md`（本报告第 2 节的数据来源）。

## 5. 局限性

- 原型只覆盖文本字符；图像、Form XObject（`all_texts`）、Type3 字体、
  加密/增量更新带来的多版本内容流未纳入。
- `ambiguous_overlap` 用 bbox 正面积重叠判定，是保守近似；精确判定
  需结合透明度与绘制混合模式。
- 多页文档的跨页顺序（页序即文件事实）未在本样本集中展开。
