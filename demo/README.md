# 同名 DLL 重定向对逆向类型/方法身份的影响（基于 dnfile）

这个目录给出一个可重跑的分析：从**声明层**、**静态选择层**、**运行时配置层**三层分别
说明“把引用重定向到本地最新同名 DLL”会怎样改变逆向看到的类型与方法身份，并明确哪些
结论在缺少运行时配置时**不能**下。

## 运行

```bash
python demo/run_demo.py --out out/
python -m pytest -q demo/tests
```

产物（全部字节稳定，仅依赖固定种子）：

```
out/
  fixtures.sha256.json          输入样本的 sha256 清单
  fixtures/Host.exe             宿主：两个同名 AssemblyRef + 两条嵌套 TypeRef
  fixtures/candidates/v1/Contoso.Utils.dll
  fixtures/candidates/v2/Contoso.Utils.dll
  exact_identity/report.{json,txt}
  name_and_token_prefer_highest/report.{json,txt}
  name_only_highest_version/report.{json,txt}
  comparison.json               三种策略的选择结果对照
```

## 身份模型（`identity.py`）

- `AssemblyRefRow.PublicKey` 在 dnfile 中其实是 **PublicKeyOrToken** blob。
  - `AssemblyFlags.afPublicKey (0x0001)` 置位 → blob 是完整公钥，token 需按
    ECMA-335 计算：`SHA1(key)` 的低 8 字节**逆序**。
  - 未置位且 8 字节 → 可直接当 token。
  - 未置位但长度不是 8 → 标为 `ambiguous`，**不做猜测**，交给调用方。
- 身份四元组：simple name、version、culture（`""` 与 `Neutral` 等价）、public key token。
- `afRetargetable (0x0100)` 单独记录，它只表示“允许重定向”，不是“已经重定向”。
- 每个 AssemblyRef / Assembly / TypeRef / MemberRef 行都保留 `file_offset`、
  `row_size`、`raw_hex`，以及行级 sha256，便于事后复核。

## 三层，不要混为一谈

| 层 | 来源 | 能得出的结论 |
|---|---|---|
| declared | 宿主元数据字节 | 宿主**声明**了什么身份，无需任何文件查找 |
| static-policy | 显式规则 + 固定候选集 | 若采用该规则，**分析器会选**哪个文件 |
| runtime | deps.json / runtimeconfig.json / app.config | 运行时**可能**怎样绑定；无文件则不作断言 |

`runtime_probe.py` 在找不到任何部署配置时返回 `configured=False`、`claim="none"`，
报告正文会写明“不声明 CLR 实际加载了哪个候选”。

## 候选选择政策（`resolver.py`）

| 政策 | 规则 | 适用/风险 |
|---|---|---|
| `exact_identity` | 名称+版本+culture+token 全等 | 最保守；适合“只做静态指认” |
| `name_and_token_prefer_highest` | 名称与 token 相同，取最高版本 | 接近 .NET Framework 统一规则的静态类比，**仍是政策选择** |
| `name_only_highest_version` | 只看 simple name，取最高版本 | 即“最新同名 DLL”，对带身份引用不安全 |

置信度按**证据**而非政策名给出：`exact` / `policy` / `weak` / `ambiguous` / `none`。
`weak` 明确表示版本或 token 被覆盖。

## 示范场景（`scenario.py`、`pebuilder.py`）

`Host.exe` 声明：

```
AssemblyRef[1] Contoso.Utils 1.0.0.0 neutral token:40ddd5b7234ad53e   (无 retargetable)
AssemblyRef[2] Contoso.Utils 2.0.0.0 neutral fullkey→b67b457ffada51eb (afRetargetable)

TypeRef[2] Contoso.Utils.Facade            ← AssemblyRef[1]
TypeRef[3] Contoso.Utils.Facade+Builder    ← TypeRef[2]      (嵌套)
TypeRef[4] Contoso.Utils.Facade            ← AssemblyRef[2]
TypeRef[5] Contoso.Utils.Facade+Builder    ← TypeRef[4]      (嵌套)

MemberRef[1] Builder::Make  sig 200001    ← TypeRef[3]
MemberRef[2] Builder::Make  sig 20000108  ← TypeRef[5]
```

两个候选文件**文件名相同、身份不同**：

| 文件 | 身份 | `Builder::Make` |
|---|---|---|
| `v1/Contoso.Utils.dll` | 1.0.0.0 / token 40dd… | `void Make()` → `200001` |
| `v2/Contoso.Utils.dll` | 2.0.0.0 / token b67b… | `int32 Make()` → `20000108` |

可观察到的差异：

- `exact_identity`：两个 AssemblyRef 分别命中 v1、v2；两个 MemberRef 签名都吻合。
- `name_only_highest_version`：两个 AssemblyRef 都落到 v2；
  `MemberRef[1]` 仍写 `200001`，解析到 `20000108` → **SIGNATURE MISMATCH**。
  这就是“重定向改变方法身份”的最小可复现证据。
- 嵌套类型 `Facade+Builder` 在两个 AssemblyRef 下是**两个不同身份**；
  扁平名字表会把它们合并。

## 需要调用方明确决定的冲突（`conflicts.py`）

- `same_simple_name_multiple_identities`：同名、不同 token 的多个引用。
- `same_name_and_version_different_key`：版本无法消歧，只能做信任决策。
- `retargetable_assembly_ref`：`afRetargetable` 已置位但**未观察到**部署配置。
- `same_nested_typename_different_assembly_refs`：同一嵌套名挂在不同 AssemblyRef 上。
- `member_ref_signature_mismatch`：所选候选的同名方法签名不同。
- `unsigned_ref_signed_candidate` / `ambiguous_key_blob`：身份证据本身不足以判断。

每条 `severity=caller_decision` 都带一个 `question` 字段，说明必须由谁、决定什么。

## 文件

| 文件 | 作用 |
|---|---|
| `pebuilder.py` | 按 ECMA-335 写 PE/CLR 元数据的最小构造器 |
| `scenario.py` | 生成宿主与两个同名候选 |
| `identity.py` | 身份建模、键/令牌判定、行级证据 |
| `resolver.py` | 声明视图、TypeRef 链解析、三种选择政策 |
| `runtime_probe.py` | 只**观察**部署配置，不做推断 |
| `conflicts.py` | 需调用方裁决的冲突清单 |
| `report.py` | JSON/文本报告 |
| `run_demo.py` | 一键重跑 |

## 局限

- 合成样本是**手工按 ECMA-335 布局**写出的，不是编译器产物；用于精确控制身份字段。
  强名称 blob 形状正确但非真实密钥，未做签名校验。
- 静态分析不执行 IL，也不模拟 CLR binder；`rollForward`、`bindingRedirect` 等只按
  配置文件字面记录，不推导最终加载对象。
- 未覆盖：`ExportedType` 转发、`TypeSpec` 泛型实例化、多模块程序集、
  `AssemblyRefProcessor/OS` 的平台过滤。
