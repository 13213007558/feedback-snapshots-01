# Source map for the review

Paths are relative to the repository root; line numbers are from `862df8a`.

| Behaviour | Location |
|---|---|
| Instance state bits interpreted as (use_default, initialized) | `dissect/cim/classes.py:100-107` |
| Class default block parsed positionally | `dissect/cim/classes.py:116-124` |
| Array flag checked by equality (`== ARRAY`), not bit | `dissect/cim/classes.py:39`, `143`, `421`; `dissect/cim/cim.py:274` |
| String-array qualifier/value returns uint32 offsets | `dissect/cim/classes.py:412-418` |
| `OBJECT`/unknown type raises and aborts enumeration | `dissect/cim/classes.py:420-443` |
| Qualifier key/value decoded from owning region | `dissect/cim/classes.py:359-368` |
| Builtin qualifier IDs (missing 4 and 5) | `dissect/cim/c_cim.py:120-126` |
| Builtin property IDs (missing 5) | `dissect/cim/c_cim.py:128-136` |
| `ClassDefinition.keys` scans own properties only | `dissect/cim/classes.py:253-260` |
| Instance enumeration dedupes by key | `dissect/cim/cim.py:287-300` |
| Instance constructed: states, TOC, qualifiers, dynprops, data | `dissect/cim/classes.py:287-296` |
| Dynprops consumes 8 opaque bytes | `dissect/cim/classes.py:371-383` |
| DynpropQualifier is empty | `dissect/cim/classes.py:386-388` |
| `ClassInstance.properties` substitutes `prop.default_value` | `dissect/cim/classes.py:310-325` |
| `ClassInstance.key` uses own-class keys only | `dissect/cim/classes.py:327-332` |
| Default-value ancestor walk by property index | `dissect/cim/cim.py:370-405` |
| Index lookup may return duplicate references | `dissect/cim/index.py:30-69` |
