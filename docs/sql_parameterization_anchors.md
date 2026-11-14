# SQL Parameterization Trust Boundary

This note documents how `Brakeman::CheckSQL` distinguishes a value placeholder
from an identifier or a raw SQL fragment, and where that trust boundary can be
crossed. The executable form lives in:

- `test/support/sql_param_generator.rb` — deterministic anchor generator
- `test/tests/sql_parameterization.rb` — assertions over the generated anchors

## Method

Every anchor reuses the same tainted source, `params[:q]`. Because the input is
held constant, a difference in the verdict is caused only by the **position**
the source occupies, never by the shape of the input.

Positions under test:

- **Value placeholder / bind position** — the source is passed as a bind value
  (`?`, `:named`, or a bind array element). Rails escapes these, so no warning.
- **Identifier position** — the source names a column/table (hash keys,
  `order`, `group`, dynamic `arel_table[...]`). These are never escaped.
- **Raw SQL fragment** — the source is interpolated, concatenated, or handed to
  `Arel.sql`/`find_by_sql`. These are verbatim SQL.

The safe controls genuinely place the source in a value position; they are not
"controls" produced by deleting `params` from the expression.

Determinism comes from a fixed seed (`SqlParamGenerator::SEED`). The anchors
are presented in a seeded permutation that differs from definition order, and
the test asserts the permutation is stable across runs.

## Anchor matrix

Categories: `safe_bind` (no warning), `danger` (high-confidence warning),
`false_negative` (dangerous, currently missed), `false_positive` (safe code
flagged at medium confidence).

| ID | Position / method | Category | Rails < 6.1 | Rails >= 6.1 |
|----|-------------------|----------|-------------|--------------|
| W01 | `where("x = ?", q)` positional bind | safe_bind | silent | silent |
| W02 | `where("x = :n", n: q)` named bind | safe_bind | silent | silent |
| W03 | `where(["x = ?", q])` bind array | safe_bind | silent | silent |
| W04 | `where("x = '#{q}'")` interpolation | danger | high | high |
| W05 | `where("x = '" + q)` concatenation | danger | high | high |
| W06 | `where(["...#{q}...", 1])` interpolated template in bind array | danger | high | high |
| W07 | `where(q => 1)` dynamic hash key | danger | high | high |
| W08 | `where([q => 1])` dynamic key hidden in array | danger | high | high |
| W09 | chained `where(hash).where("...#{q}")` | danger | high | high |
| W10 | chained `where(hash).where("x = ?", q)` | safe_bind | silent | silent |
| W11 | `where("...'%s'" % q)` `String#%` | false_negative | silent | silent |
| O01 | `order("x #{q}")` identifier interp | danger | high | not checked |
| O02 | `order("x ASC")` static fragment | safe_bind | silent | not checked |
| O03 | chained `.order(q)` raw source | danger | high | not checked |
| O04 | `order(Arel.sql("x #{q}"))` | danger | high | not checked |
| O05 | `pluck("LOWER(#{q})")` raw fragment | danger | high | not checked |
| J01 | `joins("...#{q}")` fragment | danger | high | high |
| J02 | `joins(:members)` association symbol | safe_bind | silent | silent |
| J03 | `joins(["...#{q}"])` array, no binding | danger | high | high |
| A01 | `Arel.sql("...#{q}")` | danger | high | high |
| A02 | `Arel.sql(q)` raw source | danger | high | high |
| A03 | `where(arel_table[:x].eq(q))` Arel value predicate | safe_bind | silent | silent |
| A04 | `Arel.sql("created_at DESC")` static literal | safe_bind | silent | silent |
| F01 | `where("...#{whitelist_helper}")` unresolved helper | false_positive | medium | medium |

## Version-dependent entry semantics

`CheckSQL#run_check` removes `order`, `reorder`, and `pluck` from the checked
targets for Rails 6.1+ (`version_between?("6.1.0", "9.9.9")`), matching Rails'
hardening of those methods. The O-anchors are therefore only emitted and
asserted below 6.1; on 6.1/7.0 the generator omits them entirely rather than
asserting the wrong expectation. `where`, `joins`, and `Arel.sql` keep the same
entry semantics across the tested versions.

## Minimal false negative

`W11` — `Group.where("name = '%s'" % params[:q])`.

`String#%` builds an interpolated SQL string, but `STRING_METHODS` in
`base_check.rb` only contains `:<<, :+, :concat, :prepend`, so `string_building?`
returns false and the value is not treated as string construction. The test
pins the current silence so adding `:%` support is a deliberate change. A second
known gap is an interpolated symbol such as `order(:"#{q} ASC")`.

## Minimal false positive

`F01` — `Group.where("1 = 1 ORDER BY #{sort_column}")` where `sort_column`
returns only values from a fixed whitelist. Brakeman cannot resolve the helper's
return value, so it reports medium confidence (no immediate user input is
visible in the expression). This is conservative rather than a high-confidence
taint warning.

## Fix: array-wrapped dynamic identifier keys

Before the fix, `where(params[:q] => 1)` warned (W07) but wrapping the same hash
in an array, `where([params[:q] => 1])`, went silent (W08). The array reached
`unsafe_sql?(arg, :ignore_hash)`; the `:array` branch only inspected the first
element and then routed the inner hash through the `:ignore_hash` path,
skipping the dynamic-key check. The array was effectively assumed to be a
parameterized bind fragment.

`check_query_arguments` now handles arrays explicitly via
`check_query_array_arguments`:

- the first element is the SQL template; nested arrays are unwrapped,
- a hash template still goes through `check_hash_keys`, so a dynamic identifier
  key is caught,
- anything else is checked as a fragment,
- the remaining positional elements stay treated as bind values in value
  position and are not flagged.

### Why the same source stops warning when moved to a legal bind

W04 (`where("name = '#{params[:q]}'")`) and W02 (`where("name = :name", name:
params[:q])`) use the identical source. In W04 the source is concatenated into
the template string, so it changes SQL structure and stays dangerous. In W02 the
template is a static literal containing a named placeholder; the source is only
ever substituted as an escaped bind value, so it cannot alter structure and the
checker correctly stays silent. W08/W03 make the same point for the array form:
`[params[:q] => 1]` puts the source in an identifier (key) position, while
`["name = ?", params[:q]]` puts it in a value position.
