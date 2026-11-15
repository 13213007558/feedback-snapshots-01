# strict2 migration checklist

Generated from the grammar-driven differential corpus. Work top to bottom;
each item names the template shape, why it stops being safe, and the rewrite.

## Variable filter chains

- [ ] `var-trailing-pipe` — Lax drops the dangling pipe and runs diff_f1 only
  - Template: `{{ p | diff_f1 | }}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `| filter: arg1, arg2` with a name, commas, and no parenthesised arguments.
- [ ] `var-leading-pipe` — Lax skips the empty filter slot; strict2 rejects the duplicate separator
  - Template: `{{ p || diff_f1 }}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `| filter: arg1, arg2` with a name, commas, and no parenthesised arguments.
- [ ] `var-comma-separates-filters` — Lax treats comma as a filter argument, so only diff_f1 runs
  - Template: `{{ p | diff_f1, diff_f2 }}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `| filter: arg1, arg2` with a name, commas, and no parenthesised arguments.
- [ ] `var-quoted-filter-name` — Lax resolves quoted text as a filter name
  - Template: `{{ p | 'diff_f1' }}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `| filter: arg1, arg2` with a name, commas, and no parenthesised arguments.
- [ ] `var-paren-arguments` — Lax ignores the parenthesised argument entirely
  - Template: `{{ p | diff_f1(1) }}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `| filter: arg1, arg2` with a name, commas, and no parenthesised arguments.
- [ ] `var-args-no-comma` — Lax silently drops the extra positional argument
  - Template: `{{ p | diff_f1: 1 2 | diff_f2 }}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `| filter: arg1, arg2` with a name, commas, and no parenthesised arguments.
- [ ] `var-two-strings-no-comma` — Second string is dropped by lax
  - Template: `{{ p | diff_f1: 'a' 'b' | diff_f2 }}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `| filter: arg1, arg2` with a name, commas, and no parenthesised arguments.
- [ ] `var-missing-pipe` — Lax keeps the variable and ignores the trailing token
  - Template: `{{ p diff_f1 }}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `| filter: arg1, arg2` with a name, commas, and no parenthesised arguments.
- [ ] `var-trailing-token-after-name` — Same variable, no filter, no error
  - Template: `{{ p extra }}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `| filter: arg1, arg2` with a name, commas, and no parenthesised arguments.
- [ ] `var-mismatched-quote` — Unterminated quote becomes no argument and diff_f1 still runs
  - Template: `{{ p | diff_f1: 'x }}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `| filter: arg1, arg2` with a name, commas, and no parenthesised arguments.
- [ ] `var-arg-empty-between-commas` — Leading empty argument is dropped
  - Template: `{{ p | diff_f1: , 1 }}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `| filter: arg1, arg2` with a name, commas, and no parenthesised arguments.
- [ ] `var-arg-double-comma` — Lax merges the adjacent comma into one argument list
  - Template: `{{ p | diff_f1: 1,,2 }}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `| filter: arg1, arg2` with a name, commas, and no parenthesised arguments.
- [ ] `var-bare-bracket` — Lax and strict accept bare bracket access (evaluating to nil, but still running the filter); strict2 requires self[...]
  - Template: `{{ [p] | diff_f1 }}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `| filter: arg1, arg2` with a name, commas, and no parenthesised arguments.

## render parameters

- [ ] `render-double-comma` — Lax silently accepts the empty slot
  - Template: `{% render 'sn',, x: p %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `, key: value` arguments only; move conditionals into the snippet.
- [ ] `render-missing-colon` — Lax turns 'x p' into a positional token, so x stays unset in the partial
  - Template: `{% render 'sn', x p %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `, key: value` arguments only; move conditionals into the snippet.
- [ ] `render-quoted-key` — Quoted key is not a TagAttributes key, so it does not bind x
  - Template: `{% render 'sn', 'x': p %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `, key: value` arguments only; move conditionals into the snippet.
- [ ] `render-empty-value` — Empty expression value; partial still runs with x unset
  - Template: `{% render 'sn', x: %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `, key: value` arguments only; move conditionals into the snippet.
- [ ] `render-trailing-token` — Lax ignores the trailing token after the alias
  - Template: `{% render 'sn' with p as q extra %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `, key: value` arguments only; move conditionals into the snippet.
- [ ] `render-trailing-pipe` — Pipe is ignored by the lax render regex
  - Template: `{% render 'sn' | diff_f1 %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `, key: value` arguments only; move conditionals into the snippet.
- [ ] `render-trailing-comment` — Hash comment text is ignored by the lax render regex
  - Template: `{% render 'sn' # diff_f1 %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `, key: value` arguments only; move conditionals into the snippet.
- [ ] `render-semicolon` — Semicolon is skipped and x still binds
  - Template: `{% render 'sn'; x: p %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `, key: value` arguments only; move conditionals into the snippet.
- [ ] `render-with-no-expression` — with without a value is ignored
  - Template: `{% render 'sn' with %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `, key: value` arguments only; move conditionals into the snippet.
- [ ] `render-as-no-name` — Alias with no name is ignored; the partial still renders with its default variable name
  - Template: `{% render 'sn' with p as %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `, key: value` arguments only; move conditionals into the snippet.
- [ ] `render-as-quoted` — Quoted alias is ignored
  - Template: `{% render 'sn' with p as 'q' %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `, key: value` arguments only; move conditionals into the snippet.
- [ ] `render-with-filter` — Filters are not part of render arguments; lax regex drops the pipe clause
  - Template: `{% render 'sn' with p | diff_f1 %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `, key: value` arguments only; move conditionals into the snippet.
- [ ] `render-attr-filter` — TagAttributes value regex stops at the pipe, so the filter never binds
  - Template: `{% render 'sn', x: p | diff_f1 %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use `, key: value` arguments only; move conditionals into the snippet.

## liquid multi-statement tags

- [ ] `liquid-two-statements-one-line` — Lax splits on the second echo; strict2 sees trailing tokens
  - Template: `{% liquid echo p | diff_f1 echo q | diff_f2 %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Split statements onto separate lines; remove inline # comments and semicolons.
- [ ] `liquid-semicolon-separator` — Semicolon is not a statement separator in strict2
  - Template: `{% liquid echo p | diff_f1; echo q | diff_f2 %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Split statements onto separate lines; remove inline # comments and semicolons.
- [ ] `liquid-trailing-comment` — Inline # text is dropped by lax, strict2 rejects it
  - Template: `{% liquid
echo p | diff_f1 # diff_f2
%}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Split statements onto separate lines; remove inline # comments and semicolons.
- [ ] `liquid-case-when-junk` — when trailing tokens tolerated by lax
  - Template: `{% liquid
case p
when 'PV' extra
echo p | diff_f1
endcase
%}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Split statements onto separate lines; remove inline # comments and semicolons.
- [ ] `liquid-cycle` — Cycle arguments cannot carry a filter chain in strict2
  - Template: `{% liquid
cycle 'a', p | diff_f1
%}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Split statements onto separate lines; remove inline # comments and semicolons.
- [ ] `liquid-hash-no-space` — # attached to the expression is not a comment
  - Template: `{% liquid
echo p | diff_f1# diff_f2
%}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Split statements onto separate lines; remove inline # comments and semicolons.

## Control-flow tags

- [ ] `ctrl-if-filter` — Lax treats the whole pipe clause as an expression; strict2 rejects it
  - Template: `{% if p | diff_f1 %}{% diff_tag yes %}{% endif %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Compute the value in an `assign` first, then test the variable.
- [ ] `ctrl-if-parens` — Redundant parentheses rejected by strict2
  - Template: `{% if (p == 'PV') %}{% diff_tag yes %}{% endif %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Remove the redundant parentheses around the comparison.
- [ ] `ctrl-if-double-amp` — Lax interprets && loosely
  - Template: `{% if true && true %}{% diff_tag yes %}{% endif %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Replace `&&`/`||` with the keyword operators `and`/`or`.
- [ ] `ctrl-if-two-filters` — Filter chain inside a condition
  - Template: `{% if p | diff_f1 | diff_f2 %}{% diff_tag yes %}{% endif %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Compute the filtered value in an `assign` first.
- [ ] `ctrl-if-extra-token` — Trailing token becomes an unknown operator at render time
  - Template: `{% if true extra %}{% diff_tag yes %}{% endif %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Remove the trailing token; each comparison takes exactly two operands.
- [ ] `ctrl-unless-filter` — Same issue for unless
  - Template: `{% unless p | diff_f1 %}{% diff_tag yes %}{% endunless %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Compute the value in an `assign` first, then test it with `unless`.
- [ ] `ctrl-case-filter` — Filter chain in when clause
  - Template: `{% case p %}{% when 'PV' | diff_f1 %}{% diff_tag yes %}{% endcase %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Compute the filtered value before the `case` and compare the variable.
- [ ] `ctrl-case-extra` — Trailing token after when value
  - Template: `{% case p %}{% when 'PV' extra %}{% diff_tag yes %}{% endcase %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Remove the trailing token after the `when` value.
- [ ] `ctrl-for-unknown-attr` — Unknown for attribute ignored by lax
  - Template: `{% for i in arr foo: 1 %}{% diff_tag i %}{% endfor %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use only `limit` and `offset` attributes on `for`.
- [ ] `ctrl-for-extra-dots` — Three dots in range accepted only by lax
  - Template: `{% for i in (1...3) %}{% diff_tag i %}{% endfor %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use the two-dot range `(a..b)`.
- [ ] `ctrl-tablerow-unknown-attr` — Unknown tablerow attribute
  - Template: `{% tablerow i in arr foo: 1 %}{% diff_tag i %}{% endtablerow %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use only `cols`, `limit`, and `offset` attributes on `tablerow`.
- [ ] `ctrl-cycle-extra` — Trailing token after cycle list
  - Template: `{% cycle 'a', 'b' extra %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Remove trailing tokens; separate cycle values with commas.
- [ ] `ctrl-increment-extra` — increment takes exactly one id in strict2
  - Template: `{% increment x y %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Give `increment` a single bare identifier.
- [ ] `ctrl-decrement-extra` — decrement takes exactly one id in strict2
  - Template: `{% decrement x y %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Give `decrement` a single bare identifier.
- [ ] `ctrl-assign-dotted` — Lax accepts dotted targets; strict2 requires an id
  - Template: `{% assign a.b = p %}{{ a.b }}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Assign to a single bare identifier, not a dotted or bracketed path.
- [ ] `ctrl-assign-numeric` — Numeric identifier accepted only by lax
  - Template: `{% assign 1abc = p %}{{ 1abc }}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Use an identifier that starts with a letter or underscore.
- [ ] `ctrl-capture-quoted` — Quoted capture target
  - Template: `{% capture 'c' %}x{% endcapture %}{{ c }}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Name the capture with a bare identifier, not a quoted string.
- [ ] `ctrl-echo-extra` — Trailing token in echo
  - Template: `{% echo p extra %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Remove the trailing token; `echo` takes one expression.
- [ ] `ctrl-include-filter-arg` — Filter after an include argument
  - Template: `{% include 'sn', x: p | diff_f1 %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Move the filter into an `assign` before `include`, or into the snippet.
- [ ] `ctrl-include-double-comma` — Empty argument slot
  - Template: `{% include 'sn',, x: p %}`
  - REWRITE BEFORE MIGRATING: strict2 rejects the template
  - Action: Remove the empty argument slot.

## Warn-mode caveat

`:warn` is a hybrid, not a gate: tags fall back from strict2, variables fall back
from strict. A warning therefore does not prove the executed callbacks match lax;
use the callback fingerprints in the report, not the warning count.

In particular, these corpus entries are rejected by strict2 yet produce **no**
warning because warn falls back to strict for variables or to lax `when` parsing:

- `var-bare-bracket`
- `liquid-case-when-junk`
- `ctrl-case-filter`
- `ctrl-case-extra`

Run `Template.parse(source, error_mode: :strict2)` in CI to catch these; a clean
warn log will not.
