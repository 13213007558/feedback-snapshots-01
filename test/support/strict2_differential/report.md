# strict2 migration differential report

Seed: `20261114`  
Probe tag: `diff_tag`  
Probe filters: `diff_f1`, `diff_f2`, `diff_f3`

Oracle: ordered list of probe callbacks that actually ran, plus rendered output.
A callback list proves execution; literal `{% ... %}` text inside `raw`/`comment`
does not, so those regions are counted as inert by construction.

## Counts

| Category | Meaning | Count |
| --- | --- | ---: |
| `execution_change` | RENAME / RESTRUCTURE | 0 |
| `output_change` | REVIEW OUTPUT | 0 |
| `loose_only` | REWRITE BEFORE MIGRATING | 52 |
| `strict2_only` | NEW SYNTAX | 0 |
| `equivalent` | KEEP AS IS | 53 |
| `rejected_both` | INVALID IN EVERY MODE | 8 |

## Rows

### REWRITE BEFORE MIGRATING (`loose_only`)

- `var-trailing-pipe` (Variable filter chains): `{{ p | diff_f1 | }}`
  - Lax drops the dangling pipe and runs diff_f1 only
  - lax: out="PV" callbacks=["filter:diff_f1()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `var-leading-pipe` (Variable filter chains): `{{ p || diff_f1 }}`
  - Lax skips the empty filter slot; strict2 rejects the duplicate separator
  - lax: out="PV" callbacks=["filter:diff_f1()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `var-comma-separates-filters` (Variable filter chains): `{{ p | diff_f1, diff_f2 }}`
  - Lax treats comma as a filter argument, so only diff_f1 runs
  - lax: out="PV" callbacks=["filter:diff_f1(nil)"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `var-quoted-filter-name` (Variable filter chains): `{{ p | 'diff_f1' }}`
  - Lax resolves quoted text as a filter name
  - lax: out="PV" callbacks=["filter:diff_f1()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `var-paren-arguments` (Variable filter chains): `{{ p | diff_f1(1) }}`
  - Lax ignores the parenthesised argument entirely
  - lax: out="PV" callbacks=["filter:diff_f1()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `var-args-no-comma` (Variable filter chains): `{{ p | diff_f1: 1 2 | diff_f2 }}`
  - Lax silently drops the extra positional argument
  - lax: out="PV" callbacks=["filter:diff_f1(integer=1)", "filter:diff_f2()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `var-two-strings-no-comma` (Variable filter chains): `{{ p | diff_f1: 'a' 'b' | diff_f2 }}`
  - Second string is dropped by lax
  - lax: out="PV" callbacks=["filter:diff_f1(str=\"a\")", "filter:diff_f2()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `var-missing-pipe` (Variable filter chains): `{{ p diff_f1 }}`
  - Lax keeps the variable and ignores the trailing token
  - lax: out="PV" callbacks=[]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `var-trailing-token-after-name` (Variable filter chains): `{{ p extra }}`
  - Same variable, no filter, no error
  - lax: out="PV" callbacks=[]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `var-mismatched-quote` (Variable filter chains): `{{ p | diff_f1: 'x }}`
  - Unterminated quote becomes no argument and diff_f1 still runs
  - lax: out="PV" callbacks=["filter:diff_f1()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `var-arg-empty-between-commas` (Variable filter chains): `{{ p | diff_f1: , 1 }}`
  - Leading empty argument is dropped
  - lax: out="PV" callbacks=["filter:diff_f1(integer=1)"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `var-arg-double-comma` (Variable filter chains): `{{ p | diff_f1: 1,,2 }}`
  - Lax merges the adjacent comma into one argument list
  - lax: out="PV" callbacks=["filter:diff_f1(integer=1,integer=2)"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `var-bare-bracket` (Variable filter chains): `{{ [p] | diff_f1 }}`
  - Lax and strict accept bare bracket access (evaluating to nil, but still running the filter); strict2 requires self[...]
  - lax: out="" callbacks=["filter:diff_f1()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `render-double-comma` (render parameters): `{% render 'sn',, x: p %}`
  - Lax silently accepts the empty slot
  - lax: out="x=PVq=" callbacks=["read:sn", "tag:diff_tag(in_partial)", "filter:diff_f1()", "filter:diff_f2()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `render-missing-colon` (render parameters): `{% render 'sn', x p %}`
  - Lax turns 'x p' into a positional token, so x stays unset in the partial
  - lax: out="x=q=" callbacks=["read:sn", "tag:diff_tag(in_partial)", "filter:diff_f1()", "filter:diff_f2()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `render-quoted-key` (render parameters): `{% render 'sn', 'x': p %}`
  - Quoted key is not a TagAttributes key, so it does not bind x
  - lax: out="x=q=" callbacks=["read:sn", "tag:diff_tag(in_partial)", "filter:diff_f1()", "filter:diff_f2()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `render-empty-value` (render parameters): `{% render 'sn', x: %}`
  - Empty expression value; partial still runs with x unset
  - lax: out="x=q=" callbacks=["read:sn", "tag:diff_tag(in_partial)", "filter:diff_f1()", "filter:diff_f2()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `render-trailing-token` (render parameters): `{% render 'sn' with p as q extra %}`
  - Lax ignores the trailing token after the alias
  - lax: out="x=q=PV" callbacks=["read:sn", "tag:diff_tag(in_partial)", "filter:diff_f1()", "filter:diff_f2()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `render-trailing-pipe` (render parameters): `{% render 'sn' | diff_f1 %}`
  - Pipe is ignored by the lax render regex
  - lax: out="x=q=" callbacks=["read:sn", "tag:diff_tag(in_partial)", "filter:diff_f1()", "filter:diff_f2()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `render-trailing-comment` (render parameters): `{% render 'sn' # diff_f1 %}`
  - Hash comment text is ignored by the lax render regex
  - lax: out="x=q=" callbacks=["read:sn", "tag:diff_tag(in_partial)", "filter:diff_f1()", "filter:diff_f2()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `render-semicolon` (render parameters): `{% render 'sn'; x: p %}`
  - Semicolon is skipped and x still binds
  - lax: out="x=PVq=" callbacks=["read:sn", "tag:diff_tag(in_partial)", "filter:diff_f1()", "filter:diff_f2()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `render-with-no-expression` (render parameters): `{% render 'sn' with %}`
  - with without a value is ignored
  - lax: out="x=q=" callbacks=["read:sn", "tag:diff_tag(in_partial)", "filter:diff_f1()", "filter:diff_f2()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `render-as-no-name` (render parameters): `{% render 'sn' with p as %}`
  - Alias with no name is ignored; the partial still renders with its default variable name
  - lax: out="x=q=" callbacks=["read:sn", "tag:diff_tag(in_partial)", "filter:diff_f1()", "filter:diff_f2()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `render-as-quoted` (render parameters): `{% render 'sn' with p as 'q' %}`
  - Quoted alias is ignored
  - lax: out="x=q=" callbacks=["read:sn", "tag:diff_tag(in_partial)", "filter:diff_f1()", "filter:diff_f2()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `render-with-filter` (render parameters): `{% render 'sn' with p | diff_f1 %}`
  - Filters are not part of render arguments; lax regex drops the pipe clause
  - lax: out="x=q=" callbacks=["read:sn", "tag:diff_tag(in_partial)", "filter:diff_f1()", "filter:diff_f2()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `render-attr-filter` (render parameters): `{% render 'sn', x: p | diff_f1 %}`
  - TagAttributes value regex stops at the pipe, so the filter never binds
  - lax: out="x=PVq=" callbacks=["read:sn", "tag:diff_tag(in_partial)", "filter:diff_f1()", "filter:diff_f2()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `liquid-two-statements-one-line` (liquid multi-statement tags): `{% liquid echo p | diff_f1 echo q | diff_f2 %}`
  - Lax splits on the second echo; strict2 sees trailing tokens
  - lax: out="PV" callbacks=["filter:diff_f1()", "filter:diff_f2()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `liquid-semicolon-separator` (liquid multi-statement tags): `{% liquid echo p | diff_f1; echo q | diff_f2 %}`
  - Semicolon is not a statement separator in strict2
  - lax: out="PV" callbacks=["filter:diff_f1()", "filter:diff_f2()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `liquid-trailing-comment` (liquid multi-statement tags): `{% liquid
echo p | diff_f1 # diff_f2
%}`
  - Inline # text is dropped by lax, strict2 rejects it
  - lax: out="PV" callbacks=["filter:diff_f1()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `liquid-case-when-junk` (liquid multi-statement tags): `{% liquid
case p
when 'PV' extra
echo p | diff_f1
endcase
%}`
  - when trailing tokens tolerated by lax
  - lax: out="PV" callbacks=["filter:diff_f1()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `liquid-cycle` (liquid multi-statement tags): `{% liquid
cycle 'a', p | diff_f1
%}`
  - Cycle arguments cannot carry a filter chain in strict2
  - lax: out="a" callbacks=[]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `liquid-hash-no-space` (liquid multi-statement tags): `{% liquid
echo p | diff_f1# diff_f2
%}`
  - # attached to the expression is not a comment
  - lax: out="PV" callbacks=["filter:diff_f1()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `ctrl-if-filter` (Control-flow tags): `{% if p | diff_f1 %}{% diff_tag yes %}{% endif %}`
  - Lax treats the whole pipe clause as an expression; strict2 rejects it
  - lax: out="" callbacks=["tag:diff_tag(yes)"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `ctrl-if-parens` (Control-flow tags): `{% if (p == 'PV') %}{% diff_tag yes %}{% endif %}`
  - Redundant parentheses rejected by strict2
  - lax: out="" callbacks=["tag:diff_tag(yes)"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `ctrl-if-double-amp` (Control-flow tags): `{% if true && true %}{% diff_tag yes %}{% endif %}`
  - Lax interprets && loosely
  - lax: out="" callbacks=["tag:diff_tag(yes)"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `ctrl-if-two-filters` (Control-flow tags): `{% if p | diff_f1 | diff_f2 %}{% diff_tag yes %}{% endif %}`
  - Filter chain inside a condition
  - lax: out="" callbacks=["tag:diff_tag(yes)"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `ctrl-if-extra-token` (Control-flow tags): `{% if true extra %}{% diff_tag yes %}{% endif %}`
  - Trailing token becomes an unknown operator at render time
  - lax: out="Liquid error (line 1): Unknown operator extra" callbacks=[]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `ctrl-unless-filter` (Control-flow tags): `{% unless p | diff_f1 %}{% diff_tag yes %}{% endunless %}`
  - Same issue for unless
  - lax: out="" callbacks=[]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `ctrl-case-filter` (Control-flow tags): `{% case p %}{% when 'PV' | diff_f1 %}{% diff_tag yes %}{% endcase %}`
  - Filter chain in when clause
  - lax: out="" callbacks=["tag:diff_tag(yes)"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `ctrl-case-extra` (Control-flow tags): `{% case p %}{% when 'PV' extra %}{% diff_tag yes %}{% endcase %}`
  - Trailing token after when value
  - lax: out="" callbacks=["tag:diff_tag(yes)"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `ctrl-for-unknown-attr` (Control-flow tags): `{% for i in arr foo: 1 %}{% diff_tag i %}{% endfor %}`
  - Unknown for attribute ignored by lax
  - lax: out="" callbacks=["tag:diff_tag(i)", "tag:diff_tag(i)"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `ctrl-for-extra-dots` (Control-flow tags): `{% for i in (1...3) %}{% diff_tag i %}{% endfor %}`
  - Three dots in range accepted only by lax
  - lax: out="" callbacks=["tag:diff_tag(i)", "tag:diff_tag(i)", "tag:diff_tag(i)"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `ctrl-tablerow-unknown-attr` (Control-flow tags): `{% tablerow i in arr foo: 1 %}{% diff_tag i %}{% endtablerow %}`
  - Unknown tablerow attribute
  - lax: out="<tr class=\"row1\">\n<td class=\"col1\"></td><td class=\"col2\"></td></tr>\n" callbacks=["tag:diff_tag(i)", "tag:diff_tag(i)"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `ctrl-cycle-extra` (Control-flow tags): `{% cycle 'a', 'b' extra %}`
  - Trailing token after cycle list
  - lax: out="a" callbacks=[]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `ctrl-increment-extra` (Control-flow tags): `{% increment x y %}`
  - increment takes exactly one id in strict2
  - lax: out="0" callbacks=[]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `ctrl-decrement-extra` (Control-flow tags): `{% decrement x y %}`
  - decrement takes exactly one id in strict2
  - lax: out="-1" callbacks=[]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `ctrl-assign-dotted` (Control-flow tags): `{% assign a.b = p %}{{ a.b }}`
  - Lax accepts dotted targets; strict2 requires an id
  - lax: out="" callbacks=[]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `ctrl-assign-numeric` (Control-flow tags): `{% assign 1abc = p %}{{ 1abc }}`
  - Numeric identifier accepted only by lax
  - lax: out="PV" callbacks=[]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `ctrl-capture-quoted` (Control-flow tags): `{% capture 'c' %}x{% endcapture %}{{ c }}`
  - Quoted capture target
  - lax: out="x" callbacks=[]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `ctrl-echo-extra` (Control-flow tags): `{% echo p extra %}`
  - Trailing token in echo
  - lax: out="PV" callbacks=[]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `ctrl-include-filter-arg` (Control-flow tags): `{% include 'sn', x: p | diff_f1 %}`
  - Filter after an include argument
  - lax: out="x=PVq=QV" callbacks=["read:sn", "tag:diff_tag(in_partial)", "filter:diff_f1()", "filter:diff_f2()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax
- `ctrl-include-double-comma` (Control-flow tags): `{% include 'sn',, x: p %}`
  - Empty argument slot
  - lax: out="x=PVq=QV" callbacks=["read:sn", "tag:diff_tag(in_partial)", "filter:diff_f1()", "filter:diff_f2()"]
  - strict2: rejected (Liquid syntax error)
  - warn: fallback matches lax

### KEEP AS IS (`equivalent`)

- `var-valid-chain` (Variable filter chains): `{{ p | diff_f1 | diff_f2 }}`
  - Baseline accepted chain
  - warn: fallback matches lax
- `var-arg-trailing-comma` (Variable filter chains): `{{ p | diff_f1: 1, }}`
  - Trailing comma accepted by strict2 and lax but rejected by strict; warn is a hybrid (strict2 for tags, strict for variables) so it warns then falls back.
  - warn: fallback matches lax
- `var-arg-colon-empty` (Variable filter chains): `{{ p | diff_f1: }}`
  - No arguments on either parser
  - warn: fallback matches lax
- `var-double-quote-arg` (Variable filter chains): `{{ p | diff_f1: "x" }}`
  - Both parsers accept double-quoted argument
  - warn: fallback matches lax
- `var-arg-named-value` (Variable filter chains): `{{ p | diff_f1: k: 1 }}`
  - Lax turns k: 1 into a positional hash; strict2 also records one positional hash here
  - warn: fallback matches lax
- `var-filter-name-punctuation` (Variable filter chains): `{{ p | diff_f1? }}`
  - Unknown filter name is looked up but not invoked; both parsers agree
  - warn: fallback matches lax
- `var-filter-name-hyphen` (Variable filter chains): `{{ p | diff-f1 }}`
  - Hyphenated name is not a registered filter; both parsers agree
  - warn: fallback matches lax
- `render-valid-params` (render parameters): `{% render 'sn', x: p, y: q %}`
  - Comma separated named arguments
  - warn: fallback matches lax
- `render-valid-no-comma` (render parameters): `{% render 'sn' x: p %}`
  - Comma is optional between the name and arguments
  - warn: fallback matches lax
- `render-valid-trailing-comma` (render parameters): `{% render 'sn', x: p, %}`
  - Trailing comma accepted by both
  - warn: fallback matches lax
- `render-double-quoted-name` (render parameters): `{% render "sn" x: p %}`
  - Double quoted snippet name
  - warn: fallback matches lax
- `render-with-as-attr-no-comma` (render parameters): `{% render 'sn' with p as q x: p %}`
  - Both parsers bind the argument after the alias
  - warn: fallback matches lax
- `render-leading-comma-only` (render parameters): `{% render 'sn', %}`
  - Comma with no attributes leaves both x and q unset; lax and strict2 agree
  - warn: fallback matches lax
- `liquid-newline-statements` (liquid multi-statement tags): `{% liquid
echo p | diff_f1
echo q | diff_f2
%}`
  - One statement per line works in every mode
  - warn: fallback matches lax
- `liquid-comment-line` (liquid multi-statement tags): `{% liquid
# diff_f2
echo p | diff_f1
%}`
  - A full comment line is valid in both
  - warn: fallback matches lax
- `liquid-end-marker-junk` (liquid multi-statement tags): `{% liquid
if true
echo p | diff_f1
endif extra
%}`
  - Extra tokens on an end marker are ignored by every mode
  - warn: fallback matches lax
- `liquid-nested-end-markers` (liquid multi-statement tags): `{% liquid
if true
for i in arr
echo i | diff_f1
endfor
endif
%}`
  - Nested blocks close correctly
  - warn: fallback matches lax
- `liquid-block-junk-end` (liquid multi-statement tags): `{% liquid
for i in arr
echo i | diff_f1
endfor extra
%}`
  - Extra tokens on endfor are ignored by every mode
  - warn: fallback matches lax
- `liquid-case-valid` (liquid multi-statement tags): `{% liquid
case p
when 'PV' or 'a'
echo p | diff_f1
endcase
%}`
  - When with or is valid
  - warn: fallback matches lax
- `liquid-nested-liquid` (liquid multi-statement tags): `{% liquid
liquid
 echo p | diff_f1
%}`
  - Nested liquid tag works in both
  - warn: fallback matches lax
- `liquid-empty-lines` (liquid multi-statement tags): `{% liquid

 echo p | diff_f1

%}`
  - Blank lines are skipped
  - warn: fallback matches lax
- `liquid-trailing-space-before-close` (liquid multi-statement tags): `{% liquid
 echo p | diff_f1 
%}`
  - Trailing spaces are trimmed
  - warn: fallback matches lax
- `liquid-empty` (liquid multi-statement tags): `{% liquid %}`
  - Empty liquid tag is a no-op
  - warn: fallback matches lax
- `sep-tag-space` (Delimiters, quotes, trailing tokens): `{% diff_tag one %}`
  - Baseline tag
  - warn: fallback matches lax
- `sep-tag-no-space` (Delimiters, quotes, trailing tokens): `{%diff_tag one%}`
  - No spaces at all
  - warn: fallback matches lax
- `sep-tag-newline` (Delimiters, quotes, trailing tokens): `{%
diff_tag one
%}`
  - Newlines inside tag
  - warn: fallback matches lax
- `sep-tag-tab` (Delimiters, quotes, trailing tokens): `{%	diff_tag one	%}`
  - Tabs inside tag
  - warn: fallback matches lax
- `sep-whitespace-control-left` (Delimiters, quotes, trailing tokens): `a {%- diff_tag one %}`
  - Left trim marker parsed before the tag
  - warn: fallback matches lax
- `sep-whitespace-control-right` (Delimiters, quotes, trailing tokens): `{% diff_tag one -%} b`
  - Right trim marker parsed after the tag
  - warn: fallback matches lax
- `sep-variable-whitespace-control` (Delimiters, quotes, trailing tokens): `a {{- p | diff_f1 -}} b`
  - Trim markers on a variable
  - warn: fallback matches lax
- `sep-variable-inner-spaces` (Delimiters, quotes, trailing tokens): `{{  p  |  diff_f1  }}`
  - Padded inside the delimiters
  - warn: fallback matches lax
- `sep-variable-adjacent-text` (Delimiters, quotes, trailing tokens): `a{{ p | diff_f1 }}b`
  - Variable flush against text
  - warn: fallback matches lax
- `end-if-extra-tokens` (Block end markers): `{% if true %}{% diff_tag body %}{% endif extra %}`
  - Tag-level endif tolerates extra markup in every mode
  - warn: fallback matches lax
- `end-if-hash-note` (Block end markers): `{% if true %}{% diff_tag body %}{% endif # note %}`
  - Hash text on the ending tag is inert
  - warn: fallback matches lax
- `end-extra-else` (Block end markers): `{% if true %}{% diff_tag body %}{% else %}{% else %}{% endif %}`
  - Duplicate else is tolerated by every mode; only the first branch body runs
  - warn: fallback matches lax
- `end-case-extra` (Block end markers): `{% case p %}{% when 'PV' %}{% diff_tag body %}{% endcase extra %}`
  - endcase extra tokens tolerated
  - warn: fallback matches lax
- `end-tablerow-extra` (Block end markers): `{% tablerow i in arr %}{% diff_tag body %}{% endtablerow extra %}`
  - endtablerow extra tokens tolerated
  - warn: fallback matches lax
- `end-capture-extra` (Block end markers): `{% capture c %}{% diff_tag body %}{% endcapture extra %}`
  - endcapture extra tokens tolerated
  - warn: fallback matches lax
- `raw-probe-text` (raw / comment protected regions): `{% raw %}{% diff_tag hidden %}{{ x | diff_f1 }}{% endraw %}`
  - Raw text is emitted literally and never executed
  - warn: fallback matches lax
- `comment-probe-text` (raw / comment protected regions): `{% comment %}{% diff_tag hidden %}{{ x | diff_f1 }}{% endcomment %}`
  - Comment body is never executed
  - warn: fallback matches lax
- `raw-end-extra` (raw / comment protected regions): `{% raw %}{% diff_tag hidden %}{% endraw extra %}`
  - Raw terminator with extra tokens still ends the raw body
  - warn: fallback matches lax
- `comment-end-extra` (raw / comment protected regions): `{% comment %}{% diff_tag hidden %}{% endcomment extra %}`
  - Comment terminator with extra tokens
  - warn: fallback matches lax
- `comment-nested-comment` (raw / comment protected regions): `{% comment %}{% comment %}{% diff_tag hidden %}{% endcomment %}{% endcomment %}`
  - Nested comment tracked by depth
  - warn: fallback matches lax
- `raw-probe-nearby` (raw / comment protected regions): `{% raw %}{% diff_tag hidden %}{% endraw %}{% diff_tag after %}`
  - Only the tag outside raw runs
  - warn: fallback matches lax
- `comment-probe-nearby` (raw / comment protected regions): `{% comment %}x{% endcomment %}{% diff_tag after %}`
  - Only the tag outside comment runs
  - warn: fallback matches lax
- `raw-nested-liquid` (raw / comment protected regions): `{% raw %}{% liquid echo p | diff_f1 %}{% endraw %}`
  - liquid text inside raw is literal
  - warn: fallback matches lax
- `comment-nested-liquid` (raw / comment protected regions): `{% comment %}{% liquid echo p | diff_f1 %}{% endcomment %}`
  - liquid text inside comment is not executed
  - warn: fallback matches lax
- `doc-probe-text` (raw / comment protected regions): `{% doc %}{% diff_tag hidden %}{% enddoc %}`
  - Doc body is parsed but never executed
  - warn: fallback matches lax
- `comment-probe-tag-looking-markup` (raw / comment protected regions): `{% comment %}{% assign x = p | diff_f1 %}{% endcomment %}{{ x }}`
  - Assignments inside comment do not mutate state
  - warn: fallback matches lax
- `ctrl-if-valid` (Control-flow tags): `{% if p == 'PV' %}{% diff_tag yes %}{% else %}{% diff_tag no %}{% endif %}`
  - Baseline condition
  - warn: fallback matches lax
- `ctrl-if-and-or` (Control-flow tags): `{% if true and true or false %}{% diff_tag yes %}{% endif %}`
  - and/or chain valid in both
  - warn: fallback matches lax
- `ctrl-for-valid-attrs` (Control-flow tags): `{% for i in arr limit: 1, offset: 1 %}{% diff_tag i %}{% endfor %}`
  - Comma separated for attributes
  - warn: fallback matches lax
- `ctrl-if-quoted-delimiter` (Control-flow tags): `{% if '{% diff_tag x %' == 'x' %}{% diff_tag y %}{% endif %}`
  - Tag-looking text inside a quoted condition is inert
  - warn: fallback matches lax

### INVALID IN EVERY MODE (`rejected_both`)

- `liquid-close-outer-block` (liquid multi-statement tags): `{% if true %}{% liquid
endif
%}{% diff_tag after %}`
  - A liquid tag cannot close a block opened outside it
  - lax: rejected (Liquid syntax error)
  - strict2: rejected (Liquid syntax error)
  - warn: not applicable
- `sep-missing-tag-close` (Delimiters, quotes, trailing tokens): `{% diff_tag one`
  - Unterminated tag is a parse error everywhere
  - lax: rejected (Liquid syntax error)
  - strict2: rejected (Liquid syntax error)
  - warn: not applicable
- `sep-quoted-brace-text` (Delimiters, quotes, trailing tokens): `{{ 'a{% diff_tag x %}' }}`
  - Quotes do not shield {% from the tokenizer, so the inner tag is split and left unterminated
  - lax: rejected (Liquid syntax error)
  - strict2: rejected (Liquid syntax error)
  - warn: not applicable
- `end-mismatched` (Block end markers): `{% if true %}{% diff_tag body %}{% endunless %}`
  - Mismatched end tag rejected everywhere
  - lax: rejected (Liquid syntax error)
  - strict2: rejected (Liquid syntax error)
  - warn: not applicable
- `end-for-mismatched` (Block end markers): `{% for i in arr %}{% diff_tag body %}{% endif %}`
  - for cannot be closed by endif
  - lax: rejected (Liquid syntax error)
  - strict2: rejected (Liquid syntax error)
  - warn: not applicable
- `end-never-closed` (Block end markers): `{% if true %}{% diff_tag body %}`
  - Missing endif
  - lax: rejected (Liquid syntax error)
  - strict2: rejected (Liquid syntax error)
  - warn: not applicable
- `end-block-unknown` (Block end markers): `{% if true %}{% diff_tag body %}{% endwat %}`
  - Unknown end tag
  - lax: rejected (Liquid syntax error)
  - strict2: rejected (Liquid syntax error)
  - warn: not applicable
- `comment-nested-raw-marker` (raw / comment protected regions): `{% comment %}{% raw %}{% endcomment %}{% endraw %}{% diff_tag after %}`
  - endcomment inside raw does not close the outer comment
  - lax: rejected (Liquid syntax error)
  - strict2: rejected (Liquid syntax error)
  - warn: not applicable

