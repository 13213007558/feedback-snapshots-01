# frozen_string_literal: true

require_relative 'strict2_differential'

# Minimal ambiguous templates, grouped by grammar axis.
#
# Each entry is a Strict2Differential::Case plus the expected relationship a
# migration owner should see. The expectations are checked by the differential
# test so a corpus entry can never silently rot into a different category.
#
# Template variable meanings:
#   p=PV q=QV arr=[1,2] h={"x"=>"XV"}      partial 'sn'  → {% diff_tag in_partial %}... x/q filters
#
# Markers that must remain inert (never counted as executed callbacks):
#   {% raw %}{% diff_tag hidden %}...{% endraw %}
#   {% comment %}{% diff_tag hidden %}
module Strict2DifferentialCorpus
  Case = Strict2Differential::Case
  PARTIAL = Strict2Differential::PARTIALS

  def self.entry(id, axis, template, category, warn_relation, notes, partials: PARTIAL)
    {
      case: Case.new(id: id, axis: axis, template: template, partials: partials, notes: notes),
      category: category,
      warn_relation: warn_relation,
    }
  end

  def self.all
    @all ||= [
      *variable_cases,
      *render_cases,
      *liquid_cases,
      *separator_cases,
      *block_end_cases,
      *protected_region_cases,
      *control_cases,
    ]
  end

  def self.variable_cases
    [
      entry("var-valid-chain", :variable, "{{ p | diff_f1 | diff_f2 }}", :equivalent, :fallback_matches_lax,
        "Baseline accepted chain"),
      entry("var-trailing-pipe", :variable, "{{ p | diff_f1 | }}", :loose_only, :fallback_matches_lax,
        "Lax drops the dangling pipe and runs diff_f1 only"),
      entry("var-leading-pipe", :variable, "{{ p || diff_f1 }}", :loose_only, :fallback_matches_lax,
        "Lax skips the empty filter slot; strict2 rejects the duplicate separator"),
      entry("var-comma-separates-filters", :variable, "{{ p | diff_f1, diff_f2 }}", :loose_only, :fallback_matches_lax,
        "Lax treats comma as a filter argument, so only diff_f1 runs"),
      entry("var-quoted-filter-name", :variable, "{{ p | 'diff_f1' }}", :loose_only, :fallback_matches_lax,
        "Lax resolves quoted text as a filter name"),
      entry("var-paren-arguments", :variable, "{{ p | diff_f1(1) }}", :loose_only, :fallback_matches_lax,
        "Lax ignores the parenthesised argument entirely"),
      entry("var-args-no-comma", :variable, "{{ p | diff_f1: 1 2 | diff_f2 }}", :loose_only, :fallback_matches_lax,
        "Lax silently drops the extra positional argument"),
      entry("var-two-strings-no-comma", :variable, "{{ p | diff_f1: 'a' 'b' | diff_f2 }}",
        :loose_only, :fallback_matches_lax, "Second string is dropped by lax"),
      entry("var-missing-pipe", :variable, "{{ p diff_f1 }}", :loose_only, :fallback_matches_lax,
        "Lax keeps the variable and ignores the trailing token"),
      entry("var-trailing-token-after-name", :variable, "{{ p extra }}", :loose_only, :fallback_matches_lax,
        "Same variable, no filter, no error"),
      entry("var-mismatched-quote", :variable, "{{ p | diff_f1: 'x }}", :loose_only, :fallback_matches_lax,
        "Unterminated quote becomes no argument and diff_f1 still runs"),
      entry("var-arg-trailing-comma", :variable, "{{ p | diff_f1: 1, }}", :equivalent,
        :fallback_matches_lax,
        "Trailing comma accepted by strict2 and lax but rejected by strict; " \
          "warn is a hybrid (strict2 for tags, strict for variables) so it warns then falls back."),
      entry("var-arg-empty-between-commas", :variable, "{{ p | diff_f1: , 1 }}", :loose_only, :fallback_matches_lax,
        "Leading empty argument is dropped"),
      entry("var-arg-double-comma", :variable, "{{ p | diff_f1: 1,,2 }}", :loose_only, :fallback_matches_lax,
        "Lax merges the adjacent comma into one argument list"),
      entry("var-arg-colon-empty", :variable, "{{ p | diff_f1: }}", :equivalent, :fallback_matches_lax,
        "No arguments on either parser"),
      entry("var-bare-bracket", :variable, "{{ [p] | diff_f1 }}", :loose_only, :fallback_matches_lax,
        "Lax and strict accept bare bracket access (evaluating to nil, but still running the filter); " \
          "strict2 requires self[...]"),
      entry("var-double-quote-arg", :variable, %q({{ p | diff_f1: "x" }}), :equivalent, :fallback_matches_lax,
        "Both parsers accept double-quoted argument"),
      entry("var-arg-named-value", :variable, "{{ p | diff_f1: k: 1 }}", :equivalent, :fallback_matches_lax,
        "Lax turns k: 1 into a positional hash; strict2 also records one positional hash here"),
      entry("var-filter-name-punctuation", :variable, "{{ p | diff_f1? }}", :equivalent, :fallback_matches_lax,
        "Unknown filter name is looked up but not invoked; both parsers agree"),
      entry("var-filter-name-hyphen", :variable, "{{ p | diff-f1 }}", :equivalent, :fallback_matches_lax,
        "Hyphenated name is not a registered filter; both parsers agree"),
    ]
  end

  def self.render_cases
    [
      entry("render-valid-params", :render, "{% render 'sn', x: p, y: q %}", :equivalent, :fallback_matches_lax,
        "Comma separated named arguments"),
      entry("render-valid-no-comma", :render, "{% render 'sn' x: p %}", :equivalent, :fallback_matches_lax,
        "Comma is optional between the name and arguments"),
      entry("render-valid-trailing-comma", :render, "{% render 'sn', x: p, %}", :equivalent, :fallback_matches_lax,
        "Trailing comma accepted by both"),
      entry("render-double-comma", :render, "{% render 'sn',, x: p %}", :loose_only, :fallback_matches_lax,
        "Lax silently accepts the empty slot"),
      entry("render-missing-colon", :render, "{% render 'sn', x p %}", :loose_only, :fallback_matches_lax,
        "Lax turns 'x p' into a positional token, so x stays unset in the partial"),
      entry("render-quoted-key", :render, "{% render 'sn', 'x': p %}", :loose_only, :fallback_matches_lax,
        "Quoted key is not a TagAttributes key, so it does not bind x"),
      entry("render-empty-value", :render, "{% render 'sn', x: %}", :loose_only, :fallback_matches_lax,
        "Empty expression value; partial still runs with x unset"),
      entry("render-trailing-token", :render, "{% render 'sn' with p as q extra %}", :loose_only, :fallback_matches_lax,
        "Lax ignores the trailing token after the alias"),
      entry("render-trailing-pipe", :render, "{% render 'sn' | diff_f1 %}", :loose_only, :fallback_matches_lax,
        "Pipe is ignored by the lax render regex"),
      entry("render-trailing-comment", :render, "{% render 'sn' # diff_f1 %}", :loose_only, :fallback_matches_lax,
        "Hash comment text is ignored by the lax render regex"),
      entry("render-semicolon", :render, "{% render 'sn'; x: p %}", :loose_only, :fallback_matches_lax,
        "Semicolon is skipped and x still binds"),
      entry("render-with-no-expression", :render, "{% render 'sn' with %}", :loose_only, :fallback_matches_lax,
        "with without a value is ignored"),
      entry("render-as-no-name", :render, "{% render 'sn' with p as %}", :loose_only, :fallback_matches_lax,
        "Alias with no name is ignored; the partial still renders with its default variable name"),
      entry("render-as-quoted", :render, "{% render 'sn' with p as 'q' %}", :loose_only, :fallback_matches_lax,
        "Quoted alias is ignored"),
      entry("render-double-quoted-name", :render, %q({% render "sn" x: p %}), :equivalent, :fallback_matches_lax,
        "Double quoted snippet name"),
      entry("render-with-filter", :render, "{% render 'sn' with p | diff_f1 %}", :loose_only, :fallback_matches_lax,
        "Filters are not part of render arguments; lax regex drops the pipe clause"),
      entry("render-attr-filter", :render, "{% render 'sn', x: p | diff_f1 %}", :loose_only, :fallback_matches_lax,
        "TagAttributes value regex stops at the pipe, so the filter never binds"),
      entry("render-with-as-attr-no-comma", :render, "{% render 'sn' with p as q x: p %}",
        :equivalent, :fallback_matches_lax, "Both parsers bind the argument after the alias"),
      entry("render-leading-comma-only", :render, "{% render 'sn', %}", :equivalent, :fallback_matches_lax,
        "Comma with no attributes leaves both x and q unset; lax and strict2 agree"),
    ]
  end

  def self.liquid_cases
    [
      entry("liquid-newline-statements", :liquid, "{% liquid\necho p | diff_f1\necho q | diff_f2\n%}",
        :equivalent, :fallback_matches_lax, "One statement per line works in every mode"),
      entry("liquid-two-statements-one-line", :liquid, "{% liquid echo p | diff_f1 echo q | diff_f2 %}",
        :loose_only, :fallback_matches_lax, "Lax splits on the second echo; strict2 sees trailing tokens"),
      entry("liquid-semicolon-separator", :liquid, "{% liquid echo p | diff_f1; echo q | diff_f2 %}",
        :loose_only, :fallback_matches_lax, "Semicolon is not a statement separator in strict2"),
      entry("liquid-trailing-comment", :liquid, "{% liquid\necho p | diff_f1 # diff_f2\n%}",
        :loose_only, :fallback_matches_lax, "Inline # text is dropped by lax, strict2 rejects it"),
      entry("liquid-comment-line", :liquid, "{% liquid\n# diff_f2\necho p | diff_f1\n%}",
        :equivalent, :fallback_matches_lax, "A full comment line is valid in both"),
      entry("liquid-end-marker-junk", :liquid, "{% liquid\nif true\necho p | diff_f1\nendif extra\n%}",
        :equivalent, :fallback_matches_lax, "Extra tokens on an end marker are ignored by every mode"),
      entry("liquid-nested-end-markers", :liquid,
        "{% liquid\nif true\nfor i in arr\necho i | diff_f1\nendfor\nendif\n%}",
        :equivalent, :fallback_matches_lax, "Nested blocks close correctly"),
      entry("liquid-block-junk-end", :liquid, "{% liquid\nfor i in arr\necho i | diff_f1\nendfor extra\n%}",
        :equivalent, :fallback_matches_lax, "Extra tokens on endfor are ignored by every mode"),
      entry("liquid-case-when-junk", :liquid, "{% liquid\ncase p\nwhen 'PV' extra\necho p | diff_f1\nendcase\n%}",
        :loose_only, :fallback_matches_lax, "when trailing tokens tolerated by lax"),
      entry("liquid-case-valid", :liquid, "{% liquid\ncase p\nwhen 'PV' or 'a'\necho p | diff_f1\nendcase\n%}",
        :equivalent, :fallback_matches_lax, "When with or is valid"),
      entry("liquid-cycle", :liquid, "{% liquid\ncycle 'a', p | diff_f1\n%}", :loose_only, :fallback_matches_lax,
        "Cycle arguments cannot carry a filter chain in strict2"),
      entry("liquid-nested-liquid", :liquid, "{% liquid\nliquid\n echo p | diff_f1\n%}", :equivalent,
        :fallback_matches_lax, "Nested liquid tag works in both"),
      entry("liquid-empty-lines", :liquid, "{% liquid\n\n echo p | diff_f1\n\n%}", :equivalent,
        :fallback_matches_lax, "Blank lines are skipped"),
      entry("liquid-close-outer-block", :liquid, "{% if true %}{% liquid\nendif\n%}{% diff_tag after %}",
        :rejected_both, :not_applicable, "A liquid tag cannot close a block opened outside it"),
      entry("liquid-trailing-space-before-close", :liquid, "{% liquid\n echo p | diff_f1 \n%}", :equivalent,
        :fallback_matches_lax, "Trailing spaces are trimmed"),
      entry("liquid-hash-no-space", :liquid, "{% liquid\necho p | diff_f1# diff_f2\n%}", :loose_only,
        :fallback_matches_lax, "# attached to the expression is not a comment"),
      entry("liquid-empty", :liquid, "{% liquid %}", :equivalent, :fallback_matches_lax, "Empty liquid tag is a no-op"),
    ]
  end

  def self.separator_cases
    [
      entry("sep-tag-space", :separator, "{% diff_tag one %}", :equivalent, :fallback_matches_lax, "Baseline tag"),
      entry("sep-tag-no-space", :separator, "{%diff_tag one%}", :equivalent, :fallback_matches_lax, "No spaces at all"),
      entry("sep-tag-newline", :separator, "{%\ndiff_tag one\n%}", :equivalent, :fallback_matches_lax,
        "Newlines inside tag"),
      entry("sep-tag-tab", :separator, "{%\tdiff_tag one\t%}", :equivalent, :fallback_matches_lax, "Tabs inside tag"),
      entry("sep-whitespace-control-left", :separator, "a {%- diff_tag one %}", :equivalent, :fallback_matches_lax,
        "Left trim marker parsed before the tag"),
      entry("sep-whitespace-control-right", :separator, "{% diff_tag one -%} b", :equivalent, :fallback_matches_lax,
        "Right trim marker parsed after the tag"),
      entry("sep-variable-whitespace-control", :separator, "a {{- p | diff_f1 -}} b", :equivalent,
        :fallback_matches_lax, "Trim markers on a variable"),
      entry("sep-variable-inner-spaces", :separator, "{{  p  |  diff_f1  }}", :equivalent, :fallback_matches_lax,
        "Padded inside the delimiters"),
      entry("sep-missing-tag-close", :separator, "{% diff_tag one", :rejected_both, :not_applicable,
        "Unterminated tag is a parse error everywhere"),
      entry("sep-variable-adjacent-text", :separator, "a{{ p | diff_f1 }}b", :equivalent, :fallback_matches_lax,
        "Variable flush against text"),
      entry("sep-quoted-brace-text", :separator, "{{ 'a{% diff_tag x %}' }}", :rejected_both, :not_applicable,
        "Quotes do not shield {% from the tokenizer, so the inner tag is split and left unterminated"),
    ]
  end

  def self.block_end_cases
    [
      entry("end-if-extra-tokens", :block_end, "{% if true %}{% diff_tag body %}{% endif extra %}",
        :equivalent, :fallback_matches_lax, "Tag-level endif tolerates extra markup in every mode"),
      entry("end-if-hash-note", :block_end, "{% if true %}{% diff_tag body %}{% endif # note %}",
        :equivalent, :fallback_matches_lax, "Hash text on the ending tag is inert"),
      entry("end-mismatched", :block_end, "{% if true %}{% diff_tag body %}{% endunless %}",
        :rejected_both, :not_applicable, "Mismatched end tag rejected everywhere"),
      entry("end-for-mismatched", :block_end, "{% for i in arr %}{% diff_tag body %}{% endif %}",
        :rejected_both, :not_applicable, "for cannot be closed by endif"),
      entry("end-never-closed", :block_end, "{% if true %}{% diff_tag body %}", :rejected_both, :not_applicable,
        "Missing endif"),
      entry("end-extra-else", :block_end, "{% if true %}{% diff_tag body %}{% else %}{% else %}{% endif %}",
        :equivalent, :fallback_matches_lax,
        "Duplicate else is tolerated by every mode; only the first branch body runs"),
      entry("end-case-extra", :block_end, "{% case p %}{% when 'PV' %}{% diff_tag body %}{% endcase extra %}",
        :equivalent, :fallback_matches_lax, "endcase extra tokens tolerated"),
      entry("end-tablerow-extra", :block_end, "{% tablerow i in arr %}{% diff_tag body %}{% endtablerow extra %}",
        :equivalent, :fallback_matches_lax, "endtablerow extra tokens tolerated"),
      entry("end-capture-extra", :block_end, "{% capture c %}{% diff_tag body %}{% endcapture extra %}",
        :equivalent, :fallback_matches_lax, "endcapture extra tokens tolerated"),
      entry("end-block-unknown", :block_end, "{% if true %}{% diff_tag body %}{% endwat %}",
        :rejected_both, :not_applicable, "Unknown end tag"),
    ]
  end

  def self.protected_region_cases
    [
      entry("raw-probe-text", :protected_region, "{% raw %}{% diff_tag hidden %}{{ x | diff_f1 }}{% endraw %}",
        :equivalent, :fallback_matches_lax, "Raw text is emitted literally and never executed"),
      entry("comment-probe-text", :protected_region,
        "{% comment %}{% diff_tag hidden %}{{ x | diff_f1 }}{% endcomment %}",
        :equivalent, :fallback_matches_lax, "Comment body is never executed"),
      entry("raw-end-extra", :protected_region, "{% raw %}{% diff_tag hidden %}{% endraw extra %}",
        :equivalent, :fallback_matches_lax, "Raw terminator with extra tokens still ends the raw body"),
      entry("comment-end-extra", :protected_region, "{% comment %}{% diff_tag hidden %}{% endcomment extra %}",
        :equivalent, :fallback_matches_lax, "Comment terminator with extra tokens"),
      entry("comment-nested-raw-marker", :protected_region,
        "{% comment %}{% raw %}{% endcomment %}{% endraw %}{% diff_tag after %}", :rejected_both, :not_applicable,
        "endcomment inside raw does not close the outer comment"),
      entry("comment-nested-comment", :protected_region,
        "{% comment %}{% comment %}{% diff_tag hidden %}{% endcomment %}{% endcomment %}", :equivalent,
        :fallback_matches_lax, "Nested comment tracked by depth"),
      entry("raw-probe-nearby", :protected_region, "{% raw %}{% diff_tag hidden %}{% endraw %}{% diff_tag after %}",
        :equivalent, :fallback_matches_lax, "Only the tag outside raw runs"),
      entry("comment-probe-nearby", :protected_region, "{% comment %}x{% endcomment %}{% diff_tag after %}",
        :equivalent, :fallback_matches_lax, "Only the tag outside comment runs"),
      entry("raw-nested-liquid", :protected_region, "{% raw %}{% liquid echo p | diff_f1 %}{% endraw %}",
        :equivalent, :fallback_matches_lax, "liquid text inside raw is literal"),
      entry("comment-nested-liquid", :protected_region, "{% comment %}{% liquid echo p | diff_f1 %}{% endcomment %}",
        :equivalent, :fallback_matches_lax, "liquid text inside comment is not executed"),
      entry("doc-probe-text", :protected_region, "{% doc %}{% diff_tag hidden %}{% enddoc %}", :equivalent,
        :fallback_matches_lax, "Doc body is parsed but never executed"),
      entry("comment-probe-tag-looking-markup", :protected_region,
        "{% comment %}{% assign x = p | diff_f1 %}{% endcomment %}{{ x }}", :equivalent, :fallback_matches_lax,
        "Assignments inside comment do not mutate state"),
    ]
  end

  def self.control_cases
    [
      entry("ctrl-if-valid", :control, "{% if p == 'PV' %}{% diff_tag yes %}{% else %}{% diff_tag no %}{% endif %}",
        :equivalent, :fallback_matches_lax, "Baseline condition"),
      entry("ctrl-if-filter", :control, "{% if p | diff_f1 %}{% diff_tag yes %}{% endif %}", :loose_only,
        :fallback_matches_lax, "Lax treats the whole pipe clause as an expression; strict2 rejects it"),
      entry("ctrl-if-parens", :control, "{% if (p == 'PV') %}{% diff_tag yes %}{% endif %}", :loose_only,
        :fallback_matches_lax, "Redundant parentheses rejected by strict2"),
      entry("ctrl-if-double-amp", :control, "{% if true && true %}{% diff_tag yes %}{% endif %}", :loose_only,
        :fallback_matches_lax, "Lax interprets && loosely"),
      entry("ctrl-if-two-filters", :control, "{% if p | diff_f1 | diff_f2 %}{% diff_tag yes %}{% endif %}",
        :loose_only, :fallback_matches_lax, "Filter chain inside a condition"),
      entry("ctrl-if-extra-token", :control, "{% if true extra %}{% diff_tag yes %}{% endif %}", :loose_only,
        :fallback_matches_lax, "Trailing token becomes an unknown operator at render time"),
      entry("ctrl-unless-filter", :control, "{% unless p | diff_f1 %}{% diff_tag yes %}{% endunless %}", :loose_only,
        :fallback_matches_lax, "Same issue for unless"),
      entry("ctrl-if-and-or", :control, "{% if true and true or false %}{% diff_tag yes %}{% endif %}", :equivalent,
        :fallback_matches_lax, "and/or chain valid in both"),
      entry("ctrl-case-filter", :control,
        "{% case p %}{% when 'PV' | diff_f1 %}{% diff_tag yes %}{% endcase %}", :loose_only,
        :fallback_matches_lax, "Filter chain in when clause"),
      entry("ctrl-case-extra", :control,
        "{% case p %}{% when 'PV' extra %}{% diff_tag yes %}{% endcase %}", :loose_only,
        :fallback_matches_lax, "Trailing token after when value"),
      entry("ctrl-for-unknown-attr", :control, "{% for i in arr foo: 1 %}{% diff_tag i %}{% endfor %}", :loose_only,
        :fallback_matches_lax, "Unknown for attribute ignored by lax"),
      entry("ctrl-for-extra-dots", :control, "{% for i in (1...3) %}{% diff_tag i %}{% endfor %}", :loose_only,
        :fallback_matches_lax, "Three dots in range accepted only by lax"),
      entry("ctrl-for-valid-attrs", :control, "{% for i in arr limit: 1, offset: 1 %}{% diff_tag i %}{% endfor %}",
        :equivalent, :fallback_matches_lax, "Comma separated for attributes"),
      entry("ctrl-tablerow-unknown-attr", :control, "{% tablerow i in arr foo: 1 %}{% diff_tag i %}{% endtablerow %}",
        :loose_only, :fallback_matches_lax, "Unknown tablerow attribute"),
      entry("ctrl-cycle-extra", :control, "{% cycle 'a', 'b' extra %}", :loose_only, :fallback_matches_lax,
        "Trailing token after cycle list"),
      entry("ctrl-increment-extra", :control, "{% increment x y %}", :loose_only, :fallback_matches_lax,
        "increment takes exactly one id in strict2"),
      entry("ctrl-decrement-extra", :control, "{% decrement x y %}", :loose_only, :fallback_matches_lax,
        "decrement takes exactly one id in strict2"),
      entry("ctrl-assign-dotted", :control, "{% assign a.b = p %}{{ a.b }}", :loose_only, :fallback_matches_lax,
        "Lax accepts dotted targets; strict2 requires an id"),
      entry("ctrl-assign-numeric", :control, "{% assign 1abc = p %}{{ 1abc }}", :loose_only, :fallback_matches_lax,
        "Numeric identifier accepted only by lax"),
      entry("ctrl-capture-quoted", :control, "{% capture 'c' %}x{% endcapture %}{{ c }}", :loose_only,
        :fallback_matches_lax, "Quoted capture target"),
      entry("ctrl-echo-extra", :control, "{% echo p extra %}", :loose_only, :fallback_matches_lax,
        "Trailing token in echo"),
      entry("ctrl-include-filter-arg", :control, "{% include 'sn', x: p | diff_f1 %}", :loose_only,
        :fallback_matches_lax, "Filter after an include argument"),
      entry("ctrl-include-double-comma", :control, "{% include 'sn',, x: p %}", :loose_only, :fallback_matches_lax,
        "Empty argument slot"),
      entry("ctrl-if-quoted-delimiter", :control, "{% if '{% diff_tag x %' == 'x' %}{% diff_tag y %}{% endif %}",
        :equivalent, :fallback_matches_lax, "Tag-looking text inside a quoted condition is inert"),
    ]
  end
end
