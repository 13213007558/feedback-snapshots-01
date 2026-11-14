# Snippet include → render migration audit

This example is a read-only checker, not an auto-rewriter. It helps a caller
add only the explicit arguments a snippet actually needs, without forwarding the
whole parent context.

## What the checker reports

For every `{% include %}` with a statically resolvable snippet name:

- `dependencies`: variables the snippet reads that are not defined locally.
- `caller_can_provide`: the expression the caller can pass based on its known
  bindings or the include's own arguments. Globals are marked optional because
  `render` still sees them without an argument.
- `include_implicit_bindings`: the bare-include variable resolved from caller
  scope (including the `include "x" as y` form, which reads `x`, not `y`).
- `local_shadowing`: loop variables, `assign`, `capture`, `increment`, and
  `decrement` definitions inside the snippet.
- `include_side_effects`: snippet assignments that `include` leaks back to the
  caller, and which `render` isolates. If the caller reads that name after the
  include, the call is marked `manual_review`.
- `suggested_render`: a proposed call for review. Nothing is written back.

Everything the checker cannot prove is listed under `manual_review` instead of
being guessed:

- dynamic template names and dynamic bracket keys;
- custom tags;
- nested `include` calls;
- private parent values.

`render` is not a sandbox. The report always lists global/static environment
data that remains visible inside the isolated subcontext, and global
dependencies are marked `global_environment_still_visible` with
`render_argument_needed: false`.

## Run it

```sh
bin/liquid-snippet-migration \
  --template example/snippet_migration/templates/caller.liquid \
  --snippets example/snippet_migration/snippets \
  --caller-binding featured_product \
  --caller-binding badge \
  --caller-binding entries \
  --global shop \
  --global routes \
  --global all_products \
  --private private_token \
  --format text
```

The three snippets cover the requested cases:

| Snippet | Case |
| --- | --- |
| `product_card.liquid` | explicit `with ... as` value plus an argument; also assigns `heading`, shadowing a caller local |
| `line_items.liquid` | loop item and `forloop` names that must stay local |
| `secret_probe.liquid` | reads a private parent value; never suggested as a render argument |

`line_items.liquid` deliberately reads `entries` from the parent scope. Without
`--caller-binding entries`, the checker marks it `manual_review`; with that
declaration it produces the explicit `render` argument shown below.

## Reproduce the behavior

```sh
bundle exec ruby example/snippet_migration/run.rb
```

The script renders the same templates through legacy `include` and migrated
`render` and asserts:

- the legitimate outputs are byte-for-byte identical;
- the private value is read once by legacy `include` and zero times by `render`;
- an assignment inside a snippet leaks to the caller under `include`, but not
  under `render`.

Private values are connected to a counting drop, so the example proves reads
without printing the secret.
