CCITT Group 4 mutation testing
==============================

.. default-literal-role:: code

This note describes the reproducible, budget-bounded mutation tests for the
CCITT Group 4 (T.6) decoder in :mod:`pdfminer.ccitt`. They live in
:file:`tests/test_pdfminer_ccitt_mutation.py` and target the realistic attack
surface of a malicious scanned PDF: short, hand-shaped bitstreams fed through
`CCITTFaxDecoder.feedbytes`. There is no random fuzzing and no long collision
loop; every input is generated from a small, fixed set of legal encodings and
explicit, single-purpose mutation operators. The whole module runs in about
1.4 seconds.

Why a dedicated harness
-----------------------

The decoder keeps its state in three places: the changing-element cursor
`_curpos`, the per-line coding colour `_color`, and the output arrays
`_curline` / `_refline`. A correct T.6 stream must keep every write inside the
declared column geometry `[0, Columns)`, must emit rows whose width equals
`Columns`, and must terminate. Two implementation details make those
invariants hard to verify with ordinary assertions:

* `array.array("b")` maps a *negative* index onto a real element, so an
  out-of-domain write at index `-1` is silently aliased to the last pixel
  instead of raising.
* The decoder has no row or byte budget, so a very short stream can request an
  unbounded number of output rows.

The harness addresses both directly rather than waiting for them to crash by
luck.

Harness layers
--------------

The test module is organised in five deterministic layers.

1. **Code-table recovery.** `reverse_code_tables` walks the parser's own
   `WHITE`, `BLACK` and `MODE` decision trees to recover the exact T.6 code
   strings. The encoder therefore cannot drift from the decoder, and the
   recovered tables are asserted to be uniquely decodable.
2. **Independent reference renderer.** `render_row` renders a coding row from
   high-level operations against a reference row. It does not import or call
   any decoder state; its vertical and pass boundary scans are written
   independently. Every *legal* seed must match it pixel for pixel, so the
   "good" outputs are certified by a separate line-mode model rather than by
   the code under test.
3. **Boundary instrumentation.** `CheckedCCITTFaxDecoder` swaps the output
   arrays for a `CheckedArray` that raises `IndexError` on any negative or
   past-the-end index. This turns the silent `-1` alias into an observable
   `index_out_of_domain` violation.
4. **Explicit mutators.** `MUTATORS` applies small transformations to legal
   bitstrings — truncation, single-bit flips/inserts, first-mode swaps, EOFB
   removal and alignment shifts — which target vertical/pass/horizontal mode
   switching, line termination, byte alignment and column width. A separate
   `PREFIX_CASES` table drives the degenerate geometry corners directly.
5. **Minimisation with legal neighbours.** `minimize` delta-debugs every
   failing bitstring by bit deletion and bit flipping until no shorter string
   keeps the same violation class, then records the single-edit *legal
   neighbours* that no longer violate any invariant. This proves each
   counterexample is a sharp, localised edge.

All execution is bounded by `line_cap(width)` (a fixed multiple of the
declared width) and a byte budget derived from it, so runaway output is
stopped deterministically instead of hanging the test run.

State invariants and the counterexamples
----------------------------------------

Each failure label names the invariant that was broken.

`index_out_of_domain`
    Every cursor write must land in `[0, Columns)`. Three reachable inputs
    break it:

    * **Pass mode as the first coding element of a row.** At row start
      `_curpos == -1`. `_do_pass` executes `range(self._curpos, x1)`, i.e.
      `range(-1, x1)`, and writes through index `-1`. A `array.array` aliases
      that onto the last pixel, so the corruption is invisible without the
      `CheckedArray` wrapper. The four-bit pass code `0001` alone triggers it
      at any positive width; minimisation of longer mutants always converges
      on this same root code.

    * **Vertical mode with `Columns == 0`.** The single vertical(0) code `1`
      indexes the empty reference line on the first changing-element scan and
      raises `array index out of range`. A PDF that declares zero columns
      reaches this immediately.

    * **Pass mode with `Columns == 0`.** The pass code `0001` hits the same
      empty-line index on its boundary scan.

`line_width_mismatch`
    Every emitted row must contain exactly `Columns` pixels. The collecting
    callback asserts this on each flush; no current legal or mutated input in
    the fixed corpus breaks it, which pins the geometry contract against
    regressions.

`line_budget_exceeded` / `output_budget_exceeded`
    Output must stay within the explicit row/byte budgets. A single four-bit
    pass code can fill an entire declared row, so a short repeated stream has
    no natural stopping point. For example, eight pass codes (four input
    bytes) at `Columns = 1728` produce eight full rows — 1728 output bytes —
    and the growth continues linearly with no EOFB. The harness hard-stops the
    amplification at `line_cap(width)`; the underlying decoder itself has no
    such cap, which is the uncontrolled-output weakness.

`unterminated_or_invalid_stream`
    A well-formed image ends with the 24-bit EOFB. An unparseable mode prefix
    (for example a stray bit inserted into a legal all-white row) raises
    `InvalidData` and is classified here. A stream merely truncated before
    EOFB does *not* raise in the current decoder; the test pins that observed
    behaviour and still requires it to terminate within budget rather than run
    away.

Minimised counterexamples and legal neighbours
-----------------------------------------------

The minimiser collapses every failing family to its root T.6 code while
preserving the violation class:

* the pass/negative-index family reduces to the four bits `0001`;
* the zero-column vertical family reduces to the single bit `1`.

For `0001` at width 8 the legal neighbours include `001`, `1001`, `0101`,
`0011`, `000` and `0000` — each a single edit away, each clean under every
invariant. Their presence shows the defect is the specific pass-at-row-start
boundary, not broad bitstream corruption.

Legal seed certification
-------------------------

Three legal seed families are encoded at widths `(1, 2, 4, 8, 16, 17, 33)`:

* an all-white row built from `width` vertical(0) codes against the implicit
  white reference;
* a single black-stripe row built from horizontal run-length codes;
* an alternating row that reaches the stripe boundary with vertical(0), then
  uses pass mode and vertical(0) to reproduce the reference.

Every legal seed is asserted violation-free and its pixels are asserted equal
to the independent `render_row` output. Pass mode is deliberately never the
first element of a legal seed, since that position is precisely the
negative-index defect documented above.

Running the tests
-----------------

::

    python -m pytest tests/test_pdfminer_ccitt_mutation.py -q

The campaign performs roughly 1.5k deterministic trials plus the targeted
prefix and minimisation cases, and finishes in about 1.4 seconds.
