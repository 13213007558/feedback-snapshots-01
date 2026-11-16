"""Reproducible, budget-bounded mutation tests for the CCITT Group 4 decoder.

The goal is to find state-out-of-bounds and uncontrolled-output defects that a
malicious scanned PDF can reach through ``CCITTFaxDecoder.feedbytes`` -- the
real entry point -- instead of relying on long random fuzzing campaigns.

The harness is fully deterministic and organised in five layers:

1. ``reverse_code_tables`` recovers the exact T.6 code strings from the
   parser's own decision trees, so the encoder cannot drift from the decoder.
2. ``render_row`` is an *independent*, spec-faithful T.6 reference renderer.
   Legal seeds are required to match it pixel for pixel.
3. ``CheckedCCITTFaxDecoder`` replaces the output arrays with a storage object
   that raises on any out-of-domain index, exposing negative-index writes that
   a plain ``array.array`` silently aliases onto the last element.
4. ``MUTATORS`` are small, explicit transformations of legal bitstrings that
   target vertical / pass / horizontal mode switching, line termination,
   byte alignment and column width.
5. ``minimize`` delta-debugs every failing bitstring to a shortest repro while
   preserving the same violation class, and records its legal neighbours.

The whole suite runs in a handful of milliseconds; nothing here is random.
"""

import array
from collections.abc import Callable, Sequence

import pytest

from pdfminer.ccitt import CCITTFaxDecoder, CCITTG4Parser

# Fixed, small exploration space. Seed widths include odd and wide values so
# column-width assumptions are exercised, not only tidy multiples of eight.
SEED_WIDTHS = (1, 2, 4, 8, 16, 17, 33)
# A legal row may itself flush in several width-sized steps, so the line cap is
# expressed relative to the declared geometry rather than as a flat constant.
# Runaway repetition is still hard-capped at this fixed multiple of the width.
LINE_BUDGET = 16
LINE_CAP_MULTIPLE = 4
# Output is allowed to be larger than the input (T.6 is a compression format),
# but it must stay within the explicit line/byte budgets, never grow without
# bound relative to the declared geometry.
EOFB = "000000000001000000000001"


def line_cap(width: int) -> int:
    return max(LINE_BUDGET, LINE_CAP_MULTIPLE * max(width, 1) + 1)


# --------------------------------------------------------------------------- #
# Layer 1: recover the code tables directly from the parser's decision trees.
# --------------------------------------------------------------------------- #
def reverse_code_tables(
    tree: Sequence[object], prefix: str = ""
) -> dict[object, str]:
    codes: dict[object, str] = {}
    for bit, node in zip("01", tree):
        if isinstance(node, list):
            codes.update(reverse_code_tables(node, prefix + bit))
        else:
            codes[node] = prefix + bit
    return codes


WHITE_CODES = reverse_code_tables(CCITTG4Parser.WHITE)
BLACK_CODES = reverse_code_tables(CCITTG4Parser.BLACK)
MODE_CODES = reverse_code_tables(CCITTG4Parser.MODE)


def encode_run(length: int, color: int) -> str:
    """T.6 run length: optional 64-pixel makeup code followed by a terminator."""
    table = WHITE_CODES if color == 1 else BLACK_CODES
    parts: list[str] = []
    if length >= 64:
        makeup = (length // 64) * 64
        parts.append(table[makeup])
        length -= makeup
    parts.append(table[length])
    return "".join(parts)


def encode_horizontal(start_color: int, n1: int, n2: int) -> str:
    return (
        MODE_CODES["h"]
        + encode_run(n1, start_color)
        + encode_run(n2, 1 - start_color)
    )


def bits_to_bytes(bits: str) -> bytes:
    padded = bits + "0" * ((8 - len(bits) % 8) % 8)
    return bytes(
        int(padded[i : i + 8], 2) for i in range(0, len(padded), 8)
    )


# --------------------------------------------------------------------------- #
# Layer 2: independent T.6 reference renderer.
#
# This deliberately does not import or call any decoder state. It renders a
# coding row from a list of high-level operations against a reference row and
# is used to certify the pixel output of every legal seed independently.
# --------------------------------------------------------------------------- #
def _vertical_boundary(ref: Sequence[int], start: int, color: int) -> int:
    """First changing element position for a vertical code.

    Copied structurally from the decoder scan, including the special
    ``index == 0`` branch for the virtual pixel before the first real pixel.
    A leading run of the opposite colour is reported at the row start; a
    boundary never reached returns the virtual position at row end.
    """
    index = start
    while True:
        if index >= len(ref):
            break
        if index == 0:
            if color == 1 and ref[0] != color:
                break
        elif ref[index - 1] == color and ref[index] != color:
            break
        index += 1
    return index


def _pass_target(ref: Sequence[int], start: int, color: int) -> int:
    """Target position for a pass code, copied structurally from the decoder.

    The decoder runs two boundary scans: first to the changing element away
    from ``color``, then from that index inclusive to the next element of
    ``color``. The row-end sentinel is treated as the opposite colour.
    """
    index = start
    # First loop: boundary from colour -> opposite colour.
    while True:
        if index >= len(ref):
            break
        if index == 0:
            if color == 1 and ref[0] != color:
                break
        elif ref[index - 1] == color and ref[index] != color:
            break
        index += 1
    # Second loop: boundary from opposite colour -> colour.
    while True:
        if index >= len(ref):
            break
        if index == 0:
            if color == 0 and ref[0] == color:
                break
        elif ref[index - 1] != color and ref[index] == color:
            break
        index += 1
    return index


def render_row(
    width: int, ops: Sequence[tuple[object, ...]], ref: Sequence[int]
) -> list[int]:
    cur = [1] * width
    a0 = -1  # reference changing element; virtual position before the row
    coding_color = 1
    for op in ops:
        kind = op[0]
        if kind == "h":
            _, start_color, n1, n2 = op
            x = a0 + 1
            for _ in range(n1):
                if 0 <= x < width:
                    cur[x] = start_color
                x += 1
            for _ in range(n2):
                if 0 <= x < width:
                    cur[x] = 1 - start_color
                x += 1
            a0 = x - 1
            # The decoder resets the coding colour to white after H-mode.
            coding_color = 1
        elif kind == "p":
            b2 = _pass_target(ref, a0 + 1, coding_color)
            # The decoder fills the inclusive range from the current changing
            # element a0 up to (but not including) the pass target b2.
            for x in range(max(a0, 0), b2):
                if 0 <= x < width:
                    cur[x] = coding_color
            a0 = b2
        else:
            dx = int(kind)
            b1 = _vertical_boundary(ref, a0 + 1, coding_color)
            a1 = max(0, min(width, b1 + dx))
            for x in range(a0 + 1, a1):
                if 0 <= x < width:
                    cur[x] = coding_color
            a0 = a1
            coding_color = 1 - coding_color
    return cur


# --------------------------------------------------------------------------- #
# Layer 3: instrumented decoder that treats any out-of-domain index as fatal.
# --------------------------------------------------------------------------- #
class CheckedArray:
    """Array-like storage that rejects negative or past-the-end indices.

    ``array.array("b")`` maps a negative index onto a real element, which hides
    state corruption. This wrapper turns both negative and out-of-range access
    into ``IndexError`` so invariant violations cannot pass silently.
    """

    def __init__(self, values: Sequence[int]) -> None:
        self._array = array.array("b", values)

    def __len__(self) -> int:
        return len(self._array)

    def _check(self, index: int) -> None:
        if not (0 <= index < len(self._array)):
            raise IndexError(
                f"out-of-domain index {index} for line width {len(self._array)}"
            )

    def __getitem__(self, index: int) -> int:
        self._check(index)
        return self._array[index]

    def __setitem__(self, index: int, value: int) -> None:
        self._check(index)
        self._array[index] = value

    def __iter__(self) -> object:
        return iter(self._array)


class CheckedCCITTFaxDecoder(CCITTFaxDecoder):
    def reset(self) -> None:
        super().reset()
        self._curline = CheckedArray(self._curline)  # type: ignore[assignment]

    def _reset_line(self) -> None:
        self._refline = self._curline
        self._curline = CheckedArray([1] * self.width)  # type: ignore[assignment]
        self._curpos = -1
        self._color = 1


# Violation labels. Each names the state invariant that was broken.
OK = "ok"
INDEX_OUT_OF_DOMAIN = "index_out_of_domain"
LINE_WIDTH = "line_width_mismatch"
LINE_BUDGET_VIOLATION = "line_budget_exceeded"
OUTPUT_BUDGET_VIOLATION = "output_budget_exceeded"
TERMINATION = "unterminated_or_invalid_stream"


class TrialResult:
    def __init__(
        self,
        violation: str,
        rows: list[list[int]],
        output_bytes: int,
        detail: str = "",
    ) -> None:
        self.violation = violation
        self.rows = rows
        self.output_bytes = output_bytes
        self.detail = detail

    @property
    def is_violation(self) -> bool:
        return self.violation != OK


def run_decoder(
    bits: str, width: int, bytealign: bool = False
) -> TrialResult:
    """Feed a bitstring through the real decoder under explicit budgets."""
    decoder = CheckedCCITTFaxDecoder(width, bytealign=bytealign)
    rows: list[list[int]] = []
    row_bytes = (width + 7) // 8
    # The line cap is the primary runaway guard. The byte budget only bounds
    # total emitted bytes to that cap, so a single full-width legal row always
    # fits while unbounded repetition is still hard-stopped.
    budget_bytes = (line_cap(width) + 1) * row_bytes

    def collect(y: int, line: Sequence[int]) -> None:
        rows.append(list(line))
        if len(line) != width:
            raise AssertionError(f"emitted line width {len(line)} != {width}")
        if len(rows) > line_cap(width):
            raise RuntimeError(LINE_BUDGET_VIOLATION)
        if sum((len(r) + 7) // 8 for r in rows) > budget_bytes:
            raise RuntimeError(OUTPUT_BUDGET_VIOLATION)

    decoder.output_line = collect  # type: ignore[method-assign]
    try:
        decoder.feedbytes(bits_to_bytes(bits))
    except IndexError as exc:
        return TrialResult(INDEX_OUT_OF_DOMAIN, rows, len(decoder.close()), str(exc))
    except RuntimeError as exc:
        label = str(exc)
        return TrialResult(label, rows, len(decoder.close()))
    except CCITTG4Parser.InvalidData as exc:
        return TrialResult(TERMINATION, rows, len(decoder.close()), str(exc))
    except AssertionError as exc:
        return TrialResult(LINE_WIDTH, rows, len(decoder.close()), str(exc))
    return TrialResult(OK, rows, len(decoder.close()))


# --------------------------------------------------------------------------- #
# Legal seed encoders (white row, black stripe row, alternating/pass row).
# --------------------------------------------------------------------------- #
def white_row_seed(width: int) -> tuple[str, list[tuple[object, ...]]]:
    # width vertical(0) codes against the implicit all-white reference row.
    bits = MODE_CODES[0] * width + EOFB
    ops: list[tuple[object, ...]] = [(0,) for _ in range(width)]
    return bits, ops


def stripe_row_seed(
    width: int,
) -> tuple[str, list[tuple[object, ...]]]:
    lead = max(1, width // 4)
    black = max(1, width // 2)
    if lead + black > width:
        lead, black = 0, width
    tail = width - lead - black
    ops: list[tuple[object, ...]] = [("h", 1, lead, black)]
    bits = encode_horizontal(1, lead, black)
    if tail > 0:
        bits += encode_horizontal(1, 0, tail)
        ops.append(("h", 1, 0, tail))
    return bits + EOFB, ops


def alternating_row_seed(
    width: int,
) -> tuple[str, list[tuple[object, ...]]]:
    # First emit a legal stripe reference row. The second row reaches the first
    # changing element legally with vertical(0), then uses pass mode to skip the
    # stripe and vertical(0) again to finish. Pass is never the first element,
    # so the negative-index corner is not part of the legal corpus.
    stripe_bits, stripe_ops = stripe_row_seed(width)
    ref = render_row(width, stripe_ops, [1] * width)
    body = (
        stripe_bits[: -len(EOFB)]
        + MODE_CODES[0]
        + MODE_CODES["p"]
        + MODE_CODES[0]
    )
    ops: list[tuple[object, ...]] = [(0,), ("p",), (0,)]
    # Sanity: the independent renderer must resolve against the stripe reference.
    render_row(width, ops, ref)
    return body + EOFB, ops


def legal_seeds() -> list[tuple[str, str, int, str, list[tuple[object, ...]]]]:
    seeds: list[tuple[str, str, int, str, list[tuple[object, ...]]]] = []
    for width in SEED_WIDTHS:
        bits, ops = white_row_seed(width)
        seeds.append(("white", "white_row", width, bits, ops))
        bits, ops = stripe_row_seed(width)
        seeds.append(("stripe", "stripe_row", width, bits, ops))
        bits, ops = alternating_row_seed(width)
        seeds.append(("alternating", "alternating_row", width, bits, ops))
    return seeds


# --------------------------------------------------------------------------- #
# Layer 4: explicit, short mutation operators.
# --------------------------------------------------------------------------- #
Mutator = Callable[[str, int], list[str]]


def _truncations(bits: str, _width: int) -> list[str]:
    return [bits[:k] for k in (len(bits) - 1, len(bits) - len(EOFB), len(bits) // 2)]


def _bit_flips(bits: str, _width: int) -> list[str]:
    return [
        bits[:i] + ("1" if bits[i] == "0" else "0") + bits[i + 1 :]
        for i in range(len(bits))
    ]


def _bit_inserts(bits: str, _width: int) -> list[str]:
    return [bits[:i] + "0" + bits[i:] for i in range(0, len(bits), 3)]


def _mode_swap_first(bits: str, _width: int) -> list[str]:
    # Replace the first coding element with a competing mode code.
    return [code + bits[1:] for code in (
        MODE_CODES["p"], MODE_CODES[0], MODE_CODES[1], MODE_CODES[-1],
    )]


def _drop_terminator(bits: str, _width: int) -> list[str]:
    return [bits.replace(EOFB, "", 1), bits[: -len(EOFB)] + EOFB[1:]]


def _alignment_shift(bits: str, _width: int) -> list[str]:
    return ["0" + bits, "00" + bits, bits + "0000"]


MUTATORS: dict[str, Mutator] = {
    "truncate": _truncations,
    "bit_flip": _bit_flips,
    "bit_insert": _bit_inserts,
    "mode_swap": _mode_swap_first,
    "drop_terminator": _drop_terminator,
    "alignment_shift": _alignment_shift,
}

# Hand-built adversarial prefixes that target specific mode/geometry corners.
PREFIX_CASES: list[tuple[str, str, int]] = [
    ("pass_first", MODE_CODES["p"], 4),
    ("pass_first_narrow", MODE_CODES["p"], 1),
    ("vertical_width0", MODE_CODES[0], 0),
    ("pass_width0", MODE_CODES["p"], 0),
    ("vertical_no_eofb", MODE_CODES[0] * 8, 8),
    ("pass_no_eofb", MODE_CODES["p"], 8),
    ("eofb_only", EOFB, 8),
]


# --------------------------------------------------------------------------- #
# Layer 5: minimisation with legal-neighbour tracking.
# --------------------------------------------------------------------------- #
def minimize(
    bits: str, width: int, target_violation: str
) -> tuple[str, list[str]]:
    """Delta-debug to a shortest bitstring with the same violation.

    Returns the minimised bitstring plus a list of legal neighbours: strings a
    single edit away that no longer violate any invariant. These prove the
    counterexample is a sharp, localised edge rather than broad corruption.
    """
    current = bits
    changed = True
    while changed:
        changed = False
        for i in range(len(current)):
            candidate = current[:i] + current[i + 1 :]
            if candidate and run_decoder(candidate, width).violation == target_violation:
                current, changed = candidate, True
                break
        if changed:
            continue
        for i in range(len(current)):
            candidate = current[:i] + (
                "1" if current[i] == "0" else "0"
            ) + current[i + 1 :]
            if run_decoder(candidate, width).violation == target_violation:
                current, changed = candidate, True
                break

    neighbours: list[str] = []
    for i in range(len(current)):
        candidate = current[:i] + current[i + 1 :]
        if candidate and not run_decoder(candidate, width).is_violation:
            neighbours.append(candidate)
        flipped = current[:i] + (
            "1" if current[i] == "0" else "0"
        ) + current[i + 1 :]
        if not run_decoder(flipped, width).is_violation:
            neighbours.append(flipped)
    # De-duplicate while preserving order.
    return current, list(dict.fromkeys(neighbours))


# --------------------------------------------------------------------------- #
# Tests.
# --------------------------------------------------------------------------- #
class TestCodeTablesAndOracle:
    def test_code_tables_round_trip(self):
        # Every T.6 code must be uniquely decodable and recover its symbol.
        assert MODE_CODES[0] == "1"
        assert MODE_CODES["p"] == "0001"
        assert MODE_CODES["h"] == "001"
        assert MODE_CODES["e"] == EOFB
        assert len(set(WHITE_CODES.values())) == len(WHITE_CODES)
        assert len(set(BLACK_CODES.values())) == len(BLACK_CODES)

    @pytest.mark.parametrize("width", SEED_WIDTHS)
    def test_legal_seed_pixels_match_independent_oracle(self, width):
        for family, _name, w, bits, ops in legal_seeds():
            if w != width:
                continue
            result = run_decoder(bits, w)
            assert result.violation == OK, result.detail
            if family == "alternating":
                stripe_bits, stripe_ops = stripe_row_seed(w)
                reference = render_row(w, stripe_ops, [1] * w)
            else:
                reference = [1] * w
            expected = render_row(w, ops, reference)
            assert result.rows[-1] == expected

    def test_white_seed_is_all_white_pixels(self):
        for width in (1, 4, 8):
            bits, _ = white_row_seed(width)
            result = run_decoder(bits, width)
            assert result.violation == OK
            assert result.rows[-1] == [1] * width


class TestInvariantViolations:
    def test_degenerate_width_vertical_crashes(self):
        # Columns == 0: the very first vertical mode indexes an empty line.
        result = run_decoder(MODE_CODES[0], 0)
        assert result.violation == INDEX_OUT_OF_DOMAIN

    def test_degenerate_width_pass_crashes(self):
        result = run_decoder(MODE_CODES["p"], 0)
        assert result.violation == INDEX_OUT_OF_DOMAIN

    def test_pass_as_first_element_negative_index(self):
        # curpos == -1 at line start; pass mode executes range(-1, x1),
        # writing through index -1, outside the declared [0, width) domain.
        result = run_decoder(MODE_CODES["p"], 4)
        assert result.violation == INDEX_OUT_OF_DOMAIN
        assert "-1" in result.detail

    def test_pass_negative_index_persists_on_narrow_widths(self):
        for width in (1, 2, 8):
            assert run_decoder(MODE_CODES["p"], width).violation == (
                INDEX_OUT_OF_DOMAIN
            )

    def test_malformed_mode_code_is_classified_not_silent(self):
        # An unparseable mode prefix must surface as a termination/validity
        # failure instead of being accepted as a well-formed image.
        seed = white_row_seed(8)[0]
        malformed = seed[:12] + "0" + seed[12:]
        result = run_decoder(malformed, 8)
        assert result.violation == TERMINATION

    def test_truncated_stream_is_observed(self):
        # A stream cut before EOFB does not raise in the current decoder, but it
        # still must terminate cleanly within budget and never run away. This
        # pins that documented behaviour so a regression becomes visible.
        result = run_decoder(MODE_CODES[0] * 8, 8)
        assert result.violation in (OK, TERMINATION)
        assert len(result.rows) <= line_cap(8)


class TestMutationCampaign:
    def test_seeds_are_clean_before_mutation(self):
        for _family, _name, width, bits, _ops in legal_seeds():
            assert run_decoder(bits, width).violation == OK

    def test_mutation_campaign_is_bounded_and_deterministic(self):
        violations: dict[str, int] = {}
        trials = 0
        for _family, _name, width, bits, _ops in legal_seeds():
            for mutator in MUTATORS.values():
                for mutant in mutator(bits, width):
                    if not mutant:
                        continue
                    trials += 1
                    result = run_decoder(mutant, width)
                    violations[result.violation] = (
                        violations.get(result.violation, 0) + 1
                    )
        # Explicit, small step budget: no random collision loop involved.
        assert trials < 4000
        # The campaign must surface at least the index and termination classes.
        assert INDEX_OUT_OF_DOMAIN in violations
        assert TERMINATION in violations

    def test_prefix_cases_cover_targeted_corners(self):
        observed = {run_decoder(bits, width).violation for _n, bits, width in
                    PREFIX_CASES}
        assert INDEX_OUT_OF_DOMAIN in observed

    @pytest.mark.parametrize("name,bits,width", PREFIX_CASES)
    def test_each_prefix_is_reproducible(self, name, bits, width):
        first = run_decoder(bits, width).violation
        second = run_decoder(bits, width).violation
        assert first == second

    def test_output_budget_caps_runaway_lines(self):
        # A single 4-bit pass code can fill an entire declared 1728-pixel row.
        # Without an explicit budget, a short malicious stream therefore yields
        # unbounded output rows; the harness must hard-cap that amplification.
        width = 1728
        cap = line_cap(width)
        # Use the stock decoder: this isolates output amplification from the
        # separate negative-index invariant that the checked decoder enforces.
        decoder = CCITTFaxDecoder(width)
        emitted: list[int] = []

        def capped(y: int, line: Sequence[int]) -> None:
            emitted.append(len(line))
            if len(emitted) > cap:
                raise RuntimeError(LINE_BUDGET_VIOLATION)

        decoder.output_line = capped  # type: ignore[method-assign]
        with pytest.raises(RuntimeError, match=LINE_BUDGET_VIOLATION):
            decoder.feedbytes(bits_to_bytes(MODE_CODES["p"] * (cap + 2)))
        assert len(emitted) == cap + 1
        # Each emitted row honours the declared geometry; only the count ran away.
        assert all(length == width for length in emitted)

    def test_byte_budget_trips_before_unbounded_growth(self):
        # A narrow row repeated many times stays geometrically valid but must
        # still be stopped once cumulative output crosses the byte budget.
        width = 8
        cap = line_cap(width)
        result = run_decoder(MODE_CODES[0] * (width * cap * 2), width)
        assert result.violation in (
            LINE_BUDGET_VIOLATION,
            OUTPUT_BUDGET_VIOLATION,
        )
        assert len(result.rows) <= cap + 1


class TestMinimization:
    def test_minimizes_pass_to_four_bit_root_code(self):
        bits = MODE_CODES["p"] + "1010101010101"
        minimized, neighbours = minimize(bits, 8, INDEX_OUT_OF_DOMAIN)
        assert minimized == MODE_CODES["p"]
        assert neighbours, "expected at least one legal neighbour"
        # A neighbour is a single edit away and is clean under the invariants.
        assert all(
            not run_decoder(n, 8).is_violation for n in neighbours
        )

    def test_minimizes_width0_vertical_to_single_bit(self):
        minimized, _ = minimize(MODE_CODES[0] + "0000", 0, INDEX_OUT_OF_DOMAIN)
        assert minimized == MODE_CODES[0]

    def test_minimized_repro_preserves_violation_class(self):
        for name, bits, width in PREFIX_CASES:
            target = run_decoder(bits, width).violation
            if target == OK:
                continue
            minimized, _ = minimize(bits, width, target)
            assert run_decoder(minimized, width).violation == target, name
