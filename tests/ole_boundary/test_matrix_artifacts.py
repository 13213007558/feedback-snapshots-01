"""Guardrails keeping the retained size-matrix artifacts trustworthy."""

import os

from .matrix import DIFAT_ONSET_PLAINTEXT, matrix_entries, package_uses_mini_stream
from .report import render_csv, render_text
from .runner import run_matrix

HERE = os.path.dirname(__file__)


def test_matrix_covers_all_three_regions():
    regions = {region for _, _, region, _ in matrix_entries()}
    assert regions == {"mini", "regular", "difat"}


def test_difat_onset_is_empirically_bracketed():
    sizes = {size for _, size, _, _ in matrix_entries()}
    assert DIFAT_ONSET_PLAINTEXT in sizes
    assert DIFAT_ONSET_PLAINTEXT - 1 in sizes


def test_mini_flag_consistent_for_every_row():
    for label, size, region, goes_mini in matrix_entries():
        assert goes_mini == package_uses_mini_stream(size)


def test_retained_artifacts_match_current_matrix():
    rows = run_matrix()
    csv_text = render_csv(rows)
    text = render_text(rows)
    with open(os.path.join(HERE, "SIZE_MATRIX.csv"), encoding="utf-8") as fh:
        assert fh.read() == csv_text
    with open(os.path.join(HERE, "SIZE_MATRIX.txt"), encoding="utf-8") as fh:
        assert fh.read() == text


def test_every_regular_row_passes_and_every_mini_row_is_flagged():
    rows = run_matrix()
    for row in rows:
        if row.goes_mini:
            assert not row.fully_ok
            assert row.defect_codes  # the defect is always localized, never silent
        else:
            assert row.fully_ok, (row.label, row.defect_codes, row.leak_codes)
