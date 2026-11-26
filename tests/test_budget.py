"""Tests for the shared single-run work budget (parse/clean/linkify)."""

from functools import partial

import pytest

import bleach
from bleach.budget import (
    STAGE_CLEAN,
    STAGE_LINKIFY,
    STAGE_PARSE,
    Budget,
    BudgetExceeded,
    BudgetExceededError,
    coerce_budget,
)
from bleach.linkifier import Linker, LinkifyFilter
from bleach.sanitizer import Cleaner


LINK_TAGS = ["p", "a", "ul", "li"]


def measure(text, **cleaner_kwargs):
    """Run with a meter-only budget and return its report."""
    budget = Budget(limit=None)
    cleaner_kwargs["budget"] = budget
    Cleaner(**cleaner_kwargs).clean(text)
    return budget


# ---------------------------------------------------------------------------
# Budget object / coercion
# ---------------------------------------------------------------------------


def test_coerce_budget_accepts_none_int_budget_dict():
    assert coerce_budget(None) is None

    from_int = coerce_budget(100)
    assert isinstance(from_int, Budget)
    assert from_int.limit == 100

    budget = Budget(5)
    assert coerce_budget(budget) is budget

    from_dict = coerce_budget({"limit": 7, "node_cost": 3})
    assert from_dict.limit == 7
    assert from_dict.node_cost == 3

    with pytest.raises(TypeError):
        coerce_budget("nope")


def test_budget_reset_zeroes_counters():
    budget = Budget(100)
    budget.charge(40, STAGE_PARSE, nodes=2)
    assert budget.spent == 40
    assert budget.counts["nodes"] == 2

    budget.reset()
    assert budget.spent == 0
    assert budget.used == 0
    assert budget.exceeded_stage is None
    assert budget.stage_spent[STAGE_PARSE] == 0
    assert budget.counts["nodes"] == 0


def test_budget_charge_raises_naming_stage():
    budget = Budget(10)
    budget.charge(6, STAGE_PARSE)
    # Exactly at the limit is still allowed.
    budget.charge(4, STAGE_PARSE)
    with pytest.raises(BudgetExceeded) as exc_info:
        budget.charge(1, STAGE_CLEAN)

    err = exc_info.value
    assert err.stage == STAGE_CLEAN
    assert err.limit == 10
    assert err.used == 11
    assert err.spent == 11
    assert err.stage_spent[STAGE_CLEAN] == 1
    assert "clean" in str(err)
    # Alias exception type is the same class.
    assert BudgetExceededError is BudgetExceeded


def test_unlimited_budget_meters_without_raising():
    budget = Budget(limit=None)
    for _ in range(100):
        budget.charge(10, STAGE_PARSE)
    assert budget.spent == 1000
    assert budget.remaining is None


# ---------------------------------------------------------------------------
# Backwards compatibility
# ---------------------------------------------------------------------------


def test_default_cleaner_has_no_budget():
    assert Cleaner().budget is None
    assert bleach.Cleaner().budget is None


def test_clean_without_budget_behaves_as_before():
    assert bleach.clean("<b>hi</b>") == "<b>hi</b>"
    assert bleach.clean("") == ""


# ---------------------------------------------------------------------------
# Stage attribution
# ---------------------------------------------------------------------------


def test_tiny_budget_fails_during_parse():
    cleaner = Cleaner(budget=Budget(10))
    with pytest.raises(BudgetExceeded) as exc_info:
        cleaner.clean("x" * 1000)
    assert exc_info.value.stage == STAGE_PARSE
    assert exc_info.value.used > 10


def test_budget_between_parse_and_clean_fails_in_clean():
    text = "<b>hello</b> " * 20
    parse_spent = measure(text).stage_spent[STAGE_PARSE]

    cleaner = Cleaner(budget=Budget(parse_spent))
    with pytest.raises(BudgetExceeded) as exc_info:
        cleaner.clean(text)
    assert exc_info.value.stage == STAGE_CLEAN


def test_linkify_transform_is_what_crosses_the_limit():
    text = (
        "<p>" + " ".join(f"https://example{i}.com/path/{i}" for i in range(20)) + "</p>"
    )

    meter = measure(text, tags=LINK_TAGS, filters=[LinkifyFilter])
    parse_and_clean = meter.stage_spent[STAGE_PARSE] + meter.stage_spent[STAGE_CLEAN]
    assert meter.stage_spent[STAGE_LINKIFY] > 0

    cleaner = Cleaner(
        tags=LINK_TAGS,
        filters=[partial(LinkifyFilter, callbacks=[])],
        budget=Budget(parse_and_clean),
    )
    with pytest.raises(BudgetExceeded) as exc_info:
        cleaner.clean(text)

    err = exc_info.value
    assert err.stage == STAGE_LINKIFY
    assert err.counts["transforms"] >= 1
    assert err.stage_spent[STAGE_LINKIFY] >= err.limit - parse_and_clean


def test_module_level_clean_accepts_budget():
    with pytest.raises(BudgetExceeded) as exc_info:
        bleach.clean("y" * 500, budget=5)
    assert exc_info.value.stage == STAGE_PARSE


def test_module_level_linkify_accepts_budget():
    with pytest.raises(BudgetExceeded) as exc_info:
        bleach.linkify("z" * 500, budget=5)
    assert exc_info.value.stage == STAGE_PARSE


# ---------------------------------------------------------------------------
# No partial result + reuse after failure
# ---------------------------------------------------------------------------


def test_no_partial_output_is_returned_and_cleaner_recovers():
    budget = Budget(10)
    cleaner = Cleaner(budget=budget)

    with pytest.raises(BudgetExceeded):
        cleaner.clean("<p>" + "w" * 5000 + "</p>")

    # The same entry point with the same configuration immediately works
    # for an ordinary short document; counters are per-run, not cumulative.
    short_result = cleaner.clean("<b>ok</b>")
    assert short_result == "<b>ok</b>"
    assert budget.spent <= 10
    assert budget.exceeded_stage is None


def test_same_cleaner_handles_success_failure_then_success():
    cleaner = Cleaner(
        tags=LINK_TAGS,
        filters=[LinkifyFilter],
        budget=Budget(300),
    )

    assert cleaner.clean("<p>short and plain</p>") == "<p>short and plain</p>"

    with pytest.raises(BudgetExceeded) as exc_info:
        cleaner.clean(
            "<p>" + " ".join(f"https://e{i}.example/x" for i in range(60)) + "</p>"
        )
    assert exc_info.value.stage in {STAGE_PARSE, STAGE_CLEAN, STAGE_LINKIFY}

    # Post-failure document completes normally through the same instance.
    assert cleaner.clean("<p>after failure</p>") == "<p>after failure</p>"
    assert cleaner.budget.spent < 300


def test_linker_reuse_after_link_budget_failure():
    linker = Linker(budget=Budget(60))

    with pytest.raises(BudgetExceeded):
        linker.linkify(" ".join(f"https://example{i}.com" for i in range(40)))

    assert linker.linkify("just a short note") == "just a short note"
    assert linker.budget.spent < 60


def test_passed_budget_instance_is_reset_per_call():
    budget = Budget(None)
    cleaner = Cleaner(budget=budget)

    cleaner.clean("first document " * 50)
    first_spent = budget.spent
    assert first_spent > 0

    cleaner.clean("tiny")
    # Reset means the second run reports only its own spend.
    assert budget.spent < first_spent
    assert budget.spent <= len("tiny") * 2 + 4


# ---------------------------------------------------------------------------
# Metering dimensions
# ---------------------------------------------------------------------------


def test_report_counts_nodes_text_and_transforms():
    budget = Budget(None)
    cleaner = Cleaner(tags=LINK_TAGS, filters=[LinkifyFilter], budget=budget)
    cleaner.clean(
        "<ul><li>alpha text</li><li>beta " "https://example.com/resource</li></ul>"
    )

    report = budget.as_report()
    assert report["counts"]["nodes"] > 0
    assert report["counts"]["characters"] > 0
    assert report["counts"]["transforms"] >= 1
    assert set(report["stage_spent"]) == {
        STAGE_PARSE,
        STAGE_CLEAN,
        STAGE_LINKIFY,
    }
    assert report["stage_spent"][STAGE_PARSE] > 0
    assert report["stage_spent"][STAGE_CLEAN] > 0
    assert report["stage_spent"][STAGE_LINKIFY] > 0


def test_long_text_without_transforms_uses_no_linkify_budget():
    budget = Budget(None)
    Cleaner(filters=[LinkifyFilter], budget=budget).clean(
        "ordinary long comment text. " * 40
    )
    assert budget.stage_spent[STAGE_LINKIFY] == 0
    assert budget.counts["transforms"] == 0
    assert budget.stage_spent[STAGE_PARSE] > 0
    assert budget.stage_spent[STAGE_CLEAN] > 0


def test_top_level_aliases_available():
    assert bleach.Budget is Budget
    assert bleach.BudgetExceeded is BudgetExceeded
    assert bleach.BudgetExceededError is BudgetExceededError
    assert bleach.STAGE_PARSE == "parse"
    assert bleach.STAGE_CLEAN == "clean"
    assert bleach.STAGE_LINKIFY == "linkify"


def test_work_budget_keyword_alias():
    cleaner = Cleaner(work_budget=1000)
    assert isinstance(cleaner.budget, Budget)
    assert cleaner.budget.limit == 1000

    linker = Linker(work_budget=1000)
    assert linker.budget.limit == 1000

    with pytest.raises(BudgetExceeded):
        bleach.clean("q" * 500, work_budget=5)


def test_empty_call_after_failure_still_resets_for_next_call():
    budget = Budget(10)
    cleaner = Cleaner(budget=budget)

    with pytest.raises(BudgetExceeded):
        cleaner.clean("z" * 500)

    # Empty input returns "" but must not leave stale state that breaks
    # the next real call through the same entry point.
    assert cleaner.clean("") == ""
    assert cleaner.clean("<b>ok</b>") == "<b>ok</b>"
    assert budget.exceeded_stage is None
