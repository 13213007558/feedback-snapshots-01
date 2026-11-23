import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from referencing import Resource, exceptions
from referencing.budget import (
    UNLIMITED,
    BranchBudgetExceeded,
    Budget,
    BudgetedResolver,
    BudgetExceeded,
    BudgetLimits,
    CachingRetriever,
    ReferenceBudgetExceeded,
    RetrievalBudgetExceeded,
    WorkKind,
    budget_scope,
    budgeted_resolver,
    current_budget,
    make_budgeted_registry,
)
from referencing.jsonschema import DRAFT202012

SCHEMA = "https://json-schema.org/draft/2020-12/schema"


def schema(**kwargs):
    return {"$schema": SCHEMA, **kwargs}


def root_with_shared_child():
    root = Resource.from_contents(
        schema(
            **{
                "$id": "urn:root",
                "properties": {
                    "a": {"$id": "urn:child", "type": "string"},
                    "b": {"$ref": "urn:child"},
                },
            }
        )
    )
    return root


class TestBudget:
    def test_charge_tracks_each_kind(self):
        budget = Budget(BudgetLimits())
        for kind in WorkKind:
            assert budget.used(kind) == 0
            assert budget.remaining(kind) is None
        budget.charge(WorkKind.REFERENCE, "x")
        budget.charge(WorkKind.BRANCH, "y", amount=2)
        assert budget.used(WorkKind.REFERENCE) == 1
        assert budget.used(WorkKind.BRANCH) == 2
        assert budget.snapshot() == {
            WorkKind.REFERENCE: 1,
            WorkKind.BRANCH: 2,
            WorkKind.RETRIEVAL: 0,
        }

    def test_charge_at_limit_is_allowed_but_over_is_not(self):
        budget = Budget(BudgetLimits(references=1))
        budget.charge(WorkKind.REFERENCE, "first")  # exactly at the limit
        assert budget.remaining(WorkKind.REFERENCE) == 0
        with pytest.raises(ReferenceBudgetExceeded) as exc_info:
            budget.charge(WorkKind.REFERENCE, "second")
        error = exc_info.value
        assert error.kind is WorkKind.REFERENCE
        assert error.limit == 1
        assert error.used == 1  # failed charge consumed nothing
        assert "reference" in str(error)

    def test_each_kind_raises_its_own_exception(self):
        cases = [
            (WorkKind.REFERENCE, "references", ReferenceBudgetExceeded),
            (WorkKind.BRANCH, "branches", BranchBudgetExceeded),
            (WorkKind.RETRIEVAL, "retrievals", RetrievalBudgetExceeded),
        ]
        for kind, field_name, expected in cases:
            budget = Budget(BudgetLimits(**{field_name: 0}))
            with pytest.raises(expected) as exc_info:
                budget.charge(kind, "boom")
            assert isinstance(exc_info.value, BudgetExceeded)

    def test_two_budgets_are_independent(self):
        first = Budget(BudgetLimits(references=5))
        second = Budget(BudgetLimits(references=5))
        for _ in range(3):
            first.charge(WorkKind.REFERENCE, "x")
        assert first.used(WorkKind.REFERENCE) == 3
        assert second.used(WorkKind.REFERENCE) == 0


class TestBudgetScope:
    def test_scope_sets_and_restores_budget(self):
        outer = Budget(BudgetLimits(), name="outer")
        inner = Budget(BudgetLimits(), name="inner")
        assert current_budget() is None
        with budget_scope(outer):
            assert current_budget() is outer
            with budget_scope(inner):
                assert current_budget() is inner
            assert current_budget() is outer
        assert current_budget() is None

    def test_scope_restores_even_on_error(self):
        budget = Budget(BudgetLimits())
        with pytest.raises(RuntimeError):
            with budget_scope(budget):
                raise RuntimeError("boom")
        assert current_budget() is None

    def test_nested_resolution_keeps_one_budget(self):
        # A budget must survive entering a nested resource and returning to
        # continue resolving further references in the parent.
        registry, _ = make_budgeted_registry()
        root = root_with_shared_child()
        registry = root @ registry
        budget = Budget(BudgetLimits())
        resolver = budgeted_resolver(registry, base_uri="urn:root")
        with budget_scope(budget):
            resolver.lookup("urn:child")           # crawl + nested entry
            seen_during = current_budget()
            resolver.lookup("urn:root#/properties/b")  # back in the parent
        assert seen_during is budget
        assert current_budget() is None
        # Both lookups are billed to the same budget.
        assert budget.used(WorkKind.REFERENCE) == 2
        assert budget.used(WorkKind.BRANCH) >= 1


class TestReferenceMetering:
    def test_each_lookup_charges_one_reference(self):
        registry, _ = make_budgeted_registry()
        registry = root_with_shared_child() @ registry
        budget = Budget(BudgetLimits(references=2))
        resolver = budgeted_resolver(registry, base_uri="urn:root")
        with budget_scope(budget):
            resolver.lookup("urn:child")
            resolver.lookup("urn:child")  # reused resource, still a $ref
            with pytest.raises(ReferenceBudgetExceeded):
                resolver.lookup("urn:child")
        assert budget.used(WorkKind.REFERENCE) == 2

    def test_no_scope_means_no_reference_charge(self):
        registry, _ = make_budgeted_registry()
        registry = root_with_shared_child() @ registry
        resolver = budgeted_resolver(registry, base_uri="urn:root")
        # Without an active budget, ordinary resolution is untouched.
        assert resolver.lookup("urn:child").contents["type"] == "string"


class TestBranchMetering:
    def test_crawling_subresources_charges_branches(self):
        registry, _ = make_budgeted_registry()
        root = root_with_shared_child()
        registry = root @ registry
        budget = Budget(BudgetLimits(branches=1))
        resolver = budgeted_resolver(registry, base_uri="urn:root")
        with budget_scope(budget):
            with pytest.raises(BranchBudgetExceeded) as exc_info:
                resolver.lookup("urn:child")
        assert exc_info.value.kind is WorkKind.BRANCH

    def test_already_crawled_resource_charges_no_more_branches(self):
        registry, _ = make_budgeted_registry()
        registry = root_with_shared_child() @ registry
        warm = Budget(BudgetLimits())
        with budget_scope(warm):
            first = budgeted_resolver(registry, "urn:root").lookup("urn:child")
        assert warm.used(WorkKind.BRANCH) >= 1

        # Resolution returns an evolved, now-crawled registry; a later request
        # over that same crawled registry does not re-expand those branches.
        crawled = first.resolver._registry
        later = Budget(BudgetLimits())
        with budget_scope(later):
            budgeted_resolver(crawled, "urn:root").lookup("urn:child")
        assert later.used(WorkKind.BRANCH) == 0


class TestRetrievalMetering:
    def test_cache_miss_bills_retrieval_hit_does_not(self):
        calls = []

        def retrieve(uri):
            calls.append(uri)
            return Resource.from_contents(
                schema(**{"$id": uri, "type": "null"})
            )

        caching = CachingRetriever(retrieve)
        registry, _ = make_budgeted_registry(caching)
        budget = Budget(BudgetLimits(retrievals=5))
        with budget_scope(budget):
            first = registry.get_or_retrieve("urn:x")
            # Reuse through the registry the first retrieval produced, and
            # directly through the shared cache -- neither fetches again.
            first.registry.get_or_retrieve("urn:x")
            assert caching("urn:x").contents["type"] == "null"
        assert calls == ["urn:x"]
        assert budget.used(WorkKind.RETRIEVAL) == 1

    def test_retrieval_limit_stops_the_chain(self):
        def retrieve(uri):
            return Resource.from_contents(
                schema(**{"$id": uri, "type": "null"})
            )

        registry, _ = make_budgeted_registry(retrieve)
        budget = Budget(BudgetLimits(retrievals=1))
        with budget_scope(budget):
            registry.get_or_retrieve("urn:first")
            with pytest.raises(RetrievalBudgetExceeded):
                registry.get_or_retrieve("urn:second")
        assert budget.used(WorkKind.RETRIEVAL) == 1

    def test_budget_error_is_not_masked_as_retrieval_failure(self):
        def retrieve(uri):
            return Resource.from_contents(schema(**{"$id": uri}))

        registry, _ = make_budgeted_registry(retrieve)
        budget = Budget(BudgetLimits(retrievals=0))
        resolver = budgeted_resolver(registry)
        with budget_scope(budget):
            with pytest.raises(RetrievalBudgetExceeded):
                resolver.lookup("urn:anything")
            # It must not have been converted into a normal Unresolvable.
            with pytest.raises(RetrievalBudgetExceeded):
                try:
                    resolver.lookup("urn:other")
                except exceptions.Unresolvable:  # pragma: no cover
                    pytest.fail("budget error was masked")

    def test_concurrent_first_fetch_dedupes_to_one_resource(self):
        # Two threads missing the same URI at once both call the underlying
        # retriever, but the cache only keeps the first result.
        barrier = threading.Barrier(2)

        def retrieve(uri):
            barrier.wait()
            return Resource.from_contents(schema(**{"$id": uri}))

        caching = CachingRetriever(retrieve)
        results = []

        def fetch():
            results.append(caching("urn:race"))

        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda _: fetch(), range(2)))
        assert len(caching._cache) == 1
        assert results[0] is results[1]

    def test_default_retriever_signals_no_such_resource(self):
        registry, _ = make_budgeted_registry()
        budget = Budget(BudgetLimits())
        with budget_scope(budget):
            with pytest.raises(exceptions.NoSuchResource):
                registry.get_or_retrieve("urn:missing")
        # A failed lookup performs no billable on-demand retrieval.
        assert budget.used(WorkKind.RETRIEVAL) == 0


class TestBudgetedResolver:
    def test_in_subresource_and_underlying_resolver(self):
        registry, _ = make_budgeted_registry()
        registry = root_with_shared_child() @ registry
        wrapper = budgeted_resolver(registry, base_uri="urn:root")
        child = Resource.from_contents(
            schema(**{"$id": "urn:child", "type": "string"})
        )
        nested = wrapper.in_subresource(child)
        assert isinstance(nested, BudgetedResolver)
        assert nested.resolver is not wrapper.resolver
        # The underlying resolver's base URI follows the nested resource.
        assert nested.resolver._base_uri == "urn:child"

    def test_lookup_without_active_budget_is_unmetered(self):
        registry, _ = make_budgeted_registry()
        registry = root_with_shared_child() @ registry
        wrapper = budgeted_resolver(registry, base_uri="urn:root")
        assert current_budget() is None
        assert wrapper.lookup("urn:child").contents["type"] == "string"


class TestCrossRequestReuseAndIsolation:
    def _chain_registry(self):
        def retrieve(uri):
            n = int(uri.rsplit(":", 1)[1])
            return Resource.from_contents(
                schema(
                    **{
                        "$id": uri,
                        "allOf": [{"$ref": f"urn:new:{n + 1}"}],
                    }
                )
            )

        registry, caching = make_budgeted_registry(retrieve)
        return registry, caching

    def test_resource_fetched_once_is_reused_by_later_request(self):
        registry, caching = self._chain_registry()
        first = Budget(BudgetLimits())
        with budget_scope(first):
            budgeted_resolver(registry).lookup("urn:new:0")
        assert len(caching._cache) == 1

        second = Budget(BudgetLimits())
        with budget_scope(second):
            budgeted_resolver(registry).lookup("urn:new:0")
        # The second request reuses the cached resource: no new retrieval.
        assert len(caching._cache) == 1
        assert second.used(WorkKind.RETRIEVAL) == 0
        assert second.used(WorkKind.REFERENCE) == 1

    def test_concurrent_budgets_stay_independent(self):
        registry, _ = self._chain_registry()

        def worker(limit, hops):
            budget = Budget(BudgetLimits(references=limit, retrievals=limit))
            resolver = budgeted_resolver(registry)
            result = {"budget": budget}
            with budget_scope(budget):
                try:
                    for index in range(hops):
                        resolver.lookup(f"urn:new:{index}")
                    result["status"] = "completed"
                except BudgetExceeded as error:
                    result["status"] = "stopped"
                    result["kind"] = error.kind
            return result

        with ThreadPoolExecutor(max_workers=2) as pool:
            blocked_future = pool.submit(worker, 2, 5)
            healthy_future = pool.submit(worker, 50, 5)
            blocked = blocked_future.result()
            healthy = healthy_future.result()

        assert blocked["status"] == "stopped"
        assert blocked["kind"] in {
            WorkKind.REFERENCE,
            WorkKind.RETRIEVAL,
        }
        assert healthy["status"] == "completed"
        # The healthy budget is unaffected by the blocked one.
        assert healthy["budget"].used(WorkKind.REFERENCE) == 5

    def test_async_tasks_isolate_budgets_across_await(self):
        registry, _ = self._chain_registry()

        async def task(limit, hops):
            await asyncio.sleep(0)
            budget = Budget(BudgetLimits(references=limit, retrievals=limit))
            resolver = budgeted_resolver(registry)
            with budget_scope(budget):
                try:
                    for index in range(hops):
                        await asyncio.sleep(0)
                        resolver.lookup(f"urn:new:{index}")
                    return "completed", budget
                except ReferenceBudgetExceeded:
                    return "stopped", budget

        async def run():
            return await asyncio.gather(task(2, 5), task(50, 5))

        (blocked_status, blocked_budget), (
            healthy_status,
            healthy_budget,
        ) = asyncio.run(run())
        assert blocked_status == "stopped"
        assert healthy_status == "completed"
        assert healthy_budget.used(WorkKind.REFERENCE) == 5
        assert blocked_budget.used(WorkKind.REFERENCE) == 2


def test_unlimited_sentinel_does_not_raise():
    assert UNLIMITED == -1
    budget = Budget(BudgetLimits())  # everything unlimited
    for _ in range(100):
        budget.charge(WorkKind.BRANCH, "x")
    assert budget.used(WorkKind.BRANCH) == 100
    assert budget.remaining(WorkKind.BRANCH) is None


def test_draft202012_standard_resolution_still_works():
    # Guard that the metering hooks do not change normal recursive semantics.
    registry, _ = make_budgeted_registry()
    root = root_with_shared_child()
    registry = root @ registry
    resolver = budgeted_resolver(registry, base_uri="urn:root")
    resolved = resolver.lookup("urn:root#/properties/a")
    assert resolved.contents == {"$id": "urn:child", "type": "string"}
    assert DRAFT202012 is not None
