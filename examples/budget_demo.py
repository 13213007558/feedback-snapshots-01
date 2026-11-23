"""
Demo: per-request resource budgets for JSON-schema reference resolution.

Run with::

    .venv/bin/python examples/budget_demo.py

It builds one shared in-memory registry that contains:

* a *shared subresource* referenced from multiple places (exercising branch
  expansion and in-request / cross-request reuse), and
* a retriever that keeps producing brand-new resources on demand (exercising
  the retrieval budget as the chain grows).

Three requests then run. Two share a thread pool concurrently:

1. an *approved* request with a generous budget that walks a shared chain;
2. an *over-budget* request that chases the ever-growing chain and is stopped
   predictably once a limit is reached;
3. a *normal* request running alongside them, proving its balance is
   independent of the over-budget one.

A fourth, asyncio-based check demonstrates the same isolation across
``await`` boundaries (contextvars copy per task).
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

from referencing import Resource
from referencing.budget import (
    BranchBudgetExceeded,
    Budget,
    BudgetExceeded,
    BudgetLimits,
    WorkKind,
    budget_scope,
    budgeted_resolver,
    make_budgeted_registry,
)

SCHEMA = "https://json-schema.org/draft/2020-12/schema"


def schema(**kw: object) -> dict[str, object]:
    return {"$schema": SCHEMA, **kw}


# On-demand store: every requested `urn:new:N` is a fresh resource that
# points at the next one through a *bare* top-level `$ref` (wrapped in
# `allOf`). A bare `$ref` is not a crawlable subresource, so `crawl()` never
# pre-fetches the chain; each hop is genuinely retrieved on demand.
def make_retriever():
    def retrieve(uri: str) -> Resource:
        n = int(uri.rsplit(":", 1)[1])
        contents = schema(
            **{
                "$id": uri,
                "type": "object",
                "allOf": [{"$ref": f"urn:new:{n + 1}"}],
            }
        )
        return Resource.from_contents(contents)

    return retrieve


def build_registry():
    registry, caching = make_budgeted_registry(make_retriever())

    # A shared subresource, reused by several branches of the root document.
    shared = Resource.from_contents(
        schema(**{"$id": "urn:shared", "type": "string", "minLength": 1}),
    )

    # Root references the shared subresource three times. It deliberately does
    # not embed the on-demand chain, so chain resources are only fetched when a
    # request explicitly looks one up rather than during the initial crawl.
    root = Resource.from_contents(
        schema(
            **{
                "$id": "urn:root",
                "type": "object",
                "properties": {
                    "a": {"$ref": "urn:shared"},
                    "b": {"$ref": "urn:shared"},
                    "c": {"$ref": "urn:shared"},
                },
            }
        )
    )
    return (shared @ registry).with_resource("urn:root", root), caching


def walk_chain(resolver, *, hops: int, start: int = 0) -> int:
    """Follow `hops` $refs through the ever-growing on-demand chain."""
    index = start
    done = 0
    for _ in range(hops):
        resolver.lookup(f"urn:new:{index}")
        index += 1
        done += 1
    return done


def run_request(
    label: str,
    registry,
    limits: BudgetLimits,
    hops: int,
    start: int = 0,
) -> dict:
    budget = Budget(limits, name=label)
    resolver = budgeted_resolver(registry, base_uri="urn:root")
    outcome: dict = {"label": label}
    with budget_scope(budget):
        # Shared references resolve via the in-memory registry, no retrieval.
        shared = resolver.lookup("urn:shared")
        outcome["shared_type"] = shared.contents["type"]

        try:
            outcome["hops"] = walk_chain(
                resolver, hops=hops, start=start
            )
            outcome["status"] = "completed"
        except BudgetExceeded as error:
            outcome["status"] = "stopped"
            outcome["exceeded"] = error.kind.value
            outcome["detail"] = str(error)

    outcome["usage"] = {kind.value: n for kind, n in budget.snapshot().items()}
    outcome["remaining"] = {
        kind.value: budget.remaining(kind) for kind in WorkKind
    }
    return outcome


def print_outcome(outcome: dict) -> None:
    print(f"  [{outcome['label']}] status={outcome['status']}")
    if outcome["status"] == "stopped":
        print(f"      exceeded={outcome['exceeded']}")
        print(f"      {outcome['detail']}")
    print(f"      used={outcome['usage']}")
    print(f"      remaining={outcome['remaining']}")


def demo_over_budget_then_concurrent(registry) -> None:
    print("== over-budget chain stops predictably on retrieval ==")
    # This request reaches an as-yet-uncached part of the chain first, so each
    # hop is a genuine on-demand fetch. It is allowed only three retrievals.
    tight = BudgetLimits(references=20, branches=100, retrievals=3)
    over_budget = run_request(
        "over-budget", registry, tight, hops=10, start=0
    )
    print_outcome(over_budget)
    assert over_budget["status"] == "stopped", over_budget
    assert (
        over_budget["exceeded"] == WorkKind.RETRIEVAL.value
    ), over_budget
    assert over_budget["usage"][WorkKind.RETRIEVAL.value] == 3, over_budget

    print("\n== two further requests run concurrently, reusing resources ==")
    generous = BudgetLimits(references=100, branches=100, retrievals=50)
    normal = BudgetLimits(references=20, branches=100, retrievals=20)

    # Both walk the already-fetched prefix (cached) and a fresh suffix. They
    # share the registry and retriever cache but keep independent balances.
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(
                run_request, "approved", registry, generous, 8, start=0
            ),
            pool.submit(
                run_request, "normal", registry, normal, 5, start=0
            ),
        ]
        approved, normal_outcome = (f.result() for f in futures)

    print_outcome(approved)
    print_outcome(normal_outcome)
    assert approved["status"] == "completed", approved
    assert normal_outcome["status"] == "completed", normal_outcome
    # The normal request's reference balance is only its own 1 shared lookup
    # plus its 5 chain hops, regardless of the approved request's work.
    assert normal_outcome["remaining"][WorkKind.REFERENCE.value] == (
        20 - 1 - normal_outcome["hops"]
    ), normal_outcome
    # Reused prefix resources cost no extra retrievals to the normal request.
    assert normal_outcome["usage"][WorkKind.RETRIEVAL.value] <= (
        normal_outcome["hops"]
    ), normal_outcome
    print(
        "  assertions: over-budget stopped at the retrieval limit; the "
        "concurrent requests completed with independent balances ✓"
    )


async def demo_async_isolation(registry) -> None:
    print("\n== asyncio tasks: budget follows resolution across await ==")

    async def task(label: str, limits: BudgetLimits, hops: int) -> dict:
        await asyncio.sleep(0)  # yield to the event loop before resolving
        return await asyncio.to_thread(
            run_request, label, registry, limits, hops
        )

    tight = BudgetLimits(references=4, branches=100, retrievals=100)
    roomy = BudgetLimits(references=50, branches=100, retrievals=50)
    blocked, healthy = await asyncio.gather(
        task("tight-async", tight, 10),
        task("roomy-async", roomy, 6),
    )
    print_outcome(blocked)
    print_outcome(healthy)
    assert blocked["status"] == "stopped", blocked
    assert blocked["exceeded"] == WorkKind.REFERENCE.value, blocked
    assert healthy["status"] == "completed", healthy
    print("  assertions: tight task stopped on references without touching "
          "the roomy task's balance ✓")


def demo_branch_limit() -> None:
    print("\n== branch-expansion limit names the failing work kind ==")
    # A fresh, uncrawled registry whose child is only reachable by crawling,
    # so the lookup genuinely expands branches inside this budget scope.
    fresh, _ = make_budgeted_registry(make_retriever())
    root = Resource.from_contents(
        schema(
            **{
                "$id": "urn:branch-root",
                "properties": {
                    "a": {"$id": "urn:branch-child", "type": "string"},
                    "b": {"type": "integer"},
                },
            }
        )
    )
    fresh = root @ fresh
    budget = Budget(BudgetLimits(branches=1), name="branch-limited")
    resolver = budgeted_resolver(fresh, base_uri="urn:branch-root")
    with budget_scope(budget):
        try:
            resolver.lookup("urn:branch-child")
        except BranchBudgetExceeded as error:
            print(f"      stopped: {error}")
            assert error.kind is WorkKind.BRANCH
        else:  # pragma: no cover - defensive
            raise AssertionError("expected a branch budget failure")


def main() -> None:
    registry, caching = build_registry()
    print(f"shared registry prepared: {registry!r}\n")

    demo_over_budget_then_concurrent(registry)
    asyncio.run(demo_async_isolation(registry))
    demo_branch_limit()

    print("\n== cross-request resource reuse ==")
    print(f"  retriever cache entries after all requests: "
          f"{len(caching._cache)}")
    print("  (each urn:new:N is fetched once and then reused; urn:shared is "
          "served from the in-memory registry)")


if __name__ == "__main__":
    main()
