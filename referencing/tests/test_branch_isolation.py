"""
Regression tests for multi-tenant registry "branches".

A verification service builds one registry branch per workspace on top of
a shared base registry, fetching external documents through a single
pluggable retrieval interface. These tests guard against regressions
where a library upgrade could let retrieval state -- a transient failure,
a recovery, or an explicit withdrawal -- leak from one branch into
another. Only the external fetch interface is replaced; real `Registry`
and `Resolver` objects drive every read.
"""

from collections import Counter

import pytest

from referencing import Registry, Resource, exceptions

SHARED_URI = "urn:example:shared-schema"
COMMON_URI = "urn:example:common-tenant-config"


def schema(**kwargs):
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        **kwargs,
    }


class FakeBackend:
    """
    The external document store -- the only thing tests replace.
    """

    def __init__(self, documents):
        self._documents = dict(documents)
        self.fetch_counts = Counter()
        self._transient_failures = Counter()

    def fail_next_fetch(self, uri, times=1):
        """
        Arrange for the next ``times`` fetches of ``uri`` to fail the way
        a flaky network does -- retryably, not definitively.
        """
        self._transient_failures[uri] += times

    def fetch(self, uri):
        self.fetch_counts[uri] += 1
        if self._transient_failures[uri]:
            self._transient_failures[uri] -= 1
            raise ConnectionError("simulated transient network failure")
        try:
            return Resource.from_contents(self._documents[uri])
        except KeyError:
            raise exceptions.NoSuchResource(ref=uri) from None


def make_branch(shared, backend, withdrawn):
    """
    Derive a workspace branch from the shared registry.

    ``withdrawn`` is the branch's own explicitly recorded state: URIs the
    workspace has actively pulled down, which its retrieval layer refuses
    without ever consulting the external store.
    """

    def retrieve(uri):
        if uri in withdrawn:
            raise exceptions.NoSuchResource(ref=uri)
        return backend.fetch(uri)

    return shared.combine(Registry(retrieve=retrieve))


def read(registry, ref):
    """
    Perform one service read through a real resolver.

    Returns a ``(verdict, registry, contents)`` triple, where the
    registry is the (possibly evolved) one the service should keep using,
    and the verdict is one of:

    * ``"hit"`` -- the reference resolved
    * ``"transient-failure"`` -- retrieval failed retryably (e.g. network)
    * ``"withdrawn"`` -- the reference is definitively unresolvable
    """
    try:
        resolved = registry.resolver().lookup(ref)
    except exceptions.Unresolvable as error:
        if isinstance(error.__cause__, exceptions.Unretrievable):
            return "transient-failure", registry, None
        return "withdrawn", registry, None
    return "hit", resolved.resolver._registry, resolved.contents


class TestMultiTenantBranches:
    def test_interleaved_reads_isolate_failure_recovery_and_withdrawal(
        self,
    ):
        """
        An interleaved A, B, A read order keeps each branch's state its
        own: A's transient failure neither poisons A nor leaks into B,
        B's recovery stays on B, and B's later explicit withdrawal sticks
        even while A (and B's own older snapshot) keep resolving.
        """
        contents = schema(**{"$id": SHARED_URI, "type": "integer"})
        backend = FakeBackend({SHARED_URI: contents})
        backend.fail_next_fetch(SHARED_URI)  # one transient failure

        shared = Registry().with_resources(
            [(COMMON_URI, Resource.from_contents(schema(**{
                "$id": COMMON_URI,
            })))],
        )
        withdrawn_a, withdrawn_b = set(), set()
        branch_a = make_branch(shared, backend, withdrawn_a)
        branch_b = make_branch(shared, backend, withdrawn_b)
        branch_a_snapshot = branch_a

        verdicts = []

        # 1. A reads first, and the one transient network failure hits.
        verdict, branch_a_after, _ = read(branch_a, SHARED_URI)
        verdicts.append(("A", verdict))
        assert verdict == "transient-failure"
        assert branch_a_after is branch_a  # the failure left no trace
        assert backend.fetch_counts[SHARED_URI] == 1

        # 2. B reads: the backend has recovered, so B gets a real hit...
        verdict, branch_b, got = read(branch_b, SHARED_URI)
        verdicts.append(("B", verdict))
        assert verdict == "hit"
        assert got == contents
        assert backend.fetch_counts[SHARED_URI] == 2
        # ...which is cached on B's branch alone, not propagated to A's.
        assert SHARED_URI in branch_b
        assert SHARED_URI not in branch_a

        # 3. A reads again: its earlier failure was never cached, so A
        #    retries the external interface and now hits as well.
        verdict, branch_a, got = read(branch_a, SHARED_URI)
        verdicts.append(("A", verdict))
        assert verdict == "hit"
        assert got == contents
        assert backend.fetch_counts[SHARED_URI] == 3

        # B now explicitly withdraws the resource on its own branch.
        branch_b_before_withdrawal = branch_b
        withdrawn_b.add(SHARED_URI)
        branch_b = branch_b.remove(SHARED_URI)

        # B's verdict is its own recorded state -- definitive, and
        # reached without even consulting the external interface.
        verdict, branch_b_after, _ = read(branch_b, SHARED_URI)
        verdicts.append(("B", verdict))
        assert verdict == "withdrawn"
        assert branch_b_after is branch_b
        assert backend.fetch_counts[SHARED_URI] == 3

        # A is unaffected by B's withdrawal; it serves its own copy.
        verdict, branch_a, got = read(branch_a, SHARED_URI)
        verdicts.append(("A", verdict))
        assert verdict == "hit"
        assert got == contents
        assert backend.fetch_counts[SHARED_URI] == 3

        # Old snapshots still resolve per their own configuration:
        # B's pre-withdrawal snapshot serves its cached copy...
        verdict, _, got = read(branch_b_before_withdrawal, SHARED_URI)
        assert verdict == "hit"
        assert got == contents
        assert backend.fetch_counts[SHARED_URI] == 3

        # ...while A's original snapshot, which never saw the recovery,
        # still resolves by going back to the external interface itself.
        verdict, _, got = read(branch_a_snapshot, SHARED_URI)
        assert verdict == "hit"
        assert got == contents
        assert backend.fetch_counts[SHARED_URI] == 4

        assert verdicts == [
            ("A", "transient-failure"),
            ("B", "hit"),
            ("A", "hit"),
            ("B", "withdrawn"),
            ("A", "hit"),
        ]

    def test_recovery_elsewhere_does_not_override_a_withdrawal(self):
        """
        Even after the resource recovers and is actively served on one
        branch, another branch which explicitly withdrew it keeps
        reflecting its own recorded state.
        """
        contents = schema(**{"$id": SHARED_URI, "type": "integer"})
        backend = FakeBackend({SHARED_URI: contents})

        branch_a = make_branch(Registry(), backend, withdrawn=set())
        branch_b = make_branch(
            Registry(),
            backend,
            withdrawn={SHARED_URI},  # withdrawn up front on B
        )

        # B's verdict is its own, reached without any external fetch.
        verdict, _, _ = read(branch_b, SHARED_URI)
        assert verdict == "withdrawn"
        assert backend.fetch_counts[SHARED_URI] == 0

        # A fetches successfully, and re-reads are served from A's cache.
        verdict, branch_a, got = read(branch_a, SHARED_URI)
        assert verdict == "hit"
        assert got == contents
        verdict, branch_a, got = read(branch_a, SHARED_URI)
        assert verdict == "hit"
        assert got == contents
        assert backend.fetch_counts[SHARED_URI] == 1

        # B still reflects only its own explicitly recorded state.
        verdict, branch_b_after, _ = read(branch_b, SHARED_URI)
        assert verdict == "withdrawn"
        assert branch_b_after is branch_b
        assert backend.fetch_counts[SHARED_URI] == 1

    def test_failure_does_not_leak_into_later_sibling_branches(self):
        """
        A transient failure observed on one branch is not visible to a
        sibling branch derived from the same shared registry afterwards.
        """
        contents = schema(**{"$id": SHARED_URI, "type": "integer"})
        backend = FakeBackend({SHARED_URI: contents})
        backend.fail_next_fetch(SHARED_URI)

        shared = Registry()
        branch_a = make_branch(shared, backend, withdrawn=set())

        verdict, branch_a_after, _ = read(branch_a, SHARED_URI)
        assert verdict == "transient-failure"
        assert branch_a_after is branch_a
        assert backend.fetch_counts[SHARED_URI] == 1

        # A branch created after the failure gets a clean first read.
        branch_c = make_branch(shared, backend, withdrawn=set())
        verdict, _, got = read(branch_c, SHARED_URI)
        assert verdict == "hit"
        assert got == contents
        assert backend.fetch_counts[SHARED_URI] == 2

        # And so does a retry on the branch which originally failed.
        verdict, _, got = read(branch_a, SHARED_URI)
        assert verdict == "hit"
        assert got == contents
        assert backend.fetch_counts[SHARED_URI] == 3

    def test_withdrawal_does_not_remove_the_resource_from_siblings(self):
        """
        Removing a resource from one branch leaves the shared base and
        every sibling branch untouched.
        """
        resource = Resource.from_contents(schema(**{"$id": COMMON_URI}))
        shared = Registry().with_resources([(COMMON_URI, resource)])

        branch_a = make_branch(shared, FakeBackend({}), withdrawn=set())
        branch_b = make_branch(shared, FakeBackend({}), withdrawn=set())

        branch_b = branch_b.remove(COMMON_URI)
        assert COMMON_URI not in branch_b

        assert shared[COMMON_URI] is resource
        assert branch_a[COMMON_URI] is resource
        verdict, _, got = read(branch_a, COMMON_URI)
        assert verdict == "hit"
        assert got == resource.contents


def test_verdicts_distinguish_transient_failure_from_withdrawal():
    """
    The two "no" answers are distinguishable to consumers: a transient
    network-class failure surfaces as `Unresolvable` caused by
    `Unretrievable`, while an explicit withdrawal has no such cause.
    """
    backend = FakeBackend({SHARED_URI: schema(**{"$id": SHARED_URI})})
    backend.fail_next_fetch(SHARED_URI)

    registry = make_branch(Registry(), backend, withdrawn=set())
    with pytest.raises(exceptions.Unresolvable) as transient:
        registry.resolver().lookup(SHARED_URI)
    assert isinstance(transient.value.__cause__, exceptions.Unretrievable)

    withdrawn = make_branch(Registry(), backend, withdrawn={SHARED_URI})
    with pytest.raises(exceptions.Unresolvable) as definitive:
        withdrawn.resolver().lookup(SHARED_URI)
    assert definitive.value.__cause__ is None
    # the tombstone answered without any external fetch
    assert backend.fetch_counts[SHARED_URI] == 1
