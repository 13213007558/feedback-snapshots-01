"""Tests for restricted ``call_and_shelve`` handles and their approvals.

A restricted handle must always resolve to the exact artifact that was
approved when the handle was created, even after the handle left the
process that created it. These tests use a local store backend that records
every artifact load to prove that a stale handle can never be served a
rebuilt artifact.
"""

import pickle

import pytest

from joblib import Memory
from joblib._store_backends import FileSystemStoreBackend
from joblib.memory import (
    ApprovalRevokedError,
    RestrictedMemorizedResult,
    StaleResultError,
    register_store_backend,
)
from joblib.testing import raises

RECORDING_BACKEND = "recording-local"


class RecordingStoreBackend(FileSystemStoreBackend):
    """Local backend counting how often each artifact is actually loaded."""

    # Class-level counters shared by every instance reconstructed for the
    # same location (in particular by handles restored from a pickle).
    load_counts = {}

    @classmethod
    def reset_counts(cls):
        cls.load_counts.clear()

    @classmethod
    def count_for(cls, location):
        return cls.load_counts.setdefault(location, 0)

    def load_item(self, call_id, *args, **kwargs):
        self.load_counts[self.location] = self.count_for(self.location) + 1
        return super().load_item(call_id, *args, **kwargs)


@pytest.fixture
def recording_backend():
    register_store_backend(RECORDING_BACKEND, RecordingStoreBackend)
    RecordingStoreBackend.reset_counts()
    yield RECORDING_BACKEND
    # The registry is a module-level global: remove the test-only entry.
    from joblib.memory import _STORE_BACKENDS

    _STORE_BACKENDS.pop(RECORDING_BACKEND, None)
    RecordingStoreBackend.reset_counts()


def make_memory(tmp_path, **kwargs):
    options = dict(verbose=0, backend=RECORDING_BACKEND)
    options.update(kwargs)
    return Memory(location=str(tmp_path), **options)


def test_restricted_handle_returns_approved_artifact(tmp_path, recording_backend):
    memory = make_memory(tmp_path, restricted=True)
    computations = []

    @memory.cache
    def add_one(x):
        computations.append(x)
        return x + 1

    handle = add_one.call_and_shelve(41)
    assert isinstance(handle, RestrictedMemorizedResult)
    assert handle.get() == 42
    # A second resolution reads the cache again but must not recompute.
    assert handle.get() == 42
    assert computations == [41]


def test_stale_handle_rejects_rebuilt_artifact_and_counts_loads(
    tmp_path, recording_backend
):
    memory = make_memory(tmp_path, restricted=True)
    values = {"v": "approved-result"}
    computations = []

    @memory.cache
    def business_result(key):
        computations.append(key)
        return values["v"]

    cached = memory.cache(business_result)

    # An old handle is shelved and leaves the process (pickle round-trip,
    # mimicking an offline queue). The backend is reconstructed from its
    # location while unpickling, yet load counting is shared through the
    # class-level registry.
    old_handle = pickle.loads(pickle.dumps(cached.call_and_shelve("k")))
    location = old_handle.store_backend.location
    assert RecordingStoreBackend.count_for(location) == 0
    assert old_handle.get() == "approved-result"
    assert RecordingStoreBackend.count_for(location) == 1

    # Cache cleanup followed by a recomputation under the same logical key.
    cached.clear()
    values["v"] = "rebuilt-result"
    assert cached("k") == "rebuilt-result"
    # The regular call path does not load the just-written artifact.
    assert RecordingStoreBackend.count_for(location) == 1

    # The rebuilt artifact is physically present and a freshly approved
    # handle resolves to it normally (one extra actual backend load).
    new_handle = cached.call_and_shelve("k")
    assert new_handle.get() == "rebuilt-result"
    assert RecordingStoreBackend.count_for(location) == 2

    # The stale handle must give a clear error and must never load the
    # rebuilt artifact.
    with raises(StaleResultError, match="rebuilt or modified"):
        old_handle.get()
    assert RecordingStoreBackend.count_for(location) == 2

    # A second attempt is rejected deterministically, still without loading.
    with raises(StaleResultError):
        old_handle.get()
    assert RecordingStoreBackend.count_for(location) == 2

    # The business code only ever received the approved value through the
    # old handle, and the new handle sees the rebuilt one.
    assert new_handle.get() == "rebuilt-result"
    assert RecordingStoreBackend.count_for(location) == 3
    assert computations == ["k", "k"]


def test_stale_handle_fails_even_when_rebuilt_bytes_are_identical(
    tmp_path, recording_backend
):
    memory = make_memory(tmp_path, restricted=True)

    @memory.cache
    def stable(x):
        return x * 2

    cached = memory.cache(stable)
    old_handle = cached.call_and_shelve(21)
    assert old_handle.get() == 42

    cached.clear()
    # Recomputation stores a byte-identical artifact under the same key.
    assert cached(21) == 42

    with raises(StaleResultError):
        old_handle.get()

    # A new approval on the rebuilt artifact works as usual.
    new_handle = cached.call_and_shelve(21)
    assert new_handle.get() == 42


def test_revoked_approval_is_rejected_without_loading(
    tmp_path, recording_backend
):
    memory = make_memory(tmp_path, restricted=True)

    @memory.cache
    def secret(x):
        return {"x": x}

    cached = memory.cache(secret)
    handle = cached.call_and_shelve(1)
    assert handle.get() == {"x": 1}

    handle.revoke()
    location = handle.store_backend.location
    loads_before = RecordingStoreBackend.count_for(location)
    with raises(ApprovalRevokedError):
        handle.get()
    # Revocation is checked before the artifact is touched.
    assert RecordingStoreBackend.count_for(location) == loads_before


def test_revocation_is_visible_after_pickle_round_trip(
    tmp_path, recording_backend
):
    memory = make_memory(tmp_path, restricted=True)

    @memory.cache
    def secret(x):
        return x + 100

    cached = memory.cache(secret)
    handle = pickle.loads(pickle.dumps(cached.call_and_shelve(1)))
    assert handle.get() == 101

    # Revocation is persisted in the store, so a handle restored in another
    # process observes it.
    handle.revoke()
    restored = pickle.loads(pickle.dumps(handle))
    with raises(ApprovalRevokedError):
        restored.get()


def test_missing_artifact_raises_stale_result(tmp_path, recording_backend):
    memory = make_memory(tmp_path, restricted=True)

    @memory.cache
    def f(x):
        return x

    cached = memory.cache(f)
    handle = cached.call_and_shelve(7)
    assert handle.get() == 7

    # Remove only the cached item, leaving the approval in place.
    handle.clear()
    with raises(StaleResultError, match="missing"):
        handle.get()


def test_restricted_handle_survives_pickle_and_verifies_in_new_instance(
    tmp_path, recording_backend
):
    memory = make_memory(tmp_path, restricted=True)

    @memory.cache
    def f(x):
        return [x, x + 1]

    cached = memory.cache(f)
    handle = cached.call_and_shelve(3)
    restored = pickle.loads(pickle.dumps(handle))

    assert isinstance(restored, RestrictedMemorizedResult)
    assert restored.approval_id == handle.approval_id
    assert restored.approved_artifact_id == handle.approved_artifact_id
    assert restored.approved_digest == handle.approved_digest
    assert restored.get() == [3, 4]


def test_unrestricted_cache_keeps_existing_behavior(tmp_path, recording_backend):
    # The default Memory does not restrict handles.
    memory = make_memory(tmp_path)
    assert memory.restricted is False

    @memory.cache
    def f(x):
        return x + 1

    handle = f.call_and_shelve(1)
    assert not isinstance(handle, RestrictedMemorizedResult)
    assert handle.get() == 2

    # A plain handle keeps following whatever the current artifact is, even
    # after a clear and rebuild with different content.
    f.clear()
    assert f(1) == 2
    assert handle.get() == 2


def test_restricted_flag_can_be_set_per_function(tmp_path, recording_backend):
    memory = make_memory(tmp_path)

    @memory.cache
    def unrestricted(x):
        return x

    @memory.cache(restricted=True)
    def restricted(x):
        return x

    assert not unrestricted.restricted
    assert restricted.restricted
    assert not isinstance(unrestricted.call_and_shelve(1), RestrictedMemorizedResult)
    assert isinstance(
        restricted.call_and_shelve(1), RestrictedMemorizedResult
    )


def test_separate_approvals_are_independent(tmp_path, recording_backend):
    memory = make_memory(tmp_path, restricted=True)

    @memory.cache
    def f(x):
        return x * 3

    cached = memory.cache(f)
    first = cached.call_and_shelve(2)
    second = cached.call_and_shelve(2)

    assert first.approval_id != second.approval_id
    assert first.get() == 6
    assert second.get() == 6

    first.revoke()
    with raises(ApprovalRevokedError):
        first.get()
    # The other approval is untouched.
    assert second.get() == 6
