import functools
import os
import pickle as cpickle
import threading
import time
import types
import warnings
from pickle import PicklingError

import pytest

from joblib import Parallel, delayed, numpy_pickle
from joblib._store_backends import (
    CacheWarning,
    FileSystemStoreBackend,
    RETAINED_MARKER_FILENAME,
    UnreachableLimitWarning,
    _old_split_id,
)
from joblib.test.common import with_multiprocessing
from joblib.testing import parametrize, raises, timeout, warns


def write_func(output, filename):
    with open(filename, "wb") as f:
        cpickle.dump(output, f)


def load_func(expected, filename):
    for i in range(10):
        try:
            with open(filename, "rb") as f:
                reloaded = cpickle.load(f)
            break
        except (OSError, IOError):
            # On Windows you can have WindowsError ([Error 5] Access
            # is denied or [Error 13] Permission denied) when reading the file,
            # probably because a writer process has a lock on the file
            time.sleep(0.1)
    else:
        raise
    assert expected == reloaded


@timeout(0)  # No timeout as this test can be long
@with_multiprocessing
@parametrize("backend", ["multiprocessing", "loky", "threading"])
def test_concurrency_safe_write(tmpdir, backend):
    store_backend = FileSystemStoreBackend()
    store_backend.configure(tmpdir.join("store").strpath)

    # Add one item to cache
    filename = tmpdir.join("test.pkl").strpath

    obj = {str(i): i for i in range(int(1e5))}
    funcs = [
        functools.partial(store_backend._concurrency_safe_write, write_func=write_func)
        if i % 3 != 2
        else load_func
        for i in range(12)
    ]
    Parallel(n_jobs=2, backend=backend)(delayed(func)(obj, filename) for func in funcs)


def test_store_cached_func_code_is_not_written_in_place(tmpdir):
    # Non-regression test for #1694: func_code.py used to be truncated and
    # rewritten in place, so a concurrent reader could catch it half-written,
    # read that as a changed function and wipe the whole cache directory.
    backend = FileSystemStoreBackend()
    backend.configure(tmpdir.join("store").strpath)

    call_id = ("mod", "func")
    backend.store_cached_func_code(call_id, "# first line: 1\ndef f(): pass\n")
    original = backend.get_cached_func_code(call_id)

    def exploding_open(name, mode):
        open(name, mode).close()  # truncates whatever it is pointed at
        raise RuntimeError("boom")

    old_open = backend._open_item
    backend._open_item = exploding_open
    with pytest.raises(RuntimeError, match="boom"):
        backend.store_cached_func_code(call_id, "# first line: 1\ndef g(): pass\n")

    backend._open_item = old_open
    assert backend.get_cached_func_code(call_id) == original


def test_warning_on_dump_failure(tmp_path):
    # Check that a warning is raised when the dump fails for any reason but
    # a PicklingError.
    class UnpicklableObject(object):
        def __reduce__(self):
            raise RuntimeError("some exception")

    backend = FileSystemStoreBackend()
    backend.configure(str(tmp_path))

    with pytest.warns(CacheWarning, match="some exception"):
        backend.dump_item(("func", "input"), UnpicklableObject())
    assert not list(tmp_path.rglob("output.pkl.*"))


def test_warning_on_pickling_error(tmp_path):
    # This is separate from test_warning_on_dump_failure because in the
    # future we will turn this into an exception.
    class UnpicklableObject(object):
        def __reduce__(self):
            raise PicklingError("not picklable")

    backend = FileSystemStoreBackend()
    backend.configure(str(tmp_path))

    with pytest.warns(FutureWarning, match="not picklable"):
        backend.dump_item(("func", "input"), UnpicklableObject())


def test_cache_tree_versions(tmpdir):
    # Makes a backend using old cache tree
    old_store = FileSystemStoreBackend()
    old_store.configure(tmpdir.strpath)
    old_store._split_id = types.MethodType(_old_split_id, old_store)
    os.remove(os.path.join(old_store.location, "store_backend_info.json"))

    # Cache some items
    funs = ["fun1", "fun2", os.path.join("z" * 32, "fun3")]
    args = ["012" + "3" * 29, "012" + "4" * 29, "abcd" * 8]
    items = [0, "xyz", [42, 6.9]]
    for fun in funs:
        for arg, item in zip(args, items):
            old_store.dump_item((fun, arg), item)

    # Assert store_backend finds items from old cache tree
    old_items = old_store.get_items()
    assert len(old_items) == len(funs) * len(args)
    assert set(item.path for item in old_items) == set(
        tmpdir.join(fun, arg).strpath for fun in funs for arg in args
    )

    # Assert a warning is raised when configuring a FileSystemStoreBackend
    # with an old cache tree
    with warns(UserWarning, match="using old cache storage tree"):
        new_store = FileSystemStoreBackend()
        new_store.configure(tmpdir.strpath)

    # Pollute the backend
    # Creates items with new tree. After the creation:
    # (funs[0], args[0]) old tree version is more recent
    # (funs[1], args[0]) new tree version is more recent
    conflict_item = "bad"
    for fun in funs[:2]:
        arg = args[0]
        conflict_dir = tmpdir.join(fun, arg[:3], arg[3:]).strpath
        os.makedirs(conflict_dir)
        numpy_pickle.dump(conflict_item, os.path.join(conflict_dir, "output.pkl"))
    time.sleep(1.5)
    new_store.dump_item((funs[0], args[0]), items[0])

    # Assert (funs[0], args[0]) old tree version is more recent
    assert os.path.getmtime(
        tmpdir.join(funs[0], arg[:3], arg[3:], "output.pkl").strpath
    ) < os.path.getmtime(tmpdir.join(funs[0], arg, "output.pkl").strpath)

    # Assert update_cache_tree correctly updates the cache tree
    new_store.update_cache_tree()
    new_items = new_store.get_items()
    assert len(new_items) == len(funs) * len(args)
    assert set(item.path for item in new_items) == set(
        tmpdir.join(fun, arg[:3], arg[3:]).strpath for fun in funs for arg in args
    )

    # Assert no warning is raised when caching a function with a new cache tree
    with warnings.catch_warnings(record=True) as ws:
        warnings.simplefilter("always")
        FileSystemStoreBackend().configure(tmpdir.strpath)
        assert len(ws) == 0

    # Check that old_store shifted to new cache tree
    assert old_store.load_item((funs[0], args[0])) == items[0]
    assert old_store.load_item((funs[1], args[0])) == conflict_item
    with raises(KeyError):
        old_store.load_item(("not_a_function", args[0]))


###############################################################################
# Bounded cache: retained audit evidence + concurrency-safe eviction
###############################################################################

FUNC_ID = "test_eviction_func"


def _call_id(index):
    """Return a valid 32-char hex call id for a deterministic index."""
    return (FUNC_ID, f"{index:032x}")


def _populate_store(backend, num_items, item_size=1000):
    """Create ``num_items`` cache items of roughly ``item_size`` bytes."""
    for i in range(num_items):
        backend.dump_item(_call_id(i), b"v" * item_size)


def _item_path(backend, index):
    return os.path.join(backend.location, *backend._split_id(_call_id(index)))


def _call_id_from_path(path):
    """Reconstruct a full 32-char hex call id from a stored item path."""
    basename = os.path.basename(path)
    if len(basename) == 29:
        basename = os.path.basename(os.path.dirname(path)) + basename
    return (FUNC_ID, basename)


class InstrumentedStoreBackend(FileSystemStoreBackend):
    """Backend exposing control points to drive concurrent writers.

    The two concurrency control points of the eviction loop
    (``_after_eviction_scan`` and ``_before_eviction_delete``) are turned into
    barriers so a test can pause the cleaner after its scan and make another
    process or thread replace a candidate item before it is unlinked.
    """

    def __init__(self):
        self.scan_barrier = threading.Event()
        self.resume_event = threading.Event()
        self.replace_paths = set()
        self.replacement_payload = b"replacement-value"
        self.after_scan_called = threading.Event()

    def _after_eviction_scan(self, items, items_to_delete):
        self.after_scan_called.set()
        # Release the writer thread, then wait for the test to let the
        # cleaner proceed.
        self.scan_barrier.set()
        self.resume_event.wait(timeout=10)

    def _before_eviction_delete(self, item):
        if item.path in self.replace_paths:
            # Simulate another process finishing a concurrent replacement:
            # the value is rewritten through a temp file and atomically moved
            # onto output.pkl, exactly like a real joblib dump.
            output = os.path.join(item.path, "output.pkl")
            temporary = output + ".replacement"
            with open(temporary, "wb") as f:
                f.write(self.replacement_payload)
            os.replace(temporary, output)
            self.replace_paths.discard(item.path)


def test_retained_items_are_never_evicted(tmp_path):
    backend = FileSystemStoreBackend()
    backend.configure(str(tmp_path), verbose=0)
    _populate_store(backend, num_items=6)

    # Retain the two oldest items.
    items = sorted(backend.get_items(), key=lambda ci: ci.last_access)
    retained = items[:2]
    for item in retained:
        marker = os.path.join(item.path, RETAINED_MARKER_FILENAME)
        assert not os.path.exists(marker)
        # Retain through the public marker API using the item's own hash.
        backend.retain_item(_call_id_from_path(item.path))

    items = backend.get_items()
    retained_paths = {item.path for item in items if item.retained}
    assert retained_paths == {item.path for item in retained}

    # A tight limit would normally wipe every item, but retained ones stay.
    with pytest.warns(UnreachableLimitWarning):
        stats = backend.enforce_store_limits(bytes_limit=500)

    surviving = backend.get_items()
    surviving_paths = {item.path for item in surviving}
    assert surviving_paths == retained_paths
    assert all(item.retained for item in surviving)
    assert stats["retained_items"] == 2
    assert stats["final_items"] == 2
    assert stats["deleted_items"] == 4
    assert stats["limit_reached"] is False


def test_released_items_become_reclaimable(tmp_path):
    backend = FileSystemStoreBackend()
    backend.configure(str(tmp_path), verbose=0)
    _populate_store(backend, num_items=4)

    backend.retain_item(_call_id(0))
    assert any(item.retained for item in backend.get_items())

    backend.release_item(_call_id(0))
    assert not any(item.retained for item in backend.get_items())
    assert not os.path.exists(
        os.path.join(_item_path(backend, 0), RETAINED_MARKER_FILENAME)
    )

    stats = backend.enforce_store_limits(items_limit=0)
    assert stats["final_items"] == 0
    assert stats["limit_reached"] is True


def test_retain_marker_survives_replacement(tmp_path):
    # Audit evidence keeps its protected status when the cached value is
    # recomputed and the item directory is replaced.
    backend = FileSystemStoreBackend()
    backend.configure(str(tmp_path), verbose=0)
    backend.dump_item(_call_id(0), b"original")
    backend.retain_item(_call_id(0))

    backend.dump_item(_call_id(0), b"recomputed")
    assert backend.load_item(_call_id(0)) == b"recomputed"
    assert os.path.exists(
        os.path.join(_item_path(backend, 0), RETAINED_MARKER_FILENAME)
    )
    assert backend.get_items()[0].retained


def test_enforce_store_limits_returns_stats(tmp_path):
    backend = FileSystemStoreBackend()
    backend.configure(str(tmp_path), verbose=0)
    _populate_store(backend, num_items=5)

    initial = backend.get_items()
    stats = backend.enforce_store_limits(items_limit=2)

    expected_keys = {
        "initial_size",
        "final_size",
        "initial_items",
        "final_items",
        "deleted_items",
        "retained_items",
        "limit_reached",
    }
    assert expected_keys <= set(stats)
    assert stats["initial_items"] == 5
    assert stats["final_items"] == 2
    assert stats["deleted_items"] == 3
    assert stats["retained_items"] == 0
    assert stats["initial_size"] == sum(item.size for item in initial)
    assert stats["final_size"] == sum(item.size for item in backend.get_items())
    assert stats["final_size"] <= stats["initial_size"]
    assert stats["limit_reached"] is True


def test_no_warning_when_limit_is_reachable(tmp_path):
    backend = FileSystemStoreBackend()
    backend.configure(str(tmp_path), verbose=0)
    _populate_store(backend, num_items=4)
    backend.retain_item(_call_id(0))

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        stats = backend.enforce_store_limits(items_limit=1)

    assert not any(
        issubclass(w.category, UnreachableLimitWarning) for w in caught
    )
    # The retained item is the single survivor and the limit is met.
    assert stats["limit_reached"] is True
    assert stats["final_items"] == 1
    assert backend.get_items()[0].retained


def test_unreachable_bytes_limit_warns(tmp_path):
    backend = FileSystemStoreBackend()
    backend.configure(str(tmp_path), verbose=0)
    _populate_store(backend, num_items=3, item_size=2000)
    backend.retain_item(_call_id(0))
    backend.retain_item(_call_id(1))

    with pytest.warns(UnreachableLimitWarning, match="audit evidence"):
        stats = backend.enforce_store_limits(bytes_limit=10)

    # Every reclaimable item is removed but retained evidence remains.
    surviving = backend.get_items()
    assert len(surviving) == 2
    assert all(item.retained for item in surviving)
    assert stats["limit_reached"] is False
    assert stats["deleted_items"] == 1


def test_concurrent_replacement_after_scan_is_not_deleted(tmp_path):
    # Core race condition: the cleaner scans and selects a candidate, then
    # another writer replaces that item before the unlink. The cleaner must
    # only delete what it actually saw and keep the freshly written value.
    backend = InstrumentedStoreBackend()
    backend.configure(str(tmp_path), verbose=0)
    _populate_store(backend, num_items=6)

    target_path = _item_path(backend, 0)
    backend.replace_paths = {target_path}

    def writer():
        # Wait until the cleaner has finished its scan and paused.
        assert backend.scan_barrier.wait(timeout=10)
        # Trigger the replacement through the cleaner's own pre-delete hook
        # by simply resuming it; the replacement happens inside that hook.
        backend.resume_event.set()

    writer_thread = threading.Thread(target=writer)
    writer_thread.start()

    stats = backend.enforce_store_limits(items_limit=0)
    writer_thread.join(timeout=10)

    assert backend.after_scan_called.is_set()
    # The replaced item directory still exists and holds the new value.
    assert os.path.isdir(target_path)
    with open(os.path.join(target_path, "output.pkl"), "rb") as f:
        assert f.read() == backend.replacement_payload

    # Only the five untouched items were deleted; the replacement survived.
    surviving = backend.get_items()
    assert len(surviving) == 1
    assert surviving[0].path == target_path
    assert stats["deleted_items"] == 5
    assert stats["final_items"] == 1


def test_item_retained_after_scan_is_spared(tmp_path):
    # If an item is marked as retained in the window between the scan and the
    # deletion, the cleaner must not remove it.
    backend = InstrumentedStoreBackend()
    backend.configure(str(tmp_path), verbose=0)
    _populate_store(backend, num_items=4)

    target_path = _item_path(backend, 0)

    def retainer():
        assert backend.scan_barrier.wait(timeout=10)
        with open(
            os.path.join(target_path, RETAINED_MARKER_FILENAME), "wb"
        ) as f:
            f.write(b"retained\n")
        backend.resume_event.set()

    retainer_thread = threading.Thread(target=retainer)
    retainer_thread.start()
    stats = backend.enforce_store_limits(items_limit=0)
    retainer_thread.join(timeout=10)

    surviving = {item.path for item in backend.get_items()}
    assert target_path in surviving
    assert stats["deleted_items"] == 3
    assert stats["final_items"] == 1


def test_eviction_handles_item_deleted_elsewhere(tmp_path):
    # A candidate removed by another cleaner before our unlink must not be
    # counted as a deletion nor raise.
    backend = InstrumentedStoreBackend()
    backend.configure(str(tmp_path), verbose=0)
    _populate_store(backend, num_items=3)

    victim_path = _item_path(backend, 0)

    def external_cleaner():
        assert backend.scan_barrier.wait(timeout=10)
        import shutil

        shutil.rmtree(victim_path)
        backend.resume_event.set()

    cleaner_thread = threading.Thread(target=external_cleaner)
    cleaner_thread.start()
    stats = backend.enforce_store_limits(items_limit=0)
    cleaner_thread.join(timeout=10)

    assert stats["final_items"] == 0
    assert stats["deleted_items"] == 2


class _FileBarrierStoreBackend(FileSystemStoreBackend):
    """Backend coordinating a cleaner and a writer running in two processes.

    Synchronisation uses files instead of in-memory events so it works across
    ``multiprocessing`` workers. The cleaner blocks on ``resume_file`` once
    its scan is complete; the writer waits on ``scanned_file`` before
    replacing the candidate item.
    """

    def __init__(self, control_dir=None, replace_index=None):
        self.control_dir = control_dir
        self.replace_index = replace_index

    def _after_eviction_scan(self, items, items_to_delete):
        if self.control_dir is None:
            return
        scanned_file = os.path.join(self.control_dir, "scanned")
        resume_file = os.path.join(self.control_dir, "resume")
        with open(scanned_file, "w") as f:
            f.write("ready")
        # Block until the writer (or the test driver) releases us.
        for _ in range(200):
            if os.path.exists(resume_file):
                break
            time.sleep(0.05)

    def _before_eviction_delete(self, item):
        if self.control_dir is None or self.replace_index is None:
            return
        expected = None
        for index in [self.replace_index]:
            candidate = os.path.join(
                self.location, *self._split_id(_call_id(index))
            )
            if candidate == item.path:
                expected = candidate
        if expected is None:
            return
        output = os.path.join(expected, "output.pkl")
        temporary = output + ".replacement"
        with open(temporary, "wb") as f:
            f.write(b"replacement-value")
        os.replace(temporary, output)


def _two_process_cleaner(control_dir, location, replace_index):
    backend = _FileBarrierStoreBackend(control_dir, replace_index)
    backend.configure(location, verbose=0)
    return backend.enforce_store_limits(items_limit=0)


def _two_process_writer(control_dir, location, replace_index):
    # Wait for the cleaner to finish scanning, then replace the target value.
    scanned_file = os.path.join(control_dir, "scanned")
    for _ in range(200):
        if os.path.exists(scanned_file):
            break
        time.sleep(0.05)

    backend = _FileBarrierStoreBackend()
    backend.configure(location, verbose=0)
    target = os.path.join(
        backend.location, *backend._split_id(_call_id(replace_index))
    )
    output = os.path.join(target, "output.pkl")
    temporary = output + ".writer"
    with open(temporary, "wb") as f:
        f.write(b"replacement-value")
    os.replace(temporary, output)

    with open(os.path.join(control_dir, "resume"), "w") as f:
        f.write("go")


@with_multiprocessing
def test_two_processes_replacement_is_not_deleted(tmp_path):
    from joblib._multiprocessing_helpers import mp

    location = str(tmp_path / "store")
    control_dir = str(tmp_path / "control")
    os.makedirs(control_dir)

    backend = FileSystemStoreBackend()
    backend.configure(location, verbose=0)
    _populate_store(backend, num_items=5)
    target_path = os.path.join(location, *backend._split_id(_call_id(0)))

    ctx = mp.get_context("spawn")
    cleaner = ctx.Process(
        target=_two_process_cleaner, args=(control_dir, location, 0)
    )
    writer = ctx.Process(
        target=_two_process_writer, args=(control_dir, location, 0)
    )
    cleaner.start()
    writer.start()
    writer.join(timeout=30)
    cleaner.join(timeout=30)

    assert writer.exitcode == 0
    assert cleaner.exitcode == 0

    # The freshly written replacement survives the cleaner's pass.
    assert os.path.isdir(target_path)
    with open(os.path.join(target_path, "output.pkl"), "rb") as f:
        assert f.read() == b"replacement-value"

    surviving = FileSystemStoreBackend()
    surviving.configure(location, verbose=0)
    assert len(surviving.get_items()) == 1
