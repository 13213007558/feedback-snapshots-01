import threading

import pytest

from fsspec.callbacks import Callback, TqdmCallback


class EventCollector:
    """Thread-safe sink for callback hook kwargs."""

    def __init__(self):
        self.events = []
        self.lock = threading.Lock()

    def __call__(self, size, value, **kwargs):
        with self.lock:
            self.events.append({"size": size, "value": value, **kwargs})


def test_callbacks():
    empty_callback = Callback()
    assert empty_callback.call("something", somearg=None) is None

    hooks = {"something": lambda *_, arg=None: arg + 2}
    simple_callback = Callback(hooks=hooks)
    assert simple_callback.call("something", arg=2) == 4

    hooks = {"something": lambda *_, arg1=None, arg2=None: arg1 + arg2}
    multi_arg_callback = Callback(hooks=hooks)
    assert multi_arg_callback.call("something", arg1=2, arg2=2) == 4


def test_callbacks_as_callback():
    empty_callback = Callback.as_callback(None)
    assert empty_callback.call("something", arg="somearg") is None
    assert Callback.as_callback(None) is Callback.as_callback(None)

    hooks = {"something": lambda *_, arg=None: arg + 2}
    real_callback = Callback.as_callback(Callback(hooks=hooks))
    assert real_callback.call("something", arg=2) == 4


def test_callbacks_as_context_manager(mocker):
    spy_close = mocker.spy(Callback, "close")

    with Callback() as cb:
        assert isinstance(cb, Callback)

    spy_close.assert_called_once()


def test_callbacks_branched():
    callback = Callback()

    branch = callback.branched("path_1", "path_2")

    assert branch is not callback
    assert isinstance(branch, Callback)


@pytest.mark.asyncio
async def test_callbacks_branch_coro(mocker):
    async_fn = mocker.AsyncMock(return_value=10)
    callback = Callback()
    wrapped_fn = callback.branch_coro(async_fn)
    spy = mocker.spy(callback, "branched")

    assert await wrapped_fn("path_1", "path_2", key="value") == 10

    spy.assert_called_once_with("path_1", "path_2", key="value")
    async_fn.assert_called_once_with(
        "path_1", "path_2", callback=spy.spy_return, key="value"
    )


def test_callbacks_wrap():
    events = []

    class TestCallback(Callback):
        def relative_update(self, inc=1):
            events.append(inc)

    callback = TestCallback()
    for _ in callback.wrap(range(10)):
        ...

    assert events == [1] * 10


@pytest.mark.parametrize("tqdm_kwargs", [{}, {"desc": "A custom desc"}])
def test_tqdm_callback(tqdm_kwargs, mocker):
    pytest.importorskip("tqdm")
    callback = TqdmCallback(tqdm_kwargs=tqdm_kwargs)
    mocker.patch.object(callback, "_tqdm_cls")
    callback.set_size(10)
    for _ in callback.wrap(range(10)):
        ...

    assert callback.tqdm.update.call_count == 11
    if not tqdm_kwargs:
        callback._tqdm_cls.assert_called_with(total=10)
    else:
        callback._tqdm_cls.assert_called_with(total=10, **tqdm_kwargs)


def test_callbacks_path_display_mapping():
    events = EventCollector()
    callback = Callback(
        hooks={"progress": events},
        path_display={
            "/private/src.txt": "public/source.txt",
            "/private/dst.txt": "public/destination.txt",
        },
    )

    child = callback.branched("/private/src.txt", "/private/dst.txt")
    child.set_size(10)
    child.relative_update(4)
    child.relative_update(6)

    assert events.events == [
        {
            "size": 10,
            "value": 0,
            "source": "public/source.txt",
            "destination": "public/destination.txt",
        },
        {
            "size": 10,
            "value": 4,
            "source": "public/source.txt",
            "destination": "public/destination.txt",
        },
        {
            "size": 10,
            "value": 10,
            "source": "public/source.txt",
            "destination": "public/destination.txt",
        },
    ]
    assert callback.value == 0


def test_callbacks_path_display_is_per_direction():
    events = EventCollector()
    mapping = {
        "/private/src.txt": "public/source.txt",
        "/private/dst.txt": "public/destination.txt",
    }

    source_only = Callback(
        hooks={"progress": events},
        path_display={"/private/src.txt": mapping["/private/src.txt"]},
    ).branched("/private/src.txt", "/private/dst.txt")
    source_only.set_size(1)
    assert events.events[-1] == {
        "size": 1,
        "value": 0,
        "source": "public/source.txt",
    }

    events.events.clear()
    destination_only = Callback(
        hooks={"progress": events},
        path_display={"/private/dst.txt": mapping["/private/dst.txt"]},
    ).branched("/private/src.txt", "/private/dst.txt")
    destination_only.set_size(1)
    assert events.events[-1] == {
        "size": 1,
        "value": 0,
        "destination": "public/destination.txt",
    }


def test_callbacks_path_display_callable():
    def display(path):
        return None if "internal" in path else f"task/{path.rsplit('/', 1)[-1]}"

    events = EventCollector()
    callback = Callback(hooks={"progress": events}, path_display=display)
    child = callback.branched("internal/src.bin", "bucket/out.bin")
    child.set_size(2)

    assert events.events == [
        {
            "size": 2,
            "value": 0,
            "destination": "task/out.bin",
        }
    ]


def test_callbacks_path_display_rejects_bad_configuration():
    with pytest.raises(TypeError, match="path_display"):
        Callback(path_display=42)

    callback = Callback(path_display={"/private/src": 42})
    with pytest.raises(TypeError, match="strings or None"):
        callback.branched("/private/src", "/private/dst")


def test_tqdm_callback_display_children_get_own_bars(mocker):
    pytest.importorskip("tqdm")
    callback = TqdmCallback(path_display={"/private/src": "public/src"})
    mocked = mocker.patch.object(callback, "_tqdm_cls")

    child = callback.branched("/private/src", "/private/dst")
    child.set_size(2)

    assert callback.tqdm is None
    mocked.assert_called_once_with(total=2)
    assert child._display_kw == {"source": "public/src"}
    child.close()
    assert callback.tqdm is None


def test_callbacks_path_display_direct_branch_supplied_callback():
    events = []
    callback = Callback(path_display={"/private/src": "public/src"})
    kwargs = {
        "callback": Callback(
            hooks={"progress": lambda s, v, **kw: events.append(kw)}
        )
    }

    callback.branch("/private/src", "/private/dst", kwargs)

    child = kwargs["callback"]
    assert child._display_kw == {"source": "public/src"}
    child.set_size(1)
    assert events == [{"source": "public/src"}]


def test_callbacks_path_display_subclass_children_keep_display():
    seen = []

    class Branching(Callback):
        def branch(self, path_1, path_2, kwargs):
            kwargs["callback"] = Callback(
                hooks={"progress": lambda s, v, **kw: seen.append(kw)}
            )

    callback = Branching(path_display={"/private/src": "public/src"})
    child = callback.branched("/private/src", "/private/dst")
    child.set_size(1)

    assert seen == [{"source": "public/src"}]


def test_callbacks_path_display_from_class_attribute():
    class Public(Callback):
        path_display = {"/private/src": "public/src"}

    events = EventCollector()
    callback = Public(hooks={"progress": events})
    child = callback.branched("/private/src", "/private/dst")
    child.set_size(1)

    assert events.events[-1]["source"] == "public/src"


def test_callbacks_path_display_wins_over_backend_kwargs():
    events = []
    callback = Callback(
        hooks={"progress": lambda s, v, **kw: events.append(kw)},
        path_display={"/private/src": "public/src"},
    )

    child = callback.branched("/private/src", "/private/dst")
    child.call(source="/private/src", destination="/private/dst")

    assert events == [{"source": "public/src"}]


@pytest.mark.asyncio
async def test_callbacks_path_display_branch_coro_overridden_branched():
    async def transfer(path_1, path_2, callback=None, **kwargs):
        callback.set_size(1)
        return path_2

    events = []

    class Custom(Callback):
        def branched(self, path_1, path_2, **kwargs):
            return Callback(
                hooks={"progress": lambda s, v, **kw: events.append(kw)}
            )

    callback = Custom(path_display={"/private/src": "public/src"})
    await callback.branch_coro(transfer)("/private/src", "/private/dst")

    assert events == [{"source": "public/src"}]


def test_callbacks_path_display_concurrent_threads_do_not_mix_events():
    events = []
    lock = threading.Lock()
    barrier = threading.Barrier(2)

    def collect(size, value, **kwargs):
        with lock:
            events.append({"size": size, "value": value, **kwargs})

    callback = Callback(
        hooks={"progress": collect},
        path_display={"/private/a": "task/a", "/private/b": "task/b"},
    )
    children = {
        "task/a": callback.branched("/private/a", "/private/dest-a"),
        "task/b": callback.branched("/private/b", "/private/dest-b"),
    }

    def transfer(name, size):
        child = children[name]
        barrier.wait()
        child.set_size(size)
        for _ in range(size):
            child.relative_update()

    threads = [
        threading.Thread(target=transfer, args=("task/a", 3)),
        threading.Thread(target=transfer, args=("task/b", 5)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert children["task/a"].value == 3
    assert children["task/b"].value == 5
    assert callback.value == 0
    for name, size in (("task/a", 3), ("task/b", 5)):
        child_events = [e for e in events if e.get("source") == name]
        assert child_events
        assert all(e["size"] == size for e in child_events)
        assert [e["value"] for e in child_events] == [0, 1, 2, 3, 4, 5][: size + 1]
        assert all("private" not in str(e) for e in child_events)


def test_callbacks_path_display_children_have_isolated_progress():
    events = EventCollector()
    callback = Callback(
        hooks={"progress": events},
        path_display={"/a": "task/a", "/b": "task/b"},
    )

    child_a = callback.branched("/a", "/a")
    child_b = callback.branched("/b", "/b")
    child_a.set_size(2)
    child_b.set_size(3)
    child_a.relative_update(1)
    child_b.relative_update(2)
    child_a.relative_update(1)
    child_b.relative_update(1)

    assert child_a.value == 2
    assert child_b.value == 3
    assert callback.value == 0
    a_events = [e for e in events.events if e.get("source") == "task/a"]
    b_events = [e for e in events.events if e.get("source") == "task/b"]
    assert [(e["size"], e["value"]) for e in a_events] == [(2, 0), (2, 1), (2, 2)]
    assert [(e["size"], e["value"]) for e in b_events] == [(3, 0), (3, 2), (3, 3)]


def test_callbacks_without_path_display_keeps_existing_kwargs():
    events = EventCollector()
    callback = Callback(hooks={"progress": events})
    child = callback.branched("/private/src", "/private/dst")
    assert child is not callback

    callback.set_size(1)
    assert events.events == [{"size": 1, "value": 0}]
