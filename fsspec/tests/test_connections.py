import pickle

import pytest

import fsspec
from fsspec.exceptions import ConnectionNotConfigured
from fsspec.implementations.memory import MemoryFileSystem


class FakeBackend(MemoryFileSystem):
    """Distinct memory backend with a marker payload for pickling checks."""

    protocol = "fakeback"
    cachable = True

    def __init__(self, tag, *args, token=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.tag = tag
        self.token = token
        self.opened = []

    def _open(self, path, mode="rb", **kwargs):
        self.opened.append((self.tag, path))
        return super()._open(path, mode=mode, **kwargs)


@pytest.fixture
def connections():
    fsspec.clear_connections()
    first = FakeBackend(
        "first", token="secret-token-one", global_store=False, skip_instance_cache=True
    )
    second = FakeBackend(
        "second", token="secret-token-two", global_store=False, skip_instance_cache=True
    )
    first.pipe("/file", b"from-first")
    second.pipe("/file", b"from-second")
    fsspec.register_connection("first", fs=first)
    fsspec.register_connection("second", fs=second)
    try:
        yield first, second
    finally:
        fsspec.clear_connections()


def test_openfile_connection_payload_has_name_only(connections):
    first, second = connections
    of = fsspec.open("file", mode="rb", connection="first")
    payload = pickle.dumps(of)
    assert b"first" in payload
    assert b"second" not in payload
    assert b"from-first" not in payload
    assert b"from-second" not in payload
    # No filesystem instance/constructor args (or credentials) travel along.
    assert b"MemoryFileSystem" not in payload
    assert b"secret-token-one" not in payload
    assert b"secret-token-two" not in payload
    assert of.fs is first


def test_openfile_connection_restores_using_worker_configuration(connections):
    first, second = connections
    payload = pickle.dumps(fsspec.open("file", mode="rb", connection="first"))

    # Simulate a worker where only "second" is configured and the alias points
    # at a different backend than in the producer.
    fsspec.clear_connections()
    fsspec.register_connection("first", fs=second)
    second.opened.clear()
    restored = pickle.loads(payload)
    assert restored.fs is second
    assert restored.connection == "first"
    with restored as f:
        assert f.read() == b"from-second"
    assert second.opened == [("second", "/file")]


def test_openfile_connection_missing_configuration(connections):
    _, _ = connections
    payload = pickle.dumps(fsspec.open("file", mode="rb", connection="first"))
    fsspec.clear_connections()
    with pytest.raises(ConnectionNotConfigured) as excinfo:
        pickle.loads(payload)
    assert "first" in str(excinfo.value)


def test_openfile_opened_object_does_not_carry_connection_state(connections):
    first, _ = connections
    of = fsspec.open("file", mode="rb", connection="first")
    live = of.open()
    assert live.read() == b"from-first"
    payload = pickle.dumps(of)
    assert b"from-first" not in payload
    assert b"MemoryFileSystem" not in payload

    restored = pickle.loads(payload)
    assert restored is not of
    assert restored.fobjects == []
    assert restored.fs is first
    assert live.closed is False
    live.close()
    of.close()


def test_openfiles_connection_batch(connections):
    first, second = connections
    second.pipe("/other", b"other-second")
    files = fsspec.open_files(["file", "other"], mode="rb", connection="second")
    payload = pickle.dumps(files)
    assert b"from-second" not in payload and b"other-second" not in payload
    restored = pickle.loads(payload)
    assert restored.fs is second
    with restored as fhs:
        assert [f.read() for f in fhs] == [b"from-second", b"other-second"]


def test_openfiles_after_open_does_not_carry_files(connections):
    first, _ = connections
    files = fsspec.open_files("file", mode="rb", connection="first")
    with files as fhs:
        assert fhs[0].read() == b"from-first"
    # Even while the OpenFiles object still knows the opened files, the
    # payload contains only descriptors.
    restored = pickle.loads(pickle.dumps(files))
    assert restored.files == []
    assert restored[0].fs is first
    with restored as fhs:
        assert fhs[0].read() == b"from-first"


def test_registered_filesystem_pickles_by_name(connections):
    first, second = connections
    payload = pickle.dumps(first)
    assert b"from-first" not in payload
    assert b"MemoryFileSystem" not in payload
    fsspec.clear_connections()
    fsspec.register_connection("first", fs=second)
    assert pickle.loads(payload) is second


def test_unknown_connection_at_open_time(connections):
    with pytest.raises(ConnectionNotConfigured):
        fsspec.open("file", connection="nope")


def test_connection_from_config(connections, monkeypatch):
    first, second = connections
    from fsspec.config import conf

    payload = pickle.dumps(fsspec.open("file", mode="rb", connection="first"))
    fsspec.clear_connections()
    monkeypatch.setitem(conf, "connections", {"first": {"fs": second}})
    restored = pickle.loads(payload)
    assert restored.fs is second
    with restored as f:
        assert f.read() == b"from-second"


def test_connection_config_without_alias_fails(connections, monkeypatch):
    from fsspec.config import conf

    payload = pickle.dumps(fsspec.open("file", mode="rb", connection="first"))
    fsspec.clear_connections()
    monkeypatch.setitem(conf, "connections", {"second": {"fs": connections[1]}})
    assert fsspec.registered_connections() == ("second",)
    with pytest.raises(ConnectionNotConfigured):
        pickle.loads(payload)


def test_connection_write_creates_parents(connections, tmp_path, monkeypatch):
    from fsspec.config import conf

    payload_fs = FakeBackend(
        "writer", token="write-secret", global_store=False, skip_instance_cache=True
    )
    fsspec.clear_connections()
    monkeypatch.setitem(conf, "connections", {"writer": {"fs": payload_fs}})
    files = fsspec.open_files(
        ["/nested/dir/out.txt"], mode="wb", connection="writer", auto_mkdir=True
    )
    with files as fhs:
        fhs[0].write(b"written")
    assert payload_fs.cat("/nested/dir/out.txt") == b"written"


def test_connection_bad_combination(connections):
    with pytest.raises(ValueError, match="cannot be combined"):
        fsspec.open("file", connection="first", protocol="memory")
    with pytest.raises(ValueError, match="Provide fs or connection"):
        from fsspec.core import OpenFile

        OpenFile()


def test_connection_name_validation(connections):
    with pytest.raises(ValueError):
        fsspec.register_connection("", protocol="memory")
    with pytest.raises(ValueError, match="not both"):
        fsspec.register_connection("ok", fs=object(), protocol="memory")
    with pytest.raises(ValueError, match="already registered"):
        fsspec.register_connection("first", protocol="memory", replace=False)


def test_shared_filesystem_keeps_explicit_alias(connections, monkeypatch):
    first, second = connections
    # Register the same worker instance under both names, in either order.
    fsspec.register_connection("second", fs=first)
    payload = pickle.dumps(fsspec.open("file", mode="rb", connection="second"))
    fsspec.clear_connections()
    from fsspec.config import conf

    monkeypatch.setitem(conf, "connections", {"second": {"fs": first}})
    restored = pickle.loads(payload)
    assert restored.connection == "second"
    assert restored.fs is first


def test_connection_docstring_example_roundtrip(connections):
    first, second = connections
    of = fsspec.open("file", mode="rb", connection="first")
    payload = pickle.dumps(of)
    assert payload.count(b"first") >= 1
    # Another worker with its own filesystem under the same name.
    fsspec.clear_connections()
    fsspec.register_connection("first", fs=second)
    second.opened.clear()
    restored = pickle.loads(payload)
    with restored as f:
        assert f.read() == b"from-second"
    assert second.opened == [("second", "/file")]


def test_connection_text_mode(connections):
    first, _ = connections
    with fsspec.open("/text", "wt", connection="first", encoding="utf-8") as f:
        f.write("hello\nworld")
    assert first.cat("/text") == b"hello\nworld"
    with fsspec.open("/text", "rt", connection="first") as f:
        assert f.read() == "hello\nworld"


def test_connection_with_protocol_factory(monkeypatch):
    from fsspec.config import conf

    fsspec.clear_connections()
    calls = []

    def make():
        calls.append(1)
        fs = FakeBackend("factory", global_store=False, skip_instance_cache=True)
        fs.pipe("/made", b"from-factory")
        return fs

    monkeypatch.setitem(conf, "connections", {"lazy": make})
    of = fsspec.open("/made", mode="rb", connection="lazy")
    assert calls == [1]
    payload = pickle.dumps(of)
    assert b"from-factory" not in payload
    fsspec.clear_connections()
    monkeypatch.setitem(conf, "connections", {"lazy": make})
    restored = pickle.loads(payload)
    with restored as f:
        assert f.read() == b"from-factory"
    assert len(calls) == 2


def test_unregister_removes_alias_from_filesystem(connections):
    first, _ = connections
    assert getattr(first, "_connection_name", None) == "first"
    assert fsspec.unregister_connection("first") is True
    assert getattr(first, "_connection_name", None) is None
    # Plain instance pickling is back to constructor arguments.
    fsspec.clear_connections()
    restored = pickle.loads(pickle.dumps(first))
    assert isinstance(restored, FakeBackend)
    assert restored.tag == "first"
