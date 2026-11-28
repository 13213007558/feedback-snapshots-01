from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest

from virtualenv.app_data import LayeredAppData, ReadOnlyAppData, make_layered_app_data


def _make_store(tmp_path: Path) -> LayeredAppData:
    shared: Final[Path] = tmp_path / "shared"
    private: Final[Path] = tmp_path / "private"
    shared.mkdir()
    return make_layered_app_data(str(shared), str(private))


def test_layered_store_opens_shared_read_only_and_private_writable(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    assert isinstance(store.shared, ReadOnlyAppData)
    assert (store.can_update, store.transient) == (True, False)
    assert store.lock.path.resolve() == (tmp_path / "private").resolve()
    # the shared view must never be able to update, while the layered store itself can
    assert store.shared.can_update is False


def test_layered_store_requires_existing_shared_folder(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="read-only app data directory"):
        make_layered_app_data(str(tmp_path / "missing"), str(tmp_path / "private"))


def test_wheel_image_miss_returns_private_path(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    image = store.wheel_image("3.12", "CopyPipInstall/setuptools-84.2.1-py3-none-any")
    assert str(image.resolve()).startswith(str((tmp_path / "private").resolve()))


def test_wheel_image_hit_prefers_shared_copy(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    relative = Path("wheel/3.12/image/1/CopyPipInstall/pip-26.3-py3-none-any")
    shared_image = store.shared_root / relative
    shared_image.mkdir(parents=True)
    (shared_image / "MARKER").write_text("cached", encoding="utf-8")

    image = store.wheel_image("3.12", "CopyPipInstall/pip-26.3-py3-none-any")
    assert image.resolve() == shared_image.resolve()
    assert (image / "MARKER").read_text(encoding="utf-8") == "cached"


def test_lock_target_keeps_shared_hits_out_of_read_only_tree(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    relative = Path("wheel/3.12/image/1/CopyPipInstall/pip-26.3-py3-none-any")
    shared_image = store.shared_root / relative
    shared_image.mkdir(parents=True)

    mapped = store.lock_target(store.wheel_image("3.12", "CopyPipInstall/pip-26.3-py3-none-any"))
    assert str(mapped.resolve()).startswith(str((tmp_path / "private").resolve()))
    assert not str(mapped.resolve()).startswith(str(store.shared_root.resolve()))


def test_private_path_refuses_to_leave_staging_folder(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    with pytest.raises(ValueError, match="must remain inside|belongs to neither"):
        store.lock_target(tmp_path / "private" / ".." / "elsewhere")


def test_locks_are_only_created_in_private_folder(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    target = store.wheel_image("3.12", "CopyPipInstall/foo")
    with store.locked(target):
        private_locks = list((tmp_path / "private").rglob("*.lock"))
        assert private_locks and all(
            str(p.resolve()).startswith(str((tmp_path / "private").resolve())) for p in private_locks
        )
    assert list((tmp_path / "shared").rglob("*.lock")) == []


def test_reset_only_touches_private_folder(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    shared_marker = store.shared_root / "keep.txt"
    shared_marker.write_text("shared", encoding="utf-8")
    private_marker = tmp_path / "private" / "drop.txt"
    private_marker.parent.mkdir(parents=True, exist_ok=True)
    private_marker.write_text("private", encoding="utf-8")

    store.reset()

    assert shared_marker.exists()
    assert not private_marker.exists()


def test_py_info_reads_shared_entry_and_writes_private(tmp_path: Path) -> None:
    import json
    from hashlib import sha256

    store = _make_store(tmp_path)
    interpreter = Path("/usr/bin/python3")
    # a read-only cache is pre-filled by the build machine, so place the JSON entry directly on disk
    key = sha256(str(interpreter).encode("utf-8")).hexdigest()
    shared_json = store.shared_root / "py_info" / "5" / f"{key}.json"
    shared_json.parent.mkdir(parents=True, exist_ok=True)
    shared_json.write_text(json.dumps({"shared": True}), encoding="utf-8")

    layered_store = store.py_info(interpreter)
    assert layered_store.exists() is True
    assert layered_store.read() == {"shared": True}

    layered_store.write({"private": True})
    private_files = list((tmp_path / "private" / "py_info").rglob("*.json"))
    assert private_files
    assert list((tmp_path / "shared").rglob("*.json")) == [shared_json]


def test_private_folder_created_with_restrictive_permissions(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    mode = store.lock.path.stat().st_mode & 0o777
    assert mode == 0o700
