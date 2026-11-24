"""Tests for strict, allowlist-based loading of joblib artifacts."""

import json
import os
import pickle

import pytest

import joblib
from joblib import (
    ApprovedArtifacts,
    ArtifactIntegrityError,
    StrictLoadError,
    UnapprovedArtifactError,
    numpy_pickle,
    strict_load,
)
from joblib.security import compute_file_digest, verified_fd_path
from joblib.test.common import np, with_numpy
from joblib.testing import parametrize


def _write_array(path, array):
    numpy_pickle.dump(array, path)


def test_approved_artifacts_manifest_roundtrip(tmpdir):
    first = tmpdir.join("first.joblib").strpath
    second = tmpdir.join("second.joblib").strpath
    _write_array(first, np.arange(5))
    _write_array(second, np.arange(10))

    approved = ApprovedArtifacts.from_paths([first, second])

    manifest_path = tmpdir.join("manifest.json").strpath
    approved.write_manifest(manifest_path)

    with open(manifest_path) as fobj:
        payload = json.load(fobj)
    assert payload["hash_name"] == "sha256"
    assert {entry["path"] for entry in payload["artifacts"]} == {
        os.path.abspath(first),
        os.path.abspath(second),
    }

    rebuilt = ApprovedArtifacts.from_manifest(manifest_path)
    assert rebuilt.digest_of(first) == approved.digest_of(first)
    assert rebuilt.contains(second)

    in_memory = ApprovedArtifacts.from_manifest(payload)
    assert in_memory.contains(first)


def test_approved_artifacts_rejects_unknown_path(tmpdir):
    filename = tmpdir.join("model.joblib").strpath
    _write_array(filename, np.arange(3))

    approved = ApprovedArtifacts()
    assert not approved.contains(filename)
    with pytest.raises(UnapprovedArtifactError):
        strict_load(filename, approved)


def test_approved_artifacts_rejects_wrong_digest(tmpdir):
    filename = tmpdir.join("model.joblib").strpath
    _write_array(filename, np.arange(3))

    approved = ApprovedArtifacts(
        [{"path": filename, "digest": "0" * 64}]
    )
    with pytest.raises(ArtifactIntegrityError):
        strict_load(filename, approved)


def test_strict_load_rejects_file_like_object(tmpdir):
    filename = tmpdir.join("model.joblib").strpath
    _write_array(filename, np.arange(3))
    approved = ApprovedArtifacts.from_paths([filename])

    with open(filename, "rb") as fobj:
        with pytest.raises(StrictLoadError):
            strict_load(fobj, approved)


@with_numpy
def test_swapped_artifact_rejected_before_unpickling(tmpdir, monkeypatch):
    genuine = tmpdir.join("genuine.joblib").strpath
    decoy = tmpdir.join("decoy.joblib").strpath
    _write_array(genuine, np.arange(10))
    _write_array(decoy, np.arange(100, 110))

    approved = ApprovedArtifacts.from_paths([genuine])

    def fail_unpickle(*args, **kwargs):  # pragma: no cover - never called
        raise AssertionError("unpickling started on the swapped artifact")

    monkeypatch.setattr(numpy_pickle, "_unpickle", fail_unpickle)

    # Swap the input between approval and actual reading.
    os.replace(decoy, genuine)

    with pytest.raises(ArtifactIntegrityError):
        strict_load(genuine, approved)

    # An unapproved replacement path is rejected even earlier.
    with pytest.raises(UnapprovedArtifactError):
        strict_load(decoy, approved)


@with_numpy
def test_strict_load_plain_artifact(tmpdir):
    filename = tmpdir.join("plain.joblib").strpath
    payload = np.arange(12).reshape(3, 4)
    _write_array(filename, payload)

    result = strict_load(filename, ApprovedArtifacts.from_paths([filename]))
    np.testing.assert_array_equal(result, payload)


@with_numpy
@parametrize(
    "extension, compress",
    [
        (".joblib.gz", ("gzip", 3)),
        (".joblib.bz2", ("bz2", 3)),
        (".joblib.xz", ("xz", 3)),
        (".joblib.z", ("zlib", 3)),
    ],
)
def test_strict_load_compressed_artifact(tmpdir, extension, compress):
    filename = tmpdir.join("compressed" + extension).strpath
    payload = np.arange(8)
    numpy_pickle.dump(payload, filename, compress=compress)

    result = strict_load(filename, ApprovedArtifacts.from_paths([filename]))
    np.testing.assert_array_equal(result, payload)


@with_numpy
def test_strict_load_mmap_artifact(tmpdir):
    filename = tmpdir.join("mmapped.joblib").strpath
    payload = np.linspace(0, 1, 16)
    _write_array(filename, payload)

    result = strict_load(
        filename, ApprovedArtifacts.from_paths([filename]), mmap_mode="r"
    )
    assert isinstance(result, np.memmap)
    np.testing.assert_array_equal(np.asarray(result), payload)


@with_numpy
def test_strict_load_mmap_uses_verified_descriptor(tmpdir, monkeypatch):
    if os.name == "nt":
        pytest.skip("/dev/fd is not available on this platform")

    filename = tmpdir.join("mmapped.joblib").strpath
    _write_array(filename, np.arange(10, dtype=np.float64))
    approved = ApprovedArtifacts.from_paths([filename])

    captured = {}
    original = numpy_pickle.make_memmap

    def spy(memmap_filename, **kwargs):
        captured["filename"] = memmap_filename
        return original(memmap_filename, **kwargs)

    monkeypatch.setattr(numpy_pickle, "make_memmap", spy)

    strict_load(filename, approved, mmap_mode="r")
    assert captured["filename"].startswith("/dev/fd/")
    assert captured["filename"] == verified_fd_path(
        int(captured["filename"].rsplit("/", 1)[-1])
    )


@with_numpy
def test_strict_load_mmap_binds_descriptor_after_path_swap(tmpdir):
    genuine = tmpdir.join("genuine.joblib").strpath
    decoy = tmpdir.join("decoy.joblib").strpath
    payload = np.arange(10, dtype=np.float64)
    _write_array(genuine, payload)
    _write_array(decoy, np.arange(100, 110, dtype=np.float64))
    approved = ApprovedArtifacts.from_paths([genuine])

    if os.name == "nt":
        pytest.skip("/dev/fd is not available on this platform")

    # Hold the verified descriptor open, then replace the path out from under
    # the loader: the mapped bytes must remain the approved ones.
    with approved.verified_open(genuine) as (fobj, identity):
        os.replace(decoy, genuine)
        with numpy_pickle._validate_fileobject_and_memmap(
            fobj, identity.path, "r"
        ) as (validated_fobj, validated_mmap_mode):
            result = numpy_pickle._unpickle(
                validated_fobj,
                ensure_native_byte_order=False,
                filename=identity.fd_path,
                mmap_mode=validated_mmap_mode,
            )
    np.testing.assert_array_equal(np.asarray(result), payload)


@with_numpy
def test_strict_load_compressed_ignores_mmap_mode(tmpdir):
    filename = tmpdir.join("compressed.joblib.gz").strpath
    payload = np.arange(6)
    numpy_pickle.dump(payload, filename, compress=("gzip", 3))

    with pytest.warns(UserWarning):
        result = strict_load(
            filename,
            ApprovedArtifacts.from_paths([filename]),
            mmap_mode="r",
        )
    np.testing.assert_array_equal(result, payload)


@with_numpy
def test_compute_file_detects_tampering(tmpdir):
    filename = tmpdir.join("model.joblib").strpath
    _write_array(filename, np.arange(4))
    approved_digest = compute_file_digest(filename)

    approved = ApprovedArtifacts(
        [{"path": filename, "digest": approved_digest}]
    )
    np.testing.assert_array_equal(
        strict_load(filename, approved), np.arange(4)
    )

    # Append bytes: same path, different content must be caught.
    with open(filename, "ab") as fobj:
        fobj.write(b"tampered")
    with pytest.raises(ArtifactIntegrityError):
        strict_load(filename, approved)


@with_numpy
def test_memory_cache_uses_strict_load_when_approved(tmpdir):
    location = tmpdir.join("cache").strpath
    payload = np.arange(7)

    memory = joblib.Memory(location=location)

    @memory.cache
    def compute(value):
        return payload + value

    # Populate the cache and derive the exact cached artifact path.
    compute(0)
    assert compute.check_call_in_cache(0)
    call_id = [compute.func_id, compute._get_args_id(0)]
    cached_path = os.path.join(
        memory.store_backend.location,
        *memory.store_backend._split_id(call_id),
        "output.pkl",
    )
    assert os.path.exists(cached_path)

    # With the cached artifact approved, a cache hit loads through strict_load.
    strict_memory = joblib.Memory(
        location=location,
        approved_artifacts=ApprovedArtifacts.from_paths([cached_path]),
    )
    strict_func = strict_memory.cache(compute)
    assert strict_func.check_call_in_cache(0)
    np.testing.assert_array_equal(strict_func(0), payload)

    # The store backend itself refuses a tampered cache entry before
    # unpickling. (The decorated call would otherwise recompute on any load
    # error, which is joblib's standard cache fallback.)
    with open(cached_path, "ab") as fobj:
        fobj.write(b"tampered")
    with pytest.raises(ArtifactIntegrityError):
        strict_memory.store_backend.load_item(call_id)


@with_numpy
def test_memory_without_allowlist_keeps_ordinary_loading(tmpdir):
    location = tmpdir.join("cache").strpath
    memory = joblib.Memory(location=location)

    @memory.cache
    def compute(value):
        return np.arange(value)

    np.testing.assert_array_equal(compute(4), np.arange(4))
    np.testing.assert_array_equal(compute(4), np.arange(4))
    assert memory.store_backend.approved_artifacts is None


def test_store_backend_pickles_allowlist(tmpdir):
    from joblib._store_backends import FileSystemStoreBackend

    filename = tmpdir.join("model.joblib").strpath
    _write_array(filename, np.arange(2))
    approved = ApprovedArtifacts.from_paths([filename])

    backend = FileSystemStoreBackend()
    backend.configure(
        tmpdir.join("store").strpath,
        verbose=0,
        backend_options=dict(approved_artifacts=approved),
    )
    restored = pickle.loads(pickle.dumps(backend))
    assert restored.approved_artifacts.digest_of(filename) == approved.digest_of(
        filename
    )
