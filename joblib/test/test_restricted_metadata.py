import json
import logging

from joblib import Memory


SECRET_MARKER = "restricted-metadata-secret"


def _metadata_path(cached_func, *args, **kwargs):
    args_id = cached_func._get_args_id(*args, **kwargs)
    call_id = (cached_func.func_id, args_id)
    item_info = cached_func.store_backend.get_item_info(call_id)
    return call_id, args_id, item_info["location"] + "/metadata.json"


def _read_metadata(path):
    with open(path, encoding="utf-8") as metadata_file:
        return json.load(metadata_file)


def test_restricted_metadata_legacy_hit_recompute_and_shelve(
    tmp_path, capsys, caplog
):
    calls = []

    def risk_score(task_id, token):
        calls.append(task_id)
        return {"task_id": task_id, "score": 87}

    cache_dir = tmp_path / "cache"

    legacy_memory = Memory(location=str(cache_dir), verbose=0)
    legacy_func = legacy_memory.cache(risk_score)
    for task_id in ("old-hit", "recompute", "lazy"):
        legacy_func(task_id, SECRET_MARKER)

    hit_call_id, hit_args_id, hit_metadata_file = _metadata_path(
        legacy_func, "old-hit", SECRET_MARKER
    )
    _, recompute_args_id, recompute_metadata_file = _metadata_path(
        legacy_func, "recompute", SECRET_MARKER
    )
    _, lazy_args_id, lazy_metadata_file = _metadata_path(
        legacy_func, "lazy", SECRET_MARKER
    )

    legacy_hit_metadata = _read_metadata(hit_metadata_file)
    assert SECRET_MARKER in legacy_hit_metadata["input_args"]["token"]
    assert _read_metadata(recompute_metadata_file)["input_args"]
    assert _read_metadata(lazy_metadata_file)["input_args"]

    caplog.set_level(logging.DEBUG, logger="joblib")
    restricted_memory = Memory(
        location=str(cache_dir),
        verbose=100,
        restricted_metadata=True,
    )

    validated_metadata = []
    hit_func = restricted_memory.cache(
        risk_score,
        cache_validation_callback=lambda metadata: (
            validated_metadata.append(metadata),
            True,
        )[1],
    )
    calls.clear()

    assert hit_func("old-hit", SECRET_MARKER) == {
        "task_id": "old-hit",
        "score": 87,
    }
    assert calls == []
    assert hit_func._get_args_id("old-hit", SECRET_MARKER) == hit_args_id

    assert len(validated_metadata) == 1
    safe_metadata = validated_metadata[0]
    assert "input_args" not in safe_metadata
    assert safe_metadata["args_id"] == hit_args_id
    assert safe_metadata["func_id"] == hit_call_id[0]
    assert isinstance(safe_metadata["duration"], float)
    assert isinstance(safe_metadata["time"], float)

    persisted_hit_metadata = _read_metadata(hit_metadata_file)
    assert "input_args" not in persisted_hit_metadata
    assert persisted_hit_metadata["args_id"] == hit_args_id

    recomputed_metadata = []

    def reject_legacy_metadata(metadata):
        recomputed_metadata.append(metadata)
        return False

    recompute_func = restricted_memory.cache(
        risk_score,
        cache_validation_callback=reject_legacy_metadata,
    )
    assert recompute_func("recompute", SECRET_MARKER) == {
        "task_id": "recompute",
        "score": 87,
    }
    assert calls == ["recompute"]
    assert recompute_func._get_args_id("recompute", SECRET_MARKER) == (
        recompute_args_id
    )
    assert recomputed_metadata[0]["args_id"] == recompute_args_id
    persisted_recompute_metadata = _read_metadata(recompute_metadata_file)
    assert "input_args" not in persisted_recompute_metadata
    assert persisted_recompute_metadata["args_id"] == recompute_args_id

    lazy_func = restricted_memory.cache(risk_score)
    shelved_result = lazy_func.call_and_shelve("lazy", SECRET_MARKER)
    assert shelved_result.args_id == lazy_args_id
    assert "input_args" not in shelved_result.metadata
    assert shelved_result.metadata["args_id"] == lazy_args_id
    assert shelved_result.get() == {"task_id": "lazy", "score": 87}

    persisted_lazy_metadata = _read_metadata(lazy_metadata_file)
    assert "input_args" not in persisted_lazy_metadata
    assert persisted_lazy_metadata["args_id"] == lazy_args_id

    captured = capsys.readouterr()
    displayed = "\n".join(
        [
            captured.out,
            captured.err,
            caplog.text,
            repr(safe_metadata),
            repr(recomputed_metadata[0]),
            repr(shelved_result.metadata),
        ]
    )
    assert SECRET_MARKER not in displayed
    assert hit_args_id in displayed
    assert lazy_args_id in displayed


def test_default_metadata_still_records_input_args(tmp_path):
    def add(a, b):
        return a + b

    memory = Memory(location=str(tmp_path / "cache"), verbose=0)
    cached = memory.cache(add)
    assert cached(2, 3) == 5

    _, args_id, metadata_file = _metadata_path(cached, 2, 3)
    metadata = _read_metadata(metadata_file)
    assert metadata["input_args"] == {"a": "2", "b": "3"}
    assert args_id == cached._get_args_id(2, 3)
