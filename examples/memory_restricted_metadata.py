"""Demonstrate privacy-preserving Joblib cache metadata.

Run from the repository root:

    python examples/memory_restricted_metadata.py

The example intentionally creates a legacy metadata.json containing
``input_args`` first. It then opens the same cache with
``restricted_metadata=True`` and compares an old cache hit, a forced
recomputation, and a shelved/lazy result.
"""

import contextlib
import io
import json
import tempfile
from pathlib import Path

from joblib import Memory


SECRET_TOKEN = "ops-token-DO-NOT-PERSIST-7558"


def hit_rate_task(task_id, token):
    """Example offline task. The token is an argument, not result data."""
    return {"task_id": task_id, "status": "processed", "score": 91}


def metadata_file_for(cached_func, *args, **kwargs):
    args_id = cached_func._get_args_id(*args, **kwargs)
    call_id = (cached_func.func_id, args_id)
    location = cached_func.store_backend.get_item_info(call_id)["location"]
    return args_id, Path(location) / "metadata.json"


def read_metadata(path):
    return json.loads(path.read_text(encoding="utf-8"))


def public_metadata(metadata):
    return {
        key: (round(value, 6) if key == "duration" else value)
        for key, value in metadata.items()
    }


def main():
    cache_dir = Path(tempfile.mkdtemp(prefix="joblib-restricted-metadata-"))

    # Write entries with the historical metadata format.
    legacy_memory = Memory(location=str(cache_dir), verbose=0)
    legacy_task = legacy_memory.cache(hit_rate_task)
    legacy_task("old-hit", SECRET_TOKEN)
    legacy_task("recompute", SECRET_TOKEN)
    legacy_task("lazy-value", SECRET_TOKEN)

    old_args_id, old_metadata_file = metadata_file_for(
        legacy_task, "old-hit", SECRET_TOKEN
    )
    recompute_args_id, recompute_metadata_file = metadata_file_for(
        legacy_task, "recompute", SECRET_TOKEN
    )
    lazy_args_id, lazy_metadata_file = metadata_file_for(
        legacy_task, "lazy-value", SECRET_TOKEN
    )

    legacy_metadata_before = read_metadata(old_metadata_file)
    legacy_disk_summary = {
        "fields": sorted(legacy_metadata_before),
        "input_args_fields": sorted(
            legacy_metadata_before.get("input_args", {})
        ),
        "contains_secret_marker": SECRET_TOKEN
        in old_metadata_file.read_text(encoding="utf-8"),
    }

    callback_metadata = []

    def validation_callback(metadata):
        callback_metadata.append(metadata)
        # Telemetry may use metadata["time"] / metadata["duration"] here.
        return True

    restricted_memory = Memory(
        location=str(cache_dir),
        verbose=10,
        restricted_metadata=True,
    )
    cached_task = restricted_memory.cache(
        hit_rate_task,
        cache_validation_callback=validation_callback,
    )

    displayed = io.StringIO()
    with contextlib.redirect_stdout(displayed):
        old_hit_result = cached_task("old-hit", SECRET_TOKEN)
        recomputed_result, recomputed_metadata = cached_task.call(
            "recompute", SECRET_TOKEN
        )
        shelved_result = cached_task.call_and_shelve(
            "lazy-value", SECRET_TOKEN
        )
        lazy_result = shelved_result.get()

    old_hit_disk = read_metadata(old_metadata_file)
    recompute_disk = read_metadata(recompute_metadata_file)
    lazy_disk = read_metadata(lazy_metadata_file)

    report = {
        "legacy_disk_before_upgrade": legacy_disk_summary,
        "old_hit": {
            "business_result": old_hit_result,
            "stable_args_id": old_args_id,
            "validation_callback_metadata": public_metadata(
                callback_metadata[0]
            ),
            "displayed_metadata": public_metadata(callback_metadata[0]),
            "disk_fields_after_hit": sorted(old_hit_disk),
            "disk_metadata_after_hit": public_metadata(old_hit_disk),
        },
        "recomputation": {
            "business_result": recomputed_result,
            "stable_args_id": recompute_args_id,
            "returned_metadata": public_metadata(recomputed_metadata),
            "disk_fields": sorted(recompute_disk),
            "disk_metadata": public_metadata(recompute_disk),
        },
        "lazy_value": {
            "business_result_after_get": lazy_result,
            "stable_args_id": lazy_args_id,
            "memorized_result_metadata": public_metadata(
                shelved_result.metadata
            ),
            "disk_fields": sorted(lazy_disk),
            "disk_metadata": public_metadata(lazy_disk),
        },
        "joblib_stdout_diagnostics": displayed.getvalue().strip().splitlines(),
    }

    restricted_text = json.dumps(report, ensure_ascii=False, default=str)
    assert SECRET_TOKEN not in restricted_text
    assert "input_args" not in callback_metadata[0]
    assert "input_args" not in recomputed_metadata
    assert "input_args" not in shelved_result.metadata
    assert old_hit_disk["args_id"] == old_args_id
    assert recompute_disk["args_id"] == recompute_args_id
    assert lazy_disk["args_id"] == lazy_args_id

    print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
    print("\nSelf-check passed: restricted output contains no token/input_args.")
    print(f"Cache directory (inspect manually): {cache_dir}")


if __name__ == "__main__":
    main()
