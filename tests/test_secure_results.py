import asyncio
import json
import pickle
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from taskiq import (
    InMemoryBroker,
    SecureResultBackend,
    SimpleRetryMiddleware,
    TaskiqResult,
)
from taskiq.brokers.inmemory_broker import InmemoryResultBackend
from taskiq.exceptions import NoResultError, SecurityError

SECRET = "customer-secret-7558"  # noqa: S105
ADMIN_TOKEN = "unit-test-admin-token"  # noqa: S105
WRONG_TOKEN = "unit-test-wrong-token"  # noqa: S105


class JsonDiskDouble:
    """Serialize records like a disk-backed sink and retain raw JSON files."""

    def __init__(self) -> None:
        self.files: dict[str, str] = {}
        self.writes: list[tuple[str, str, str, float | None]] = []
        self.deletes: list[tuple[str, str]] = []

    def _path(self, collection: str, key: str) -> str:
        return f"{collection}/{key}.json"

    async def write_record(
        self,
        collection: str,
        key: str,
        record: dict[str, Any],
        ttl_seconds: float | None = None,
    ) -> None:
        raw = json.dumps(record, sort_keys=True)
        self.files[self._path(collection, key)] = raw
        self.writes.append((collection, key, raw, ttl_seconds))

    async def read_record(
        self,
        collection: str,
        key: str,
    ) -> dict[str, Any] | None:
        raw = self.files.get(self._path(collection, key))
        return json.loads(raw) if raw is not None else None

    async def delete_record(self, collection: str, key: str) -> None:
        self.files.pop(self._path(collection, key), None)
        self.deletes.append((collection, key))


def make_result(
    *,
    error: BaseException | None = None,
    return_value: Any = None,
    attempt: int = 0,
) -> TaskiqResult[Any]:
    return TaskiqResult(
        is_err=error is not None,
        return_value=return_value,
        execution_time=0.03,
        error=error,
        labels={"_retries": attempt},
    )


async def test_hidden_original_error_is_not_publicly_serialized() -> None:
    result = make_result(error=NoResultError())
    result.failure_category = "validation"
    result.set_original_error(ValueError(SECRET))

    assert SECRET not in result.model_dump_json()
    assert SECRET.encode() not in pickle.dumps(result)
    assert result.get_original_error() is not None


async def test_public_status_redacts_persisted_and_normal_views() -> None:
    disk = JsonDiskDouble()
    backend = SecureResultBackend(disk, admin_token=ADMIN_TOKEN)
    task_id = "redaction-check"
    failed = make_result(error=ValueError(f"account dump: {SECRET}"))

    await backend.set_result(task_id, failed)

    public = await backend.get_public_status(task_id)
    normal = await backend.get_result(task_id)
    public_raw = disk.files[f"public_statuses/{task_id}.json"]

    assert public.status == "failure"
    assert public.failure_category == "validation"
    assert SECRET not in public_raw
    assert "ValueError" not in public_raw
    assert normal.return_value is None
    assert normal.failure_category == "validation"
    assert str(normal.error) == "Task failed with category 'validation'."
    assert SECRET not in repr(normal)

    with pytest.raises(SecurityError):
        await backend.get_admin_result(task_id)
    with pytest.raises(SecurityError):
        await backend.get_admin_result(task_id, admin_token=WRONG_TOKEN)

    admin = await backend.get_admin_result(task_id, admin_token=ADMIN_TOKEN)
    assert isinstance(admin.error, ValueError)
    assert SECRET in str(admin.error)
    diagnostic_raw = disk.files[f"diagnostics/{task_id}.json"]
    assert SECRET in diagnostic_raw
    assert disk.writes[0][0] == "public_statuses"
    assert disk.writes[1][0] == "diagnostics"


async def test_classic_result_backend_double_receives_redacted_result() -> None:
    classic_backend = InmemoryResultBackend()
    backend = SecureResultBackend(classic_backend, admin_token=ADMIN_TOKEN)
    task_id = "classic-backend-double"

    await backend.set_result(
        task_id,
        make_result(error=ValueError(f"persisted {SECRET}")),
    )

    persisted = classic_backend.results[task_id]
    assert persisted.return_value is None
    assert persisted.failure_category == "validation"
    assert SECRET not in repr(persisted)
    assert SECRET not in str(persisted.model_dump())


async def test_success_can_purge_diagnostics_when_configured() -> None:
    disk = JsonDiskDouble()
    backend = SecureResultBackend(
        disk,
        admin_token=ADMIN_TOKEN,
        purge_diagnostics_on_success=True,
    )
    task_id = "retry-success"

    await backend.set_result(
        task_id,
        make_result(error=ValueError(f"private exception {SECRET}"), attempt=0),
    )
    await backend.set_result(
        task_id,
        make_result(return_value={"customer_note": SECRET}, attempt=1),
    )

    public = await backend.get_public_status(task_id)
    normal = await backend.get_result(task_id)
    public_raw = disk.files[f"public_statuses/{task_id}.json"]

    assert public.status == "success"
    assert public.failure_category is None
    assert normal.is_err is False
    assert normal.return_value is None
    assert SECRET not in public_raw
    assert f"diagnostics/{task_id}.json" not in disk.files
    assert ("diagnostics", task_id) in disk.deletes
    with pytest.raises(SecurityError):
        await backend.get_admin_result(task_id, admin_token=ADMIN_TOKEN)


async def test_successful_retry_keeps_failure_diagnostic_until_ttl() -> None:
    backend = SecureResultBackend(admin_token=ADMIN_TOKEN)
    task_id = "retry-keeps-diagnostic"

    await backend.set_result(
        task_id,
        make_result(error=ValueError(f"private exception {SECRET}"), attempt=0),
    )
    await backend.set_result(task_id, make_result(return_value="ok", attempt=1))

    status = await backend.get_public_status(task_id)
    assert status.status == "success"
    assert status.failure_category is None

    admin = await backend.get_admin_result(task_id, admin_token=ADMIN_TOKEN)
    assert isinstance(admin.error, ValueError)
    assert SECRET in str(admin.error)


async def test_stale_failed_attempt_cannot_override_newer_success() -> None:
    disk = JsonDiskDouble()
    backend = SecureResultBackend(disk, admin_token=ADMIN_TOKEN)
    task_id = "stale-attempt"

    await backend.set_result(task_id, make_result(return_value="ok", attempt=1))
    await backend.set_result(
        task_id,
        make_result(error=ValueError(f"late {SECRET}"), attempt=0),
    )

    status = await backend.get_public_status(task_id)
    assert status.status == "success"
    assert status.attempt == 1
    assert f"diagnostics/{task_id}.json" not in disk.files


async def test_diagnostic_records_expire() -> None:
    current_time = datetime(2026, 11, 25, tzinfo=timezone.utc)
    backend = SecureResultBackend(
        admin_token=ADMIN_TOKEN,
        diagnostic_ttl_seconds=10,
        clock=lambda: current_time,
    )
    task_id = "expiring"
    await backend.set_result(task_id, make_result(error=ValueError(SECRET)))

    admin = await backend.get_admin_result(task_id, admin_token=ADMIN_TOKEN)
    assert SECRET in str(admin.error)

    current_time += timedelta(seconds=11)
    with pytest.raises(SecurityError):
        await backend.get_admin_result(task_id, admin_token=ADMIN_TOKEN)


async def test_short_lived_grant_allows_admin_query() -> None:
    current_time = datetime(2026, 11, 25, tzinfo=timezone.utc)
    backend = SecureResultBackend(
        admin_token=ADMIN_TOKEN,
        diagnostic_ttl_seconds=30,
        clock=lambda: current_time,
    )
    task_id = "grant-check"
    await backend.set_result(task_id, make_result(error=ValueError(SECRET)))

    grant = await backend.create_diagnostic_grant(
        ADMIN_TOKEN,
        task_id=task_id,
        ttl_seconds=5,
    )
    admin = await backend.get_admin_result(
        task_id,
        diagnostic_token=grant.token,
    )
    assert SECRET in str(admin.error)

    current_time += timedelta(seconds=6)
    with pytest.raises(SecurityError):
        await backend.get_admin_result(task_id, diagnostic_token=grant.token)


async def test_inmemory_retry_separates_public_and_admin_views() -> None:
    disk = JsonDiskDouble()
    backend = SecureResultBackend(disk, admin_token=ADMIN_TOKEN)
    second_attempt_started = asyncio.Event()
    release_second_attempt = asyncio.Event()
    attempts = 0

    broker = InMemoryBroker().with_result_backend(backend)
    broker = broker.with_middlewares(
        SimpleRetryMiddleware(default_retry_count=2),
    )

    @broker.task("secure_retry_job", retry_on_error=True)
    async def secure_retry_job() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ValueError(f"customer data {SECRET}")
        second_attempt_started.set()
        await release_second_attempt.wait()
        return f"success {SECRET}"

    await broker.startup()
    task = await secure_retry_job.kiq()

    await asyncio.wait_for(second_attempt_started.wait(), timeout=1)
    for _ in range(100):
        status = await backend.get_public_status(task.task_id)
        if status.failure_category is not None:
            break
        await asyncio.sleep(0.01)
    else:  # pragma: no cover - defensive test timeout
        pytest.fail("Public failure category was not persisted")

    normal_during_retry = await task.get_result()
    admin_during_retry = await task.get_admin_result(admin_token=ADMIN_TOKEN)
    public_disk = disk.files[f"public_statuses/{task.task_id}.json"]

    assert attempts == 2
    assert status.status == "retrying"
    assert status.is_ready is False
    assert status.failure_category == "validation"
    assert SECRET not in public_disk
    assert normal_during_retry.return_value is None
    assert SECRET not in str(normal_during_retry.error)
    assert SECRET in str(admin_during_retry.error)

    release_second_attempt.set()
    final = await task.wait_result(check_interval=0.01, timeout=2)
    await broker.wait_all()

    final_status = await task.get_public_status()
    final_normal = await task.get_result()
    final_public_disk = disk.files[f"public_statuses/{task.task_id}.json"]

    assert final_status.status == "success"
    assert final_status.failure_category is None
    assert final.is_err is False
    assert final.return_value is None
    assert final_normal.return_value is None
    assert SECRET not in final_public_disk
    public_writes = [
        raw
        for collection, _, raw, _ in disk.writes
        if collection == "public_statuses"
    ]
    assert public_writes
    assert all(SECRET not in raw for raw in public_writes)
    admin_after_success = await task.get_admin_result(admin_token=ADMIN_TOKEN)
    assert isinstance(admin_after_success.error, ValueError)
    assert SECRET in str(admin_after_success.error)

    await broker.shutdown()
