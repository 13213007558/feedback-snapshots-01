from datetime import datetime, timedelta, timezone
from unittest import mock

import anyio
import pytest

from aiobotocore import credentials, utils
from aiobotocore.httpxsession import is_httpx_session_cls


FUTURE_EXPIRY = '2030-01-01T00:00:00Z'
PAST_EXPIRY = '2000-01-01T00:00:00Z'


def _refreshable_cls(http_session_cls):
    return (
        credentials.AnyioRefreshableCredentials
        if is_httpx_session_cls(http_session_cls)
        else credentials.AioRefreshableCredentials
    )


def _expired_credentials(credential_cls, refresh_using):
    # Expiry in the past puts every caller straight into the mandatory window.
    return credential_cls.create_from_metadata(
        metadata={
            'access_key': 'old-access',
            'secret_key': 'old-secret',
            'token': 'old-token',
            'expiry_time': PAST_EXPIRY,
        },
        refresh_using=refresh_using,
        method='test',
    )


async def test_refreshable_credentials_serialize_refreshes(http_session_cls):
    credential_cls = (
        credentials.AnyioRefreshableCredentials
        if is_httpx_session_cls(http_session_cls)
        else credentials.AioRefreshableCredentials
    )
    refresh_calls = 0

    async def refresh():
        nonlocal refresh_calls
        refresh_calls += 1
        await anyio.sleep(0)
        return {
            'access_key': 'refreshed-access',
            'secret_key': 'refreshed-secret',
            'token': 'refreshed-token',
            'expiry_time': '2030-01-01T00:00:00Z',
        }

    creds = credential_cls.create_from_metadata(
        metadata={
            'access_key': 'expired-access',
            'secret_key': 'expired-secret',
            'token': 'expired-token',
            'expiry_time': '2000-01-01T00:00:00Z',
        },
        refresh_using=refresh,
        method='test',
    )
    results = []

    async def get_credentials():
        results.append(await creds.get_frozen_credentials())

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(get_credentials)
        task_group.start_soon(get_credentials)

    assert refresh_calls == 1
    assert [result.access_key for result in results] == [
        'refreshed-access',
        'refreshed-access',
    ]


async def test_assumerolecredprovider_concurrent_load_no_race_condition():
    """Regression test for https://github.com/aio-libs/aiobotocore/issues/1455.

    When multiple async tasks share the same AioAssumeRoleProvider and call
    load() concurrently, _visited_profiles must not leak between tasks.
    Without the fix, a second task entering load() while the first task is
    awaiting inside _resolve_credentials_from_profile would see the first
    task's _visited_profiles entries and raise InfiniteLoopConfigError.
    """
    fake_config = {
        'profiles': {
            'a': {
                'role_arn': 'arn:aws:iam::123456789012:role/RoleA',
                'source_profile': 'b',
            },
            'b': {
                'aws_access_key_id': 'akid',
                'aws_secret_access_key': 'skid',
            },
        }
    }

    # A mock provider whose load() yields control, allowing another task to
    # interleave and expose the race condition.
    static_creds = credentials.AioCredentials('akid', 'skid')

    class _YieldingProvider:
        METHOD = 'mock-static'
        CANONICAL_NAME = None

        async def load(self):
            await anyio.sleep(0)
            return static_creds

    mock_builder = mock.Mock()
    mock_builder.providers.return_value = [_YieldingProvider()]

    # client_creator is never invoked: load() returns AioDeferredRefreshableCredentials
    # without calling STS, so a bare Mock() is sufficient.
    provider = credentials.AioAssumeRoleProvider(
        lambda: fake_config,
        mock.Mock(),
        cache={},
        profile_name='a',
        profile_provider_builder=mock_builder,
    )

    # Both tasks must succeed; without the fix the second task raises
    # InfiniteLoopConfigError because it sees 'b' already in _visited_profiles.
    results = [None, None]

    async def load_into(index):
        results[index] = await provider.load()

    async with anyio.create_task_group() as tg:
        tg.start_soon(load_into, 0)
        tg.start_soon(load_into, 1)

    assert all(r is not None for r in results)


@pytest.fixture
def container_fetcher_cls(current_http_backend):
    # aiohttp sleeps via asyncio, httpx (which also runs on trio) via anyio.
    if current_http_backend == 'httpx':
        return utils.AnyioContainerMetadataFetcher
    return utils.AioContainerMetadataFetcher


async def test_container_provider_keeps_a_caller_supplied_fetcher(
    container_fetcher_cls,
):
    # botocore's blocking default is swapped for an async one, but a fetcher
    # the caller passed in (with its own session or timeout) is left alone.
    fetcher = container_fetcher_cls()
    provider = credentials.AnyioContainerProvider(fetcher=fetcher)
    assert provider._fetcher is fetcher

    assert isinstance(
        credentials.AioContainerProvider()._fetcher,
        utils.AioContainerMetadataFetcher,
    )


def test_anyio_container_provider_uses_httpx_fetcher_by_default():
    # The anyio provider's default fetcher is the httpx-backed
    # AnyioContainerMetadataFetcher, whose construction requires httpx.
    pytest.importorskip("httpx")
    assert isinstance(
        credentials.AnyioContainerProvider()._fetcher,
        utils.AnyioContainerMetadataFetcher,
    )


async def test_cancelled_caller_does_not_abort_refresh_for_survivor(
    http_session_cls,
):
    """The refresh is owned by the credentials object, not by one caller.

    Two API calls block on the same mandatory refresh. When the upstream of the
    call that started the refresh cancels it, that call raises
    CancelledError, but the detached refresh keeps running and the surviving
    call still receives the freshly refreshed material. Only a single refresh
    attempt may run.
    """
    credential_cls = _refreshable_cls(http_session_cls)
    refresh_started = anyio.Event()
    resume_refresh = anyio.Event()
    refresh_calls = 0

    async def refresh():
        nonlocal refresh_calls
        refresh_calls += 1
        refresh_started.set()
        await resume_refresh.wait()
        return {
            'access_key': 'new-access',
            'secret_key': 'new-secret',
            'token': 'new-token',
            'expiry_time': FUTURE_EXPIRY,
        }

    creds = _expired_credentials(credential_cls, refresh)
    outcomes = {}

    async def fetch(name):
        try:
            frozen = await creds.get_frozen_credentials()
            outcomes[name] = ('ok', frozen.access_key)
        except anyio.get_cancelled_exc_class():
            outcomes[name] = ('cancelled', None)
            raise

    async with anyio.create_task_group() as task_group:
        owner = task_group.start_soon(fetch, 'owner')
        await refresh_started.wait()
        survivor = task_group.start_soon(fetch, 'survivor')
        # Let the survivor settle into waiting on the in-flight refresh.
        await anyio.sleep(0.05)
        assert creds._refresh_in_flight is True

        # Upstream cancellation of the call that owns the refresh.
        owner.cancel()
        await anyio.sleep(0.05)
        assert creds._refresh_in_flight is True

        resume_refresh.set()
        # Keep a reference so the survivor task is not garbage collected early.
        assert survivor is not None

    assert outcomes == {
        'owner': ('cancelled', None),
        'survivor': ('ok', 'new-access'),
    }
    assert refresh_calls == 1
    final = await creds.get_frozen_credentials()
    assert final.access_key == 'new-access'
    await creds.aclose()


async def test_three_coroutines_one_cancelled_two_serve_with_new_material(
    http_session_cls,
):
    """Three API calls coordinate on one refresh with a controlled order.

    Coroutine A starts the (mandatory) refresh; B and C join it while it is in
    flight. After B and C are both waiting, A's upstream cancels A. The single
    detached refresh still completes, and both surviving callers B and C sign
    with the same independently obtained, fully valid material. No signature
    uses the expired generation, and only one refresh runs.
    """
    credential_cls = _refreshable_cls(http_session_cls)
    refresh_started = anyio.Event()
    resume_refresh = anyio.Event()
    refresh_calls = 0

    async def refresh():
        nonlocal refresh_calls
        refresh_calls += 1
        refresh_started.set()
        await resume_refresh.wait()
        return {
            'access_key': 'new-access',
            'secret_key': 'new-secret',
            'token': 'new-token',
            'expiry_time': FUTURE_EXPIRY,
        }

    creds = _expired_credentials(credential_cls, refresh)
    outcomes = {}

    async def fetch(name):
        try:
            frozen = await creds.get_frozen_credentials()
            outcomes[name] = frozen.access_key
        except anyio.get_cancelled_exc_class():
            outcomes[name] = 'cancelled'
            raise

    async with anyio.create_task_group() as task_group:
        # 1. A starts the refresh and parks inside the refresher.
        owner = task_group.start_soon(fetch, 'A')
        await refresh_started.wait()

        # 2. B and C start while the refresh is in flight; both join it.
        survivor_b = task_group.start_soon(fetch, 'B')
        survivor_c = task_group.start_soon(fetch, 'C')
        await anyio.sleep(0.05)
        assert creds._refresh_in_flight is True

        # 3. A's upstream cancels A; the object-owned refresh is unaffected.
        owner.cancel()
        await anyio.sleep(0.05)
        assert creds._refresh_in_flight is True

        resume_refresh.set()
        assert survivor_b is not None and survivor_c is not None

    assert outcomes == {
        'A': 'cancelled',
        'B': 'new-access',
        'C': 'new-access',
    }
    assert refresh_calls == 1
    # The expired generation never reappears after the valid refresh lands.
    assert (await creds.get_frozen_credentials()).access_key == 'new-access'
    await creds.aclose()


async def test_transient_refresh_failure_propagates_then_retry_succeeds(
    http_session_cls,
):
    """A transient failure during a mandatory refresh is raised to the caller,
    leaves the accepted snapshot untouched, and a later retry succeeds with a
    fresh, fully valid set of material."""
    credential_cls = _refreshable_cls(http_session_cls)
    refresh_calls = 0

    async def refresh():
        nonlocal refresh_calls
        refresh_calls += 1
        if refresh_calls == 1:
            raise ConnectionError("temporary network problem")
        return {
            'access_key': 'new-access',
            'secret_key': 'new-secret',
            'token': 'new-token',
            'expiry_time': FUTURE_EXPIRY,
        }

    creds = _expired_credentials(credential_cls, refresh)

    with pytest.raises(ConnectionError, match='temporary network problem'):
        await creds.get_frozen_credentials()

    # The failed attempt must not have replaced the previously accepted
    # snapshot, and no attempt is left running afterwards.
    assert creds._frozen_credentials.access_key == 'old-access'
    assert creds._refresh_in_flight is False

    frozen = await creds.get_frozen_credentials()
    assert frozen.access_key == 'new-access'
    assert refresh_calls == 2
    await creds.aclose()


async def test_refresh_returning_expired_material_is_never_published(
    http_session_cls,
):
    """Material that is itself expired is rejected before it is published, so a
    later signature can never observe credentials already known to be invalid.
    The previously accepted snapshot remains the one in force."""
    credential_cls = _refreshable_cls(http_session_cls)

    async def refresh():
        return {
            'access_key': 'stale-access',
            'secret_key': 'stale-secret',
            'token': 'stale-token',
            'expiry_time': PAST_EXPIRY,
        }

    creds = _expired_credentials(credential_cls, refresh)

    with pytest.raises(RuntimeError, match='still expired'):
        await creds.get_frozen_credentials()

    assert creds._frozen_credentials.access_key == 'old-access'
    assert creds._expiry_time == credentials.parse(PAST_EXPIRY)
    assert creds._staged_expiry_time is None
    assert creds._refresh_in_flight is False
    await creds.aclose()


async def test_advisory_refresh_failure_keeps_current_credentials(
    http_session_cls,
):
    """Outside the mandatory window, a failed advisory refresh is swallowed and
    the caller keeps using its current, still-valid credentials."""
    credential_cls = _refreshable_cls(http_session_cls)
    expiry = datetime.now(timezone.utc) + timedelta(minutes=12)

    async def refresh():
        raise ConnectionError("advisory blip")

    creds = credential_cls(
        'current-access',
        'current-secret',
        'current-token',
        expiry,
        refresh,
        'test',
    )
    assert creds.refresh_needed(creds._advisory_refresh_timeout)
    assert not creds.refresh_needed(creds._mandatory_refresh_timeout)

    frozen = await creds.get_frozen_credentials()
    assert frozen.access_key == 'current-access'
    assert creds._refresh_in_flight is False
    await creds.aclose()
