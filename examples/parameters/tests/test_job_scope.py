"""Security tests for the job-scoped parameter provider.

These tests drive only the public Powertools surface (``get`` / ``get_multiple``)
and the SDK call audit trail exposed by the in-memory fake clients.
"""

import pytest
from src.job_scope.demo_job_scope import SECRET_STORE, SSM_STORE
from src.job_scope.fake_backends import (
    FakeSecretsClient,
    FakeSecretsProvider,
    FakeSSMClient,
    FakeSSMProvider,
)
from src.job_scope.job_scoped_provider import JobScopedProvider
from src.job_scope.policy import JobAccessDeniedError, JobAccessPolicy


@pytest.fixture
def job_a_ssm() -> JobScopedProvider:
    client = FakeSSMClient(SSM_STORE, page_size=2)
    policy = JobAccessPolicy.from_paths("job-a", ["/team-a"])
    return JobScopedProvider(FakeSSMProvider(client), policy)


@pytest.fixture
def job_a_glitchy_ssm() -> tuple[JobScopedProvider, FakeSSMClient]:
    client = FakeSSMClient(SSM_STORE, page_size=2, inject_extra_entries=True)
    policy = JobAccessPolicy.from_paths("job-a", ["/team-a"])
    return JobScopedProvider(FakeSSMProvider(client), policy), client


@pytest.fixture
def job_a_glitchy_secrets() -> tuple[JobScopedProvider, FakeSecretsClient]:
    client = FakeSecretsClient(SECRET_STORE, page_size=2, inject_extra_entries=True)
    policy = JobAccessPolicy.from_paths("job-a", ["/team-a"])
    return JobScopedProvider(FakeSecretsProvider(client), policy), client


def test_legal_single_and_paginated_batch_read(job_a_ssm: JobScopedProvider):
    assert job_a_ssm.get("/team-a/billing/api_key") == "ta-billing-key"

    values = job_a_ssm.get_multiple("/team-a", recursive=True)

    assert set(values) == {"billing/api_key", "billing/endpoint", "reports/cron"}
    sdk_operations = [call["operation"] for call in job_a_ssm._inner.client.calls]
    assert sdk_operations == ["get_parameter", "get_parameters_by_path"]


def test_repeated_read_is_served_from_the_job_cache(job_a_ssm: JobScopedProvider):
    client = job_a_ssm._inner.client

    assert job_a_ssm.get("/team-a/billing/api_key") == "ta-billing-key"
    assert job_a_ssm.get("/team-a/billing/api_key") == "ta-billing-key"

    get_calls = [call for call in client.calls if call["operation"] == "get_parameter"]
    assert len(get_calls) == 1
    assert any(cache_key[0] == "/team-a/billing/api_key" for cache_key in job_a_ssm.store)
    assert not job_a_ssm._inner.store, "the inner provider must not hold job data in its own cache"


def test_out_of_bounds_single_read_never_reaches_sdk(job_a_ssm: JobScopedProvider):
    client = job_a_ssm._inner.client
    calls_before = len(client.calls)

    with pytest.raises(JobAccessDeniedError):
        job_a_ssm.get("/team-admin/break-glass")
    with pytest.raises(JobAccessDeniedError):
        job_a_ssm.get("/team-b/search/api_key")

    assert len(client.calls) == calls_before
    assert job_a_ssm._policy.denied_attempts == [
        "/team-admin/break-glass",
        "/team-b/search/api_key",
    ]


def test_out_of_bounds_batch_request_never_reaches_sdk(job_a_ssm: JobScopedProvider):
    client = job_a_ssm._inner.client
    calls_before = len(client.calls)

    with pytest.raises(JobAccessDeniedError):
        job_a_ssm.get_multiple("/team-admin")

    assert len(client.calls) == calls_before


def test_sibling_path_is_not_allowed_by_prefix_match():
    policy = JobAccessPolicy.from_paths("job-a", ["/team-a"])
    assert not policy.allows("/team-admin/break-glass")
    assert policy.allows("/team-a/billing/api_key")


def test_extra_ssm_entries_are_filtered_from_results(job_a_glitchy_ssm):
    provider, client = job_a_glitchy_ssm

    values = provider.get_multiple("/team-a", recursive=True)

    raw_names = [
        parameter["Name"]
        for page in client.get_paginator("get_parameters_by_path").paginate(Path="/team-a", Recursive=True)
        for parameter in page["Parameters"]
    ]
    assert "/team-admin/break-glass" in raw_names
    assert set(values) == {"billing/api_key", "billing/endpoint", "reports/cron"}
    assert all(not key.startswith("/team-admin") for key in values)


def test_leaked_secret_name_is_never_requested_from_sdk(job_a_glitchy_secrets):
    provider, client = job_a_glitchy_secrets

    values = provider.get_multiple("/team-a")

    assert set(values) == {
        "/team-a/billing/db_password",
        "/team-a/billing/signing_key",
        "/team-a/reports/webhook",
    }
    fetched_names = [
        name for call in client.calls if call["operation"] == "batch_get_secret_value" for name in call["SecretIdList"]
    ]
    assert fetched_names and all("/team-admin/" not in name for name in fetched_names)


def test_secrets_pagination_returns_every_page():
    client = FakeSecretsClient(SECRET_STORE, page_size=2)
    provider = FakeSecretsProvider(client)

    names = provider.list_names("/team-a")

    assert names == [
        "/team-a/billing/db_password",
        "/team-a/billing/signing_key",
        "/team-a/reports/webhook",
    ]
    list_calls = [call for call in client.calls if call["operation"] == "list_secrets"]
    assert len(list_calls) == 2


def test_jobs_sharing_an_environment_have_independent_caches():
    ssm_client = FakeSSMClient(SSM_STORE, page_size=2)
    job_a = JobScopedProvider(FakeSSMProvider(ssm_client), JobAccessPolicy.from_paths("job-a", ["/team-a"]))
    job_b = JobScopedProvider(FakeSSMProvider(ssm_client), JobAccessPolicy.from_paths("job-b", ["/team-b"]))

    job_a.get_multiple("/team-a", recursive=True)
    job_b.get_multiple("/team-b", recursive=True)

    assert {key[0] for key in job_a.store} == {"/team-a"}
    assert {key[0] for key in job_b.store} == {"/team-b"}
    with pytest.raises(JobAccessDeniedError):
        job_b.get("/team-a/billing/api_key")
