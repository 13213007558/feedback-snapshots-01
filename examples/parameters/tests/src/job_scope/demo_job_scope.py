"""End-to-end demonstration of job-scoped parameter access.

Run from examples/parameters/tests:

    python -m src.job_scope.demo_job_scope

Two team jobs share this execution environment. Each gets its own
``JobScopedProvider`` bound to its registered paths. The script prints what each
job observes and asserts the two security invariants:

* a rejected read never reaches the underlying SDK client;
* results only ever contain keys inside the job's allow-list, even when the
  service leaks extra entries in a paginated batch response.
"""

from __future__ import annotations

from pprint import pformat
from typing import Any

from aws_lambda_powertools import Logger

from .fake_backends import FakeSecretsClient, FakeSecretsProvider, FakeSSMClient, FakeSSMProvider
from .job_scoped_provider import JobScopedProvider
from .policy import JobAccessDeniedError, JobAccessPolicy

logger = Logger(service="job-scoped-parameters", use_rfc3339=True)

# ---------------------------------------------------------------------------
# Upstream stores. Both backends hold data for both teams plus an admin scope;
# page_size=2 forces every batch read to span several pages.
# ---------------------------------------------------------------------------
SSM_STORE = {
    "/team-a/billing/api_key": "ta-billing-key",
    "/team-a/billing/endpoint": "https://billing.example.org",
    "/team-a/reports/cron": "0 6 * * *",
    "/team-b/search/endpoint": "https://search.example.org",
    "/team-b/search/api_key": "tb-search-key",
    "/team-admin/break-glass": "admin-only",
}

SECRET_STORE = {
    "/team-a/billing/db_password": "ta-db-password",
    "/team-a/billing/signing_key": "ta-signing-key",
    "/team-a/reports/webhook": "ta-webhook",
    "/team-b/search/db_password": "tb-db-password",
    "/team-admin/break-glass-secret": "admin-only-secret",
}


def _section(title: str) -> None:
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


def _sdk_operations(client: FakeSSMClient | FakeSecretsClient) -> list[str]:
    return [call["operation"] for call in client.calls]


def _build_providers(
    jobs: dict[str, JobAccessPolicy],
    job_id: str,
    ssm_client: FakeSSMClient,
    secrets_client: FakeSecretsClient,
) -> tuple[JobScopedProvider, JobScopedProvider]:
    ssm = JobScopedProvider(FakeSSMProvider(ssm_client), jobs[job_id])
    secrets = JobScopedProvider(FakeSecretsProvider(secrets_client), jobs[job_id])
    return ssm, secrets


def scenario_legal_reads(job_a_ssm: JobScopedProvider, ssm_client: FakeSSMClient) -> dict[str, Any]:
    _section("1. Legal reads: single parameter and paginated batch (job A / SSM)")
    single = job_a_ssm.get("/team-a/billing/api_key")
    batch = job_a_ssm.get_multiple("/team-a", recursive=True)
    print("single  :", single)
    print("batch   :", pformat(batch))
    print("SDK saw :", _sdk_operations(ssm_client))
    assert single == "ta-billing-key"
    assert set(batch) == {"billing/api_key", "billing/endpoint", "reports/cron"}
    return batch


def scenario_denied_reads(job_a_ssm: JobScopedProvider, ssm_client: FakeSSMClient, jobs: dict[str, JobAccessPolicy]):
    _section("2. Out-of-bounds requests (job A denied; no SDK call is made)")
    before = len(ssm_client.calls)
    for forbidden in ("/team-admin/break-glass", "/team-b/search/api_key"):
        try:
            job_a_ssm.get(forbidden)
        except JobAccessDeniedError as error:
            print(f"DENIED get({forbidden!r}) -> {error}")
    try:
        job_a_ssm.get_multiple("/team-admin")
    except JobAccessDeniedError as error:
        print(f"DENIED get_multiple('/team-admin') -> {error}")
    assert len(ssm_client.calls) == before, "a denied request was sent to the SDK"
    print(f"SDK call count unchanged ({before}); denied attempts: {jobs['job-a'].denied_attempts}")


def scenario_ssm_leaked_entry(glitchy_ssm: JobScopedProvider, glitchy_ssm_client: FakeSSMClient):
    _section("3. Over-permissive service: extra SSM entry on a paginated response")
    values = glitchy_ssm.get_multiple("/team-a", recursive=True)
    print("returned keys:", sorted(values))
    raw_names = [
        parameter["Name"]
        for page in glitchy_ssm_client.get_paginator("get_parameters_by_path").paginate(
            Path="/team-a",
            Recursive=True,
        )
        for parameter in page["Parameters"]
    ]
    print("service actually returned:", raw_names)
    assert "/team-admin/break-glass" in raw_names, "fixture check: the glitch must include an admin key"
    assert all(not key.startswith("/team-admin") for key in values)
    assert set(values) == {"billing/api_key", "billing/endpoint", "reports/cron"}


def scenario_secret_leaked_name(job_a_secrets: JobScopedProvider, glitchy_secrets_client: FakeSecretsClient):
    _section("4. Over-permissive service: leaked secret name is never fetched")
    secret_values = job_a_secrets.get_multiple("/team-a")
    print("returned secrets:", sorted(secret_values))
    batch_requests = [
        call["SecretIdList"] for call in glitchy_secrets_client.calls if call["operation"] == "batch_get_secret_value"
    ]
    print("batch_get_secret_value SecretIdLists:", batch_requests)
    assert all("/team-admin/" not in name for request in batch_requests for name in request)
    assert set(secret_values) == {
        "/team-a/billing/db_password",
        "/team-a/billing/signing_key",
        "/team-a/reports/webhook",
    }


def scenario_job_isolation(
    jobs: dict[str, JobAccessPolicy],
    ssm_client: FakeSSMClient,
    secrets_client: FakeSecretsClient,
    job_a_ssm: JobScopedProvider,
    job_a_batch: dict[str, Any],
):
    _section("5. Shared execution environment: job B only sees team B, caches are separate")
    job_b_ssm, job_b_secrets = _build_providers(jobs, "job-b", ssm_client, secrets_client)

    team_b = job_b_ssm.get_multiple("/team-b", recursive=True)
    team_b_secret = job_b_secrets.get("/team-b/search/db_password")
    print("job B SSM batch:", team_b)
    print("job B secret  :", team_b_secret)
    assert set(team_b) == {"search/api_key", "search/endpoint"}
    assert team_b_secret == "tb-db-password"
    try:
        job_b_secrets.get("/team-a/billing/db_password")
    except JobAccessDeniedError as error:
        print(f"DENIED job B secret read -> {error}")

    # Re-reading job A's batch hits the same provider cache built in scenario 1,
    # while job B owns a separate store: cached keys can therefore never overlap.
    sdk_calls_before_reread = len(ssm_client.calls)
    assert job_a_ssm.get_multiple("/team-a", recursive=True) == job_a_batch
    assert len(ssm_client.calls) == sdk_calls_before_reread, "the re-read must be served from cache"
    job_a_cache_keys = {cache_key[0] for cache_key in job_a_ssm.store}
    job_b_cache_keys = {cache_key[0] for cache_key in job_b_ssm.store}
    assert job_a_cache_keys and job_b_cache_keys
    assert not (job_a_cache_keys & job_b_cache_keys), "jobs must not share a parameter cache"
    print("job A cache keys:", sorted(job_a_cache_keys))
    print("job B cache keys:", sorted(job_b_cache_keys))


def main() -> None:
    ssm_client = FakeSSMClient(SSM_STORE, page_size=2)
    secrets_client = FakeSecretsClient(SECRET_STORE, page_size=2)
    glitchy_ssm_client = FakeSSMClient(SSM_STORE, page_size=2, inject_extra_entries=True)
    glitchy_secrets_client = FakeSecretsClient(SECRET_STORE, page_size=2, inject_extra_entries=True)

    jobs = {
        "job-a": JobAccessPolicy.from_paths("job-a", ["/team-a"]),
        "job-b": JobAccessPolicy.from_paths("job-b", ["/team-b"]),
    }
    job_a_ssm, _ = _build_providers(jobs, "job-a", ssm_client, secrets_client)
    glitchy_ssm, glitchy_secrets = _build_providers(
        jobs,
        "job-a",
        glitchy_ssm_client,
        glitchy_secrets_client,
    )

    job_a_batch = scenario_legal_reads(job_a_ssm, ssm_client)
    scenario_denied_reads(job_a_ssm, ssm_client, jobs)
    scenario_ssm_leaked_entry(glitchy_ssm, glitchy_ssm_client)
    scenario_secret_leaked_name(glitchy_secrets, glitchy_secrets_client)
    scenario_job_isolation(jobs, ssm_client, secrets_client, job_a_ssm, job_a_batch)

    _section("All invariants held")
    print("- denied reads raise JobAccessDeniedError before any SDK call")
    print("- batch results contain only keys inside the job's registered paths")
    print("- leaked entries are dropped (SSM after the fact, Secrets before fetching values)")
    print("- jobs sharing the execution environment have independent providers and caches")
    logger.info("job-scoped parameter demo completed")


if __name__ == "__main__":
    main()
