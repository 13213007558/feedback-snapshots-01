#!/usr/bin/env python3
"""End-to-end check for executable-sourced pluggable auth cache provenance.

Scenario:
  * Two approved enterprise identity provider configurations (A and B) run on
    the same host and share one output-file cache location.
  * Provider A leaves a legitimate cache first.
  * The active configuration then switches to provider B.

The script verifies both operational modes against the same cache:
  * Execution disabled (offline): only a cache with explicit, still-valid
    provenance matching the active configuration is admitted; otherwise the
    flow fails closed before any executable run or STS exchange.
  * Execution enabled (online): an unattributable / foreign / expired cache is
    rebuilt through provider B, and the STS backend exchange as well as the
    audit records only see provider B's admission identity.

Run from the repository root:
    .venv/bin/python scripts/pluggable_provenance_e2e.py
"""

import json
import logging
import os
import shutil
import sys
import tempfile
from contextlib import contextmanager

from google.auth import exceptions
from google.auth import pluggable

TOKEN_URL = "https://sts.googleapis.com/v1/token"
SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
POOL = (
    "//iam.googleapis.com/projects/123/locations/global/"
    "workloadIdentityPools/pool/providers/"
)

PROVIDER_A = {
    "name": "provider-a",
    "audience": POOL + "provider-a",
    "subject_token": "SUBJECT_TOKEN_FROM_PROVIDER_A",
    "command": None,  # filled in once the temp directory exists
}
PROVIDER_B = {
    "name": "provider-b",
    "audience": POOL + "provider-b",
    "subject_token": "SUBJECT_TOKEN_FROM_PROVIDER_B",
    "command": None,
}

EXECUTABLE_TEMPLATE = """#!/usr/bin/env python3
import json
import os
import sys
import time

output_file = os.environ["GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE"]
payload = {{
    "version": 1,
    "success": True,
    "token_type": "urn:ietf:params:oauth:token-type:id_token",
    "id_token": {subject_token!r},
    "expiration_time": int(time.time()) + 3600,
}}
with open(output_file, "w", encoding="utf-8") as file_obj:
    json.dump(payload, file_obj)
# Executables may also emit the payload on stdout.
sys.stdout.write(json.dumps(payload))
"""


class FakeStsRequest(object):
    """Records the subject token each STS exchange would send to the backend."""

    def __init__(self):
        self.exchanges = []

    def __call__(self, url, method, headers, body):
        from urllib.parse import parse_qs

        fields = parse_qs(body.decode("utf-8"))
        self.exchanges.append(
            {
                "url": url,
                "subject_token": fields["subject_token"][0],
                "audience": fields["audience"][0],
            }
        )
        response = json.dumps(
            {"access_token": "STS_ACCESS_TOKEN", "expires_in": 3600}
        )
        return type("Response", (), {"status": 200, "data": response.encode("utf-8")})()


def build_credentials(provider, output_file, scopes):
    credential_source = {
        "executable": {
            "command": provider["command"],
            "timeout_millis": 30000,
            "output_file": output_file,
        }
    }
    return pluggable.Credentials(
        audience=provider["audience"],
        subject_token_type=SUBJECT_TOKEN_TYPE,
        token_url=TOKEN_URL,
        credential_source=credential_source,
        scopes=scopes,
    )


def write_executable(workdir, provider):
    path = os.path.join(workdir, provider["name"] + ".py")
    with open(path, "w", encoding="utf-8") as file_obj:
        file_obj.write(
            EXECUTABLE_TEMPLATE.format(subject_token=provider["subject_token"])
        )
    os.chmod(path, 0o755)
    provider["command"] = path


@contextmanager
def collect_logs(logger_name, level):
    records = []

    class Collector(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    logger = logging.getLogger(logger_name)
    handler = Collector()
    handler.setLevel(level)
    logger.addHandler(handler)
    previous_level = logger.level
    logger.setLevel(level)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)


def main():
    workdir = tempfile.mkdtemp(prefix="pluggable-provenance-e2e-")
    output_file = os.path.join(workdir, "shared_output_file.json")
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
    failures = []

    try:
        write_executable(workdir, PROVIDER_A)
        write_executable(workdir, PROVIDER_B)

        print("== Phase 1: provider A leaves a legitimate cache ==")
        os.environ["GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES"] = "1"
        credentials_a = build_credentials(PROVIDER_A, output_file, scopes)
        token_a = credentials_a.retrieve_subject_token(None)
        assert token_a == PROVIDER_A["subject_token"]
        provenance_path = output_file + pluggable.PROVENANCE_FILE_SUFFIX
        assert os.path.exists(provenance_path), "provenance sidecar was not written"
        with open(provenance_path, encoding="utf-8") as provenance_file:
            provenance_a = json.load(provenance_file)
        assert provenance_a["config_fingerprint"] == credentials_a.config_fingerprint
        print(
            "  A cache admitted from executable; provenance fingerprint: {}".format(
                credentials_a.config_fingerprint[:12]
            )
        )

        print("\n== Phase 2: switch to provider B, execution disabled (offline) ==")
        os.environ["GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES"] = "0"
        credentials_b = build_credentials(PROVIDER_B, output_file, scopes)
        assert (
            credentials_b.config_fingerprint != credentials_a.config_fingerprint
        ), "A and B must not share a configuration fingerprint"

        sts_request = FakeStsRequest()
        with collect_logs("google.auth.pluggable", logging.DEBUG) as offline_logs:
            try:
                credentials_b.refresh(sts_request)
            except exceptions.MalformedError as error:
                print("  offline refresh failed closed: {}".format(error))
            else:
                failures.append("offline mode unexpectedly admitted A's cache")

        if sts_request.exchanges:
            failures.append("offline mode reached the STS endpoint")
        else:
            print("  no STS exchange attempted (stopped before STS)")

        joined_logs = "\n".join(offline_logs)
        if PROVIDER_A["subject_token"] in joined_logs:
            failures.append("offline logs leaked provider A's subject token identity")
        if credentials_a.config_fingerprint[:12] not in joined_logs:
            failures.append("offline logs did not identify the foreign cache owner")
        if credentials_b.config_fingerprint[:12] not in joined_logs:
            failures.append("offline logs did not identify the active provider B")
        print("  audit trail only references configuration fingerprints")

        print("\n== Phase 3: switch to provider B, execution enabled (online) ==")
        os.environ["GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES"] = "1"
        sts_request = FakeStsRequest()
        with collect_logs("google.auth.pluggable", logging.DEBUG) as online_logs:
            credentials_b.refresh(sts_request)

        decision = credentials_b.admission_decision
        assert decision is not None
        assert decision.source == pluggable._AdmissionDecision.EXECUTABLE
        assert decision.rebuilt_cache is True
        assert decision.config_fingerprint == credentials_b.config_fingerprint
        print(
            "  cache rebuilt and admitted under provider B: {}".format(
                credentials_b.config_fingerprint[:12]
            )
        )

        assert len(sts_request.exchanges) == 1
        exchange = sts_request.exchanges[0]
        assert exchange["subject_token"] == PROVIDER_B["subject_token"]
        assert exchange["audience"] == PROVIDER_B["audience"]
        print("  STS backend exchange received provider B's subject token only")

        with open(output_file, encoding="utf-8") as file_obj:
            rebuilt_cache = json.load(file_obj)
        assert rebuilt_cache["id_token"] == PROVIDER_B["subject_token"]
        with open(provenance_path, encoding="utf-8") as provenance_file:
            provenance_b = json.load(provenance_file)
        assert provenance_b["config_fingerprint"] == credentials_b.config_fingerprint
        print("  rebuilt cache and provenance now belong to provider B")

        joined_logs = "\n".join(online_logs)
        online_admission_logs = "\n".join(
            message
            for message in online_logs
            if "admitted" in message or "Rebuilt" in message
        )
        if credentials_a.config_fingerprint[:12] in online_admission_logs:
            failures.append("online admission records reference provider A's identity")
        if credentials_b.config_fingerprint[:12] not in online_admission_logs:
            failures.append(
                "online admission records do not reference provider B's identity"
            )
        if PROVIDER_A["subject_token"] in joined_logs:
            failures.append("online logs leaked provider A's subject token")
        print(
            "  admission records reference provider B only; rebuild diagnostics "
            "identify the displaced provider A cache"
        )

        print("\n== Phase 4: provider B cache is reusable offline after rebuild ==")
        os.environ["GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES"] = "0"
        credentials_b_offline = build_credentials(PROVIDER_B, output_file, scopes)
        subject_token = credentials_b_offline.retrieve_subject_token(None)
        assert subject_token == PROVIDER_B["subject_token"]
        assert credentials_b_offline.admission_decision.admitted_from_cache is True
        print("  B's attributed, unexpired cache admitted without execution")

    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    if failures:
        print("\nFAILURES:")
        for failure in failures:
            print("  - {}".format(failure))
        return 1
    print("\nAll provenance and dual-mode checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
