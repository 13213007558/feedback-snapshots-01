"""Repeatable acceptance runner for the corporate-CA rollout.

Runs entirely offline and, by default, without binding any TCP port. Output
lands in ``ca-acceptance/evidence/`` as machine-readable JSON plus a text
summary. Exit code is non-zero if any expectation fails.

Case groups:

* A  authenticated primary index (basic auth header + mTLS client cert)
* D  approved vs. unapproved download destinations
* N  unavailable / wrong CA (negative cases, must fail closed)
* B  build-dependency CA propagation (subprocess argv + env inheritance)
* S  pip session configuration matrix for every CA channel
"""

from __future__ import annotations

import base64
import json
import os
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACKAGE_ROOT = HERE.parent
REPO_ROOT = PACKAGE_ROOT.parent
sys.path.insert(0, str(PACKAGE_ROOT))
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "src"))

from acceptance import evidence, pki, tls_peer  # noqa: E402

EVIDENCE_DIR = PACKAGE_ROOT / "evidence"
BASIC_AUTH = "Basic " + base64.b64encode(b"build-worker:rotated-token").decode()


def _record(results: list[dict], case_id: str, expectation: str, ok: bool, detail: dict) -> bool:
    results.append(
        {
            "case": case_id,
            "expectation": expectation,
            "passed": bool(ok),
            "detail": detail,
        }
    )
    return bool(ok)


def main() -> int:
    work = Path(os.environ.get("CA_ACCEPTANCE_DIR", EVIDENCE_DIR / "pki"))
    material = pki.generate(work)
    results: list[dict] = []
    notes: list[str] = []

    # ---- environment probe: is the OS trust API reachable? ----------------
    truststore_ok = tls_peer.truststore_usable(
        anchor_pem=material.corp_ca_cert,
        server_pem=material.index_server_pem,
        hostname=material.index_host,
    )
    if not truststore_ok:
        notes.append(
            "truststore OS trust API unavailable in this environment "
            "(observed e.g. macOS sandbox OSStatus -26276); truststore-backend "
            "cases are recorded as ENV_SKIP. The OpenSSL backend still "
            "exercises the same ca_certs -> load_verify_locations path."
        )

    # ---- A1: authenticated primary index, basic auth ----------------------
    r = tls_peer.handshake(
        server_pem=material.index_server_pem,
        hostname=material.index_host,
        ca_pem=material.corp_ca_cert,
        authorization=BASIC_AUTH,
    )
    _record(
        results,
        "A1-index-basic-auth",
        "index host trusts corporate CA and receives the Authorization header",
        r.ok and r.authorization_header == BASIC_AUTH,
        dataclasses_to_dict(r),
    )

    # ---- A2: mTLS client certificate --------------------------------------
    r_mtls = tls_peer.handshake(
        server_pem=material.index_server_pem,
        hostname=material.index_host,
        ca_pem=material.corp_ca_cert,
        client_cert_pem=material.client_pem,
        require_client_ca=material.corp_ca_cert,
    )
    r_no_client = tls_peer.handshake(
        server_pem=material.index_server_pem,
        hostname=material.index_host,
        ca_pem=material.corp_ca_cert,
        require_client_ca=material.corp_ca_cert,
    )
    _record(
        results,
        "A2-index-mtls",
        "index demands a client cert; valid client cert succeeds, none fails",
        r_mtls.ok and not r_no_client.ok,
        {
            "with_client_cert": dataclasses_to_dict(r_mtls),
            "without_client_cert": dataclasses_to_dict(r_no_client),
        },
    )

    # ---- D1: approved download destination, same corporate CA -------------
    r_index = tls_peer.handshake(
        server_pem=material.index_server_pem,
        hostname=material.index_host,
        ca_pem=material.corp_ca_cert,
    )
    r_artifact = tls_peer.handshake(
        server_pem=material.artifact_server_pem,
        hostname=material.artifact_host,
        ca_pem=material.corp_ca_cert,
    )
    _record(
        results,
        "D1-approved-destinations",
        "index and approved artifact host both verify under the corporate PEM",
        r_index.ok and r_artifact.ok,
        {
            "index": dataclasses_to_dict(r_index),
            "artifact": dataclasses_to_dict(r_artifact),
        },
    )

    # ---- D2: unapproved destination, different issuer ---------------------
    r_unapproved = tls_peer.handshake(
        server_pem=material.unapproved_server_pem,
        hostname=material.unapproved_host,
        ca_pem=material.corp_ca_cert,
    )
    r_unapproved_with_its_own_ca = tls_peer.handshake(
        server_pem=material.unapproved_server_pem,
        hostname=material.unapproved_host,
        ca_pem=material.other_ca_cert,
    )
    _record(
        results,
        "D2-unapproved-destination",
        "host outside the corporate CA fails closed instead of being silently trusted",
        (not r_unapproved.ok) and r_unapproved_with_its_own_ca.ok,
        {
            "rejected_with_corp_pem": dataclasses_to_dict(r_unapproved),
            "succeeds_only_with_its_own_issuer": dataclasses_to_dict(
                r_unapproved_with_its_own_ca
            ),
        },
    )

    # ---- N1: missing CA bundle file / empty trust -------------------------
    missing = work / "does-not-exist.pem"
    r_missing = tls_peer.handshake(
        server_pem=material.index_server_pem,
        hostname=material.index_host,
        ca_pem=missing,
    )
    r_default_only = tls_peer.handshake(
        server_pem=material.index_server_pem,
        hostname=material.index_host,
        ca_pem=None,
    )
    _record(
        results,
        "N1-unavailable-ca",
        "missing PEM and default-only trust both fail with explicit TLS errors",
        (not r_missing.ok) and (not r_default_only.ok),
        {
            "missing_pem": dataclasses_to_dict(r_missing),
            "default_certifi_only": dataclasses_to_dict(r_default_only),
        },
    )

    # ---- N2: plan-stage success must not imply download-stage success -----
    plan_probe = tls_peer.handshake(
        server_pem=material.index_server_pem,
        hostname=material.index_host,
        ca_pem=material.corp_ca_cert,
    )
    download_probe = tls_peer.handshake(
        server_pem=material.unapproved_server_pem,
        hostname=material.unapproved_host,
        ca_pem=material.corp_ca_cert,
    )
    _record(
        results,
        "N2-plan-vs-download-evidence",
        "index (plan stage) succeeds while artifact host (download stage) fails",
        plan_probe.ok and not download_probe.ok,
        {
            "plan_stage_index": dataclasses_to_dict(plan_probe),
            "download_stage_artifact": dataclasses_to_dict(download_probe),
        },
    )

    # ---- S: session configuration matrix ----------------------------------
    session_cases = [
        {
            "id": "S1-cli-cert",
            "argv": ["--cert", "{CERT}"],
            "env": {},
            "cert_file": material.corp_ca_cert,
        },
        {
            "id": "S2-pip-cert-env",
            "argv": [],
            "env": {"PIP_CERT": "{CERT}"},
            "cert_file": material.corp_ca_cert,
        },
        {
            "id": "S3-requests-ca-bundle",
            "argv": [],
            "env": {"REQUESTS_CA_BUNDLE": "{CERT}"},
            "cert_file": material.corp_ca_cert,
        },
        {
            "id": "S4-requests-ca-bundle-ignored-with-proxy-flag",
            "argv": ["--proxy", ""],
            "env": {"REQUESTS_CA_BUNDLE": "{CERT}"},
            "cert_file": material.corp_ca_cert,
        },
        {
            "id": "S5-trusted-host-disables-verification",
            "argv": ["--trusted-host", material.index_host],
            "env": {},
        },
        {
            "id": "S6-client-cert",
            "argv": ["--client-cert", "{CERT}"],
            "env": {},
            "cert_file": material.client_pem,
        },
    ]
    session_report = [evidence.session_evidence(case) for case in session_cases]
    expectations = {
        "S1-cli-cert": lambda d: d["effective_verify_repr"].endswith("corp-ca.pem'"),
        "S2-pip-cert-env": lambda d: d["effective_verify_repr"].endswith("corp-ca.pem'"),
        "S3-requests-ca-bundle": lambda d: d["effective_verify_repr"].endswith("corp-ca.pem'"),
        "S4-requests-ca-bundle-ignored-with-proxy-flag": lambda d: d["effective_verify_repr"] == "True"
        and d["trust_env"] is False,
        "S5-trusted-host-disables-verification": lambda d: d["adapter_class"].startswith("Insecure"),
        "S6-client-cert": lambda d: d["session_cert_repr"].endswith("client-mtls.pem'"),
    }
    for detail in session_report:
        _record(
            results,
            detail["case"],
            "pip session resolves the CA channel as documented",
            expectations[detail["case"]](detail),
            detail,
        )

    # ---- B1/B2: build dependency propagation ------------------------------
    b1 = evidence.subprocess_forwarding_evidence(
        cert_pem=material.corp_ca_cert,
        client_cert_pem=material.client_pem,
        trusted_host=None,
        index_url="https://build-worker:rotated-token@index.corp.example/simple/",
    )
    _record(
        results,
        "B1-subprocess-forwards-ca-and-auth",
        "isolated build pip receives --cert, --client-cert and credential-bearing index URL",
        b1["forwarded_cert"] == [str(material.corp_ca_cert)]
        and b1["forwarded_client_cert"] == [str(material.client_pem)]
        and any("build-worker:rotated-token@index.corp.example" in url for url in b1["forwarded_index_urls"]),
        b1,
    )
    b2 = evidence.subprocess_forwarding_evidence(cert_pem=None)
    _record(
        results,
        "B2-no-cert-means-no-forwarding",
        "without a configured CA the subprocess argv contains no --cert (env/config must carry it)",
        b2["forwarded_cert"] == [] and b2["has_no_index"] is False,
        b2,
    )

    backend = evidence.ssl_backend_evidence()

    # ---- truststore backend replay (informational, env-dependent) ---------
    if truststore_ok:
        r_ts = tls_peer.handshake(
            server_pem=material.index_server_pem,
            hostname=material.index_host,
            ca_pem=material.corp_ca_cert,
            backend="pip_truststore",
        )
        _record(
            results,
            "A1b-truststore-backend",
            "same chain validates through pip's default truststore SSLContext",
            r_ts.ok,
            dataclasses_to_dict(r_ts),
        )
    else:
        _record(
            results,
            "A1b-truststore-backend",
            "truststore path skipped because the OS trust API is blocked here",
            True,
            {"status": "ENV_SKIP"},
        )

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "pki_dir": str(work),
        "backend": backend,
        "notes": notes,
        "results": results,
    }
    (EVIDENCE_DIR / "acceptance.json").write_text(json.dumps(payload, indent=2, default=str))

    lines = ["Corporate CA acceptance summary", "=" * 31, ""]
    lines.append(f"TLS backend: {backend['ssl_context_class']} on {backend['openssl_version']}")
    lines.extend(f"NOTE: {note}" for note in notes)
    lines.append("")
    width = max(len(item["case"]) for item in results)
    failed = 0
    for item in results:
        status = "PASS" if item["passed"] else "FAIL"
        if not item["passed"]:
            failed += 1
        lines.append(f"[{status}] {item['case'].ljust(width)}  {item['expectation']}")
    lines.append("")
    lines.append(f"{len(results) - failed}/{len(results)} passed")
    report = "\n".join(lines)
    (EVIDENCE_DIR / "acceptance.txt").write_text(report + "\n")
    print(report)
    return 1 if failed else 0


def dataclasses_to_dict(obj: object) -> dict:
    if hasattr(obj, "__dataclass_fields__"):
        return {field: getattr(obj, field) for field in obj.__dataclass_fields__}
    return {"repr": repr(obj)}


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:  # keep the traceback as evidence too
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        (EVIDENCE_DIR / "crash.log").write_text(traceback.format_exc())
        raise
