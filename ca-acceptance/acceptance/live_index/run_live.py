"""End-to-end acceptance against local HTTPS stand-ins.

Unlike run_acceptance.py this needs loopback port binding and therefore runs
on a normal CI runner / developer machine, not in a sandbox that denies
bind(2). It drives the real pip CLI through both evidence stages:

* plan stage  - ``pip install --dry-run --ignore-installed --report`` against
  the authenticated index. In this pip version dry-run returns after
  resolution and before ``prepare_linked_requirements_more`` (see
  install.py), so the evidence is index-host TLS + basic auth + candidate
  metadata, with no artifact download;
* download stage - real ``pip download --dest`` for the wheel and for an
  sdist whose build dependencies force a nested pip invocation against the
  same authenticated index (records artifact-host TLS + build isolation).

Hostname resolution: the generated certificates carry
``index.corp.example`` / ``files.corp.example`` SANs. Map them to loopback in
``/etc/hosts`` (documented in RUNBOOK.md), or override with ``--bind-host``
plus matching SANs in pki.py for your own environment.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACKAGE_ROOT = HERE.parents[1]
REPO_ROOT = PACKAGE_ROOT.parent
sys.path.insert(0, str(PACKAGE_ROOT))
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "src"))

from acceptance import pki  # noqa: E402
from acceptance.live_index import build_packages, server  # noqa: E402

EVIDENCE_DIR = PACKAGE_ROOT / "evidence" / "live"


def _can_bind(host: str, port: int) -> bool:
    probe = socket.socket()
    try:
        probe.bind((host, port))
    except OSError:
        return False
    else:
        return True
    finally:
        probe.close()


def _run(cmd: list[str], env: dict[str, str], log_path: Path) -> dict:
    proc = subprocess.run(
        cmd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    log_path.write_text(
        "$ " + " ".join(cmd) + "\n\n--- stdout ---\n" + proc.stdout + "\n--- stderr ---\n" + proc.stderr
    )
    return {"cmd": cmd, "returncode": proc.returncode, "log": str(log_path)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind-host", default="127.0.0.1")
    parser.add_argument("--index-port", type=int, default=18443)
    parser.add_argument("--artifact-port", type=int, default=18444)
    parser.add_argument("--unapproved-port", type=int, default=18445)
    args = parser.parse_args()

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    work = EVIDENCE_DIR / "pki"
    material = pki.generate(work)
    artifact_root = EVIDENCE_DIR / "artifacts"
    packages = build_packages.build(artifact_root)

    if not all(_can_bind(args.bind_host, port) for port in (args.index_port, args.artifact_port, args.unapproved_port)):
        reason = {
            "status": "ENV_SKIP",
            "reason": "loopback port binding denied in this environment",
            "ports": [args.index_port, args.artifact_port, args.unapproved_port],
        }
        (EVIDENCE_DIR / "live-result.json").write_text(json.dumps(reason, indent=2))
        print(json.dumps(reason, indent=2))
        return 0

    access_log = EVIDENCE_DIR / "access.log"
    access_log.write_text("")
    index_handle = server.serve(
        bind_host=args.bind_host,
        port=args.index_port,
        server_pem=material.index_server_pem,
        artifact_root=artifact_root,
        access_log=access_log,
        basic_user="build-worker",
        basic_password="rotated-token",
        artifact_port=args.artifact_port,
        server_name="index",
    )
    artifact_handle = server.serve(
        bind_host=args.bind_host,
        port=args.artifact_port,
        server_pem=material.artifact_server_pem,
        artifact_root=artifact_root,
        access_log=access_log,
        basic_user="",
        basic_password="",
        artifact_port=args.artifact_port,
        server_name="artifact",
    )
    unapproved_handle = server.serve(
        bind_host=args.bind_host,
        port=args.unapproved_port,
        server_pem=material.unapproved_server_pem,
        artifact_root=artifact_root,
        access_log=access_log,
        basic_user="",
        basic_password="",
        artifact_port=args.unapproved_port,
        server_name="unapproved",
    )

    pip = [sys.executable, "-m", "pip"]
    base_env = dict(os.environ)
    base_env["PIP_CERT"] = str(material.corp_ca_cert)
    base_env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    base_env["PIP_NO_CACHE_DIR"] = "1"
    index_url = f"https://build-worker:rotated-token@index.corp.example:{args.index_port}/simple/"

    results: list[dict] = []
    # Plan stage: resolver evidence. --dry-run is an install-command option
    # in this pip version; --report requires it.
    plan = _run(
        [
            *pip,
            "install",
            "--dry-run",
            "--ignore-installed",
            "--report",
            str(EVIDENCE_DIR / "plan-report.json"),
            "-i",
            index_url,
            "corpdemo",
        ],
        base_env,
        EVIDENCE_DIR / "01-plan-stage.log",
    )
    results.append({"stage": "plan", **plan, "ok": plan["returncode"] == 0})

    # Download stage: wheel from the approved artifact host.
    wheel_dest = EVIDENCE_DIR / "dest-wheel"
    wheel_dest.mkdir(exist_ok=True)
    wheel_run = _run(
        [*pip, "download", "--dest", str(wheel_dest), "-i", index_url, "corpdemo"],
        base_env,
        EVIDENCE_DIR / "02-download-wheel.log",
    )
    results.append({"stage": "download-wheel", **wheel_run, "ok": wheel_run["returncode"] == 0})

    # Download stage: sdist whose build deps trigger the nested pip installer.
    sdist_dest = EVIDENCE_DIR / "dest-sdist"
    sdist_dest.mkdir(exist_ok=True)
    sdist_run = _run(
        [*pip, "download", "--no-binary", ":all:", "--dest", str(sdist_dest), "-i", index_url, "needbuild"],
        base_env,
        EVIDENCE_DIR / "03-download-sdist-builddeps.log",
    )
    results.append({"stage": "download-sdist-builddeps", **sdist_run, "ok": sdist_run["returncode"] == 0})

    # Negative: a direct artifact URL on a host whose certificate is signed
    # by a different CA. The corporate PEM does not chain to it, so pip must
    # fail closed even though the URL itself is well-formed and reachable.
    negative_env = dict(base_env)
    negative_run = _run(
        [
            *pip,
            "download",
            "--dest",
            str(EVIDENCE_DIR / "dest-negative"),
            "https://cdn.unapproved.example:{}/files/corpdemo-1.0-py3-none-any.whl".format(
                args.unapproved_port
            ),
        ],
        negative_env,
        EVIDENCE_DIR / "04-unapproved-host.log",
    )
    results.append(
        {
            "stage": "unapproved-host",
            **negative_run,
            "ok": negative_run["returncode"] != 0,
            "expectation": "must fail with a TLS verification error",
        }
    )

    for handle in (index_handle, artifact_handle, unapproved_handle):
        handle.httpd.shutdown()

    summary = {
        "results": results,
        "access_log": access_log.read_text(),
        "packages": {key: str(value) for key, value in packages.items()},
        "pki": str(work),
    }
    (EVIDENCE_DIR / "live-result.json").write_text(json.dumps(summary, indent=2))
    failed = [item for item in results if not item["ok"]]
    for item in results:
        print(f"[{'PASS' if item['ok'] else 'FAIL'}] {item['stage']} (rc={item['returncode']})")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
