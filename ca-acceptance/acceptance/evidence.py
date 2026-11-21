"""Evidence collection using pip's own option/session construction.

No network calls are made: we drive ``create_command(...).parse_args`` and
``SessionCommandMixin._build_session`` exactly like the real CLI, then inspect
the resulting ``PipSession`` and the argument list the build-isolation
subprocess would receive. This proves what each configuration channel
delivers to (a) index/file requests and (b) the build dependency installer.
"""

from __future__ import annotations

import contextlib
import os
import ssl
import tempfile
import unittest.mock as mock
from pathlib import Path
from typing import Any

from pip._internal.build_env import SubprocessBuildEnvironmentInstaller
from pip._internal.cli.index_command import SessionCommandMixin
from pip._internal.commands import create_command

from tests.lib import make_test_finder

_ENV_VARS = (
    "PIP_CERT",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "HTTPS_PROXY",
    "https_proxy",
)


@contextlib.contextmanager
def _clean_env(monkey: dict[str, str] | None = None):
    saved = {key: os.environ.get(key) for key in _ENV_VARS}
    for key in _ENV_VARS:
        os.environ.pop(key, None)
    try:
        for key, value in (monkey or {}).items():
            os.environ[key] = value
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def build_session(argv: list[str], env: dict[str, str] | None = None) -> tuple[Any, Any, Any]:
    """Construct a PipSession the same way the pip CLI would.

    The merged verify value is resolved while the environment is still
    active, so env-var-driven bundles are visible in the evidence.
    """
    with _clean_env(env):
        command = create_command("download")
        options, _ = command.parse_args([*argv, "demo-package"])
        with command.main_context():
            session = SessionCommandMixin._build_session(command, options)
        merged_verify = effective_verify(session)
        return options, session, merged_verify


def effective_verify(session: Any, url: str = "https://index.corp.example/simple/") -> Any:
    """Resolve the final verify value including trust_env env-var merging."""
    settings = session.merge_environment_settings(url, dict(session.proxies), None, session.verify, session.cert)
    return settings["verify"]


def session_evidence(case: dict[str, Any]) -> dict[str, Any]:
    argv = list(case["argv"])
    env = dict(case.get("env", {}))
    if case.get("cert_file"):
        cert_file = str(case["cert_file"])
        argv = [part.replace("{CERT}", cert_file) for part in argv]
        env = {key: value.replace("{CERT}", cert_file) for key, value in env.items()}
    options, session, merged_verify = build_session(argv, env)
    adapter = session.get_adapter("https://index.corp.example/")
    return {
        "case": case["id"],
        "argv": argv,
        "env": env,
        "session_verify_repr": repr(session.verify),
        "effective_verify_repr": repr(merged_verify),
        "trust_env": session.trust_env,
        "adapter_class": type(adapter).__name__,
        "ssl_context_present": getattr(adapter, "_ssl_context", None) is not None,
        "session_cert_repr": repr(session.cert),
    }


def subprocess_forwarding_evidence(
    *,
    cert_pem: Path | None = None,
    client_cert_pem: Path | None = None,
    trusted_host: str | None = None,
    index_url: str | None = None,
) -> dict[str, Any]:
    """Capture the exact argv the build-isolation subprocess would receive."""
    finder = make_test_finder(
        index_urls=[index_url or "https://index.corp.example/simple/"]
    )
    session = finder._link_collector.session
    if cert_pem is not None:
        session.verify = str(cert_pem)
    if client_cert_pem is not None:
        session.cert = str(client_cert_pem)
    if trusted_host is not None:
        session.add_trusted_host(trusted_host)

    installer = SubprocessBuildEnvironmentInstaller(finder)
    from pip._internal.build_env.base import Prefix

    with mock.patch("pip._internal.build_env.installer.call_subprocess") as called:
        with tempfile.TemporaryDirectory() as tmp:
            installer.install(
                requirements=["seabuild-backend"],
                prefix=Prefix(tmp),
                kind="build dependencies",
                for_req=None,
            )
    args = called.call_args.args[0]
    extra_environ = called.call_args.kwargs.get("extra_environ")
    paired = list(zip(args, args[1:]))
    return {
        "forwarded_cert": [value for flag, value in paired if flag == "--cert"],
        "forwarded_client_cert": [value for flag, value in paired if flag == "--client-cert"],
        "forwarded_trusted_hosts": [value for flag, value in paired if flag == "--trusted-host"],
        "forwarded_index_urls": [value for flag, value in paired if flag in ("-i", "--index-url", "--extra-index-url")],
        "has_no_index": "--no-index" in args,
        "extra_environ": extra_environ,
        "raw_args": args,
    }


def ssl_backend_evidence() -> dict[str, Any]:
    """Record which TLS backend a default session mounts (truststore vs legacy)."""
    _options, session, _merged = build_session([])
    adapter = session.get_adapter("https://index.corp.example/")
    ctx = getattr(adapter, "_ssl_context", None)
    return {
        "adapter_class": type(adapter).__name__,
        "ssl_context_class": type(ctx).__module__ + "." + type(ctx).__name__ if ctx else None,
        "default_verify_repr": repr(session.verify),
        "openssl_version": ssl.OPENSSL_VERSION,
    }
