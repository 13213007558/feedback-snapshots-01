"""Corporate CA rollout: certificate configuration propagation.

These tests need no network and no TCP port binding. They assert the two
boundaries that matter for a platform switching pip onto a private CA:

1. how each configuration channel lands on the shared ``PipSession`` used
   for index fetches and artifact downloads;
2. what the build-isolation installer hands to its nested pip invocation;
3. end-to-end TLS behaviour over a socketpair-backed peer.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path
from unittest import mock

_CA_ACCEPTANCE_ROOT = Path(__file__).resolve().parents[2] / "ca-acceptance"
if str(_CA_ACCEPTANCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CA_ACCEPTANCE_ROOT))

import pytest

from pip._internal.build_env import SubprocessBuildEnvironmentInstaller
from pip._internal.build_env.base import Prefix
from pip._internal.cli.index_command import SessionCommandMixin
from pip._internal.commands import create_command
from pip._internal.network.session import PipSession

from tests.lib import make_test_finder

CA_ENV_VARS = ("PIP_CERT", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")


@pytest.fixture
def pki_material(tmp_path: Path) -> Path:
    from acceptance import pki

    return pki.generate(tmp_path / "pki")


def _session_for(monkeypatch: pytest.MonkeyPatch, argv: list[str], env: dict[str, str] | None = None):
    for name in CA_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    for name, value in (env or {}).items():
        monkeypatch.setenv(name, value)
    command = create_command("download")
    options, _ = command.parse_args([*argv, "demo-package"])
    with command.main_context():
        session = SessionCommandMixin._build_session(command, options)
        merged = session.merge_environment_settings(
            "https://index.corp.example/simple/",
            dict(session.proxies),
            None,
            session.verify,
            session.cert,
        )
    return options, session, merged


class TestSessionCAChannels:
    def test_cli_cert_sets_string_verify(
        self, monkeypatch: pytest.MonkeyPatch, pki_material: Path
    ) -> None:
        _options, session, merged = _session_for(
            monkeypatch, ["--cert", str(pki_material.corp_ca_cert)]
        )
        assert session.verify == str(pki_material.corp_ca_cert)
        assert merged["verify"] == str(pki_material.corp_ca_cert)

    def test_pip_cert_env_equivalent_to_cli(
        self, monkeypatch: pytest.MonkeyPatch, pki_material: Path
    ) -> None:
        _options, _session, merged = _session_for(
            monkeypatch, [], {"PIP_CERT": str(pki_material.corp_ca_cert)}
        )
        assert merged["verify"] == str(pki_material.corp_ca_cert)

    def test_requests_ca_bundle_honoured_with_trust_env(
        self, monkeypatch: pytest.MonkeyPatch, pki_material: Path
    ) -> None:
        _options, session, merged = _session_for(
            monkeypatch, [], {"REQUESTS_CA_BUNDLE": str(pki_material.corp_ca_cert)}
        )
        assert session.trust_env is True
        assert merged["verify"] == str(pki_material.corp_ca_cert)

    def test_explicit_cert_overrides_requests_ca_bundle(
        self, monkeypatch: pytest.MonkeyPatch, pki_material: Path
    ) -> None:
        _options, _session, merged = _session_for(
            monkeypatch,
            ["--cert", str(pki_material.corp_ca_cert)],
            {"REQUESTS_CA_BUNDLE": str(pki_material.other_ca_cert)},
        )
        assert merged["verify"] == str(pki_material.corp_ca_cert)

    def test_proxy_flag_disables_trust_env_and_env_ca_bundle(
        self, monkeypatch: pytest.MonkeyPatch, pki_material: Path
    ) -> None:
        _options, session, merged = _session_for(
            monkeypatch,
            ["--proxy", ""],
            {"REQUESTS_CA_BUNDLE": str(pki_material.corp_ca_cert)},
        )
        assert session.trust_env is False
        assert merged["verify"] is True

    def test_trusted_host_mounts_insecure_adapter(
        self, monkeypatch: pytest.MonkeyPatch, pki_material: Path
    ) -> None:
        _options, session, _merged = _session_for(
            monkeypatch, ["--trusted-host", pki_material.index_host]
        )
        adapter = session.get_adapter(f"https://{pki_material.index_host}/")
        assert type(adapter).__name__.startswith("Insecure")

    def test_client_cert_separate_from_ca_trust(
        self, monkeypatch: pytest.MonkeyPatch, pki_material: Path
    ) -> None:
        _options, session, _merged = _session_for(
            monkeypatch,
            ["--cert", str(pki_material.corp_ca_cert), "--client-cert", str(pki_material.client_pem)],
        )
        assert session.verify == str(pki_material.corp_ca_cert)
        assert session.cert == str(pki_material.client_pem)

    def test_default_session_uses_truststore_context(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _options, session, _merged = _session_for(monkeypatch, [])
        adapter = session.get_adapter("https://index.corp.example/")
        assert type(adapter._ssl_context).__module__.endswith("truststore._api")


class TestBuildIsolationForwarding:
    def _capture_args(self, finder) -> list[str]:
        installer = SubprocessBuildEnvironmentInstaller(finder)
        with mock.patch("pip._internal.build_env.installer.call_subprocess") as called:
            with mock.patch("pip._internal.build_env.installer.open_spinner"):
                installer.install(
                    requirements=["seabuild-backend"],
                    prefix=Prefix("/tmp/build-prefix"),
                    kind="build dependencies",
                    for_req=None,
                )
        return called.call_args.args[0]

    def test_cert_and_client_cert_forwarded_to_subprocess(
        self, pki_material: Path
    ) -> None:
        finder = make_test_finder(
            index_urls=["https://index.corp.example/simple/"]
        )
        finder._link_collector.session.verify = str(pki_material.corp_ca_cert)
        finder._link_collector.session.cert = str(pki_material.client_pem)

        args = self._capture_args(finder)

        assert args[args.index("--cert") + 1] == str(pki_material.corp_ca_cert)
        assert args[args.index("--client-cert") + 1] == str(pki_material.client_pem)

    def test_embedded_basic_auth_index_url_forwarded(self) -> None:
        url = "https://build-worker:rotated-token@index.corp.example/simple/"
        finder = make_test_finder(index_urls=[url])

        args = self._capture_args(finder)

        assert "-i" in args
        assert args[args.index("-i") + 1] == url

    def test_no_cert_configuration_means_no_cert_flag(self) -> None:
        finder = make_test_finder(
            index_urls=["https://index.corp.example/simple/"]
        )
        assert finder.custom_cert is None

        args = self._capture_args(finder)

        assert "--cert" not in args
        assert "--client-cert" not in args

    def test_trusted_host_forwarded(self, pki_material: Path) -> None:
        finder = make_test_finder(
            index_urls=["https://index.corp.example/simple/"]
        )
        finder._link_collector.session.add_trusted_host(pki_material.index_host)

        args = self._capture_args(finder)

        assert pki_material.index_host in args


class TestBindFreeTLSChain:
    def test_corporate_ca_trusts_approved_hosts(self, pki_material: Path) -> None:
        from acceptance import tls_peer

        index_result = tls_peer.handshake(
            server_pem=pki_material.index_server_pem,
            hostname=pki_material.index_host,
            ca_pem=pki_material.corp_ca_cert,
            authorization="Basic " + base64.b64encode(b"u:p").decode(),
        )
        artifact_result = tls_peer.handshake(
            server_pem=pki_material.artifact_server_pem,
            hostname=pki_material.artifact_host,
            ca_pem=pki_material.corp_ca_cert,
        )
        assert index_result.ok
        assert index_result.authorization_header is not None
        assert artifact_result.ok

    def test_unapproved_host_fails_closed(self, pki_material: Path) -> None:
        from acceptance import tls_peer

        rejected = tls_peer.handshake(
            server_pem=pki_material.unapproved_server_pem,
            hostname=pki_material.unapproved_host,
            ca_pem=pki_material.corp_ca_cert,
        )
        accepted_with_own_anchor = tls_peer.handshake(
            server_pem=pki_material.unapproved_server_pem,
            hostname=pki_material.unapproved_host,
            ca_pem=pki_material.other_ca_cert,
        )
        assert not rejected.ok
        assert rejected.error_type in {
            "SSLCertVerificationError",
            "SSLVerificationError",
            "FileNotFoundError",
        }
        assert accepted_with_own_anchor.ok

    def test_mtls_required_client_certificate(self, pki_material: Path) -> None:
        from acceptance import tls_peer

        with_cert = tls_peer.handshake(
            server_pem=pki_material.index_server_pem,
            hostname=pki_material.index_host,
            ca_pem=pki_material.corp_ca_cert,
            client_cert_pem=pki_material.client_pem,
            require_client_ca=pki_material.corp_ca_cert,
        )
        without_cert = tls_peer.handshake(
            server_pem=pki_material.index_server_pem,
            hostname=pki_material.index_host,
            ca_pem=pki_material.corp_ca_cert,
            require_client_ca=pki_material.corp_ca_cert,
        )
        assert with_cert.ok
        assert not without_cert.ok

    def test_missing_bundle_is_explicit_failure(self, pki_material: Path) -> None:
        from acceptance import tls_peer

        result = tls_peer.handshake(
            server_pem=pki_material.index_server_pem,
            hostname=pki_material.index_host,
            ca_pem=pki_material.root_dir / "missing.pem",
        )
        assert not result.ok
        assert result.error_type is not None
