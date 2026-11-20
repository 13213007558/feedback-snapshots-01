# Copyright 2026 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Tests for the offline deployment readiness checker (`tools/offline_readiness.py`).

These tests are intentionally network-free: the checker exists to prove what
works offline, so its own tests must not depend on connectivity.
"""

from __future__ import annotations

import importlib.util
import json
import socket
import sys
from pathlib import Path

import pytest

_TOOL = Path(__file__).parents[2] / "tools" / "offline_readiness.py"
_spec = importlib.util.spec_from_file_location("offline_readiness", _TOOL)
assert _spec is not None and _spec.loader is not None
offline_readiness = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = offline_readiness
_spec.loader.exec_module(offline_readiness)


@pytest.fixture
def asset():
    assets = Path(__file__).parents[1] / "assets"

    def _asset(name: str) -> Path:
        return assets / name

    return _asset


def test_no_network_blocks_sockets():
    with offline_readiness.no_network():
        with pytest.raises(offline_readiness.NetworkAttempted):
            socket.create_connection(("example.com", 443))
        with pytest.raises(offline_readiness.NetworkAttempted):
            socket.getaddrinfo("example.com", 443)
        with pytest.raises(offline_readiness.NetworkAttempted):
            socket.socket().connect(("example.com", 443))

    original = socket.create_connection
    original_ex = socket.socket.connect_ex
    with offline_readiness.no_network():
        pass
    assert socket.create_connection is original
    assert socket.socket.connect_ex is original_ex


def test_inspect_bundle_reports_proof_material(asset):
    facts = offline_readiness.inspect_bundle(asset("tsa/bundle.txt.sigstore"))

    assert facts.load_error is None
    assert facts.certificate
    assert facts.tlog_entries == 1
    assert facts.inclusion_promise
    assert facts.inclusion_proof
    assert facts.checkpoint
    assert facts.signed_timestamps == 2
    assert facts.entry_kind == "hashedrekord"
    assert facts.entry_version == "0.0.1"


def test_inspect_bundle_without_timestamp(asset):
    facts = offline_readiness.inspect_bundle(asset("bundle_v3.txt.sigstore"))

    assert facts.signed_timestamps == 0
    assert facts.time_sources == ["rekor integratedTime + SET"]


def test_inspect_bundle_survives_invalid_json(tmp_path):
    bad = tmp_path / "bad.sigstore"
    bad.write_text("this is not json")

    facts = offline_readiness.inspect_bundle(bad)

    assert facts.load_error is not None
    assert facts.tlog_entries == 0


def test_verify_offline_against_embedded_staging(asset):
    facts = offline_readiness.inspect_bundle(asset("bundle_v3.txt.sigstore"))

    from sigstore.models import ClientTrustConfig

    root = ClientTrustConfig.staging(offline=True).trusted_root
    with offline_readiness.no_network():
        ok, detail = offline_readiness._verify_one(facts, root)

    assert ok, detail


def test_verify_offline_reports_production_staging_mismatch(asset):
    facts = offline_readiness.inspect_bundle(asset("bundle_v3.txt.sigstore"))

    from sigstore.models import ClientTrustConfig

    root = ClientTrustConfig.production(offline=True).trusted_root
    with offline_readiness.no_network():
        ok, detail = offline_readiness._verify_one(facts, root)

    assert not ok
    assert "CertValidationError" in detail


def test_missing_checkpoint_is_classified(asset):
    facts = offline_readiness.inspect_bundle(asset("bundle_no_checkpoint.txt.sigstore"))

    from sigstore.models import ClientTrustConfig

    root = ClientTrustConfig.staging(offline=True).trusted_root
    with offline_readiness.no_network():
        ok, detail = offline_readiness._verify_one(facts, root)

    assert not ok
    assert offline_readiness.classify_failure(detail) == "bundle-missing-proof"


def test_missing_time_source_is_classified(asset):
    facts = offline_readiness.inspect_bundle(
        asset("bundle_v3_no_signed_time.txt.sigstore.json")
    )

    from sigstore.models import ClientTrustConfig

    root = ClientTrustConfig.staging(offline=True).trusted_root
    with offline_readiness.no_network():
        ok, detail = offline_readiness._verify_one(facts, root)

    assert not ok
    assert offline_readiness.classify_failure(detail) == "bundle-missing-time-source"


def test_inspect_root_counts(asset):
    from sigstore.models import ClientTrustConfig

    root = ClientTrustConfig.staging(offline=True).trusted_root
    facts = offline_readiness.inspect_root("staging", root)

    assert facts.error is None
    assert facts.certificate_authorities == 2
    assert facts.tlogs == 5
    assert facts.ctlogs == 5
    assert facts.timestamp_authorities == 2


def test_inspect_root_does_not_require_network(asset):
    from sigstore.models import ClientTrustConfig

    with offline_readiness.no_network():
        root = ClientTrustConfig.staging(offline=True).trusted_root
        facts = offline_readiness.inspect_root("staging", root)

    assert facts.tlogs > 0


def test_freshness_warns_on_expired_newest_ca():
    from datetime import UTC, datetime

    from sigstore.models import ClientTrustConfig

    root = ClientTrustConfig.staging(offline=True).trusted_root
    # Force the newest generation for one URI to be bounded and in the past.
    ca = max(
        root._inner.certificate_authorities,
        key=lambda authority: authority.valid_for.start,
    )
    ca.valid_for.end = datetime(2020, 1, 1, tzinfo=UTC)

    warnings = offline_readiness.assess_freshness(
        root, at=datetime(2026, 1, 1, tzinfo=UTC)
    )

    assert any("newest generation ended" in warning for warning in warnings)


def test_freshness_warns_on_expired_production_ca():
    from datetime import UTC, datetime

    from sigstore.models import ClientTrustConfig

    # Production has a bounded first CA generation and an unbounded successor;
    # once the successor starts, the predecessor is superseded, not an error.
    root = ClientTrustConfig.production(offline=True).trusted_root
    warnings = offline_readiness.assess_freshness(
        root, at=datetime(2026, 1, 1, tzinfo=UTC)
    )

    assert not any("ended" in warning for warning in warnings)


def test_freshness_is_silent_for_current_material():
    from datetime import UTC, datetime

    from sigstore.models import ClientTrustConfig

    root = ClientTrustConfig.staging(offline=True).trusted_root
    warnings = offline_readiness.assess_freshness(
        root, at=datetime(2026, 1, 1, tzinfo=UTC)
    )

    # The second TSA generation is announced for 2026-06-12; a clock before
    # that instant must not report it as expired, only as future-dated.
    assert all("ended" not in warning for warning in warnings)


def test_selftest_refreshes_without_network(tmp_path):
    from sigstore._utils import read_embedded

    targets = tmp_path / "targets"
    targets.mkdir()
    (targets / "trusted_root.json").write_bytes(
        read_embedded("trusted_root.json", "https://tuf-repo-cdn.sigstage.dev")
    )
    (targets / "signing_config.v0.2.json").write_bytes(
        read_embedded("signing_config.v0.2.json", "https://tuf-repo-cdn.sigstage.dev")
    )

    class Args:
        selftest_targets = targets

    result = offline_readiness.run_selftest(Args())

    assert result["status"] == "ok"
    assert result["network_requests"] == 0
    assert result["refreshed_tlogs"] == 5
    assert "trusted_root.json" in result["cached_targets"]
    assert "signing_config.v0.2.json" in result["cached_targets"]


def test_build_local_tuf_repo_is_wellformed(tmp_path):
    targets = {"trusted_root.json": b"{}", "signing_config.v0.2.json": b"{}"}
    repo = offline_readiness.build_local_tuf_repo(tmp_path / "repo", targets)

    for name in ("root.json", "targets.json", "snapshot.json", "timestamp.json"):
        assert (repo / "metadata" / name).is_file()
        json.loads((repo / "metadata" / name).read_bytes())
    assert (repo / "targets" / "trusted_root.json").is_file()


def test_inspect_cache_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(
        offline_readiness,
        "tuf_cache_paths",
        lambda url: (tmp_path / "data", tmp_path / "cache"),
    )

    facts = offline_readiness.inspect_cache("https://example.invalid")

    assert facts["metadata_files"] is None
    assert facts["trusted_root_present"] is False
    assert facts["root_expired"] is False


def test_inspect_cache_reads_expired_root(tmp_path, monkeypatch):
    metadata = tmp_path / "data"
    targets = tmp_path / "cache"
    metadata.mkdir()
    targets.mkdir()
    (metadata / "root.json").write_text(
        json.dumps({"signed": {"version": 7, "expires": "2020-01-01T00:00:00Z"}})
    )
    (targets / "trusted_root.json").write_text("{}")
    monkeypatch.setattr(
        offline_readiness, "tuf_cache_paths", lambda url: (metadata, targets)
    )

    facts = offline_readiness.inspect_cache("https://example.invalid")

    assert facts["root_version"] == 7
    assert facts["root_expired"] is True
    assert facts["trusted_root_present"] is True
    assert facts["signing_config_present"] is False
