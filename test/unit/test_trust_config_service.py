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

import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from demo.trust_config_service import (
    ArtifactVerificationError,
    ConfigUnavailableError,
    ConfigValidationError,
    TrustConfigManager,
    VerificationService,
)

PREVIEW = "preview"
RELEASE = "release"


def _key():
    return Ed25519PrivateKey.generate()


def _write_config(directory, name, environment, version, keys):
    path = directory / name
    path.write_text(
        json.dumps(
            {
                "environment": environment,
                "version": version,
                "roots": [
                    {"key_id": key_id, "public_key": key.public_key().public_bytes_raw().hex()}
                    for key_id, key in keys.items()
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _write_artifact(directory, name, key_id, key, payload="payload"):
    path = directory / name
    path.write_text(
        json.dumps(
            {
                "payload": payload,
                "key_id": key_id,
                "signature": key.sign(payload.encode("utf-8")).hex(),
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def keys():
    return {
        "preview_v1": _key(),
        "preview_v2": _key(),
        "release": _key(),
    }


@pytest.fixture
def configs(tmp_path, keys):
    return {
        "preview_v1": _write_config(
            tmp_path, "preview-v1.json", PREVIEW, 1, {"p1": keys["preview_v1"]}
        ),
        "preview_v2": _write_config(
            tmp_path, "preview-v2.json", PREVIEW, 2, {"p2": keys["preview_v2"]}
        ),
        "release_v1": _write_config(
            tmp_path, "release-v1.json", RELEASE, 1, {"r1": keys["release"]}
        ),
    }


@pytest.fixture
def artifacts(tmp_path, keys):
    return {
        "preview_v1": _write_artifact(
            tmp_path, "artifact-preview-v1.json", "p1", keys["preview_v1"]
        ),
        "preview_v2": _write_artifact(
            tmp_path, "artifact-preview-v2.json", "p2", keys["preview_v2"]
        ),
        "release": _write_artifact(
            tmp_path, "artifact-release.json", "r1", keys["release"]
        ),
    }


@pytest.fixture
def manager(configs):
    manager = TrustConfigManager()
    manager.load(configs["preview_v1"])
    manager.load(configs["release_v1"])
    return manager


@pytest.fixture
def service(manager):
    return VerificationService(manager)


class TestLoadAndVerify:
    def test_both_environments_verify(self, service, manager, artifacts):
        result = service.verify(PREVIEW, artifacts["preview_v1"])
        assert (result.environment, result.config_version, result.key_id) == (
            PREVIEW,
            1,
            "p1",
        )
        result = service.verify(RELEASE, artifacts["release"])
        assert (result.environment, result.config_version, result.key_id) == (
            RELEASE,
            1,
            "r1",
        )
        assert manager.current_version(PREVIEW) == 1
        assert manager.current_version(RELEASE) == 1

    def test_double_load_rejected(self, manager, configs):
        with pytest.raises(ConfigValidationError, match="already loaded"):
            manager.load(configs["preview_v1"])

    def test_bad_signature_rejected(self, service, tmp_path, keys):
        artifact = _write_artifact(
            tmp_path, "forged.json", "p1", keys["release"], "forged"
        )
        with pytest.raises(ArtifactVerificationError, match="signature"):
            service.verify(PREVIEW, artifact)


class TestUpdate:
    def test_successful_update(self, service, manager, configs, artifacts):
        manager.update(PREVIEW, configs["preview_v2"])
        assert manager.current_version(PREVIEW) == 2
        assert manager.current_version(RELEASE) == 1
        result = service.verify(PREVIEW, artifacts["preview_v2"])
        assert result.config_version == 2
        # The rotated-out key no longer verifies new one-shot checks.
        with pytest.raises(ArtifactVerificationError, match="not trusted"):
            service.verify(PREVIEW, artifacts["preview_v1"])

    def test_identity_mismatch_rejected(self, manager, configs):
        with pytest.raises(ConfigValidationError, match="does not match"):
            manager.update(PREVIEW, configs["release_v1"])
        assert manager.current_version(PREVIEW) == 1

    def test_stale_version_rejected(self, manager, configs):
        with pytest.raises(ConfigValidationError, match="does not advance"):
            manager.update(PREVIEW, configs["preview_v1"])
        assert manager.current_version(PREVIEW) == 1

    @pytest.mark.parametrize(
        "config",
        [
            {"environment": PREVIEW, "version": 2, "roots": []},
            {"environment": PREVIEW, "version": "2", "roots": [{"key_id": "x"}]},
            {"environment": "", "version": 2, "roots": [{"key_id": "x"}]},
            {
                "environment": PREVIEW,
                "version": 2,
                "roots": [{"key_id": "x", "public_key": "zz"}],
            },
            {
                "environment": PREVIEW,
                "version": 2,
                "roots": [{"key_id": "x", "public_key": "00" * 16}],
            },
        ],
        ids=["empty-roots", "version-type", "empty-env", "bad-hex", "short-key"],
    )
    def test_invalid_configs_rejected(self, manager, tmp_path, config):
        path = tmp_path / "bad.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        with pytest.raises(ConfigValidationError):
            manager.update(PREVIEW, path)
        assert manager.current_version(PREVIEW) == 1

    def test_missing_file_rejected(self, manager, tmp_path):
        with pytest.raises(ConfigValidationError, match="cannot load"):
            manager.update(PREVIEW, tmp_path / "nonexistent.json")
        assert manager.current_version(PREVIEW) == 1

    def test_update_unknown_environment(self, manager, configs):
        with pytest.raises(ConfigUnavailableError):
            manager.update("staging", configs["preview_v2"])


class TestInterleaving:
    def test_in_flight_session_keeps_its_snapshot(
        self, service, manager, configs, artifacts
    ):
        session = service.begin(PREVIEW)
        assert session.config_version == 1

        manager.update(PREVIEW, configs["preview_v2"])
        assert manager.current_version(PREVIEW) == 2

        # The started session still verifies with v1 root material.
        result = session.verify(artifacts["preview_v1"])
        assert result.config_version == 1
        with pytest.raises(ArtifactVerificationError, match="not trusted"):
            session.verify(artifacts["preview_v2"])

        # New verifications see the swapped-in config.
        result = service.verify(PREVIEW, artifacts["preview_v2"])
        assert result.config_version == 2

    def test_concurrent_sessions_across_swap(
        self, service, manager, configs, artifacts
    ):
        import threading

        manager.update(PREVIEW, configs["preview_v2"])
        started = threading.Event()
        swap = threading.Event()
        outcomes = {}

        def slow_verify():
            session = service.begin(PREVIEW)
            started.set()
            swap.wait(timeout=5)
            outcomes["slow"] = session.verify(artifacts["preview_v2"])

        thread = threading.Thread(target=slow_verify)
        thread.start()
        assert started.wait(timeout=5)

        preview_v3 = configs["preview_v2"].parent / "preview-v3.json"
        preview_v3.write_text(
            json.dumps(
                {
                    "environment": PREVIEW,
                    "version": 3,
                    "roots": [
                        {
                            "key_id": "p1",
                            "public_key": Ed25519PrivateKey.generate()
                            .public_key()
                            .public_bytes_raw()
                            .hex(),
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        manager.update(PREVIEW, preview_v3)
        swap.set()
        thread.join(timeout=5)

        assert outcomes["slow"].config_version == 2
        assert manager.current_version(PREVIEW) == 3


class TestNoCrossEnvironmentFallback:
    def test_unavailable_config_never_borrows(self, configs, artifacts):
        manager = TrustConfigManager()
        manager.load(configs["release_v1"])
        service = VerificationService(manager)
        with pytest.raises(ConfigUnavailableError, match=PREVIEW):
            service.verify(PREVIEW, artifacts["preview_v1"])
        with pytest.raises(ConfigUnavailableError, match=PREVIEW):
            manager.current_version(PREVIEW)

    def test_other_environments_keys_not_trusted(self, service, artifacts):
        with pytest.raises(ArtifactVerificationError, match="not trusted"):
            service.verify(PREVIEW, artifacts["release"])
        with pytest.raises(ArtifactVerificationError, match="not trusted"):
            service.verify(RELEASE, artifacts["preview_v1"])
