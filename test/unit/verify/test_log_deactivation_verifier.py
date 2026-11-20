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
End-to-end, fully offline tests for the transparency log deactivation policy.

These tests exercise the same fixed deactivation point against two offline log
materials:

* a Rekor v1 bundle (inclusion promise + integrated time, no RFC 3161 timestamp)
* a Rekor v2 bundle (inclusion proof + RFC 3161 timestamp, no integrated time)
"""

from datetime import UTC, datetime, timedelta

import pytest

from sigstore.errors import VerificationError
from sigstore.models import Bundle
from sigstore.verify import (
    AcceptedMaterial,
    LogDeactivation,
    LogDeactivationPolicy,
    LogMaterial,
)
from sigstore.verify.verifier import Verifier

# A fixed trusted "now", deliberately later than the deactivation point so that
# the old log is retired for every test unless a case says otherwise.
REFERENCE_TIME = datetime(2026, 11, 20, tzinfo=UTC)
DEACTIVATION_AT = datetime(2026, 1, 1, tzinfo=UTC)
WINDOW_START = datetime(2024, 1, 1, tzinfo=UTC)


class _NullPolicy:
    def verify(self, cert):
        return None


@pytest.fixture
def offline_verifier() -> Verifier:
    # Trust root comes from the embedded/TUF-cached materials; no network.
    return Verifier.staging(offline=True)


@pytest.fixture
def v1_bundle(asset) -> Bundle:
    return Bundle.from_json(asset("bundle_v3.txt.sigstore").read_bytes())


@pytest.fixture
def v2_bundle(asset) -> Bundle:
    return Bundle.from_json(asset("staging-rekor-v2.txt.sigstore.json").read_bytes())


def _material(verifier: Verifier, bundle: Bundle) -> LogMaterial:
    return LogMaterial.from_bundle(bundle, verifier._establish_time(bundle))


def _policy(log_id: bytes, *, reference_time=REFERENCE_TIME) -> LogDeactivationPolicy:
    return LogDeactivationPolicy(
        [
            LogDeactivation(
                log_id=log_id,
                deactivated_at=DEACTIVATION_AT,
                historical_window_start=WINDOW_START,
            )
        ],
        reference_time=reference_time,
    )


class TestOfflineDeactivationPoint:
    def test_old_v1_material_accepted_only_as_historical(
        self, offline_verifier, v1_bundle, asset
    ):
        material = _material(offline_verifier, v1_bundle)
        verifier = Verifier(
            trusted_root=offline_verifier._trusted_root,
            log_policy=_policy(material.log_id),
        )

        receipt = verifier.verify_artifact_with_receipt(
            asset("bundle_v3.txt").read_bytes(), v1_bundle, _NullPolicy()
        )

        assert receipt is not None
        assert receipt.accepted_material is AcceptedMaterial.RETIRED_LOG_HISTORICAL
        assert receipt.log_version == 1
        assert receipt.entry_time < DEACTIVATION_AT
        assert receipt.historical_window_start == WINDOW_START
        # the receipt must say which material was actually accepted
        assert "deactivated Rekor v1" in receipt.describe()

    def test_new_v2_material_accepted_from_current_log(
        self, offline_verifier, v2_bundle, asset
    ):
        # Deactivate the *v1* log; the v2 bundle is on a different, current log.
        v1_material = _material(
            offline_verifier,
            Bundle.from_json(asset("bundle_v3.txt.sigstore").read_bytes()),
        )
        verifier = Verifier(
            trusted_root=offline_verifier._trusted_root,
            log_policy=_policy(v1_material.log_id),
        )

        receipt = verifier.verify_artifact_with_receipt(
            asset("staging-rekor-v2.txt").read_bytes(), v2_bundle, _NullPolicy()
        )

        assert receipt is not None
        assert receipt.accepted_material is AcceptedMaterial.CURRENT_LOG
        assert receipt.log_version == 2
        assert "current Rekor v2" in receipt.describe()

    def test_same_deactivation_point_judges_both_materials(
        self, offline_verifier, v1_bundle, v2_bundle, asset
    ):
        v1_material = _material(offline_verifier, v1_bundle)
        verifier = Verifier(
            trusted_root=offline_verifier._trusted_root,
            log_policy=_policy(v1_material.log_id),
        )

        v1_receipt = verifier.verify_artifact_with_receipt(
            asset("bundle_v3.txt").read_bytes(), v1_bundle, _NullPolicy()
        )
        v2_receipt = verifier.verify_artifact_with_receipt(
            asset("staging-rekor-v2.txt").read_bytes(), v2_bundle, _NullPolicy()
        )

        # one policy, one fixed reference/deactivation time, two distinct verdicts
        assert v1_receipt.reference_time == v2_receipt.reference_time == REFERENCE_TIME
        assert v1_receipt.accepted_material is AcceptedMaterial.RETIRED_LOG_HISTORICAL
        assert v2_receipt.accepted_material is AcceptedMaterial.CURRENT_LOG

    def test_v1_material_rejected_when_window_starts_after_it(
        self, offline_verifier, v1_bundle, asset
    ):
        material = _material(offline_verifier, v1_bundle)
        late_window = LogDeactivationPolicy(
            [
                LogDeactivation(
                    log_id=material.log_id,
                    deactivated_at=DEACTIVATION_AT,
                    historical_window_start=material.entry_time + timedelta(days=1),
                )
            ],
            reference_time=REFERENCE_TIME,
        )
        verifier = Verifier(
            trusted_root=offline_verifier._trusted_root, log_policy=late_window
        )

        with pytest.raises(
            VerificationError, match="before the approved historical window"
        ):
            verifier.verify_artifact(
                asset("bundle_v3.txt").read_bytes(), v1_bundle, _NullPolicy()
            )

    def test_deactivating_the_v2_log_rejects_v2_material_at_or_after_cutoff(
        self, offline_verifier, v2_bundle, asset
    ):
        material = _material(offline_verifier, v2_bundle)
        # Put the deactivation point before the v2 entry's authenticated time:
        # a "new" artifact must never be accepted off a log that was already
        # supposed to be shut down.
        impossible = LogDeactivationPolicy(
            [
                LogDeactivation(
                    log_id=material.log_id,
                    deactivated_at=material.entry_time - timedelta(days=1),
                    historical_window_start=WINDOW_START,
                )
            ],
            reference_time=REFERENCE_TIME,
        )
        verifier = Verifier(
            trusted_root=offline_verifier._trusted_root, log_policy=impossible
        )

        with pytest.raises(
            VerificationError, match="at or after the deactivation point"
        ):
            verifier.verify_artifact(
                asset("staging-rekor-v2.txt").read_bytes(),
                v2_bundle,
                _NullPolicy(),
            )

    def test_coexistence_phase_accepts_old_log_as_current(
        self, offline_verifier, v1_bundle, asset
    ):
        material = _material(offline_verifier, v1_bundle)
        coexistence = LogDeactivationPolicy(
            [
                LogDeactivation(
                    log_id=material.log_id,
                    deactivated_at=DEACTIVATION_AT,
                    historical_window_start=WINDOW_START,
                )
            ],
            # trusted time is still before the deactivation point
            reference_time=DEACTIVATION_AT - timedelta(days=1),
        )
        verifier = Verifier(
            trusted_root=offline_verifier._trusted_root, log_policy=coexistence
        )

        receipt = verifier.verify_artifact_with_receipt(
            asset("bundle_v3.txt").read_bytes(), v1_bundle, _NullPolicy()
        )
        assert receipt.accepted_material is AcceptedMaterial.CURRENT_LOG


class TestVerifierWiring:
    def test_policy_referencing_unknown_log_is_rejected(self, offline_verifier):
        policy = LogDeactivationPolicy(
            [LogDeactivation(bytes([0x11]) * 32, DEACTIVATION_AT)],
            reference_time=REFERENCE_TIME,
        )
        with pytest.raises(VerificationError, match="absent from the trusted root"):
            Verifier(trusted_root=offline_verifier._trusted_root, log_policy=policy)

    def test_per_call_policy_referencing_unknown_log_is_rejected(
        self, offline_verifier, v1_bundle, asset
    ):
        policy = LogDeactivationPolicy(
            [LogDeactivation(bytes([0x22]) * 32, DEACTIVATION_AT)],
            reference_time=REFERENCE_TIME,
        )
        with pytest.raises(VerificationError, match="absent from the trusted root"):
            offline_verifier.verify_artifact_with_receipt(
                asset("bundle_v3.txt").read_bytes(),
                v1_bundle,
                _NullPolicy(),
                log_policy=policy,
            )

    def test_without_log_policy_methods_keep_original_contract(
        self, offline_verifier, v1_bundle, asset
    ):
        # Backwards compatibility: no policy configured -> verify_artifact still
        # returns None and the receipt API returns None.
        assert offline_verifier._log_policy is None
        assert (
            offline_verifier.verify_artifact_with_receipt(
                asset("bundle_v3.txt").read_bytes(), v1_bundle, _NullPolicy()
            )
            is None
        )
        offline_verifier.verify_artifact(
            asset("bundle_v3.txt").read_bytes(), v1_bundle, _NullPolicy()
        )

    def test_per_call_log_policy_overrides_verifier_default(
        self, offline_verifier, v2_bundle, asset
    ):
        # No policy on the verifier itself; supply one per call instead.
        material = _material(offline_verifier, v2_bundle)
        policy = LogDeactivationPolicy(
            [
                LogDeactivation(
                    log_id=material.log_id,
                    deactivated_at=DEACTIVATION_AT,
                    historical_window_start=WINDOW_START,
                )
            ],
            reference_time=REFERENCE_TIME,
        )
        receipt = offline_verifier.verify_artifact_with_receipt(
            asset("staging-rekor-v2.txt").read_bytes(),
            v2_bundle,
            _NullPolicy(),
            log_policy=policy,
        )
        # v2 entry (2025) is inside the historical window -> retired-historical
        assert receipt.accepted_material is AcceptedMaterial.RETIRED_LOG_HISTORICAL
        assert receipt.log_version == 2
