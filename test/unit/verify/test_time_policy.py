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
from datetime import UTC, datetime, timedelta

import pytest
from sigstore_models.trustroot import v1 as trustroot_v1

from sigstore._internal.timestamp import TimestampSource, TimestampVerificationResult
from sigstore._internal.trust import CertificateAuthority
from sigstore.errors import VerificationError
from sigstore.models import Bundle, TrustedRoot
from sigstore.verify import Verifier
from sigstore.verify.policy import UnsafeNoOp
from sigstore.verify.time_policy import (
    ArtifactLevel,
    VerifiedTimeMaterials,
    VerifiedTimePolicy,
)

TSA_TIME = datetime(2024, 10, 31, 10, 23, 39, tzinfo=UTC)
TLOG_TIME = TSA_TIME


def _result(source: TimestampSource, time: datetime) -> TimestampVerificationResult:
    return TimestampVerificationResult(source=source, time=time)


@pytest.fixture
def offline_verifier(asset) -> Verifier:
    """
    A verifier built only from checked-in assets: the staging trust root in
    `tsa/trust_config.json`, plus the local test TSA in `tsa/ca.json`.
    """
    trust_config = json.loads(asset("tsa/trust_config.json").read_text())
    inner = trustroot_v1.TrustedRoot.from_json(
        json.dumps(trust_config["trustedRoot"]).encode()
    )
    trusted_root = TrustedRoot(inner)
    trusted_root._inner.timestamp_authorities.append(
        CertificateAuthority.from_json(asset("tsa/ca.json").as_posix())._inner
    )
    return Verifier(trusted_root=trusted_root)


def _genuine_materials(verifier: Verifier, bundle: Bundle):
    """Return the bundle's real verified time materials, freshly established."""
    return verifier._establish_time(bundle)


class TestVerifiedTimeMaterials:
    def test_repeated_source_counts_once(self):
        materials = VerifiedTimeMaterials(
            [
                _result(TimestampSource.TIMESTAMP_AUTHORITY, TSA_TIME),
                _result(TimestampSource.TIMESTAMP_AUTHORITY, TSA_TIME),
                _result(TimestampSource.TIMESTAMP_AUTHORITY, TSA_TIME),
            ]
        )

        assert len(materials) == 3
        assert materials.source_count == 1
        assert materials.sources == {TimestampSource.TIMESTAMP_AUTHORITY}
        assert (
            materials.times_for(TimestampSource.TIMESTAMP_AUTHORITY) == (TSA_TIME,) * 3
        )

    def test_distinct_sources(self):
        materials = VerifiedTimeMaterials(
            [
                _result(TimestampSource.TIMESTAMP_AUTHORITY, TSA_TIME),
                _result(TimestampSource.TRANSPARENCY_SERVICE, TLOG_TIME),
            ]
        )

        assert materials.source_count == 2
        assert materials.sources == {
            TimestampSource.TIMESTAMP_AUTHORITY,
            TimestampSource.TRANSPARENCY_SERVICE,
        }


class TestVerifiedTimePolicy:
    def test_empty_policy_is_rejected(self):
        with pytest.raises(ValueError, match="must require at least one source"):
            VerifiedTimePolicy()

    def test_negative_minimum_is_rejected(self):
        with pytest.raises(ValueError, match="non-negative"):
            VerifiedTimePolicy(minimum_sources=-1)

    def test_unknown_source_is_rejected(self):
        with pytest.raises(ValueError):
            VerifiedTimePolicy(required_sources=["not-a-source"])

    def test_ordinary_accepts_transparency_service(self):
        policy = VerifiedTimePolicy.ordinary()
        policy.verify([_result(TimestampSource.TRANSPARENCY_SERVICE, TLOG_TIME)])

    def test_ordinary_rejects_no_evidence(self):
        with pytest.raises(
            VerificationError, match="not enough sources of verified time"
        ):
            VerifiedTimePolicy.ordinary().verify([])

    def test_important_requires_timestamp_authority(self):
        with pytest.raises(
            VerificationError, match="missing required source.*timestamp_authority"
        ):
            VerifiedTimePolicy.important().verify(
                [_result(TimestampSource.TRANSPARENCY_SERVICE, TLOG_TIME)]
            )

    def test_important_accepts_timestamp_authority(self):
        VerifiedTimePolicy.important().verify(
            [_result(TimestampSource.TIMESTAMP_AUTHORITY, TSA_TIME)]
        )

    def test_important_does_not_treat_repeats_as_independent(self):
        # Three responses from the same source are one proof. The required
        # source is present, so this specific policy is satisfied, but a
        # requirement for two distinct sources is not.
        repeated = [
            _result(TimestampSource.TIMESTAMP_AUTHORITY, TSA_TIME),
        ] * 3
        VerifiedTimePolicy.important().verify(repeated)

        with pytest.raises(
            VerificationError, match="1 distinct source\\(s\\) present, 2 required"
        ):
            VerifiedTimePolicy.at_least(2).verify(repeated)

    def test_artifact_level_mapping(self):
        assert (
            VerifiedTimePolicy.for_artifact_level(
                ArtifactLevel.ORDINARY
            ).minimum_sources
            == 1
        )
        assert VerifiedTimePolicy.for_artifact_level("important").required_sources == {
            TimestampSource.TIMESTAMP_AUTHORITY
        }

        with pytest.raises(ValueError):
            VerifiedTimePolicy.for_artifact_level("nonexistent")

    def test_clock_rejects_future_evidence(self):
        policy = VerifiedTimePolicy.ordinary(
            clock=lambda: TSA_TIME - timedelta(minutes=1)
        )
        with pytest.raises(VerificationError, match="after the verification clock"):
            policy.verify([_result(TimestampSource.TRANSPARENCY_SERVICE, TLOG_TIME)])

    def test_clock_rejects_stale_evidence(self):
        policy = VerifiedTimePolicy.ordinary(
            clock=lambda: TSA_TIME + timedelta(hours=1), max_age=timedelta(minutes=30)
        )
        with pytest.raises(VerificationError, match="older than"):
            policy.verify([_result(TimestampSource.TRANSPARENCY_SERVICE, TLOG_TIME)])

    def test_naive_clock_is_rejected(self):
        policy = VerifiedTimePolicy.ordinary(clock=lambda: datetime(2024, 10, 31))
        with pytest.raises(ValueError, match="timezone-aware"):
            policy.verify([_result(TimestampSource.TRANSPARENCY_SERVICE, TLOG_TIME)])


class TestVerifierTimePolicy:
    def test_ordinary_artifact_accepts_transparency_log_confirmation(
        self, offline_verifier, asset
    ):
        bundle = Bundle.from_json(asset("bundle_v3.txt.sigstore").read_bytes())

        # This bundle contains no TSA timestamp at all: the integrated time in
        # the transparency log entry is its only verified time.
        offline_verifier.verify_artifact(
            asset("bundle_v3.txt").read_bytes(),
            bundle,
            UnsafeNoOp(),
            time_policy=VerifiedTimePolicy.for_artifact_level(ArtifactLevel.ORDINARY),
        )

        with pytest.raises(
            VerificationError, match="missing required source.*timestamp_authority"
        ):
            offline_verifier.verify_artifact(
                asset("bundle_v3.txt").read_bytes(),
                bundle,
                UnsafeNoOp(),
                time_policy=VerifiedTimePolicy.for_artifact_level(
                    ArtifactLevel.IMPORTANT
                ),
            )

    def test_important_artifact_accepts_approved_timestamp(
        self, offline_verifier, asset
    ):
        offline_verifier.verify_artifact(
            asset("tsa/bundle.txt").read_bytes(),
            Bundle.from_json(asset("tsa/bundle.txt.sigstore").read_bytes()),
            UnsafeNoOp(),
            time_policy=VerifiedTimePolicy.important(),
        )

    def test_controlled_clock_accepts_evidence_inside_certificate_validity(
        self, offline_verifier, asset
    ):
        bundle = Bundle.from_json(asset("tsa/bundle.txt.sigstore").read_bytes())
        cert = bundle.signing_certificate

        # The archive clock is deliberately later than the short-lived signing
        # certificate: what matters is that the verified time falls inside the
        # certificate's validity period, not the wall clock.
        clock = cert.not_valid_after_utc + timedelta(days=1)
        assert clock > cert.not_valid_after_utc > cert.not_valid_before_utc

        offline_verifier.verify_artifact(
            asset("tsa/bundle.txt").read_bytes(),
            bundle,
            UnsafeNoOp(),
            time_policy=VerifiedTimePolicy.important(clock=lambda: clock),
        )

    def test_controlled_clock_rejects_time_material_outside_policy(
        self, offline_verifier, asset
    ):
        bundle = Bundle.from_json(asset("tsa/bundle.txt.sigstore").read_bytes())

        # The certificate is valid at the evidence time, but the caller's
        # policy clock is before the evidence: the archival service is being
        # asked to accept a signature that is not yet valid at its own clock.
        clock = TSA_TIME - timedelta(minutes=5)
        with pytest.raises(VerificationError, match="after the verification clock"):
            offline_verifier.verify_artifact(
                asset("tsa/bundle.txt").read_bytes(),
                bundle,
                UnsafeNoOp(),
                time_policy=VerifiedTimePolicy.important(clock=lambda: clock),
            )

    def test_certificate_valid_but_other_time_material_rejected(
        self, offline_verifier, asset
    ):
        """
        A worked example for an archival service.

        The signing certificate is valid at the bundle's verified signing time,
        so an ordinary build is accepted. The same bundle's time material then
        fails an important build's policy: at the archival clock the evidence
        is older than the policy's max age. The certificate itself is still
        valid at the evidence's time; it is the policy on the time material
        that rejects the artifact.
        """
        bundle = Bundle.from_json(asset("tsa/bundle.txt.sigstore").read_bytes())
        input_ = asset("tsa/bundle.txt").read_bytes()
        cert = bundle.signing_certificate

        # Both sources agree that signing happened inside the certificate's
        # 10-minute validity window.
        materials = _genuine_materials(offline_verifier, bundle)
        assert {result.source for result in materials} == {
            TimestampSource.TRANSPARENCY_SERVICE,
            TimestampSource.TIMESTAMP_AUTHORITY,
        }
        for result in materials:
            assert cert.not_valid_before_utc <= result.time <= cert.not_valid_after_utc

        # Ordinary builds only need transparency log confirmation, so this
        # bundle is accepted.
        offline_verifier.verify_artifact(
            input_,
            bundle,
            UnsafeNoOp(),
            time_policy=VerifiedTimePolicy.ordinary(
                clock=lambda: cert.not_valid_after_utc
            ),
        )

        # An important build evaluates the same bundle a while later, with a
        # one-hour freshness requirement. The certificate is still valid where
        # the evidence points, but the evidence itself is stale for the archive.
        archive_clock = cert.not_valid_after_utc + timedelta(hours=2)
        with pytest.raises(
            VerificationError,
            match="timestamp_authority is older than 1:00:00",
        ):
            offline_verifier.verify_artifact(
                input_,
                bundle,
                UnsafeNoOp(),
                time_policy=VerifiedTimePolicy.important(
                    clock=lambda: archive_clock, max_age=timedelta(hours=1)
                ),
            )

    def test_repeated_timestamps_are_not_independent_proofs(
        self, offline_verifier, asset, monkeypatch
    ):
        bundle = Bundle.from_json(asset("tsa/bundle.txt.sigstore").read_bytes())
        materials = _genuine_materials(offline_verifier, bundle)
        input_ = asset("tsa/bundle.txt").read_bytes()

        # The genuine bundle has two distinct sources: the transparency
        # service's integrated time and the approved TSA timestamp.
        assert {result.source for result in materials} == {
            TimestampSource.TRANSPARENCY_SERVICE,
            TimestampSource.TIMESTAMP_AUTHORITY,
        }
        offline_verifier.verify_artifact(
            input_,
            bundle,
            UnsafeNoOp(),
            time_policy=VerifiedTimePolicy.at_least(2),
        )

        # Re-supplying the same source's material (even with a different
        # claimed time) is still one proof, so a two-source requirement fails.
        tsa_result = next(
            result
            for result in materials
            if result.source is TimestampSource.TIMESTAMP_AUTHORITY
        )
        repeated = [
            tsa_result,
            TimestampVerificationResult(
                source=TimestampSource.TIMESTAMP_AUTHORITY,
                time=tsa_result.time + timedelta(seconds=1),
            ),
        ]
        monkeypatch.setattr(offline_verifier, "_establish_time", lambda _: repeated)

        # Important builds only require one approved timestamp, so they are
        # still satisfied by this single source.
        offline_verifier.verify_artifact(
            input_,
            bundle,
            UnsafeNoOp(),
            time_policy=VerifiedTimePolicy.important(),
        )

        with pytest.raises(
            VerificationError, match="1 distinct source\\(s\\) present, 2 required"
        ):
            offline_verifier.verify_artifact(
                input_,
                bundle,
                UnsafeNoOp(),
                time_policy=VerifiedTimePolicy.at_least(2),
            )
