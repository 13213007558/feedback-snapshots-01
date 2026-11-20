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

from dataclasses import asdict
from datetime import UTC, datetime, timedelta

import pytest

from sigstore.errors import VerificationError
from sigstore.verify.log_policy import (
    AcceptedMaterial,
    LogDeactivation,
    LogDeactivationPolicy,
    LogMaterial,
)

V1_LOG_ID = bytes.fromhex("d3" * 32)
V2_LOG_ID = bytes.fromhex("f3" * 32)
OTHER_LOG_ID = bytes.fromhex("aa" * 32)

REFERENCE_TIME = datetime(2026, 11, 20, tzinfo=UTC)
DEACTIVATION = datetime(2026, 1, 1, tzinfo=UTC)
WINDOW_START = datetime(2024, 1, 1, tzinfo=UTC)


def _material(
    log_id: bytes = V1_LOG_ID,
    *,
    log_version: int = 1,
    entry_kind: str = "hashedrekord/0.0.1",
    entry_time: datetime | None = None,
) -> LogMaterial:
    if entry_time is None:
        entry_time = WINDOW_START + timedelta(days=100)
    return LogMaterial(
        log_id=log_id,
        log_version=log_version,
        entry_kind=entry_kind,
        entry_time=entry_time,
    )


def _policy(**kwargs) -> LogDeactivationPolicy:
    deactivation = kwargs.pop(
        "deactivation",
        LogDeactivation(
            log_id=V1_LOG_ID,
            deactivated_at=DEACTIVATION,
            historical_window_start=WINDOW_START,
        ),
    )
    return LogDeactivationPolicy(
        [deactivation], reference_time=REFERENCE_TIME, **kwargs
    )


class TestLogDeactivation:
    def test_rejects_naive_deactivation_time(self):
        with pytest.raises(ValueError, match="timezone-aware"):
            LogDeactivation(
                log_id=V1_LOG_ID,
                deactivated_at=datetime(2026, 1, 1),
            )

    def test_rejects_naive_window_start(self):
        with pytest.raises(ValueError, match="timezone-aware"):
            LogDeactivation(
                log_id=V1_LOG_ID,
                deactivated_at=DEACTIVATION,
                historical_window_start=datetime(2024, 1, 1),
            )

    def test_rejects_window_after_deactivation(self):
        with pytest.raises(ValueError, match="must not be later"):
            LogDeactivation(
                log_id=V1_LOG_ID,
                deactivated_at=DEACTIVATION,
                historical_window_start=DEACTIVATION + timedelta(days=1),
            )


class TestLogDeactivationPolicy:
    def test_rejects_naive_reference_time(self):
        with pytest.raises(ValueError, match="timezone-aware"):
            LogDeactivationPolicy([], reference_time=datetime(2026, 11, 20))

    def test_rejects_duplicate_log_deactivation(self):
        deactivation = LogDeactivation(V1_LOG_ID, DEACTIVATION)
        with pytest.raises(ValueError, match="only be deactivated once"):
            LogDeactivationPolicy(
                [deactivation, deactivation], reference_time=REFERENCE_TIME
            )

    def test_unknown_log_is_treated_as_current(self):
        receipt = _policy().evaluate(_material(log_id=OTHER_LOG_ID, log_version=2))
        assert receipt.accepted_material is AcceptedMaterial.CURRENT_LOG
        assert receipt.deactivated_at is None

    def test_v2_log_accepted_as_current_after_deactivation(self):
        receipt = _policy().evaluate(
            _material(
                log_id=V2_LOG_ID,
                log_version=2,
                entry_kind="hashedrekord/0.0.2",
                entry_time=REFERENCE_TIME - timedelta(days=1),
            )
        )
        assert receipt.accepted_material is AcceptedMaterial.CURRENT_LOG
        assert receipt.log_version == 2

    def test_retired_log_accepted_inside_historical_window(self):
        entry_time = DEACTIVATION - timedelta(days=1)
        receipt = _policy().evaluate(_material(entry_time=entry_time))

        assert receipt.accepted_material is AcceptedMaterial.RETIRED_LOG_HISTORICAL
        assert receipt.log_id == V1_LOG_ID.hex()
        assert receipt.entry_time == entry_time
        assert receipt.reference_time == REFERENCE_TIME
        assert receipt.deactivated_at == DEACTIVATION
        assert receipt.historical_window_start == WINDOW_START
        assert "deactivated" in receipt.describe()

    def test_retired_log_boundary_entry_below_deactivation_is_accepted(self):
        receipt = _policy().evaluate(
            _material(entry_time=DEACTIVATION - timedelta(seconds=1))
        )
        assert receipt.accepted_material is AcceptedMaterial.RETIRED_LOG_HISTORICAL

    def test_retired_log_entry_at_deactivation_point_is_rejected(self):
        with pytest.raises(
            VerificationError, match="at or after the deactivation point"
        ):
            _policy().evaluate(_material(entry_time=DEACTIVATION))

    def test_retired_log_entry_after_deactivation_is_rejected(self):
        with pytest.raises(
            VerificationError, match="at or after the deactivation point"
        ):
            _policy().evaluate(_material(entry_time=DEACTIVATION + timedelta(days=1)))

    def test_retired_log_entry_before_window_start_is_rejected(self):
        with pytest.raises(
            VerificationError, match="before the approved historical window"
        ):
            _policy().evaluate(
                _material(entry_time=WINDOW_START - timedelta(seconds=1))
            )

    def test_window_start_boundary_is_accepted(self):
        receipt = _policy().evaluate(_material(entry_time=WINDOW_START))
        assert receipt.accepted_material is AcceptedMaterial.RETIRED_LOG_HISTORICAL

    def test_policy_without_window_start_accepts_any_old_entry(self):
        policy = LogDeactivationPolicy(
            [LogDeactivation(log_id=V1_LOG_ID, deactivated_at=DEACTIVATION)],
            reference_time=REFERENCE_TIME,
        )
        receipt = policy.evaluate(
            _material(entry_time=datetime(2000, 1, 1, tzinfo=UTC))
        )
        assert receipt.accepted_material is AcceptedMaterial.RETIRED_LOG_HISTORICAL
        assert receipt.historical_window_start is None

    def test_coexistence_phase_treats_retiring_log_as_current(self):
        # Before the deactivation point the old log is still active, even for
        # freshly produced entries.
        policy = LogDeactivationPolicy(
            [
                LogDeactivation(
                    log_id=V1_LOG_ID,
                    deactivated_at=DEACTIVATION,
                    historical_window_start=WINDOW_START,
                )
            ],
            reference_time=DEACTIVATION - timedelta(days=1),
        )
        receipt = policy.evaluate(
            _material(entry_time=DEACTIVATION - timedelta(days=2))
        )
        assert receipt.accepted_material is AcceptedMaterial.CURRENT_LOG

    def test_receipt_is_serializable_and_names_accepted_material(self):
        receipt = _policy().evaluate(
            _material(entry_time=DEACTIVATION - timedelta(days=1))
        )
        serialized = asdict(receipt)
        assert serialized["accepted_material"] == "retired_log_historical"
        assert isinstance(serialized["entry_time"], datetime)
        assert receipt.describe().startswith("accepted historical entry")

    def test_current_log_receipt_description(self):
        receipt = _policy().evaluate(_material(log_id=V2_LOG_ID, log_version=2))
        assert receipt.describe().startswith("accepted entry on current Rekor v2 log")


class TestLogMaterialVersionMapping:
    @pytest.mark.parametrize("kind_version,expected", [("0.0.1", 1), ("0.0.2", 2)])
    def test_kind_version_mapping(self, kind_version, expected):
        material = _material(entry_kind=f"hashedrekord/{kind_version}")
        # Rebuild through the same mapping the bundle factory uses.
        from sigstore.verify.log_policy import _log_version_from_kind

        assert _log_version_from_kind(kind_version) == expected
        assert material.entry_kind.endswith(kind_version)

    def test_unknown_kind_version_rejected(self):
        from sigstore.verify.log_policy import _log_version_from_kind

        with pytest.raises(VerificationError, match="unsupported transparency log"):
            _log_version_from_kind("0.0.3")
