# Copyright 2022 The Sigstore Authors
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
from base64 import b64encode

import pytest
from sigstore_models.bundle.v1 import Bundle as _Bundle
from sigstore_models.rekor.v1 import KindVersion
from sigstore_models.rekor.v1 import TransparencyLogEntry as _TransparencyLogEntry

from sigstore.errors import (
    BundleErrorCategory,
    MissingMaterialError,
    UnsupportedClientError,
    VerificationError,
    error_category,
)
from sigstore.models import (
    Bundle,
    IncompatibleEntry,
    InvalidBundle,
    MissingBundleMaterial,
    TimestampVerificationData,
    TransparencyLogEntry,
    UnsupportedBundleVersion,
    VerificationMaterial,
)


class TestTransparencyLogEntry:
    @pytest.mark.parametrize("integrated_time", [0, 1746819403])
    def test_missing_inclusion_proof(self, integrated_time: int):
        with pytest.raises(ValueError, match=r"inclusion_proof"):
            TransparencyLogEntry(
                _TransparencyLogEntry(
                    kind_version=KindVersion(kind="hashedrekord", version="fake"),
                    canonicalized_body=b64encode(b"fake"),
                    integrated_time=integrated_time,
                    log_id="1234",
                    log_index=1,
                    inclusion_proof=None,
                    inclusion_promise=None,
                )
            )

    # def test_missing_inclusion_promise_and_integrated_time_round_trip(
    #     self, signing_bundle
    # ):
    #     """
    #     Ensures that LogEntry._to_rekor() succeeds even without an inclusion_promise and integrated_time.
    #     """
    #     bundle: Bundle
    #     _, bundle = signing_bundle("bundle.txt")
    #     _dict = bundle.log_entry._to_rekor().to_dict()
    #     print(_dict)
    #     del _dict["inclusionPromise"]
    #     del _dict["integratedTime"]
    #     entry = LogEntry._from_dict_rekor(_dict)
    #     assert entry.inclusion_promise is None
    #     assert entry._to_rekor() is not None
    #     assert LogEntry._from_dict_rekor(entry._to_rekor().to_dict()) == entry

    def test_logentry_roundtrip(self, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")

        assert (
            TransparencyLogEntry(
                _TransparencyLogEntry.from_dict(bundle.log_entry._inner.to_dict())
            )
            == bundle.log_entry
        )


class TestTimestampVerificationData:
    """
    Tests for the `TimestampVerificationData` wrapper model.
    """

    def test_valid_timestamp(self, asset):
        timestamp = {
            "rfc3161Timestamps": [
                {
                    "signedTimestamp": "MIIEgTADAgEAMIIEeAYJKoZIhvcNAQcCoIIEaTCCBGUCAQMxDTALBglghkgBZQMEAgEwgc8GCyqGSIb3DQEJEAEEoIG/BIG8MIG5AgEBBgkrBgEEAYO/MAIwMTANBglghkgBZQMEAgEFAAQgyGobd7rprYIL0JTus5EpEb7jrrecS+cMbb42ftjtm+UCFBV/kwOOwt0tdtYXK1FGhXf7W4oFGA8yMDI0MTAyMjA3MzEwNVowAwIBAQIUTo190a2ixXglxLh7KJcwj6B4kf+gNKQyMDAxDjAMBgNVBAoTBWxvY2FsMR4wHAYDVQQDExVUZXN0IFRTQSBUaW1lc3RhbXBpbmegggHRMIIBzTCCAXKgAwIBAgIUIYzlmDAtGrQ5jmcZpeAN0Wyj8Q8wCgYIKoZIzj0EAwIwMDEOMAwGA1UEChMFbG9jYWwxHjAcBgNVBAMTFVRlc3QgVFNBIEludGVybWVkaWF0ZTAeFw0yNDEwMjIwNzIyNTNaFw0zMzEwMjIwNzI1NTNaMDAxDjAMBgNVBAoTBWxvY2FsMR4wHAYDVQQDExVUZXN0IFRTQSBUaW1lc3RhbXBpbmcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQBhKWvDUj1+VFrWudnWIRzAug99WAydJuyF9pxneWppyXbjio3RSoNBvhg+91eeue7GpRQx5ZoxdeiHJD5p7Z0o2owaDAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFD7JreyIuE9lHC9k+cFePRXIPdNaMB8GA1UdIwQYMBaAFJMEP2b7r8olhCtvCokuFyTMC0nOMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMAoGCCqGSM49BAMCA0kAMEYCIQC69iKNrM4N2/OHksX7zEJM7ImGR+Puq7ALM8l3+riChgIhAKbEWTmifAE6VaQwnL0NNTJskSgk6r8BzvbJtJEZpk6fMYIBqDCCAaQCAQEwSDAwMQ4wDAYDVQQKEwVsb2NhbDEeMBwGA1UEAxMVVGVzdCBUU0EgSW50ZXJtZWRpYXRlAhQhjOWYMC0atDmOZxml4A3RbKPxDzALBglghkgBZQMEAgGggfMwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNDEwMjIwNzMxMDVaMC8GCSqGSIb3DQEJBDEiBCBr9fx6gIRsipdGxMDIw1tpvHUv3y10SHUzEM+HHP15+DCBhQYLKoZIhvcNAQkQAi8xdjB0MHIwcAQg2PR1japGgjWt7Cd0jQJrSYlYTblz/UeoJw0LkbqIsSIwTDA0pDIwMDEOMAwGA1UEChMFbG9jYWwxHjAcBgNVBAMTFVRlc3QgVFNBIEludGVybWVkaWF0ZQIUIYzlmDAtGrQ5jmcZpeAN0Wyj8Q8wCgYIKoZIzj0EAwIERjBEAiBDfeCcnA1qIlHfMK/u3FZ1HtS9840NnXXaRdMD4R7MywIgZfoBiAMV3SFqO71+eo2kD9oBkW49Pb9eoQs00nOlvn8="
                }
            ]
        }

        timestamp_verification = TimestampVerificationData.from_json(
            json.dumps(timestamp)
        )

        assert timestamp_verification.rfc3161_timestamps

    def test_no_timestamp(self, asset):
        timestamp = {"rfc3161Timestamps": []}
        timestamp_verification = TimestampVerificationData.from_json(
            json.dumps(timestamp)
        )

        assert not timestamp_verification.rfc3161_timestamps

    def test_invalid_timestamp(self, asset):
        timestamp = {"rfc3161Timestamps": [{"signedTimestamp": "invalid-entry"}]}
        with pytest.raises(VerificationError, match="Invalid Timestamp"):
            TimestampVerificationData.from_json(json.dumps(timestamp))


class TestVerificationMaterial:
    """
    Tests for the `VerificationMaterial` wrapper model.
    """

    def test_valid_verification_material(self, asset):
        bundle = Bundle.from_json(asset("bundle.txt.sigstore").read_bytes())

        verification_material = VerificationMaterial(
            bundle._inner.verification_material
        )
        assert verification_material


class TestBundle:
    """
    Tests for the `Bundle` wrapper model.
    """

    def test_invalid_bundle_version(self, signing_bundle):
        with pytest.raises(InvalidBundle, match="failed to load bundle"):
            signing_bundle("bundle_invalid_version.txt")

    def test_invalid_empty_cert_chain(self, signing_bundle):
        with pytest.raises(
            InvalidBundle, match="expected non-empty certificate chain in bundle"
        ):
            signing_bundle("bundle_no_cert_v1.txt")

    def test_invalid_no_log_entry(self, signing_bundle):
        with pytest.raises(
            InvalidBundle, match="expected exactly one log entry in bundle"
        ):
            signing_bundle("bundle_no_log_entry.txt")

    def test_verification_materials_offline_no_checkpoint(self, signing_bundle):
        with pytest.raises(
            InvalidBundle, match="entry must contain inclusion proof, with checkpoint"
        ):
            signing_bundle("bundle_no_checkpoint.txt")

    def test_bundle_roundtrip(self, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")

        # Bundles are not directly comparable, but a round-trip preserves their
        # underlying object structure.
        assert json.loads(Bundle.from_json(bundle.to_json()).to_json()) == json.loads(
            bundle.to_json()
        )

    def test_bundle_missing_signed_time(self, signing_bundle):
        with pytest.raises(
            InvalidBundle,
            match=r"bundle must contain an inclusion promise or signed timestamp\(s\)",
        ):
            signing_bundle("bundle_v3_no_signed_time.txt")


class TestBundleFailureCategory:
    """
    The bundle ingestion API reports stable, structured failure categories
    while remaining catch-compatible with the existing `InvalidBundle`
    hierarchy.
    """

    def test_valid_bundle_has_no_category(self, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")
        assert bundle is not None

    @pytest.mark.parametrize(
        "filename",
        (
            "bundle_no_cert_v1.txt",
            "bundle_no_log_entry.txt",
            "bundle_no_checkpoint.txt",
            "bundle_v3_no_signed_time.txt",
        ),
    )
    def test_missing_material_is_categorized(self, signing_bundle, filename):
        with pytest.raises(MissingBundleMaterial) as excinfo:
            signing_bundle(filename)

        # The existing catch-compatible hierarchy still applies.
        assert isinstance(excinfo.value, InvalidBundle)

        error = excinfo.value
        assert error.category is BundleErrorCategory.MISSING_MATERIAL
        assert error.remediation == "publisher"
        assert error.category == "missing_material"

    @pytest.mark.parametrize(
        "kind_version",
        (
            {"kind": "hashedrekord", "version": "0.0.3"},
            {"kind": "hashedrekord", "version": "1.0.0"},
            {"kind": "intoto", "version": "0.0.3"},
        ),
    )
    def test_unsupported_log_entry_version_is_categorized(self, asset, kind_version):
        raw = json.loads(asset("bundle_v3.txt.sigstore").read_bytes())
        entry = raw["verificationMaterial"]["tlogEntries"][0]
        entry["kindVersion"] = kind_version

        with pytest.raises(IncompatibleEntry) as excinfo:
            Bundle.from_json(json.dumps(raw))

        error = excinfo.value
        assert isinstance(error, InvalidBundle)
        assert error.category is BundleErrorCategory.UNSUPPORTED_CLIENT
        assert error.remediation == "platform"

    def test_malformed_log_entry_version_is_not_upgrade(self, asset):
        raw = json.loads(asset("bundle_invalid_version.txt.sigstore").read_bytes())

        with pytest.raises(InvalidBundle) as excinfo:
            Bundle.from_json(json.dumps(raw))

        assert excinfo.value.category is BundleErrorCategory.MALFORMED

    def test_extra_log_entry_is_malformed_not_missing(self, asset):
        raw = json.loads(asset("bundle_v3.txt.sigstore").read_bytes())
        entries = raw["verificationMaterial"]["tlogEntries"]
        entries.append(entries[0])

        with pytest.raises(InvalidBundle) as excinfo:
            Bundle.from_json(json.dumps(raw))

        assert not isinstance(excinfo.value, MissingBundleMaterial)
        assert excinfo.value.category is BundleErrorCategory.MALFORMED

    @pytest.mark.parametrize(
        "media_type",
        (
            "application/vnd.dev.sigstore.bundle.v0.4+json",
            "application/vnd.dev.sigstore.bundle+json;version=0.4",
            "application/vnd.dev.sigstore.bundle.v1.0+json",
        ),
    )
    def test_newer_bundle_media_type_requires_upgrade(self, asset, media_type):
        raw = json.loads(asset("bundle_v3.txt.sigstore").read_bytes())
        raw["mediaType"] = media_type

        with pytest.raises(UnsupportedBundleVersion) as excinfo:
            Bundle.from_json(json.dumps(raw))

        error = excinfo.value
        # Existing handlers for both InvalidBundle and IncompatibleEntry work.
        assert isinstance(error, IncompatibleEntry)
        assert isinstance(error, InvalidBundle)
        assert error.category is BundleErrorCategory.UNSUPPORTED_CLIENT
        assert error.remediation == "platform"

    def test_missing_material_from_json(self, asset):
        raw = json.loads(asset("bundle_v3.txt.sigstore").read_bytes())
        del raw["verificationMaterial"]["certificate"]

        with pytest.raises(MissingBundleMaterial) as excinfo:
            Bundle.from_json(json.dumps(raw))

        assert excinfo.value.category is BundleErrorCategory.MISSING_MATERIAL

    def test_malformed_media_type_is_not_upgrade(self, asset):
        raw = json.loads(asset("bundle_v3.txt.sigstore").read_bytes())
        raw["mediaType"] = "this is completely wrong"

        with pytest.raises(InvalidBundle) as excinfo:
            Bundle.from_json(json.dumps(raw))

        assert not isinstance(excinfo.value, MissingBundleMaterial)
        assert not isinstance(excinfo.value, UnsupportedBundleVersion)
        assert excinfo.value.category is BundleErrorCategory.MALFORMED

    def test_categories_are_distinct(self):
        assert (
            BundleErrorCategory.MISSING_MATERIAL
            is not BundleErrorCategory.UNSUPPORTED_CLIENT
        )
        assert (
            BundleErrorCategory.MISSING_MATERIAL.remediation
            != BundleErrorCategory.UNSUPPORTED_CLIENT.remediation
        )

    def test_verification_error_aliases(self):
        # The same categories are available for verification-time failures.
        missing = MissingMaterialError("missing")
        unsupported = UnsupportedClientError("unsupported")

        assert isinstance(missing, VerificationError)
        assert isinstance(unsupported, VerificationError)
        assert missing.category is BundleErrorCategory.MISSING_MATERIAL
        assert unsupported.category is BundleErrorCategory.UNSUPPORTED_CLIENT
        assert missing.remediation == "publisher"
        assert unsupported.remediation == "platform"

    def test_object_api_matches_json_categories(self, asset):
        """
        The structured category is the same whether a bundle is assembled
        from JSON or from an already-constructed model object.
        """
        raw = json.loads(asset("bundle_v3.txt.sigstore").read_bytes())

        # Missing material, via the object API.
        inner = _Bundle.from_json(json.dumps(raw))
        inner.verification_material.certificate = None
        inner.media_type = "application/vnd.dev.sigstore.bundle.v0.3+json"
        with pytest.raises(MissingBundleMaterial) as excinfo:
            Bundle(inner)
        assert excinfo.value.category is BundleErrorCategory.MISSING_MATERIAL

        # Newer-but-recognizable format, via the object API.
        inner = _Bundle.from_json(json.dumps(raw))
        inner.media_type = "application/vnd.dev.sigstore.bundle.v0.4+json"
        with pytest.raises(UnsupportedBundleVersion) as excinfo:
            Bundle(inner)
        assert excinfo.value.category is BundleErrorCategory.UNSUPPORTED_CLIENT

        # Newer log entry version, via the object API.
        inner = _Bundle.from_json(json.dumps(raw))
        inner.verification_material.tlog_entries[0].kind_version.version = "0.0.7"
        with pytest.raises(IncompatibleEntry) as excinfo:
            Bundle(inner)
        assert excinfo.value.category is BundleErrorCategory.UNSUPPORTED_CLIENT

    def test_error_category_walks_cause_chain(self, asset):
        raw = json.loads(asset("bundle_v3.txt.sigstore").read_bytes())
        del raw["verificationMaterial"]["certificate"]

        try:
            Bundle.from_json(json.dumps(raw))
        except InvalidBundle as exc:
            wrapper = VerificationError("wrapped")
            wrapper.__cause__ = exc
        else:  # pragma: no cover - the bundle must fail to load
            pytest.fail("bundle unexpectedly loaded")

        assert error_category(wrapper) is BundleErrorCategory.MISSING_MATERIAL
        assert error_category(RuntimeError("unclassified")) is None

    def test_error_category_handles_cycles(self):
        first = VerificationError("first")
        second = VerificationError("second")
        first.__cause__ = second
        second.__cause__ = first

        assert error_category(first) is None


class TestKnownBundleTypes:
    def test_str(self):
        for type_ in Bundle.BundleType:
            assert str(type_) == type_.value
            assert type_ in Bundle.BundleType
