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

import datetime
import re

import pretend
import pytest
from cryptography import x509
from cryptography.hazmat import asn1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ExtensionNotFound
from cryptography.x509.oid import NameOID

from sigstore.errors import VerificationError
from sigstore.verify import policy


class TestVerificationPolicy:
    def test_does_not_init(self):
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            policy.VerificationPolicy(pretend.stub())


class TestUnsafeNoOp:
    def test_succeeds(self, monkeypatch):
        logger = pretend.stub(warning=pretend.call_recorder(lambda s: None))
        monkeypatch.setattr(policy, "_logger", logger)

        policy_ = policy.UnsafeNoOp()
        policy_.verify(pretend.stub())
        assert logger.warning.calls == [
            pretend.call(
                "unsafe (no-op) verification policy used! no verification performed!"
            )
        ]


class TestAnyOf:
    def test_trivially_false(self):
        policy_ = policy.AnyOf([])

        with pytest.raises(VerificationError, match="0 of 0 policies succeeded"):
            policy_.verify(pretend.stub())

    def test_fails_no_children_match(self, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")
        policy_ = policy.AnyOf(
            [
                policy.Identity(identity="foo", issuer="bar"),
                policy.Identity(identity="baz", issuer="quux"),
            ]
        )

        with pytest.raises(VerificationError, match="0 of 2 policies succeeded"):
            policy_.verify(bundle.signing_certificate)

    def test_succeeds(self, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")
        policy_ = policy.AnyOf(
            [
                policy.Identity(identity="foo", issuer="bar"),
                policy.Identity(identity="baz", issuer="quux"),
                policy.Identity(
                    identity="a@tny.town",
                    issuer="https://github.com/login/oauth",
                ),
            ]
        )

        policy_.verify(bundle.signing_certificate)


class TestAllOf:
    def test_trivially_false(self):
        policy_ = policy.AllOf([])

        with pytest.raises(VerificationError, match="no child policies to verify"):
            policy_.verify(pretend.stub())

    def test_certificate_extension_not_found(self):
        policy_ = policy.AllOf([policy.Identity(identity="foo", issuer="bar")])
        cert_ = pretend.stub(
            extensions=pretend.stub(
                get_extension_for_oid=pretend.raiser(
                    ExtensionNotFound(oid=pretend.stub(), msg=pretend.stub())
                )
            )
        )

        reason = re.escape(
            "Certificate does not contain OIDCIssuer (1.3.6.1.4.1.57264.1.1) extension"
        )
        with pytest.raises(VerificationError, match=reason):
            policy_.verify(cert_)

    def test_fails_not_all_children_match(self, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")
        policy_ = policy.AllOf(
            [
                policy.Identity(identity="foo", issuer="bar"),
                policy.Identity(identity="baz", issuer="quux"),
                policy.Identity(
                    identity="a@tny.town",
                    issuer="https://github.com/login/oauth",
                ),
            ]
        )

        with pytest.raises(
            VerificationError,
            match="Certificate's OIDCIssuer does not match",
        ):
            policy_.verify(bundle.signing_certificate)

    def test_succeeds(self, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")
        policy_ = policy.AllOf(
            [
                policy.Identity(
                    identity="a@tny.town",
                    issuer="https://github.com/login/oauth",
                ),
                policy.Identity(
                    identity="a@tny.town",
                    issuer="https://github.com/login/oauth",
                ),
            ]
        )

        policy_.verify(bundle.signing_certificate)


class TestIdentity:
    def test_fails_no_san_match(self, signing_bundle):
        _, bundle = signing_bundle("bundle.txt")
        policy_ = policy.Identity(
            identity="bad@ident.example.com",
            issuer="https://github.com/login/oauth",
        )

        with pytest.raises(
            VerificationError,
            match="Certificate's SANs do not match",
        ):
            policy_.verify(bundle.signing_certificate)


class TestSingleExtPolicy:
    def test_succeeds(self, signing_bundle):
        _, bundle = signing_bundle("bundle_v3_github.whl")

        verification_policy_extensions = [
            policy.OIDCIssuer("https://token.actions.githubusercontent.com"),
            policy.GitHubWorkflowTrigger("release"),
            policy.GitHubWorkflowSHA("d8b4a6445f38c48b9137a8099706d9b8073146e4"),
            policy.GitHubWorkflowName("release"),
            policy.GitHubWorkflowRepository("trailofbits/rfc8785.py"),
            policy.GitHubWorkflowRef("refs/tags/v0.1.2"),
            policy.OIDCIssuerV2("https://token.actions.githubusercontent.com"),
            policy.OIDCBuildSignerURI(
                "https://github.com/trailofbits/rfc8785.py/.github/workflows/release.yml@refs/tags/v0.1.2"
            ),
            policy.OIDCBuildSignerDigest("d8b4a6445f38c48b9137a8099706d9b8073146e4"),
            policy.OIDCRunnerEnvironment("github-hosted"),
            policy.OIDCSourceRepositoryURI("https://github.com/trailofbits/rfc8785.py"),
            policy.OIDCSourceRepositoryDigest(
                "d8b4a6445f38c48b9137a8099706d9b8073146e4"
            ),
            policy.OIDCSourceRepositoryRef("refs/tags/v0.1.2"),
            policy.OIDCSourceRepositoryIdentifier("768213997"),
            policy.OIDCSourceRepositoryOwnerURI("https://github.com/trailofbits"),
            policy.OIDCSourceRepositoryOwnerIdentifier("2314423"),
            policy.OIDCBuildConfigURI(
                "https://github.com/trailofbits/rfc8785.py/.github/workflows/release.yml@refs/tags/v0.1.2"
            ),
            policy.OIDCBuildConfigDigest("d8b4a6445f38c48b9137a8099706d9b8073146e4"),
            policy.OIDCBuildTrigger("release"),
            policy.OIDCRunInvocationURI(
                "https://github.com/trailofbits/rfc8785.py/actions/runs/8351058501/attempts/1"
            ),
            policy.OIDCSourceRepositoryVisibility("public"),
        ]

        policy_ = policy.AllOf(verification_policy_extensions)
        policy_.verify(bundle.signing_certificate)


def _self_signed_cert(extensions):
    """
    Builds a self-signed certificate carrying the given `(oid, raw_value)`
    pairs as unrecognized extensions.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sigstore-test")])
        )
        .issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sigstore-test")])
        )
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    for oid, raw_value in extensions:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(oid, raw_value), critical=False
        )
    return builder.sign(key, hashes.SHA256())


class TestApprovedReleaseChains:
    """
    Tests for a platform policy that permits exactly two approved release
    chains, where each chain binds a repository identifier, a build signer
    URI, and a build config URI.

    The policy under test is `AnyOf([AllOf(chain A), AllOf(chain B)])`:
    each approved chain is a complete set of requirements, and a
    certificate must satisfy one chain in full rather than an arbitrary
    mix of conditions from both.
    """

    _CHAIN_A = {
        "repo_id": "768213997",
        "signer_uri": "https://github.com/example/web/.github/workflows/release.yml@refs/tags/v1.0.0",
        "config_uri": "https://github.com/example/web/.github/workflows/release.yml@refs/tags/v1.0.0",
    }
    _CHAIN_B = {
        "repo_id": "987654321",
        "signer_uri": "https://github.com/example/api/.github/workflows/deploy.yml@refs/tags/v2.3.1",
        "config_uri": "https://github.com/example/api/.github/workflows/deploy.yml@refs/tags/v2.3.1",
    }

    @staticmethod
    def _chain_policy(chain):
        return policy.AllOf(
            [
                policy.OIDCSourceRepositoryIdentifier(chain["repo_id"]),
                policy.OIDCBuildSignerURI(chain["signer_uri"]),
                policy.OIDCBuildConfigURI(chain["config_uri"]),
            ]
        )

    @classmethod
    def _release_policy(cls):
        return policy.AnyOf(
            [cls._chain_policy(cls._CHAIN_A), cls._chain_policy(cls._CHAIN_B)]
        )

    @staticmethod
    def _chain_extensions(chain, *, omit=()):
        """
        The chain's bindings as DER-encoded ("new style") X.509 extensions.
        """
        extensions = [
            (
                policy.OIDCSourceRepositoryIdentifier.oid,
                asn1.encode_der(chain["repo_id"]),
            ),
            (policy.OIDCBuildSignerURI.oid, asn1.encode_der(chain["signer_uri"])),
            (policy.OIDCBuildConfigURI.oid, asn1.encode_der(chain["config_uri"])),
        ]
        return [(oid, raw) for oid, raw in extensions if oid not in omit]

    def test_chain_a_succeeds(self):
        cert = _self_signed_cert(self._chain_extensions(self._CHAIN_A))
        self._release_policy().verify(cert)

    def test_chain_b_succeeds(self):
        cert = _self_signed_cert(self._chain_extensions(self._CHAIN_B))
        self._release_policy().verify(cert)

    def test_compatible_cert_with_legacy_extensions_succeeds(self):
        """
        A certificate that carries both the new-style extensions and their
        legacy (pre-DER) companions verifies against the release policy, and
        its legacy extensions remain usable with the legacy policy classes.
        """
        chain = self._CHAIN_A
        extensions = self._chain_extensions(chain) + [
            (
                policy.GitHubWorkflowRepository.oid,
                b"example/web",
            ),
            (
                policy.GitHubWorkflowName.oid,
                b"release",
            ),
            (
                policy.GitHubWorkflowRef.oid,
                b"refs/tags/v1.0.0",
            ),
        ]
        cert = _self_signed_cert(extensions)

        # The release policy accepts the certificate via its new-style
        # extensions.
        self._release_policy().verify(cert)

        # The legacy companions are independently verifiable.
        legacy_chain = policy.AllOf(
            [
                policy.GitHubWorkflowRepository("example/web"),
                policy.GitHubWorkflowName("release"),
                policy.GitHubWorkflowRef("refs/tags/v1.0.0"),
            ]
        )
        legacy_chain.verify(cert)

    def test_cross_chain_mix_fails(self):
        """
        A certificate mixing chain A's repository and build config with
        chain B's signer satisfies neither chain in full and must be
        rejected: the two chains' conditions must not be split apart and
        applied independently.
        """
        mixed = {
            "repo_id": self._CHAIN_A["repo_id"],
            "signer_uri": self._CHAIN_B["signer_uri"],
            "config_uri": self._CHAIN_A["config_uri"],
        }
        cert = _self_signed_cert(self._chain_extensions(mixed))

        with pytest.raises(VerificationError, match="0 of 2 policies succeeded"):
            self._release_policy().verify(cert)

        # Guard against regressions towards the incorrect "split"
        # formulation, which checks each condition independently and would
        # wrongly accept the mixed certificate.
        split_policy = policy.AllOf(
            [
                policy.AnyOf(
                    [
                        policy.OIDCSourceRepositoryIdentifier(self._CHAIN_A["repo_id"]),
                        policy.OIDCSourceRepositoryIdentifier(self._CHAIN_B["repo_id"]),
                    ]
                ),
                policy.AnyOf(
                    [
                        policy.OIDCBuildSignerURI(self._CHAIN_A["signer_uri"]),
                        policy.OIDCBuildSignerURI(self._CHAIN_B["signer_uri"]),
                    ]
                ),
                policy.AnyOf(
                    [
                        policy.OIDCBuildConfigURI(self._CHAIN_A["config_uri"]),
                        policy.OIDCBuildConfigURI(self._CHAIN_B["config_uri"]),
                    ]
                ),
            ]
        )
        split_policy.verify(cert)

    @pytest.mark.parametrize(
        "missing_policy",
        [
            policy.OIDCSourceRepositoryIdentifier,
            policy.OIDCBuildSignerURI,
            policy.OIDCBuildConfigURI,
        ],
    )
    def test_missing_required_extension_fails(self, missing_policy):
        """
        A certificate missing any one of the chain's required extensions is
        rejected, and the failing chain reports precisely which extension
        is absent.
        """
        chain = self._CHAIN_A
        cert = _self_signed_cert(
            self._chain_extensions(chain, omit={missing_policy.oid})
        )

        with pytest.raises(VerificationError, match="0 of 2 policies succeeded"):
            self._release_policy().verify(cert)

        reason = re.escape(
            f"Certificate does not contain {missing_policy.__name__} "
            f"({missing_policy.oid.dotted_string}) extension"
        )
        with pytest.raises(VerificationError, match=reason):
            self._chain_policy(chain).verify(cert)

    def test_mismatched_value_diagnostic(self):
        """
        A certificate whose repository identifier belongs to neither chain
        is rejected, and the per-chain diagnostic names the mismatched
        values.
        """
        chain = dict(self._CHAIN_A, repo_id="000000000")
        cert = _self_signed_cert(self._chain_extensions(chain))

        with pytest.raises(VerificationError, match="0 of 2 policies succeeded"):
            self._release_policy().verify(cert)

        reason = re.escape(
            "Certificate's OIDCSourceRepositoryIdentifier does not match "
            f"(got 000000000, expected {self._CHAIN_A['repo_id']})"
        )
        with pytest.raises(VerificationError, match=reason):
            self._chain_policy(self._CHAIN_A).verify(cert)
