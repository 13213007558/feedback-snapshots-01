"""Attribute provenance policy tests.

These tests build SAML material locally with the certificates in ``tests``
so they do not depend on xmlsec being able to encrypt with the bundled keys.
"""

import logging

from base64 import b64encode
from contextlib import closing

from pathutils import dotname
from pathutils import full_path
from pytest import raises

from saml2 import BINDING_HTTP_POST
from saml2.attribute_source import AttributeClaim
from saml2.attribute_source import AttributeMapping
from saml2.attribute_source import AttributeSourceConflict
from saml2.attribute_source import AttributeSourcePolicy
from saml2.attribute_source import AttributeSourceRejected
from saml2.client import Saml2Client
from saml2.config import config_factory
from saml2.response import authn_response
from saml2.saml import attribute_statement_from_string
from saml2.server import Server
from saml_attribute_source_helpers import attribute_statement_xml
from saml_attribute_source_helpers import build_mixed_response
from saml_attribute_source_helpers import signed_assertion
from saml_attribute_source_helpers import signed_response


IDP = "urn:mace:example.com:saml:roland:idp"
SP = "urn:mace:example.com:saml:roland:sp"
ACS = "http://lingon.catalogix.se:8087/"
CERT = full_path("test_1.crt")

BUSINESS_POLICY = {
    "business_attributes": {
        "o": {"require_encrypted": True, "require_signed": True},
        "employeeType": {"require_encrypted": True, "require_signed": True},
    }
}


def _statement(*attributes):
    return attribute_statement_from_string(attribute_statement_xml(*attributes, cert_path=CERT))


def _assertion(server, statement, sign=True):
    return signed_assertion(
        IDP,
        statement,
        server.sec,
        full_path("test.key"),
        SP,
        sign=sign,
    )


def _response(server, assertion_xml):
    return signed_response(IDP, assertion_xml, server.sec, ACS)


def _mixed_response(server, plain_assertion, encrypted_assertion):
    return build_mixed_response(IDP, plain_assertion, encrypted_assertion, server.sec, ACS, CERT)


def _load_response(xml, policy=None):
    conf = config_factory("sp", dotname("server_conf"))
    conf.only_use_keys_in_metadata = False
    response = authn_response(
        conf,
        ACS,
        asynchop=False,
        allow_unsolicited=True,
        attribute_source_policy=policy,
    )
    response.timeslack = 315360000
    response.loads(xml, decode=False)
    response.verify()
    return response


class TestQualifiedEncryptedSource:
    def setup_class(self):
        with closing(Server(dotname("idp_conf"))) as server:
            self.server = server
            self.encrypted_attribute_response = _response(
                server,
                _assertion(
                    server,
                    _statement(
                        ("urn:oid:2.5.4.10", "HR-Org", True),
                        ("urn:oid:2.16.840.1.113730.3.1.4", "employee", True),
                    ),
                ),
            )
            self.plain_attribute_response = _response(
                server,
                _assertion(
                    server,
                    _statement(
                        ("urn:oid:2.5.4.10", "Portal-Org"),
                        ("urn:oid:2.16.840.1.113730.3.1.4", "contractor"),
                    ),
                ),
            )

    def test_mapper_exposes_encryption_state(self):
        response = _load_response(self.encrypted_attribute_response)
        mapping = response.get_attribute_mapping()

        assert mapping.ava["o"] == ["HR-Org"]
        assert mapping.ava["employeeType"] == ["employee"]

        claims = {claim.local_name: claim for claim in mapping.claims}
        assert claims["o"].attribute_encrypted is True
        assert claims["o"].encrypted is True
        assert claims["o"].signed is True
        assert claims["o"].issuer == IDP
        assert claims["o"].assertion_id

    def test_authorization_consumer_only_sees_qualified_source(self):
        response = _load_response(self.encrypted_attribute_response, BUSINESS_POLICY)
        identity = response.get_authorization_identity()

        assert identity["o"] == ["HR-Org"]
        assert identity["employeeType"] == ["employee"]
        assert identity.provenance()["o"][0]["encrypted"] is True
        assert identity.provenance()["o"][0]["attribute_encrypted"] is True

    def test_unencrypted_legacy_business_attribute_is_rejected(self):
        response = _load_response(self.plain_attribute_response, BUSINESS_POLICY)

        # The mapper still exposes the legacy value for display purposes.
        assert response.get_attribute_mapping().ava["o"] == ["Portal-Org"]
        with raises(AttributeSourceRejected):
            response.get_authorization_identity()

    def test_display_only_fields_do_not_need_encryption(self):
        policy = AttributeSourcePolicy(business_attributes={"o": {"require_encrypted": True}})
        response = _load_response(self.plain_attribute_response, policy)

        with raises(AttributeSourceRejected) as exc_info:
            response.get_authorization_identity()

        assert exc_info.value.local_name == "o"
        # employeeType is not a business attribute under this policy.
        assert all(field["local_name"] == "o" for field in exc_info.value.fields)


class TestConflictingSources:
    def setup_class(self):
        with closing(Server(dotname("idp_conf"))) as server:
            self.server = server
            plain = _assertion(
                server,
                _statement(("urn:oid:2.5.4.10", "Portal-Org")),
            )
            encrypted = _assertion(
                server,
                _statement(("urn:oid:2.5.4.10", "HR-Org")),
            )
            self.xml = _mixed_response(server, plain, encrypted)

    def test_mapper_shows_both_same_named_claims(self):
        response = _load_response(self.xml)
        mapping = response.get_attribute_mapping()
        claims = mapping.claims_for("o")

        assert len(claims) == 2
        assert {claim.encrypted for claim in claims} == {True, False}
        assert len({claim.assertion_id for claim in claims}) == 2
        # The legacy AVA is lossy by design; the claims list is the mapper
        # view that retains both provenance records.
        assert mapping.ava["o"] in (["HR-Org"], ["Portal-Org"])

    def test_authorization_consumer_stops_on_conflict(self):
        response = _load_response(self.xml, BUSINESS_POLICY)

        with raises(AttributeSourceConflict) as exc_info:
            response.get_authorization_identity()

        message = str(exc_info.value)
        assert "'o'" in message
        assert "assertion_id" in message
        assert "encrypted" in message
        assert "Portal-Org" not in message
        assert "HR-Org" not in message

    def test_conflict_error_identifies_both_fields(self):
        response = _load_response(self.xml, BUSINESS_POLICY)

        with raises(AttributeSourceConflict) as exc_info:
            response.get_authorization_identity()

        fields = exc_info.value.fields
        assert len(fields) == 2
        assert {field["encrypted"] for field in fields} == {True, False}
        assert all(field["local_name"] == "o" for field in fields)
        assert all(field["attribute_name"] == "urn:oid:2.5.4.10" for field in fields)
        assert len({field["assertion_id"] for field in fields}) == 2


class TestSessionNotCreatedAfterRejection:
    def test_plain_business_attribute_rejection_does_not_cache_session(self):
        with closing(Server(dotname("idp_conf"))) as server:
            xml = _response(
                server,
                _assertion(server, _statement(("urn:oid:2.5.4.10", "Portal-Org"))),
            )

            conf = config_factory("sp", dotname("server_conf"))
            conf.only_use_keys_in_metadata = False
            conf.attribute_source_policy = BUSINESS_POLICY
            client = Saml2Client(config=conf)

            with raises(AttributeSourceRejected):
                client.parse_authn_request_response(
                    b64encode(xml.encode("utf-8")),
                    BINDING_HTTP_POST,
                    {"attribute-source-request": "http://foo.example.com/service"},
                )

            assert client.users.subjects() == []

    def test_conflict_does_not_cache_session(self):
        with closing(Server(dotname("idp_conf"))) as server:
            plain = _assertion(server, _statement(("urn:oid:2.5.4.10", "Portal-Org")))
            encrypted = _assertion(server, _statement(("urn:oid:2.5.4.10", "HR-Org")))
            xml = _mixed_response(server, plain, encrypted)

            conf = config_factory("sp", dotname("server_conf"))
            conf.only_use_keys_in_metadata = False
            conf.attribute_source_policy = BUSINESS_POLICY
            client = Saml2Client(config=conf)

            with raises(AttributeSourceConflict):
                client.parse_authn_request_response(
                    b64encode(xml.encode("utf-8")),
                    BINDING_HTTP_POST,
                    {"attribute-source-request": "http://foo.example.com/service"},
                )

            assert client.users.subjects() == []

    def test_qualified_response_creates_session(self):
        with closing(Server(dotname("idp_conf"))) as server:
            xml = _response(
                server,
                _assertion(
                    server,
                    _statement(("urn:oid:2.5.4.10", "HR-Org", True)),
                ),
            )

            conf = config_factory("sp", dotname("server_conf"))
            conf.only_use_keys_in_metadata = False
            conf.attribute_source_policy = {
                "business_attributes": {"o": {"require_encrypted": True, "require_signed": True}}
            }
            client = Saml2Client(config=conf)

            response = client.parse_authn_request_response(
                b64encode(xml.encode("utf-8")),
                BINDING_HTTP_POST,
                {"attribute-source-request": "http://foo.example.com/service"},
            )

            assert response.get_authorization_identity()["o"] == ["HR-Org"]
            assert len(client.users.subjects()) == 1


class TestNoPersonalDataInLogs:
    def test_rejection_log_omits_values(self, caplog):
        with closing(Server(dotname("idp_conf"))) as server:
            xml = _response(
                server,
                _assertion(server, _statement(("urn:oid:2.5.4.10", "Portal-Org"))),
            )
            response = _load_response(xml, BUSINESS_POLICY)

            caplog.set_level(logging.DEBUG)
            with raises(AttributeSourceRejected):
                response.get_authorization_identity()

            assert "Portal-Org" not in caplog.text
            assert "Attribute source policy failed" in caplog.text
            assert "urn:oid:2.5.4.10" in caplog.text


class TestConflictDetectionAndDisplayCompatibility:
    def test_conflict_within_qualifying_sources_is_detected(self):
        policy = AttributeSourcePolicy(business_attributes={"o": {"require_encrypted": True}})
        policy.fail_on_missing = True

        claims = [
            AttributeClaim(
                local_name="o",
                values=("HR-A",),
                attribute_name="urn:oid:2.5.4.10",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                friendly_name="o",
                issuer="https://hr.example.org/idp",
                assertion_id="assertion-encrypted-1",
                encrypted=True,
                signed=True,
                attribute_encrypted=True,
            ),
            AttributeClaim(
                local_name="o",
                values=("HR-B",),
                attribute_name="urn:oid:2.5.4.10",
                name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                friendly_name="o",
                issuer="https://hr.example.org/idp",
                assertion_id="assertion-encrypted-2",
                encrypted=True,
                signed=True,
                attribute_encrypted=True,
            ),
        ]
        mapping = AttributeMapping(claims)
        with raises(AttributeSourceConflict) as exc_info:
            mapping.authorization_identity(policy)
        message = str(exc_info.value)
        assert "HR-A" not in message
        assert "HR-B" not in message
        assert "assertion-encrypted-1" in message
        assert "assertion-encrypted-2" in message

    def test_trusted_issuer_requirement(self):
        policy = AttributeSourcePolicy(
            business_attributes={
                "o": {
                    "require_encrypted": True,
                    "require_signed": True,
                    "trusted_issuers": ["https://hr.example.org/idp"],
                }
            }
        )
        with closing(Server(dotname("idp_conf"))) as server:
            xml = _response(
                server,
                _assertion(server, _statement(("urn:oid:2.5.4.10", "HR-Org", True))),
            )
            response = _load_response(xml, policy)

            with raises(AttributeSourceRejected) as exc_info:
                response.get_authorization_identity()

            fields = exc_info.value.fields
            assert fields[0]["issuer"] == IDP
            assert fields[0]["encrypted"] is True
            assert fields[0]["qualified"] is False

    def test_display_fields_remain_available_unchanged(self):
        with closing(Server(dotname("idp_conf"))) as server:
            xml = _response(
                server,
                _assertion(
                    server,
                    _statement(
                        ("urn:oid:2.5.4.10", "Portal-Org"),
                        ("urn:oid:2.16.840.1.113730.3.1.241", "Portal User"),
                    ),
                ),
            )
            response = _load_response(xml, BUSINESS_POLICY)

            with raises(AttributeSourceRejected):
                response.get_authorization_identity()

            # A portal can still render legacy display fields from the mapper.
            assert response.get_attribute_mapping().ava["displayName"] == ["Portal User"]
            # The authorization view remains empty and the login cannot be
            # cached as a new session; rendering can still use the mapper.
            with raises(AttributeSourceRejected):
                response.get_authorization_identity()


class TestPolicyConfiguration:
    def test_service_scoped_policy_is_loaded(self):
        conf = config_factory("sp", dotname("server_conf"))
        conf.load(
            {
                "service": {
                    "sp": {
                        "attribute_source_policy": {
                            "business_attributes": {"o": {"require_encrypted": True}}
                        }
                    }
                }
            }
        )

        assert conf.getattr("attribute_source_policy", "sp") == {
            "business_attributes": {"o": {"require_encrypted": True}}
        }

    def test_top_level_policy_is_visible_to_sp(self):
        conf = config_factory("sp", dotname("server_conf"))
        conf.load({"attribute_source_policy": {"business_attributes": ["o"]}})

        assert conf.attribute_source_policy == {"business_attributes": ["o"]}
        assert conf.getattr("attribute_source_policy", "sp") == {"business_attributes": ["o"]}


class TestPolicyValidation:
    def test_display_attribute_cannot_also_grant_permissions(self):
        policy = AttributeSourcePolicy(
            business_attributes={"displayName": {"require_encrypted": True}},
            display_attributes=["displayName"],
        )
        with closing(Server(dotname("idp_conf"))) as server:
            xml = _response(
                server,
                _assertion(server, _statement(("urn:oid:2.16.840.1.113730.3.1.241", "Portal User"))),
            )
            with raises(ValueError):
                _load_response(xml, policy)
