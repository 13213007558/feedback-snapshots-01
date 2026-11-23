#!/usr/bin/env python
"""End to end audience migration test using real signed assertions.

The same legitimately signed assertion (carrying the legacy audience) is
delivered to both brand entries while a fake clock keeps the migration window
open, then again after the window has closed.  The observations make explicit
which delivery establishes a session and which one is stopped at audience
validation.
"""

import base64
import copy
from contextlib import closing

import pytest

from pathutils import full_path
from pathutils import xmlsec_path

from saml2 import BINDING_HTTP_POST
from saml2.audience_migration import AudienceMigrationPolicy
from saml2.audience_migration import Clock
from saml2.authn_context import INTERNETPROTOCOLPASSWORD
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.config import config_factory
from saml2.response import authn_response
from saml2.response import response_factory
from saml2.server import Server
from saml2.time_util import str_to_time


IDP_A = "urn:mace:example.com:saml:roland:idp"
IDP_B = "urn:mace:example.com:saml:roland:idp2"

LEGACY_AUDIENCE = "urn:mace:example.com:portal:legacy"
ENTRY_A = "https://portal.example.com/brand/a"
ENTRY_B = "https://portal.example.com/brand/b"
# Both brand entries share the portal ACS endpoint; the brand is selected by the
# receiving entry's entityID, which is what the audience policy constrains.
SHARED_ACS = "https://portal.example.com/acs"
ACS_A = SHARED_ACS
ACS_B = SHARED_ACS

WINDOW_START = "2026-06-01T00:00:00Z"
WINDOW_END = "2026-07-01T00:00:00Z"
DURING_WINDOW = "2026-06-15T12:00:00Z"
AFTER_WINDOW = "2026-07-02T12:00:00Z"

IDENTITY = {"mail": ["migrator@example.com"], "givenName": ["Mig"], "surName": ["Rator"]}


class MutableClock(Clock):
    """A clock the test can move forward without rebuilding the policy."""

    def __init__(self, when):
        self._when = str_to_time(when)

    def set(self, when):
        self._when = str_to_time(when)

    def now(self):
        return self._when


def _idp_config(entity_id):
    return {
        "entityid": entity_id,
        "service": {
            "idp": {
                "endpoints": {"single_sign_on_service": [("http://localhost:8088/sso", BINDING_HTTP_POST)]},
                "policy": {"default": {"lifetime": {"minutes": 60}, "attribute_restrictions": None}},
                "subject_data": full_path("subject_data.db"),
            }
        },
        "debug": 1,
        "key_file": full_path("test.key"),
        "cert_file": full_path("test.pem"),
        "xmlsec_binary": xmlsec_path,
        "metadata": [
            {
                "class": "saml2.mdstore.MetaDataFile",
                "metadata": [
                    (full_path("metadata_sp_1.xml"),),
                    (full_path("metadata_sp_2.xml"),),
                ],
            }
        ],
        "attribute_map_dir": full_path("attributemaps"),
    }


def _sp_config(entity_id, acs, migration_conf):
    return {
        "entityid": entity_id,
        "service": {
            "sp": {
                "endpoints": {"assertion_consumer_service": [acs]},
                "allow_unsolicited": True,
                "want_assertions_signed": True,
                "want_response_signed": False,
                "audience_migration": copy.deepcopy(migration_conf),
            }
        },
        "key_file": full_path("test.key"),
        "cert_file": full_path("test.pem"),
        "xmlsec_binary": xmlsec_path,
        "metadata": [
            {
                "class": "saml2.mdstore.MetaDataFile",
                "metadata": [
                    (full_path("idp.xml"),),
                    (full_path("idp2_migration.xml"),),
                ],
            }
        ],
        "attribute_map_dir": full_path("attributemaps"),
    }


def make_signed_assertion(idp_entity_id, audience=LEGACY_AUDIENCE, in_response_to=None):
    """Mint one legitimately signed assertion with the given audience."""
    idp_conf = config_factory("idp", _idp_config(idp_entity_id))
    with closing(Server(config=idp_conf)) as server:
        name_id = server.ident.transient_nameid(audience, "id-migration")
        response = server.create_authn_response(
            IDENTITY,
            in_response_to=in_response_to,
            destination=ACS_A,
            sp_entity_id=audience,
            name_id=name_id,
            sign_assertion=True,
            sign_response=False,
            authn={"class_ref": INTERNETPROTOCOLPASSWORD},
        )
        return str(response)


def build_policy(clock, entries):
    return AudienceMigrationPolicy(
        {"window": {"start": WINDOW_START, "end": WINDOW_END}, "entries": entries},
        clock=clock,
    )


def build_sp(entity_id, acs, policy):
    conf = SPConfig()
    conf.load(
        _sp_config(
            entity_id,
            acs,
            {"window": {"start": WINDOW_START, "end": WINDOW_END}, "entries": {}},
        )
    )
    client = Saml2Client(conf)
    # Replace the config derived policy with the clock controlled one.
    client.audience_migration_policy = policy
    return client


class TestIdpInitiatedMigration:
    def setup_method(self):
        self.clock = MutableClock(DURING_WINDOW)
        entries = {
            ENTRY_A: {"legacy_audiences": [LEGACY_AUDIENCE], "issuers": [IDP_A]},
            ENTRY_B: {"legacy_audiences": [LEGACY_AUDIENCE], "issuers": [IDP_A, IDP_B]},
        }
        self.policy = build_policy(self.clock, entries)
        self.sp_a = build_sp(ENTRY_A, ACS_A, self.policy)
        self.sp_b = build_sp(ENTRY_B, ACS_B, self.policy)
        # One legitimate signed assertion, reused (same bytes) for every delivery.
        self.assertion_xml = make_signed_assertion(IDP_A)

    def _post_payload(self):
        # HTTP POST carries the base64 encoded, uncompressed SAML message.
        return base64.b64encode(self.assertion_xml.encode("utf-8")).decode("ascii")

    def _consume(self, client, acs):
        return client.parse_authn_request_response(
            self._post_payload(),
            BINDING_HTTP_POST,
            outstanding={},
            conv_info={"entity_id": acs},
        )

    def test_legacy_assertion_creates_session_on_both_brands_while_window_open(self):
        self.clock.set(DURING_WINDOW)

        resp_a = self._consume(self.sp_a, ACS_A)
        resp_b = self._consume(self.sp_b, ACS_B)

        # Both deliveries validate and produce session information.
        info_a = resp_a.session_info()
        info_b = resp_b.session_info()
        assert info_a["issuer"] == IDP_A
        assert info_b["issuer"] == IDP_A

        assert info_a["audience_migration"]["accepted"] is True
        assert info_a["audience_migration"]["used_legacy_audience"] is True
        assert info_a["audience_migration"]["window_open"] is True
        assert info_b["audience_migration"]["accepted"] is True
        assert info_b["audience_migration"]["entry_entity_id"] == ENTRY_B

    def test_same_assertion_stops_at_audience_validation_after_window(self):
        # First, while the window is open, a session is established.
        self.clock.set(DURING_WINDOW)
        accepted = self._consume(self.sp_a, ACS_A)
        assert accepted.migration_decision.accepted is True
        assert accepted.session_info()["ava"]["mail"] == IDENTITY["mail"]

        # Move only the migration clock past the end; nothing else changes.
        self.clock.set(AFTER_WINDOW)
        assert self.policy.window_is_open() is False

        with pytest.raises(Exception, match="AudienceRestrictions"):
            self._consume(self.sp_a, ACS_A)

    def test_issuer_double_constraint_blocks_unlisted_idp_even_in_window(self):
        self.clock.set(DURING_WINDOW)
        # IDP_B is not allowed to use the legacy audience on ENTRY_A.
        foreign_assertion = make_signed_assertion(IDP_B)
        resp = response_factory(
            foreign_assertion,
            self.sp_a.config,
            return_addrs=[ACS_A],
            outstanding_queries={},
            asynchop=True,
            allow_unsolicited=True,
            want_assertions_signed=True,
            conv_info={"entity_id": ACS_A},
            audience_migration_policy=self.policy,
        )
        with pytest.raises(Exception, match="AudienceRestrictions"):
            resp.verify()
        assert resp.migration_decision.accepted is False
        assert resp.migration_decision.issuer == IDP_B

    def test_stable_decision_is_kept_for_session_establishment(self):
        self.clock.set(DURING_WINDOW)
        resp = self._consume(self.sp_a, ACS_A)
        decision_snapshot = resp.migration_decision.as_dict()

        # Even if the window closes after validation, the stored decision and
        # the already built session information remain the stable record.
        self.clock.set(AFTER_WINDOW)
        assert resp.session_info()["audience_migration"] == decision_snapshot
        assert decision_snapshot["accepted"] is True


class TestSpInitiatedStillBoundToRequest:
    def test_sp_initiated_uses_request_binding_and_rejects_legacy_audience(self):
        clock = MutableClock(DURING_WINDOW)
        entries = {ENTRY_A: {"legacy_audiences": [LEGACY_AUDIENCE], "issuers": [IDP_A]}}
        policy = build_policy(clock, entries)
        client = build_sp(ENTRY_A, ACS_A, policy)

        request_id = "request-123"
        # An SP initiated assertion carries an InResponseTo the SP recognises.
        xml = make_signed_assertion(IDP_A, audience=LEGACY_AUDIENCE, in_response_to=request_id)

        # Even inside the window, SP initiated login does not use the migration
        # policy: the legacy audience fails the classic single audience check.
        resp = authn_response(
            client.config,
            ACS_A,
            outstanding_queries={request_id: "http://localhost/start"},
            asynchop=True,
            allow_unsolicited=False,
            want_assertions_signed=True,
            audience_migration_policy=policy,
        )
        resp.loads(xml, decode=False)
        with pytest.raises(Exception, match="AudienceRestrictions"):
            resp.verify()
        assert resp.migration_decision is None
        assert resp.came_from == "http://localhost/start"
