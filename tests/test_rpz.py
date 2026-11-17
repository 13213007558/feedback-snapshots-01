"""Tests for the offline RPZ interpreter in :mod:`dns.rpz`."""

import ipaddress

import pytest

import dns.flags
import dns.message
import dns.name
import dns.rdatatype
import dns.rcode
import dns.rpz

EXCEPTION_ZONE = """$ORIGIN exception.rpz.
$TTL 60
@ SOA ns.example. hostmaster.example. 1 3600 900 86400 60
@ NS ns.example.
allowed.wild.example CNAME rpz-passthru.
special.evil.example CNAME rpz-passthru.
32.254.113.0.203.rpz-ip CNAME rpz-passthru.
"""

THREAT_ZONE = """$ORIGIN threat.rpz.
$TTL 60
@ SOA ns.example. hostmaster.example. 1 3600 900 86400 60
@ NS ns.example.
evil.example CNAME .
blocked.example CNAME rpz-nxdomain.
quiet.example CNAME rpz-nodata.
*.wild.example CNAME rpz-nodata.
*.evil.example CNAME rpz-nodata.
deep.more.evil.example CNAME rpz-nxdomain.
32.2.0.192.rpz-ip CNAME rpz-nxdomain.
24.8.8.8.rpz-ip CNAME .
16.8.8.rpz-ip CNAME rpz-nodata.
32.8.b.d.0.1.0.0.2.rpz-ip6 CNAME rpz-nxdomain.
bad.rpz-nsdname CNAME .
8.rpz-nsip CNAME .
*.16.10.rpz-ip CNAME rpz-nxdomain.
mystery.example CNAME rpz-tarpit.
tarpit2.example A 192.0.2.99
24.1.2.rpz-ip CNAME rpz-drop.
40.1.2.rpz-ip CNAME rpz-nxdomain.
"""


@pytest.fixture
def engine() -> dns.rpz.PolicyEngine:
    exceptions = dns.rpz.PolicyZone.from_text(
        "exceptions", EXCEPTION_ZONE, origin="exception.rpz."
    )
    threats = dns.rpz.PolicyZone.from_text("threats", THREAT_ZONE, origin="threat.rpz.")
    return dns.rpz.PolicyEngine([exceptions, threats])


def applied_owner(evaluation: dns.rpz.Evaluation) -> str | None:
    if evaluation.applied is None:
        return None
    return evaluation.applied.rule.owner.to_text()


class TestQNameTriggers:
    def test_exact_nxdomain_legacy_root_target(self, engine):
        evaluation = engine.evaluate("evil.example.")
        assert evaluation.action() is dns.rpz.Action.NXDOMAIN
        assert applied_owner(evaluation) == "evil.example."
        assert evaluation.applied.synthetic is True
        assert evaluation.applied.rcode == dns.rcode.NXDOMAIN

    def test_exact_explicit_nxdomain(self, engine):
        evaluation = engine.evaluate("blocked.example.")
        assert evaluation.action() is dns.rpz.Action.NXDOMAIN

    def test_nodata_is_noerror_without_answers(self, engine):
        evaluation = engine.evaluate("quiet.example.")
        assert evaluation.action() is dns.rpz.Action.NODATA
        assert evaluation.applied.rcode == dns.rcode.NOERROR

    def test_wildcard_matches_subdomain_but_not_parent(self, engine):
        child = engine.evaluate("host.wild.example.")
        assert child.action() is dns.rpz.Action.NODATA
        assert applied_owner(child) == "*.wild.example."

        parent = engine.evaluate("wild.example.")
        assert parent.action() is None

    def test_wildcard_matches_multiple_left_labels(self, engine):
        evaluation = engine.evaluate("a.b.wild.example.")
        assert evaluation.action() is dns.rpz.Action.NODATA

    def test_exact_name_is_not_a_text_suffix_match(self, engine):
        # "notevil.example." ends in the same text but is a different name.
        evaluation = engine.evaluate("notevil.example.")
        assert evaluation.action() is None

    def test_unrelated_name_has_no_match(self, engine):
        assert engine.evaluate("example.org.").action() is None


class TestRuleSelection:
    def test_more_specific_wildcard_wins_within_zone(self, engine):
        evaluation = engine.evaluate("deep.more.evil.example.")
        assert evaluation.action() is dns.rpz.Action.NXDOMAIN
        assert applied_owner(evaluation) == "deep.more.evil.example."
        owners = {item.rule.owner.to_text() for item in evaluation.overridden}
        assert "*.evil.example." in owners
        assert all("more specific rule" in item.by for item in evaluation.overridden)

    def test_higher_priority_zone_passthru_overrides_lower_zone(self, engine):
        evaluation = engine.evaluate("special.evil.example.")
        assert evaluation.action() is dns.rpz.Action.PASSTHRU
        assert evaluation.applied.rule.zone_name == "exceptions"
        assert evaluation.applied.synthetic is False
        assert evaluation.applied.rcode is None
        owners = {
            (item.rule.owner.to_text(), item.rule.zone_name)
            for item in evaluation.overridden
        }
        assert ("*.evil.example.", "threats") in owners
        assert all("higher-priority zone" in item.by for item in evaluation.overridden)

    def test_passthru_wildcard_exception_keeps_lower_candidates_visible(self, engine):
        evaluation = engine.evaluate("allowed.wild.example.")
        assert evaluation.action() is dns.rpz.Action.PASSTHRU
        overridden_zones = {item.rule.zone_name for item in evaluation.overridden}
        assert "threats" in overridden_zones

    def test_qname_trigger_outranks_response_address_trigger(self, engine):
        evaluation = engine.evaluate("evil.example.", addresses=["8.8.8.9"])
        assert applied_owner(evaluation) == "evil.example."
        overridden = {item.rule.trigger for item in evaluation.overridden}
        assert dns.rpz.TriggerType.RPZ_IP in overridden


class TestAddressTriggers:
    def test_ipv4_prefix_match(self, engine):
        evaluation = engine.evaluate(addresses=["192.0.2.0"])
        assert evaluation.action() is dns.rpz.Action.NXDOMAIN
        assert applied_owner(evaluation).startswith("32.2.0.192.rpz-ip")

    def test_ipv4_outside_prefix_does_not_match(self, engine):
        evaluation = engine.evaluate(addresses=["198.51.100.1"])
        assert evaluation.action() is None

    def test_longest_prefix_wins_and_reports_override(self, engine):
        evaluation = engine.evaluate(addresses=["8.8.8.9"])
        assert evaluation.action() is dns.rpz.Action.NXDOMAIN
        assert applied_owner(evaluation).startswith("24.8.8.8.rpz-ip")
        owners = {item.rule.owner.to_text() for item in evaluation.overridden}
        assert any("16.8.8.rpz-ip" in owner for owner in owners)

    def test_ipv6_prefix_match(self, engine):
        evaluation = engine.evaluate(addresses=["2001:db8::abcd"])
        assert evaluation.action() is dns.rpz.Action.NXDOMAIN
        assert applied_owner(evaluation).startswith("32.8.b.d.0.1.0.0.2.rpz-ip6")

    def test_ipv6_outside_prefix_does_not_match(self, engine):
        assert engine.evaluate(addresses=["2001:dead::1"]).action() is None

    def test_passthru_address_exception_overrides_threat_zone(self, engine):
        evaluation = engine.evaluate(addresses=["203.0.113.254"])
        assert evaluation.action() is dns.rpz.Action.PASSTHRU
        assert evaluation.applied.rule.zone_name == "exceptions"

    def test_truncated_v4_owner_zero_pads_trailing_octet(self):
        zone = dns.rpz.PolicyZone.from_text(
            "z",
            """$ORIGIN z.
$TTL 60
@ SOA a. b. 1 1 1 1 1
@ NS a.
24.10.rpz-ip CNAME rpz-nxdomain.
""",
            origin="z.",
        )
        rule = zone._v4[0]
        assert rule.network == ipaddress.ip_network("10.0.0.0/24")
        evaluation = dns.rpz.PolicyEngine([zone]).evaluate(addresses=["10.0.0.7"])
        assert evaluation.action() is dns.rpz.Action.NXDOMAIN

    def test_invalid_probe_address_raises(self, engine):
        with pytest.raises(dns.rpz.RPZError):
            engine.evaluate(addresses=["not-an-ip"])

    def test_multiple_addresses_report_each_override_once(self, engine):
        evaluation = engine.evaluate(addresses=["8.8.8.1", "8.8.8.2"])
        owners = [item.rule.owner.to_text() for item in evaluation.overridden]
        assert len(owners) == len(set(owners))


class TestPendingRules:
    def test_unknown_action_is_pending_and_not_enforced(self, engine):
        evaluation = engine.evaluate("mystery.example.")
        assert evaluation.action() is None
        reasons = {
            (item.owner.to_text(), item.reason) for item in evaluation.pending_matched
        }
        assert ("mystery.example.", dns.rpz.PendingReason.UNKNOWN_ACTION) in reasons

    def test_nsdname_and_nsip_are_unsupported(self, engine):
        pending = engine.pending_rules()
        triggers = {item.trigger for item in pending}
        assert dns.rpz.TriggerType.RPZ_NSDNAME in triggers
        assert dns.rpz.TriggerType.RPZ_NSIP in triggers
        assert all(
            item.reason is dns.rpz.PendingReason.UNSUPPORTED_TRIGGER
            for item in pending
            if item.trigger
            in (dns.rpz.TriggerType.RPZ_NSDNAME, dns.rpz.TriggerType.RPZ_NSIP)
        )

    def test_wildcard_address_trigger_is_pending(self, engine):
        evaluation = engine.evaluate(addresses=["10.0.16.5"])
        matched = [
            item
            for item in evaluation.pending_matched
            if item.reason is dns.rpz.PendingReason.WILDCARD_ADDRESS
        ]
        assert matched and "*.16.10.rpz-ip" in matched[0].owner.to_text()

    def test_non_cname_action_rrtype_is_pending(self, engine):
        evaluation = engine.evaluate("tarpit2.example.")
        assert evaluation.action() is None
        assert any(
            item.reason is dns.rpz.PendingReason.UNSUPPORTED_ACTION_RRTYPE
            for item in evaluation.pending_matched
        )

    def test_legacy_drop_action_is_unknown_and_pending(self, engine):
        evaluation = engine.evaluate(addresses=["2.1.0.99"])
        assert evaluation.action() is None
        assert any(
            item.reason is dns.rpz.PendingReason.UNKNOWN_ACTION
            and item.owner.to_text().startswith("24.1.2.rpz-ip")
            for item in evaluation.pending_matched
        )

    def test_malformed_address_owner_is_pending(self):
        zone = dns.rpz.PolicyZone.from_text(
            "z",
            """$ORIGIN z.
$TTL 60
@ SOA a. b. 1 1 1 1 1
@ NS a.
40.1.2.rpz-ip CNAME rpz-nxdomain.
""",
            origin="z.",
        )
        assert zone.pending
        assert zone.pending[0].reason is dns.rpz.PendingReason.MALFORMED_ADDRESS_TRIGGER

    def test_pending_all_lists_every_uninterpreted_zone_rule(self, engine):
        evaluation = engine.evaluate("example.net.")
        assert evaluation.pending_matched == ()
        assert len(evaluation.pending_all) == len(engine.pending_rules())
        assert evaluation.pending_all


class TestSyntheticResponse:
    def test_nxdomain_message_has_no_aa_bit(self):
        message = dns.rpz.synthetic_response("evil.example.", dns.rpz.Action.NXDOMAIN)
        assert not (message.flags & dns.flags.AA)
        assert message.rcode() == dns.rcode.NXDOMAIN
        dns.message.from_wire(message.to_wire())

    def test_nodata_message_is_noerror_empty_answer(self):
        message = dns.rpz.synthetic_response(
            "quiet.example.", dns.rpz.Action.NODATA, rdtype=dns.rdatatype.AAAA
        )
        assert not (message.flags & dns.flags.AA)
        assert message.rcode() == dns.rcode.NOERROR
        assert message.answer == []

    def test_passthru_has_no_synthetic_message(self):
        with pytest.raises(dns.rpz.RPZError):
            dns.rpz.synthetic_response("x.example.", dns.rpz.Action.PASSTHRU)


class TestEngineGuardsAndReport:
    def test_empty_zone_list_rejected(self):
        with pytest.raises(dns.rpz.RPZError):
            dns.rpz.PolicyEngine([])

    def test_probe_requires_qname_or_address(self, engine):
        with pytest.raises(dns.rpz.RPZError):
            engine.evaluate()

    def test_run_report_is_json_ready(self, engine):
        report = engine.run(
            [
                {"qname": "evil.example.", "rdtype": "A"},
                {"addresses": ["192.0.2.9"]},
            ]
        )
        assert report["zone_priority"] == ["exceptions", "threats"]
        assert report["supported_actions"] == [
            "nxdomain",
            "nodata",
            "passthru",
        ]
        assert len(report["evaluations"]) == 2
        # Everything must be plain JSON-serializable data.
        import json

        json.dumps(report)

    def test_rdtype_is_recorded_as_text(self, engine):
        evaluation = engine.evaluate("evil.example.", rdtype=dns.rdatatype.AAAA)
        assert evaluation.rdtype == "AAAA"

    def test_apex_soa_and_ns_are_not_policy_rules(self):
        zone = dns.rpz.PolicyZone.from_text(
            "z",
            """$ORIGIN z.
$TTL 60
@ SOA a. b. 1 1 1 1 1
@ NS a.
name.example CNAME .
""",
            origin="z.",
        )
        assert not zone.pending
        assert len(zone._exact) == 1
