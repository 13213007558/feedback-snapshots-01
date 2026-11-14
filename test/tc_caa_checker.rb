# --
# Copyright 2007 Nominet UK
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

require_relative 'spec_helper'

class TestCaaChecker < Minitest::Test
  include Dnsruby

  CA = "ca.example.net".freeze
  OTHER = "other.example.org".freeze

  def provider(fixtures = {}, missing: :empty)
    CaaChecker::StaticProvider.new(fixtures, missing: missing)
  end

  def caa(name, flag, tag, value)
    "#{name}. 300 IN CAA #{flag} #{tag} \"#{value}\""
  end

  # Dnsruby's presentation parser only accepts the registered CAA tags,
  # so unknown tags are built directly as RR objects.
  def caa_unknown(name, flag, tag, value)
    rr = Dnsruby::RR::IN::CAA.new
    rr.name = "#{name}."
    rr.ttl = 300
    rr.type = "CAA"
    rr.klass = "IN"
    rr.from_hash(flag: flag, property_tag: tag, property_value: value)
    rr
  end

  # ---- tree climbing and the Relevant RRset -----------------------------

  def test_climbs_to_parent_policy_and_lists_names_and_records
    p = provider({
      "example.com" => { answer: [caa("example.com", 0, "issue", CA)] }
    })
    result = CaaChecker.authorize(domain: "www.example.com", issuer: CA, provider: p)

    assert result.allow?
    assert_equal :authorized, result.reason
    assert_equal "example.com", result.relevant_name
    assert_equal ["0 issue \"#{CA}\""], result.relevant_records.map(&:rdata_to_string)
    assert_equal %w[www.example.com example.com],
                 result.trace.map(&:queried_name)
    assert_equal [:empty, :rrset], result.trace.map(&:outcome)
  end

  def test_stops_at_first_rrset_and_never_merges_lower_and_higher_sets
    p = provider({
      "example.com" => { answer: [caa("example.com", 0, "issue", CA)] },
      "sub.example.com" => { answer: [caa("sub.example.com", 0, "issue", OTHER)] }
    })
    result = CaaChecker.authorize(domain: "host.sub.example.com", issuer: CA, provider: p)

    assert result.deny?
    assert_equal :issuer_not_listed, result.reason
    assert_equal "sub.example.com", result.relevant_name
    assert_equal ["host.sub.example.com", "sub.example.com"],
                 result.trace.map(&:queried_name)
    assert_equal 1, result.relevant_records.size
    assert_equal OTHER, parse_domain(result.relevant_records.first)
  end

  def test_no_policy_is_distinct_from_lookup_failure
    p = provider({}, missing: :empty)
    result = CaaChecker.authorize(domain: "anything.example", issuer: CA, provider: p)

    assert result.no_policy?
    assert_nil result.relevant_name
    assert_empty result.relevant_records
    assert result.trace.all? { |entry| entry.outcome == :empty }
  end

  def test_nxdomain_at_every_label_is_completed_empty_answer
    p = provider({}, missing: :nxdomain)
    result = CaaChecker.authorize(domain: "gone.example", issuer: CA, provider: p)

    assert result.no_policy?
    assert result.trace.all? { |entry| entry.rcode == Dnsruby::RCode::NXDOMAIN }
  end

  def test_servfail_is_lookup_incomplete_not_no_policy
    p = provider({ "broken.example" => { rcode: "SERVFAIL" } })
    result = CaaChecker.authorize(domain: "broken.example", issuer: CA, provider: p)

    assert result.lookup_incomplete?
    assert_equal 2, result.failure[:rcode]
    assert_equal "broken.example", result.failure[:name]
    assert_equal :failed, result.trace.last.outcome
  end

  def test_servfail_at_parent_blocks_even_when_child_is_empty
    p = provider({
      "host.broken.example" => { rcode: "NOERROR" },
      "broken.example" => { rcode: "SERVFAIL" }
    })
    result = CaaChecker.authorize(domain: "host.broken.example", issuer: CA, provider: p)

    assert result.lookup_incomplete?
    assert_equal %w[host.broken.example broken.example],
                 result.trace.map(&:queried_name)
  end

  def test_refused_and_notimp_are_incomplete
    %w[REFUSED NOTIMP].each do |rcode|
      p = provider({ "x.example" => { rcode: rcode } })
      result = CaaChecker.authorize(domain: "x.example", issuer: CA, provider: p)
      assert result.lookup_incomplete?, "#{rcode} must be incomplete"
    end
  end

  def test_missing_fixture_defaults_to_lookup_incomplete
    p = provider({}, missing: :raise)
    result = CaaChecker.authorize(domain: "unrecorded.example", issuer: CA, provider: p)

    assert result.lookup_incomplete?
    assert_equal "unrecorded.example", result.failure[:name]
  end

  # ---- empty authorization and malformed values --------------------------

  def test_empty_issuer_forbids_all_issuers
    p = provider({ "nocerts.example" => { answer: [caa("nocerts.example", 0, "issue", ";")] } })
    result = CaaChecker.authorize(domain: "nocerts.example", issuer: CA, provider: p)

    assert result.deny?
    assert_equal :empty_issuer, result.reason
  end

  def test_empty_issuer_is_additive_with_a_named_issuer
    p = provider({
      "mix.example" => {
        answer: [
          caa("mix.example", 0, "issue", ";"),
          caa("mix.example", 0, "issue", CA)
        ]
      }
    })
    result = CaaChecker.authorize(domain: "mix.example", issuer: CA, provider: p)

    assert result.allow?
    assert_equal 2, result.evaluations.size
  end

  def test_malformed_issue_value_treated_as_empty_issuer
    p = provider({ "bad.example" => { answer: [caa("bad.example", 0, "issue", "%%%%%")] } })
    result = CaaChecker.authorize(domain: "bad.example", issuer: CA, provider: p)

    assert result.deny?
    assert_equal :empty_issuer, result.reason
  end

  # ---- critical flag ------------------------------------------------------

  def test_unknown_critical_property_forbids_issuance
    p = provider({
      "new.example" => {
        answer: [
          caa("new.example", 0, "issue", CA),
          caa_unknown("new.example", 128, "tbs", "Unknown")
        ]
      }
    })
    result = CaaChecker.authorize(domain: "new.example", issuer: CA, provider: p)

    assert result.deny?
    assert_equal :unknown_critical_property, result.reason
  end

  def test_unknown_non_critical_property_does_not_block
    p = provider({
      "new.example" => {
        answer: [
          caa("new.example", 0, "issue", CA),
          caa_unknown("new.example", 0, "futuretag", "ignored")
        ]
      }
    })
    result = CaaChecker.authorize(domain: "new.example", issuer: CA, provider: p)

    assert result.allow?
  end

  def test_iodef_only_rrset_does_not_restrict_issuance
    p = provider({
      "report.example" => { answer: [caa("report.example", 0, "iodef", "mailto:sec@example")] }
    })
    result = CaaChecker.authorize(domain: "report.example", issuer: CA, provider: p)

    assert result.allow?
    assert_equal :no_restricting_properties, result.reason
  end

  # ---- wildcard / issuewild ----------------------------------------------

  def test_issuewild_ignored_for_non_wildcard_request
    p = provider({
      "wild.example" => {
        answer: [
          caa("wild.example", 0, "issue", CA),
          caa("wild.example", 0, "issuewild", OTHER)
        ]
      }
    })
    result = CaaChecker.authorize(domain: "wild.example", wildcard: false,
                                  issuer: CA, provider: p)

    assert result.allow?
    assert_equal %w[issue], result.evaluations.map { |e| e[:tag] }
  end

  def test_issuewild_takes_precedence_for_wildcard_request
    p = provider({
      "wild.example" => {
        answer: [
          caa("wild.example", 0, "issue", CA),
          caa("wild.example", 0, "issuewild", OTHER)
        ]
      }
    })
    result = CaaChecker.authorize(domain: "wild.example", wildcard: true,
                                  issuer: CA, provider: p)

    assert result.deny?
    assert_equal :issuer_not_listed, result.reason
    assert_equal %w[issuewild], result.evaluations.map { |e| e[:tag] }
  end

  def test_wildcard_prefix_in_domain_implies_wildcard_request
    p = provider({
      "wild.example" => { answer: [caa("wild.example", 0, "issuewild", CA)] }
    })
    result = CaaChecker.authorize(domain: "*.wild.example", issuer: CA, provider: p)

    assert result.allow?
    assert result.wildcard
    assert_equal "wild.example", result.domain
  end

  def test_issuewild_only_rrset_denies_non_wildcard_request
    p = provider({
      "wild3.example" => { answer: [caa("wild3.example", 0, "issuewild", OTHER)] }
    })
    result = CaaChecker.authorize(domain: "wild3.example", wildcard: false,
                                  issuer: OTHER, provider: p)

    assert result.allow?
    assert_equal :no_restricting_properties, result.reason
  end

  # ---- aliases: CNAME / DNAME must not widen authorization ---------------

  def test_cname_alias_uses_target_policy_only
    p = provider({
      "alias.example" => {
        answer: [
          "alias.example. 300 IN CNAME target.example.net.",
          "target.example.net. 300 IN CAA 0 issue \"#{OTHER}\""
        ]
      }
    })
    result = CaaChecker.authorize(domain: "alias.example", issuer: CA, provider: p)

    assert result.deny?
    assert_equal "target.example.net", result.relevant_name
    assert_equal [:alias, :rrset], result.trace.map(&:outcome)
    assert_equal "target.example.net", result.trace.first.alias_target
  end

  def test_cname_alias_does_not_merge_parent_policy
    p = provider({
      "example.com" => { answer: [caa("example.com", 0, "issue", CA)] },
      "alias.example.com" => {
        answer: [
          "alias.example.com. 300 IN CNAME target.example.org.",
          "target.example.org. 300 IN CAA 0 issue \"#{OTHER}\""
        ]
      }
    })
    result = CaaChecker.authorize(domain: "alias.example.com", issuer: CA, provider: p)

    assert result.deny?
    assert_equal "target.example.org", result.relevant_name
    refute_includes result.trace.map(&:queried_name), "example.com"
  end

  def test_cname_chase_across_separate_provider_queries
    p = provider({
      "a.example" => { answer: ["a.example. 300 IN CNAME b.example."] },
      "b.example" => { answer: ["b.example. 300 IN CNAME c.example."] },
      "c.example" => { answer: [caa("c.example", 0, "issue", CA)] }
    })
    result = CaaChecker.authorize(domain: "a.example", issuer: CA, provider: p)

    assert result.allow?
    assert_equal "c.example", result.relevant_name
    assert_equal %w[a.example b.example c.example], result.trace.map(&:queried_name)
  end

  def test_alias_loop_is_lookup_incomplete
    p = provider({
      "loop1.example" => { answer: ["loop1.example. 300 IN CNAME loop2.example."] },
      "loop2.example" => { answer: ["loop2.example. 300 IN CNAME loop1.example."] }
    })
    result = CaaChecker.authorize(domain: "loop1.example", issuer: CA, provider: p)

    assert result.lookup_incomplete?
  end

  def test_dname_redirects_with_suffix_substitution
    p = provider({
      "example.com" => {
        answer: [
          "example.com. 300 IN DNAME target.example.net.",
          "host.target.example.net. 300 IN CAA 0 issue \"#{CA}\""
        ]
      }
    })
    result = CaaChecker.authorize(domain: "host.example.com", issuer: CA, provider: p)

    assert result.allow?
    assert_equal "host.target.example.net", result.relevant_name
    assert_equal "target.example.net", result.trace.first.alias_target
  end

  # ---- parameters on issuer properties ------------------------------------

  def test_unknown_issuer_parameter_does_not_authorize
    p = provider({
      "acct.example" => { answer: [caa("acct.example", 0, "issue", "#{CA}; account=230123")] }
    })
    result = CaaChecker.authorize(domain: "acct.example", issuer: CA, provider: p)

    assert result.deny?
    assert_equal :unsupported_parameters, result.reason
  end

  # ---- failure classification ---------------------------------------------

  def test_truncated_response_is_lookup_incomplete
    message = Dnsruby::Message.new("tc.example", "CAA")
    message.header.tc = true
    p = provider({ "tc.example" => message })
    result = CaaChecker.authorize(domain: "tc.example", issuer: CA, provider: p)

    assert result.lookup_incomplete?
    assert_match(/truncated/, result.failure[:message])
  end

  def test_provider_exception_is_classified_as_lookup_incomplete
    custom = Object.new
    def custom.query(_name)
      raise Dnsruby::ResolvTimeout, "no response"
    end
    result = CaaChecker.authorize(domain: "slow.example", issuer: CA, provider: custom)

    assert result.lookup_incomplete?
    assert_equal "slow.example", result.failure[:name]
  end

  def test_any_one_of_several_issuers_authorizes
    p = provider({
      "multi.example" => {
        answer: [
          caa("multi.example", 0, "issue", "ca-a.example"),
          caa("multi.example", 0, "issue", CA),
          caa("multi.example", 0, "issue", "ca-c.example")
        ]
      }
    })
    result = CaaChecker.authorize(domain: "multi.example", issuer: CA, provider: p)

    assert result.allow?
    assert_equal 3, result.evaluations.size
  end

  def test_parent_allow_and_child_deny_are_evaluated_separately_not_merged
    fixtures = {
      "example.com" => { answer: [caa("example.com", 0, "issue", CA)] },
      "sub.example.com" => { answer: [caa("sub.example.com", 0, "issue", ";")] }
    }
    allowed = CaaChecker.authorize(
      domain: "sibling.example.com", issuer: CA, provider: provider(fixtures)
    )
    denied = CaaChecker.authorize(
      domain: "host.sub.example.com", issuer: CA, provider: provider(fixtures)
    )

    assert allowed.allow?
    assert_equal "example.com", allowed.relevant_name
    assert denied.deny?
    assert_equal :empty_issuer, denied.reason
    assert_equal "sub.example.com", denied.relevant_name
  end

  # ---- input validation ---------------------------------------------------

  def test_invalid_domain_and_issuer_raise_invalid_input
    assert_raises(CaaChecker::InvalidInput) do
      CaaChecker.authorize(domain: "", issuer: CA, provider: provider)
    end
    assert_raises(CaaChecker::InvalidInput) do
      CaaChecker.authorize(domain: "ok.example", issuer: "not a domain", provider: provider)
    end
  end

  def test_trace_and_result_are_serializable_for_review
    p = provider({
      "example.com" => { answer: [caa("example.com", 0, "issue", CA)] }
    })
    hash = CaaChecker.authorize(domain: "www.example.com", issuer: CA, provider: p).to_h

    assert_equal :allow, hash[:decision]
    assert_equal "example.com", hash[:relevant_name]
    assert_equal 2, hash[:trace].size
    assert hash[:trace].first.key?(:records)
  end

  private

  def parse_domain(rr)
    rr.property_value.to_s.split(";").first.strip
  end
end
