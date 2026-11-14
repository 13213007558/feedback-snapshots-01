# -*- ruby encoding: utf-8 -*-
require_relative 'test_helper'

class TestFilterEvaluation < Test::Unit::TestCase
  Filter = Net::LDAP::Filter
  Result = Net::LDAP::Filter::EvaluationResult

  DIRECTORY_SCHEMA = Filter::Schema.new(
    {
      "objectClass" => { equality: :case_ignore, substring: :case_ignore },
      "uid" => { equality: :case_ignore },
      "sn" => { equality: :case_ignore, substring: :case_ignore },
      "mail" => { equality: :case_ignore, substring: :case_ignore },
      "memberOf" => { equality: :case_ignore, substring: :case_ignore },
      "gidNumber" => { equality: :integer, ordering: :integer },
      "objectGUID" => { equality: :octet_string },
      "cn;lang-fr" => { equality: :case_ignore },
    },
    {
      "2.5.13.2" => { rule: :case_ignore, attributes: ["uid", "mail"] },
      "caseExactMatch" => { rule: :case_exact, attributes: ["sn"] },
    }
  )

  def setup
    @entry = Net::LDAP::Entry.new("uid=alice,ou=people,dc=example,dc=org")
    @entry["objectClass"] = %w[person top inetOrgPerson]
    @entry["uid"] = "alice"
    @entry["sn"] = "Smith"
    @entry["mail"] = %w[alice@example.com asmith@example.org]
    @entry["memberOf"] = %w[cn=admins,dc=example,dc=org cn=staff,dc=example,dc=org]
    @entry["gidNumber"] = %w[100 200]
    @entry["objectGUID"] = [["0123456789abcdef"].pack("H*")].map(&:b)
    @entry["cn;lang-fr"] = "Alicia"
  end

  def evaluate(filter_string)
    Filter.construct(filter_string).evaluate(@entry, schema: DIRECTORY_SCHEMA)
  end

  def test_result_carries_three_valued_state
    result = evaluate("(uid=alice)")

    assert_equal :match, result.state
    assert result.matched?
    assert_equal :match, result.to_sym
  end

  def test_and_is_true_only_when_all_children_match
    assert_equal :match, evaluate("(&(uid=alice)(objectClass=person))").state
    assert_equal :no_match, evaluate("(&(uid=alice)(objectClass=printer))").state
  end

  def test_and_is_false_when_any_child_is_false_even_with_unknown_sibling
    result = evaluate("(&(uid=alice)(missingAttribute=x)(objectClass=printer))")

    assert_equal :no_match, result.state
    assert_match(/objectClass|printer|unknown objectclass/i, result.reason)
  end

  def test_and_is_undetermined_when_unknown_child_and_no_false_child
    result = evaluate("(&(uid=alice)(missingAttribute=x))")

    assert_equal :undetermined, result.state
    assert_match(/missingattribute/i, result.reason)
  end

  def test_or_is_true_if_any_child_matches_even_with_unknown_sibling
    assert_equal :match, evaluate("(|(uid=alice)(missingAttribute=x))").state
  end

  def test_or_is_undetermined_when_no_child_matches_and_one_is_unknown
    assert_equal :undetermined, evaluate("(|(uid=nobody)(missingAttribute=x))").state
  end

  def test_or_is_false_when_all_children_are_definitely_false
    assert_equal :no_match, evaluate("(|(uid=nobody)(objectClass=printer))").state
  end

  def test_not_of_a_match_is_false
    assert_equal :no_match, evaluate("(!(uid=alice))").state
  end

  def test_not_of_a_non_match_is_true
    assert_equal :match, evaluate("(!(uid=nobody))").state
  end

  def test_not_of_an_unknown_rule_is_never_a_match
    result = evaluate("(!(missingAttribute=x))")

    assert_equal :undetermined, result.state
    assert_match(/NOT of undetermined/i, result.reason)
  end

  def test_not_of_unknown_matching_rule_stays_undetermined
    assert_equal :undetermined, evaluate("(!(uid:1.2.3:=alice))").state
  end

  def test_untyped_extensible_with_a_known_type_uses_that_types_equality_rule
    assert_equal :match, evaluate("(!(uid:=nobody))").state
    assert_equal :match, evaluate("(uid:=alice)").state
  end

  def test_presence_requires_a_declared_attribute
    assert_equal :match, evaluate("(uid=*)").state
    @entry["uid"] = []
    assert_equal :no_match, evaluate("(uid=*)").state
    assert_equal :undetermined, evaluate("(telephoneNumber=*)").state
  end

  def test_presence_of_a_missing_but_declared_attribute_is_false
    @entry["mail"] = []
    assert_equal :no_match, evaluate("(mail=*)").state
  end

  def test_presence_of_an_undeclared_attribute_is_undetermined
    assert_equal :undetermined, evaluate("(unknownAttribute=*)").state
  end

  def test_equality_is_case_insensitive_under_the_declared_rule
    assert_equal :match, evaluate("(objectClass=PERSON)").state
    assert_equal :match, evaluate("(UID=ALICE)").state
  end

  def test_equality_respects_the_declared_case_exact_rule
    assert_equal :no_match, evaluate("(sn:caseExactMatch:=SMITH)").state
    assert_equal :match, evaluate("(sn:caseExactMatch:=Smith)").state
  end

  def test_multi_valued_attributes_match_when_any_value_matches
    assert_equal :match, evaluate("(mail=asmith@example.org)").state
    assert_equal :no_match, evaluate("(mail=asmith@example.net)").state
    assert_equal :match, evaluate("(memberOf=cn=staff,dc=example,dc=org)").state
  end

  def test_substring_initial_any_and_final
    assert_equal :match, evaluate("(sn=Smi*)").state
    assert_equal :match, evaluate("(sn=*mit*)").state
    assert_equal :match, evaluate("(sn=*th)").state
    assert_equal :match, evaluate("(mail=*@example.*)").state
    assert_equal :no_match, evaluate("(sn=Jones*)").state
    assert_equal :no_match, evaluate("(sn=*mitx*)").state
  end

  def test_substring_requires_a_declared_substring_rule
    result = evaluate("(gidNumber=10*)")

    assert_equal :undetermined, result.state
    assert_match(/no substring matching rule/i, result.reason)
  end

  def test_substring_respects_case_ignore_rule
    assert_equal :match, evaluate("(sn=SM*)").state
  end

  def test_escaped_star_is_a_literal_not_a_wildcard
    assert_equal :no_match, evaluate("(sn=Sm\\2Aith*)").state
    @entry["sn"] = "Sm*ith"
    assert_equal :match, evaluate("(sn=Sm\\2Aith)").state
    assert_equal :match, evaluate("(sn=*\\2A*)").state
  end

  def test_ordering_uses_the_declared_integer_rule
    assert_equal :match, evaluate("(gidNumber>=100)").state
    assert_equal :match, evaluate("(gidNumber<=200)").state
    assert_equal :no_match, evaluate("(gidNumber>=300)").state
    assert_equal :no_match, evaluate("(gidNumber<=99)").state
  end

  def test_invalid_integer_assertion_is_undetermined
    assert_equal :undetermined, evaluate("(gidNumber>=abc)").state
    assert_equal :undetermined, evaluate("(gidNumber=10x)").state
  end

  def test_invalid_integer_entry_value_is_undetermined
    @entry["gidNumber"] = %w[notanumber]

    assert_equal :undetermined, evaluate("(gidNumber>=100)").state
  end

  def test_one_valid_integer_value_is_enough_for_existential_match
    @entry["gidNumber"] = %w[100 notanumber]

    assert_equal :match, evaluate("(gidNumber>=100)").state
  end

  def test_ordering_without_a_declared_rule_is_undetermined
    assert_equal :undetermined, evaluate("(mail>=a)").state
  end

  def test_extensible_rule_requires_explicit_registration
    assert_equal :match, evaluate("(uid:2.5.13.2:=ALICE)").state
    assert_equal :match, evaluate("(mail:2.5.13.2:=ASMITH@EXAMPLE.ORG)").state
    assert_equal :undetermined, evaluate("(sn:2.5.13.2:=Smith)").state
  end

  def test_unknown_extensible_rule_never_guesses
    result = evaluate("(uid:9.9.9:=alice)")

    assert_equal :undetermined, result.state
    assert_match(/unknown matching rule/i, result.reason)
  end

  def test_untyped_extensible_rule_applies_to_declared_attributes
    assert_equal :match, evaluate("(:2.5.13.2:=alice)").state
    assert_equal :no_match, evaluate("(:2.5.13.2:=nobody)".sub("nobody", "zzz")).state
  end

  def test_dn_attributes_extensible_match_is_not_supported
    result = evaluate("(uid:dn:2.5.13.2:=alice)")

    assert_equal :undetermined, result.state
    assert_match(/dnAttributes/i, result.reason)
  end

  def test_missing_attribute_does_not_match_a_negated_equality_into_allow
    result = evaluate("(!(clearance=bogus))")

    assert_equal :undetermined, result.state
  end

  def test_compound_expression_propagates_unknowns_to_final_authorization
    allowed = Filter.construct("(|(uid=alice)(memberOf=cn=admins,dc=example,dc=org))")
    guarded = Filter.construct("(&(objectClass=person)(!(memberOf=cn=contractors,dc=example,dc=org)))")

    assert allowed.authorized?(@entry, schema: DIRECTORY_SCHEMA)
    assert guarded.authorized?(@entry, schema: DIRECTORY_SCHEMA)

    unknown_guard = Filter.construct(
      "(&(objectClass=person)(!(memberOf:2.5.13.1:=cn=contractors,dc=example,dc=org)))"
    )

    refute unknown_guard.authorized?(@entry, schema: DIRECTORY_SCHEMA),
           "an unknown rule under NOT must not authorize"
    assert_equal :undetermined, unknown_guard.evaluate(@entry, schema: DIRECTORY_SCHEMA).state

    missing_guard = Filter.construct(
      "(&(objectClass=person)(!(dn:=dc=example,dc=org)))"
    )

    refute missing_guard.authorized?(@entry, schema: DIRECTORY_SCHEMA)
    refute Filter.construct("(!(missingAttribute=x))").authorized?(@entry, schema: DIRECTORY_SCHEMA),
           "a missing attribute under NOT must not authorize"
  end

  def test_object_and_string_filters_agree
    string_filters = [
      "(uid=alice)",
      "(!(uid=nobody))",
      "(&(objectClass=*)(mail=*example*))",
      "(|(uid=nobody)(memberOf=cn=staff,dc=example,dc=org))",
      "(gidNumber>=150)",
      "(missingAttribute=x)",
      "(!(missingAttribute=x))",
    ]
    object_filters = [
      Filter.eq("uid", "alice"),
      ~Filter.eq("uid", "nobody"),
      Filter.present("objectClass") & Filter.eq("mail", "*example*"),
      Filter.eq("uid", "nobody") | Filter.eq("memberOf", "cn=staff,dc=example,dc=org"),
      Filter.ge("gidNumber", "150"),
      Filter.eq("missingAttribute", "x"),
      ~Filter.eq("missingAttribute", "x"),
    ]

    string_filters.zip(object_filters).each do |string_filter, object_filter|
      from_string = Filter.construct(string_filter)
      from_object = object_filter
      from_ber = Filter.parse_ber(object_filter.to_ber.read_ber(Net::LDAP::AsnSyntax))

      assert_equal from_string.to_s, from_object.to_s
      assert_equal from_object, from_string

      [
        from_string,
        from_object,
        from_ber,
      ].map { |filter| filter.evaluate(@entry, schema: DIRECTORY_SCHEMA) }.tap do |results|
        assert_equal results[0].state, results[1].state, string_filter
        assert_equal results[1].state, results[2].state, string_filter
        assert_equal results[0].reasons, results[1].reasons, string_filter
        assert_equal results[1].reasons, results[2].reasons, string_filter
      end
    end
  end

  def test_ber_round_trip_keeps_escaped_assertions_consistent
    filters = [
      Filter.eq("sn", "Sm\\2Aith"),
      Filter.eq("sn", "*\\2A*"),
      Filter.eq("sn", "Sm\\28ith\\29"),
      Filter.eq("sn", "*"),
      Filter.bineq("objectGUID", ["0123456789abcdef"].pack("H*")),
      Filter.bineq("objectGUID", "\xFF\xFE\x00".b),
      Filter.contains("mail", "example"),
      Filter.ex("uid:2.5.13.2", "ALICE"),
    ]

    filters.each do |filter|
      round_tripped = Filter.parse_ber(filter.to_ber.read_ber(Net::LDAP::AsnSyntax))

      assert_equal filter.to_ber, round_tripped.to_ber
      assert_equal filter.evaluate(@entry, schema: DIRECTORY_SCHEMA).state,
                   round_tripped.evaluate(@entry, schema: DIRECTORY_SCHEMA).state
    end
  end

  def test_schema_refuses_unregistered_rule_kinds
    assert_raises(ArgumentError) do
      Filter::Schema.new("cn" => { equality: :phonetic })
    end
    assert_raises(ArgumentError) do
      Filter::Schema.new("cn" => { substring: :integer })
    end
  end

  def test_schema_refuses_matching_rules_for_undeclared_attributes
    assert_raises(ArgumentError) do
      Filter::Schema.new(
        { "uid" => { equality: :case_ignore } },
        { "2.5.13.2" => { rule: :case_ignore, attributes: ["mail"] } }
      )
    end
  end

  def test_schema_refuses_duplicate_declarations
    schema = Filter::Schema.new("cn" => { equality: :case_ignore })

    assert_raises(ArgumentError) { schema.add_attribute("CN", equality: :case_exact) }
    assert_raises(ArgumentError) do
      schema.add_matching_rule("2.5.13.2", rule: :case_ignore, attributes: ["cn"]).add_matching_rule(
        "2.5.13.2", rule: :case_ignore, attributes: ["cn"]
      )
    end
  end

  def test_schema_does_not_inherit_attribute_options
    assert_equal :undetermined, evaluate("(uid;lang-fr=alice)").state
    assert_equal :match, evaluate("(cn;lang-fr=Alicia)").state
    assert_equal :match, evaluate("(CN;LANG-FR=alicia)").state
  end

  def test_empty_schema_never_guesses
    result = Filter.eq("uid", "alice").evaluate(@entry)

    assert_equal :undetermined, result.state
    refute Filter.eq("uid", "alice").authorized?(@entry)
  end

  def test_plain_enumerable_entry
    plain_entry = {
      "uid" => ["alice"],
      "objectclass" => ["person"],
      "mail" => ["alice@example.com"],
    }

    assert_equal :match, Filter.construct("(uid=alice)").evaluate(plain_entry, schema: DIRECTORY_SCHEMA).state
    assert_equal :undetermined,
                 Filter.construct("(missing=*)").evaluate(plain_entry, schema: DIRECTORY_SCHEMA).state
  end

  def test_reasons_are_reported_for_undetermined_results
    result = evaluate("(gidNumber>=abc)")

    assert_equal :undetermined, result.state
    assert_match(/invalid integer assertion/i, result.reason)
  end

  def test_deep_and_chain_is_evaluated_without_recursion_failure
    filter = Filter.eq("uid", "alice")
    5_000.times { filter = filter & Filter.present("objectClass") }

    assert_equal :match, filter.evaluate(@entry, schema: DIRECTORY_SCHEMA).state
  end

  def test_deeply_negated_filter_is_undetermined_with_bounded_reasons
    filter = Filter.eq("uid", "alice")
    150.times { filter = ~filter }

    result = filter.evaluate(@entry, schema: DIRECTORY_SCHEMA)

    assert_equal :undetermined, result.state
    assert_operator result.reasons.size, :<=, Result::MAX_REASONS
    assert_operator result.reasons.first.length, :<=, Result::MAX_REASON_LENGTH
  end

  def test_authorized_predicate_rejects_undetermined
    assert Filter.construct("(uid=alice)").authorized?(@entry, schema: DIRECTORY_SCHEMA)
    refute Filter.construct("(uid=nobody)").authorized?(@entry, schema: DIRECTORY_SCHEMA)
    refute Filter.construct("(missing=x)").authorized?(@entry, schema: DIRECTORY_SCHEMA)
  end
end
