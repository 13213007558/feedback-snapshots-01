require_relative 'test_helper'
require_relative '../lib/net/ldap/dn'

class TestDN < Test::Unit::TestCase
  def test_escape
    assert_equal '\\,\\+\\"\\\\\\<\\>\\;', Net::LDAP::DN.escape(',+"\\<>;')
  end

  def test_escape_pound_sign
    assert_equal '\\#test', Net::LDAP::DN.escape('#test')
  end

  def test_escape_space
    assert_equal '\\ before_after\\ ', Net::LDAP::DN.escape(' before_after ')
  end

  def test_retain_spaces
    dn = Net::LDAP::DN.new('CN=Foo.bar.baz, OU=Foo   \ ,OU=\  Bar, O=Baz')
    assert_equal "CN=Foo.bar.baz, OU=Foo   \\ ,OU=\\  Bar, O=Baz", dn.to_s
    assert_equal ["CN", "Foo.bar.baz", "OU", "Foo    ", "OU", "  Bar", "O", "Baz"], dn.to_a
  end

  def test_escape_on_initialize
    dn = Net::LDAP::DN.new('cn', ',+"\\<>;', 'ou=company')
    assert_equal 'cn=\\,\\+\\"\\\\\\<\\>\\;,ou=company', dn.to_s
  end

  def test_to_a
    dn = Net::LDAP::DN.new('cn=James, ou=Company\\,\\20LLC')
    assert_equal ['cn', 'James', 'ou', 'Company, LLC'], dn.to_a
  end

  def test_to_a_parenthesis
    dn = Net::LDAP::DN.new('cn =  \ James , ou  =  "Comp\28ny"  ')
    assert_equal ['cn', ' James ', 'ou', 'Comp(ny'], dn.to_a
  end

  def test_to_a_hash_symbol
    dn = Net::LDAP::DN.new('1.23.4=  #A3B4D5  ,ou=Company')
    assert_equal ['1.23.4', '#A3B4D5', 'ou', 'Company'], dn.to_a
  end

  def test_bad_input_raises_error
    [
      'cn=James,',
      'cn=#aa aa',
      'cn="James',
      'cn=J\ames',
      'cn=\\',
      '1.2.d=Value',
      'd1.2=Value',
    ].each do |input|
      dn = Net::LDAP::DN.new(input)
      assert_raises(Net::LDAP::InvalidDNError) { dn.to_a }
    end
  end
end

class TestDNStructure < Test::Unit::TestCase
  def test_parse_rdns_simple
    assert_equal [[['cn', 'James']], [['ou', 'Company, LLC']], [['dc', 'example']], [['dc', 'com']]],
                 Net::LDAP::DN.parse_rdns('cn=James,ou=Company\, LLC,dc=example,dc=com')
  end

  def test_parse_rdns_multi_valued
    assert_equal [[['cn', 'foo'], ['ou', 'bar']], [['dc', 'example']]],
                 Net::LDAP::DN.parse_rdns('cn=foo+ou=bar,dc=example')
  end

  def test_parse_rdns_escaped_separators_stay_in_one_rdn
    assert_equal [[['cn', 'a,b+c']], [['dc', 'example']]],
                 Net::LDAP::DN.parse_rdns('cn=a\,b\+c,dc=example')
  end

  def test_parse_rdns_hexstring_value_is_decoded
    assert_equal [[['cn', 'John']], [['dc', 'example']]],
                 Net::LDAP::DN.parse_rdns('cn=#4A6F686E,dc=example')
  end

  def test_parse_rdns_hex_escapes_are_decoded
    assert_equal [[['cn', 'John']]], Net::LDAP::DN.parse_rdns('cn=\4A\6F\68\6E')
  end

  def test_parse_rdns_oid_attribute
    assert_equal [[['2.5.4.3', 'John']]], Net::LDAP::DN.parse_rdns('2.5.4.3=John')
  end

  def test_parse_rdns_bad_input_raises_error
    [
      'cn=James,',
      'cn=James+',
      'cn=#A3B',
      'cn=#',
      'cn="James',
      'cn=\\',
      'cn=\4',
      '1.2.=Value',
      'cn James',
    ].each do |input|
      assert_raises(Net::LDAP::InvalidDNError, input) { Net::LDAP::DN.parse_rdns(input) }
    end
  end

  def test_parse_reencodes_from_parsed_structure
    dn = Net::LDAP::DN.parse('cn=#4A6F686E,ou=eng,dc=example,dc=com')
    assert_equal 'cn=John,ou=eng,dc=example,dc=com', dn.to_s
  end

  def test_parse_reencodes_multi_valued_and_escaped
    dn = Net::LDAP::DN.parse('cn=a\,b+ou=\4Aohn,dc=example')
    assert_equal 'cn=a\,b+ou=John,dc=example', dn.to_s
  end

  def test_parse_validates_eagerly
    assert_raises(Net::LDAP::InvalidDNError) { Net::LDAP::DN.parse('cn=James,') }
  end

  def test_subtree_inside
    assert_equal true, Net::LDAP::DN.subtree_of?(
      'cn=alice,ou=eng,dc=example,dc=com', 'ou=eng,dc=example,dc=com')
  end

  def test_subtree_base_itself_is_contained
    assert_equal true, Net::LDAP::DN.subtree_of?(
      'ou=eng,dc=example,dc=com', 'ou=eng,dc=example,dc=com')
  end

  def test_subtree_lookalikes_are_rejected
    base = 'ou=eng,dc=example,dc=com'
    [
      'cn=ou=eng,dc=example,dc=com',        # base string hidden in a value
      'ou=engineering,dc=example,dc=com',   # value sharing a prefix
      'ou=eng,dc=example,dc=com,evil=x',    # extra component at the wrong end
      'ou=eng,dc=example,dc=com,dc=evil',   # base not at the root side
      'ou=eng,dc=example2,dc=com',          # near-miss component
      'ou=eng+ou=ops,dc=example,dc=com',    # extra AVA in the RDN
    ].each do |lookalike|
      assert_equal false, Net::LDAP::DN.subtree_of?(lookalike, base), lookalike
    end
  end

  def test_subtree_escaped_and_hex_equivalents_match
    base = 'ou=eng,dc=example,dc=com'
    assert_equal true, Net::LDAP::DN.subtree_of?('ou=\65\6E\67,dc=example,dc=com', base)
    assert_equal true, Net::LDAP::DN.subtree_of?('ou=#656E67,dc=example,dc=com', base)
    assert_equal true, Net::LDAP::DN.subtree_of?('ou="eng",dc=example,dc=com', base)
  end

  def test_subtree_attribute_types_are_case_insensitive
    assert_equal true, Net::LDAP::DN.subtree_of?(
      'OU=eng,DC=example,DC=com', 'ou=eng,dc=example,dc=com')
  end

  def test_subtree_values_are_not_case_folded_without_a_rule
    assert_equal false, Net::LDAP::DN.subtree_of?(
      'ou=ENG,dc=example,dc=com', 'ou=eng,dc=example,dc=com')
  end

  def test_subtree_caller_supplied_matching_rule
    rules = { 'ou' => ->(a, b) { a.casecmp?(b) } }
    assert_equal true, Net::LDAP::DN.subtree_of?(
      'ou=ENG,dc=example,dc=com', 'ou=eng,dc=example,dc=com',
      matching_rules: rules)
    # attributes without a rule still compare exactly
    assert_equal false, Net::LDAP::DN.subtree_of?(
      'ou=ENG,dc=EXAMPLE,dc=com', 'ou=eng,dc=example,dc=com',
      matching_rules: rules)
  end

  def test_subtree_indeterminate_when_rule_cannot_decide
    rules = { 'ou' => ->(_a, _b) { nil } }
    assert_nil Net::LDAP::DN.subtree_of?(
      'ou=eng,dc=example,dc=com', 'ou=eng,dc=example,dc=com',
      matching_rules: rules)
  end

  def test_subtree_indeterminate_loses_to_definite_mismatch
    rules = { 'ou' => ->(_a, _b) { nil } }
    assert_equal false, Net::LDAP::DN.subtree_of?(
      'ou=eng,dc=evil,dc=com', 'ou=eng,dc=example,dc=com',
      matching_rules: rules)
  end

  def test_subtree_attribute_aliases
    aliases = { 'cn' => '2.5.4.3', 'commonname' => '2.5.4.3' }
    assert_equal true, Net::LDAP::DN.subtree_of?(
      '2.5.4.3=eng,dc=example,dc=com', 'commonName=eng,dc=example,dc=com',
      attribute_aliases: aliases)
    # without the alias mapping the types are simply different
    assert_equal false, Net::LDAP::DN.subtree_of?(
      '2.5.4.3=eng,dc=example,dc=com', 'commonName=eng,dc=example,dc=com')
  end

  def test_subtree_multi_valued_rdn_order_independent
    assert_equal true, Net::LDAP::DN.subtree_of?(
      'cn=alice,ou=b+cn=a,dc=example', 'cn=a+ou=b,dc=example')
  end

  def test_subtree_instance_method_and_reencode_round_trip
    dn = Net::LDAP::DN.parse('cn=ali\63e,ou=eng,dc=example,dc=com')
    assert_equal true, dn.subtree_of?('ou=eng,dc=example,dc=com')
    assert_equal 'cn=alice,ou=eng,dc=example,dc=com', dn.to_s
  end
end
