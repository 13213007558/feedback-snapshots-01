# -*- ruby encoding: utf-8 -*-
require_relative 'test_helper'

class TestRangedAttributeReader < Test::Unit::TestCase
  GROUP_DN = "cn=Large Group,ou=Groups,dc=example,dc=org"

  GUID  = "guid-1"
  USN   = "42"

  def reader(options = {})
    Net::LDAP::RangedAttributeReader.new(**{
      dn:                 GROUP_DN,
      attribute:          "member",
      identity_attribute: "objectGUID",
      version_attribute:  "uSNChanged",
      validate_page_size:  false,
    }.merge(options))
  end

  def page(range_start: nil, range_end: nil, values: [], terminal: false,
           plain: false, attribute_present: true, entry_found: true,
           dn: GROUP_DN, guid: GUID, version: USN, result_code: nil,
           error: nil)
    Net::LDAP::RangedAttributeReader::Page.new(
      entry_found:       entry_found,
      dn:                dn,
      attribute_present: attribute_present,
      plain:             plain,
      range_start:       range_start,
      range_end:         range_end,
      terminal:          terminal,
      values:            values,
      object_guid:       guid,
      object_version:    version,
      result_code:       result_code,
      error:             error,
    )
  end

  def run_pages(pages, options = {})
    reader(options).read { |_offset, _count| pages.shift }
  end

  def test_merges_contiguous_ranges_across_multiple_pages
    pages = [
      page(range_start: 0, range_end: 1, values: %w(a b)),
      page(range_start: 2, range_end: 3, values: %w(c d)),
      page(range_start: 4, terminal: true, values: %w(e f)),
    ]

    result = run_pages(pages)

    assert result.complete?
    refute result.empty?
    assert_equal %w(a b c d e f), result.values
    assert result.replaceable?
    assert_equal %w(a b c d e f), result.snapshot
    assert_equal 3, result.page_count
    assert_equal :ok, result.reason
    assert result.object_verified?
    assert result.version_stable?
  end

  def test_complete_empty_is_distinct_from_unfinished
    empty = run_pages([page(attribute_present: false)])

    assert empty.complete?
    assert empty.empty?
    assert_equal [], empty.values
    assert_empty empty.values
    assert empty.replaceable?
    assert_equal [], empty.snapshot

    unfinished = run_pages([
      page(range_start: 0, range_end: 1, values: %w(a b)),
    ])

    refute unfinished.complete?
    refute unfinished.empty?
    assert_raise(Net::LDAP::IncompleteAttributeError) { unfinished.values }
    assert_nil unfinished.snapshot
    refute unfinished.replaceable?
    assert_equal %w(a b), unfinished.partial_values
  end

  def test_overlap_aborts_and_is_fully_retryable
    result = run_pages([
      page(range_start: 0, range_end: 2, values: %w(a b c)),
      page(range_start: 2, range_end: 3, values: %w(c d)),
    ])

    refute result.complete?
    assert_equal :overlap, result.reason
    assert result.retryable?
    refute result.replaceable?
    assert_equal %w(a b c), result.partial_values
    assert_raise(Net::LDAP::IncompleteAttributeError) { result.values }
  end

  def test_gap_aborts_and_is_fully_retryable
    result = run_pages([
      page(range_start: 0, range_end: 1, values: %w(a b)),
      page(range_start: 3, terminal: true, values: %w(d)),
    ])

    refute result.complete?
    assert_equal :gap, result.reason
    assert result.retryable?
    refute result.replaceable?
    assert_equal %w(a b), result.partial_values
  end

  def test_first_range_must_start_at_zero
    result = run_pages([
      page(range_start: 2, terminal: true, values: %w(c)),
    ])

    refute result.complete?
    assert_equal :gap, result.reason
    refute result.replaceable?
  end

  def test_numeric_end_is_never_terminal
    result = run_pages([
      page(range_start: 0, range_end: 1, values: %w(a b)),
    ])

    refute result.complete?
    assert_equal :missing_terminal, result.reason
    assert result.retryable?
  end

  def test_unranged_response_is_complete_without_a_terminal_star
    result = run_pages([
      page(plain: true, values: %w(a b)),
    ])

    assert result.complete?
    assert_equal %w(a b), result.values
    assert result.replaceable?
  end

  def test_terminal_star_is_required_for_ranged_response
    result = run_pages([
      page(range_start: 0, range_end: 0, values: %w(a)),
      page(range_start: 1, range_end: 1, values: %w(b)),
    ])

    refute result.complete?
    assert_equal :missing_terminal, result.reason
  end

  def test_object_identity_change_aborts_snapshot
    result = run_pages([
      page(range_start: 0, range_end: 1, values: %w(a b), guid: "guid-1"),
      page(range_start: 2, terminal: true, values: %w(c), guid: "guid-2"),
    ])

    refute result.complete?
    assert_equal :object_changed, result.reason
    refute result.replaceable?
    assert result.retryable?
  end

  def test_object_version_change_aborts_snapshot_even_when_guid_stable
    result = run_pages([
      page(range_start: 0, range_end: 1, values: %w(a b), version: "41"),
      page(range_start: 2, terminal: true, values: %w(c), version: "42"),
    ])

    refute result.complete?
    assert_equal :object_changed, result.reason
    refute result.replaceable?
  end

  def test_missing_object_identity_blocks_replaceable_snapshot
    result = run_pages([
      page(range_start: 0, terminal: true, values: %w(a), guid: nil),
    ])

    refute result.complete?
    assert_equal :unverified_object, result.reason
    refute result.retryable?
    refute result.replaceable?
    refute result.object_verified?
  end

  def test_identity_can_be_optional_but_snapshot_still_requires_complete_chain
    result = run_pages(
      [page(range_start: 0, terminal: true, values: %w(a), guid: nil, version: nil)],
      require_identity: false,
      require_version: false,
    )

    assert result.complete?
    assert_equal %w(a), result.values
    refute result.object_verified?
    refute result.version_stable?
    assert result.replaceable?
  end

  def test_multipage_read_without_identity_is_complete_but_not_replaceable
    result = run_pages(
      [
        page(range_start: 0, range_end: 1, values: %w(a b), guid: nil, version: nil),
        page(range_start: 2, terminal: true, values: %w(c), guid: nil, version: nil),
      ],
      require_identity: false,
      require_version: false,
    )

    assert result.complete?
    assert_equal %w(a b c), result.values
    refute result.replaceable?
    assert_nil result.snapshot
  end

  def test_different_entry_dn_aborts
    result = run_pages([
      page(range_start: 0, range_end: 1, values: %w(a)),
      page(range_start: 2, terminal: true, values: %w(b),
           dn: "cn=Other Group,ou=Groups,dc=example,dc=org"),
    ])

    refute result.complete?
    assert_equal :object_changed, result.reason
  end

  def test_dn_comparison_ignores_attribute_type_case_but_not_value_case
    result = run_pages([
      page(range_start: 0, range_end: 1, values: %w(a)),
      page(range_start: 2, terminal: true, values: %w(b),
           dn: "CN=Large Group, OU=Groups, DC=example, DC=org"),
    ])

    assert result.complete?

    result = run_pages([
      page(range_start: 0, range_end: 1, values: %w(a)),
      page(range_start: 2, terminal: true, values: %w(b),
           dn: "cn=large group,ou=Groups,dc=example,dc=org"),
    ])

    assert_equal :object_changed, result.reason
    refute result.complete?
  end

  def test_vanished_object_mid_read_is_retryable_but_not_complete
    result = run_pages([
      page(range_start: 0, range_end: 1, values: %w(a)),
      page(entry_found: false),
    ])

    refute result.complete?
    assert_equal :object_changed, result.reason
    assert result.retryable?
    refute result.replaceable?
  end

  def test_missing_attribute_mid_read_aborts
    result = run_pages([
      page(range_start: 0, range_end: 1, values: %w(a)),
      page(attribute_present: false),
    ])

    refute result.complete?
    assert_equal :missing_terminal, result.reason
  end

  def test_read_error_is_retryable_and_keeps_diagnostics
    pages = [page(range_start: 0, range_end: 1, values: %w(a))]

    result = reader.read do |_offset, _count|
      if pages.empty?
        raise Net::LDAP::Error, "connection reset"
      end

      pages.shift
    end

    refute result.complete?
    assert_equal :read_error, result.reason
    assert_equal "connection reset", result.error.message
    assert result.retryable?
    assert_equal %w(a), result.partial_values
  end

  def test_no_response_aborts
    result = reader.read { |_offset, _count| nil }

    refute result.complete?
    assert_equal :no_response, result.reason
    assert result.retryable?
  end

  def test_page_limit_aborts_without_looping
    pages = Array.new(5) do |i|
      page(range_start: i, range_end: i, values: [i.to_s])
    end

    result = run_pages(pages, max_pages: 3)

    refute result.complete?
    assert_equal :page_limit, result.reason
    assert_equal 3, result.page_count
    refute result.retryable?
  end

  def test_short_range_is_rejected
    result = run_pages([
      page(range_start: 0, range_end: 3, values: %w(a b)),
    ], validate_page_size: true)

    refute result.complete?
    assert_equal :short_range, result.reason
    refute result.replaceable?
  end

  def test_duplicate_values_within_a_range_are_rejected
    result = run_pages([
      page(range_start: 0, range_end: 2, values: %w(a a b)),
    ], validate_page_size: true)

    refute result.complete?
    assert_equal :short_range, result.reason
    refute result.replaceable?
  end

  def test_search_failure_is_not_treated_as_empty
    result = run_pages([
      page(range_start: 0, range_end: 1, values: %w(a)),
      page(result_code: Net::LDAP::ResultCodeOperationsError),
    ])

    refute result.complete?
    assert_equal :search_failed, result.reason
    refute result.replaceable?
    refute result.empty?
  end

  def test_result_hides_values_unless_complete
    result = run_pages([page(range_start: 0, range_end: 1, values: %w(a))])

    hash = result.to_h
    assert_nil hash[:values]
    assert_equal %w(a), hash[:partial_values]
    refute hash[:replaceable]
  end

  def test_parse_attribute_description
    plain = Net::LDAP::RangedAttributeReader.parse_attribute_description("member")
    assert_equal "member", plain.base
    refute plain.ranged

    ranged = Net::LDAP::RangedAttributeReader.parse_attribute_description("member;range=0-1499")
    assert_equal "member", ranged.base
    assert ranged.ranged
    assert_equal 0, ranged.range_start
    assert_equal 1499, ranged.range_end
    refute ranged.terminal

    terminal = Net::LDAP::RangedAttributeReader.parse_attribute_description("member;range=1500-*")
    assert terminal.terminal
    assert_nil terminal.range_end

    invalid = Net::LDAP::RangedAttributeReader.parse_attribute_description("member;range=oops")
    assert invalid.invalid
  end

  def test_page_from_entry_detects_ranged_attribute
    entry = Net::LDAP::Entry.new(GROUP_DN)
    entry["member;range=0-1"] = %w(a b)
    entry["objectGUID"]       = GUID
    entry["uSNChanged"]       = USN

    page = Net::LDAP::RangedAttributeReader.page_from_entry(
      entry,
      attribute:          "member",
      identity_attribute: "objectGUID",
      version_attribute:  "uSNChanged",
    )

    assert page.attribute_present
    refute page.plain
    assert_equal 0, page.range_start
    assert_equal 1, page.range_end
    assert_equal %w(a b), page.values
    assert_equal GUID, page.object_guid
    assert_equal USN, page.object_version
  end

  def test_page_from_entry_rejects_foreign_ranged_attribute
    entry = Net::LDAP::Entry.new(GROUP_DN)
    entry["member;range=0-1"]   = %w(a b)
    entry["memberOf;range=0-1"] = %w(g)

    page = Net::LDAP::RangedAttributeReader.page_from_entry(
      entry,
      attribute: "member",
    )

    assert_kind_of Net::LDAP::InvalidAttributeRangeError, page.error
  end
end

class TestLDAPReadRangedAttribute < Test::Unit::TestCase
  GROUP_DN = "cn=Large Group,ou=Groups,dc=example,dc=org"
  GUID     = "guid-1"

  class FakeLDAP < Net::LDAP
    attr_reader :searches

    def initialize(pages)
      super(:force_no_page => true)
      @pages    = pages
      @searches = []
      @result   = Net::LDAP::PDU.new(
        [
          1,
          Net::BER::BerIdentifiedArray.new([Net::LDAP::ResultCodeSuccess, "", ""]).tap do |ber|
            ber.ber_identifier = Net::LDAP::PDU::SearchResult
          end,
        ],
      )
    end

    def search(args = {})
      @searches << args
      page = @pages.shift
      raise Net::LDAP::Error, "connection reset" unless page

      return [] unless page[:entry]

      entry = Net::LDAP::Entry.new(page[:dn] || args[:base])
      page[:attributes].each { |name, values| entry[name] = values }
      [entry]
    end

    def get_operation_result
      result = OpenStruct.new(:code => Net::LDAP::ResultCodeSuccess,
                              :message => "Success")
      result
    end

    def queue_pages(pages)
      @pages = pages
    end
  end

  def search_page(range_start: 0, range_end: nil, terminal: false,
                  values: [], guid: GUID, dn: nil, entry: true,
                  attributes: nil)
    name = if terminal
             "member;range=#{range_start}-*"
           elsif range_end
             "member;range=#{range_start}-#{range_end}"
           else
             "member"
           end

    attributes ||= { name => values }
    attributes["objectGUID"] = guid if guid && !attributes.key?("objectGUID")
    attributes["uSNChanged"] = "7" unless attributes.key?("uSNChanged")

    { entry: entry, dn: dn, attributes: attributes }
  end

  def test_real_read_uses_same_base_dn_for_every_page
    fake = FakeLDAP.new([
      search_page(range_start: 0, range_end: 1, values: %w(a b)),
      search_page(range_start: 2, terminal: true, values: %w(c)),
    ])

    result = fake.read_ranged_attribute(dn: GROUP_DN, attribute: "member")

    assert result.complete?
    assert_equal %w(a b c), result.values
    assert result.replaceable?

    assert_equal 2, fake.searches.length
    fake.searches.each do |search|
      assert_equal GROUP_DN, search[:base]
      assert_equal Net::LDAP::SearchScope_BaseObject, search[:scope]
      assert_equal true, search[:ignore_server_caps]
    end
  end

  def test_real_read_requests_explicit_page_size_and_detects_short_page
    fake = FakeLDAP.new([
      search_page(range_start: 0, range_end: 1, values: %w(a)),
      search_page(range_start: 2, terminal: true, values: %w(c)),
    ])

    result = fake.read_ranged_attribute(
      dn: GROUP_DN, attribute: "member", page_size: 2,
    )

    assert_equal %w(member;range=0-1 objectGUID uSNChanged),
                 fake.searches.first[:attributes]
    refute result.complete?
    assert_equal :short_range, result.reason
  end

  def test_real_read_returns_complete_empty_for_missing_member
    fake = FakeLDAP.new([
      search_page(attributes: {}, entry: true),
    ])

    result = fake.read_ranged_attribute(dn: GROUP_DN)

    assert result.complete?
    assert result.empty?
    assert_equal [], result.snapshot
    assert result.replaceable?
  end

  def test_real_read_does_not_replace_snapshot_on_partial_result
    fake = FakeLDAP.new([
      search_page(range_start: 0, range_end: 1, values: %w(a b)),
    ])

    result = fake.read_ranged_attribute(dn: GROUP_DN)

    refute result.complete?
    refute result.replaceable?
    assert_nil result.snapshot
    assert_raise(Net::LDAP::IncompleteAttributeError) { result.values }
  end

  def test_real_read_can_safely_retry_from_zero_after_transport_error
    fake = FakeLDAP.new([
      search_page(range_start: 0, range_end: 1, values: %w(a b)),
    ])

    aborted = fake.read_ranged_attribute(dn: GROUP_DN)

    refute aborted.complete?
    assert_equal :read_error, aborted.reason
    assert aborted.retryable?
    refute aborted.replaceable?
    assert_equal %w(a b), aborted.partial_values
    assert_nil aborted.snapshot

    fake.queue_pages([
      search_page(range_start: 0, range_end: 1, values: %w(a b)),
      search_page(range_start: 2, terminal: true, values: %w(c)),
    ])

    retried = fake.read_ranged_attribute(dn: GROUP_DN)

    assert retried.complete?
    assert retried.replaceable?
    assert_equal %w(a b c), retried.values
    assert_equal 2, fake.searches.length - 2
    assert_equal "member;range=0-*",
                 fake.searches.last(2).first[:attributes].first
    assert_equal "member;range=2-*",
                 fake.searches.last[:attributes].first
  end

  def test_real_read_refuses_to_resume_from_offset_after_object_change
    fake = FakeLDAP.new([
      search_page(range_start: 0, range_end: 1, values: %w(a b)),
      search_page(range_start: 2, terminal: true, values: %w(c), guid: "guid-2"),
    ])

    result = fake.read_ranged_attribute(dn: GROUP_DN)

    refute result.complete?
    assert_equal :object_changed, result.reason
    assert result.retryable?
    refute result.replaceable?
    assert_nil result.snapshot

    fake.queue_pages([
      search_page(range_start: 0, range_end: 1, values: %w(a b)),
      search_page(range_start: 2, terminal: true, values: %w(c)),
    ])

    retried = fake.read_ranged_attribute(dn: GROUP_DN)

    assert retried.complete?
    assert_equal %w(a b c), retried.snapshot
  end

  def test_real_read_requires_a_dn
    fake = FakeLDAP.new([])

    assert_raise(Net::LDAP::NoSearchBaseError) do
      fake.read_ranged_attribute(attribute: "member")
    end
  end
end
