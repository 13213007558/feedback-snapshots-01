# frozen_string_literal: true
#
# Run from the repository root:
#   ruby -Ilib -Itest security/dtd-default-attributes/test_safe_import_contract.rb

require "test/unit"
require_relative "safe_import_contract"

class TestSafeImportContract < Test::Unit::TestCase
  ATTACK = <<~XML
    <?xml version="1.0"?>
    <!DOCTYPE import [
      <!ELEMENT import (record*)>
      <!ELEMENT record EMPTY>
      <!ATTLIST record
        id       CDATA #REQUIRED
        approved CDATA "true"
        display  CDATA "guest"
        fixedv   CDATA #FIXED "locked">
    ]>
    <import>
      <record id="r1"/>
      <record id="r2" approved="false"/>
      <record id="r3" approved="true"/>
      <record id="r4" approved=""/>
    </import>
  XML

  LEGIT = <<~XML
    <import>
      <record id="a" approved="true"/>
      <record id="b" display="bob"/>
    </import>
  XML

  def build(xml)
    [SafeImportContract.parse(xml), REXML::Document.new(xml)]
  end

  def record(doc, id)
    REXML::XPath.first(doc, "//record[@id='#{id}']")
  end

  # --- the vulnerability being defended against -------------------------

  def test_unhardened_dom_reader_treats_default_as_present
    doc = REXML::Document.new(ATTACK)
    r1 = record(doc, "r1")
    # The buggy pattern: presence inferred from a value accessor.
    assert_equal "true", r1["approved"]
    assert_not_nil r1.attribute("approved")
    assert !r1.attributes.key?("approved")
  end

  # --- stage 1: explicit-only boundary survives every parser -----------

  def test_parser_events_carry_only_explicit_attributes
    events = []
    parser = REXML::Parsers::BaseParser.new(REXML::Source.new(+ATTACK))
    loop do
      event = parser.pull
      events << event if event[0] == :start_element && event[1] == "record"
      break if event[0] == :end_document
    end
    r1 = events.find { |e| e[2]["id"] == "r1" }
    assert_equal ["id"], r1[2].keys
    r2 = events.find { |e| e[2]["id"] == "r2" }
    assert_equal ["id", "approved"], r2[2].keys
  end

  # --- stage 2: membership accessors keep the distinction ---------------

  def test_explicit_attr_predicate_rejects_dtd_default
    doc = REXML::Document.new(ATTACK)
    r1 = record(doc, "r1")
    assert_equal false, SafeImportContract.explicit_attr?(r1, "approved")
    assert_nil SafeImportContract.explicit_attr(r1, "approved")
    # The default is still visible through the presentation accessor.
    assert_equal "true", r1["approved"]
    assert_equal "guest", SafeImportContract.display_value(r1, "display")
  end

  def test_explicit_values_are_seen_regardless_of_dtd
    doc = REXML::Document.new(ATTACK)
    assert SafeImportContract.explicit_attr?(record(doc, "r2"), "approved")
    assert_equal "false", SafeImportContract.explicit_attr(record(doc, "r2"), "approved")
    assert SafeImportContract.explicit_attr?(record(doc, "r3"), "approved")
    # An explicitly submitted empty string is present but not a grant.
    r4 = record(doc, "r4")
    assert SafeImportContract.explicit_attr?(r4, "approved")
    assert_equal "", SafeImportContract.explicit_attr(r4, "approved")
  end

  def test_authorization_accepts_only_explicit_grant_token
    doc = REXML::Document.new(ATTACK)
    deny  = ->(id) { assert_equal false, SafeImportContract.authorized?(record(doc, id)) }
    deny.call("r1") # default "true" injected by DTD, not submitted
    deny.call("r2") # explicit false
    deny.call("r4") # explicit empty
    assert_equal true, SafeImportContract.authorized?(record(doc, "r3"))

    legit = REXML::Document.new(LEGIT)
    assert_equal true, SafeImportContract.authorized?(record(legit, "a"))
    assert_equal false, SafeImportContract.authorized?(record(legit, "b"))
  end

  # --- stage 3: copies lose or keep the fallback with the document ------

  def test_copies_outside_the_dtd_document_lose_the_default
    doc = REXML::Document.new(ATTACK)
    r1 = record(doc, "r1")
    detached = r1.deep_clone
    assert_nil detached["approved"]
    assert_equal false, SafeImportContract.explicit_attr?(detached, "approved")

    other = REXML::Document.new("<other/>")
    other.root.add_element(r1.deep_clone)
    assert_nil other.root.elements[1]["approved"]

    reattached = r1.clone
    doc.root.add_element(reattached)
    # Reattached: fallback returns, but explicit membership is still false.
    assert_equal "true", reattached["approved"]
    assert_equal false, SafeImportContract.explicit_attr?(reattached, "approved")
  end

  # --- stage 4: serialization never materializes the default ------------

  def test_serialization_round_trip_keeps_explicit_boundary
    doc = REXML::Document.new(ATTACK)
    r1 = record(doc, "r1")
    assert_equal "<record id='r1'/>", r1.to_s
    reparsed = REXML::Document.new(doc.to_s)
    again = record(reparsed, "r1")
    assert_equal false, SafeImportContract.explicit_attr?(again, "approved")
    assert_equal "true", again["approved"] # DTD round-tripped with the doc
  end

  # --- hardening: strip the DTD before building the tree ----------------

  def test_parse_removes_doctype_and_defaults
    doc = SafeImportContract.parse(ATTACK)
    assert_nil doc.doctype
    r1 = record(doc, "r1")
    assert_nil r1["approved"]
    assert_nil r1["display"]
    assert_equal false, SafeImportContract.authorized?(r1)
    # Explicit attributes survive the strip.
    assert_equal true, SafeImportContract.authorized?(record(doc, "r3"))
  end

  def test_parse_keeps_body_and_explicit_attributes_intact
    doc = SafeImportContract.parse(LEGIT)
    ids = REXML::XPath.match(doc, "//record").map { |e| e["id"] }
    assert_equal ["a", "b"], ids
    assert_equal "bob", record(doc, "b")["display"]
  end

  def test_contract_on_stripped_document_matches_contract_on_full_document
    stripped = SafeImportContract.parse(ATTACK)
    full = REXML::Document.new(ATTACK)
    %w[r1 r2 r3 r4].each do |id|
      assert_equal SafeImportContract.authorized?(record(full, id)),
                   SafeImportContract.authorized?(record(stripped, id)),
                   id
    end
  end

  def test_display_contract_preserves_legitimate_defaults_when_dtd_kept
    # Services that intentionally use DTD defaults for presentation keep
    # them via display_value, while authorization stays explicit-only.
    doc = REXML::Document.new(ATTACK)
    r1 = record(doc, "r1")
    assert_equal "guest", SafeImportContract.display_value(r1, "display")
    assert_equal "fallback", SafeImportContract.display_value(r1, "nope", "fallback")
    assert_equal false, SafeImportContract.authorized?(r1)
  end
end
