# frozen_string_literal: false

require "rexml/document"
require "rexml/entity_expansion_ledger"

module REXMLTests
  class EntityExpansionLedgerTest < Test::Unit::TestCase
    # A document whose three text nodes each expand the same shared entity
    # chain. Reading any single node stays well inside a small budget, while
    # the old cumulative counter would eventually make the document
    # unusable simply because it had been read several times.
    def shared_chain_document
      REXML::Document.new(shared_chain_source)
    end

    def shared_chain_source
      <<~XML
        <!DOCTYPE r [
          <!ENTITY leaf "ABCDEFGHIJ">
          <!ENTITY chain "&leaf;&leaf;&leaf;&leaf;">
        ]>
        <root>
          <a>&chain;</a>
          <b>&chain;</b>
          <c attr="&chain;&chain;">&chain;</c>
        </root>
      XML
    end

    def text_values(doc)
      doc.root.elements.collect { |element| element.text }
    end

    def test_ledger_is_created_per_read_and_discarded
      doc = shared_chain_document
      doc.entity_expansion_limit = 20

      ledger = doc.new_entity_expansion_ledger
      assert_kind_of(REXML::EntityExpansionLedger, ledger)
      assert_equal(0, ledger.expansion_count)
      assert_equal(20, ledger.expansion_limit)
      assert_not_same(ledger, doc.new_entity_expansion_ledger)
    end

    def test_repeated_legitimate_reads_are_stable
      doc = shared_chain_document
      doc.entity_expansion_limit = 20

      first = text_values(doc)
      5.times do
        assert_equal(first, text_values(doc))
      end
    end

    def test_read_order_does_not_change_availability
      doc = shared_chain_document
      doc.entity_expansion_limit = 20

      forward = doc.root.elements.collect { |e| e.text }
      reverse = doc.root.elements.to_a.reverse.collect { |e| e.text }
      assert_equal(forward, reverse.reverse)

      # Force genuinely fresh expansions (bypassing the node cache) in both
      # orders. Every read is charged the same deterministic cost because it
      # receives its own full ledger instead of a depleted shared counter.
      [["a", "b", "c"], ["c", "b", "a"]].each do |order|
        fresh = REXML::Document.new(shared_chain_source)
        fresh.entity_expansion_limit = 20
        counts = order.map do |name|
          element = fresh.root.elements[name]
          element.texts.each { |text| text.send(:clear_cache) }
          element.text
          fresh.entity_expansion_count
        end
        assert_equal([5, 5, 5], counts)
      end
    end

    def test_cache_hit_is_not_charged_again
      doc = shared_chain_document
      element = doc.root.elements["a"]

      element.text
      charged_once = doc.entity_expansion_count
      assert_operator(charged_once, :>, 0)

      element.text
      element.text
      assert_equal(charged_once, doc.entity_expansion_count)
    end

    def test_failed_read_does_not_poison_later_reads
      doc = shared_chain_document
      # A single &chain; expands leaf four times, so a limit of one aborts
      # every real expansion attempt instead of failing only "eventually".
      doc.entity_expansion_limit = 1

      3.times do
        assert_raise(RuntimeError) do
          doc.root.elements["a"].text
        end
        # Each attempt spends its own fresh ledger up to the same point, so
        # the recorded cost never grows across retries.
        assert_equal(2, doc.entity_expansion_count)
      end

      # Raising never publishes a partial cached value.
      assert_nil(doc.root.elements["a"].instance_variable_get(:@unnormalized))
    end

    def test_malicious_expansion_aborts_only_when_budget_is_exceeded
      doc = REXML::Document.new(<<~XML)
        <!DOCTYPE bomb [
          <!ENTITY a "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
          <!ENTITY b "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
          <!ENTITY c "xxxxxxxxxx">
        ]>
        <bomb>&a;</bomb>
      XML

      # Generous budget: the same document is fully readable.
      doc.entity_expansion_limit = 10_000
      assert_equal(1000, doc.root.text.bytesize)

      # Tight budget: the genuinely excessive expansion is rejected on its
      # own cost, regardless of how many reads happened before it.
      tight = REXML::Document.new(<<~XML)
        <!DOCTYPE bomb [
          <!ENTITY a "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
          <!ENTITY b "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
          <!ENTITY c "xxxxxxxxxx">
        ]>
        <bomb>&a;</bomb>
      XML
      tight.entity_expansion_limit = 5
      assert_raise(RuntimeError) do
        tight.root.text
      end
    end

    def test_two_documents_keep_independent_budgets
      modest = shared_chain_document
      modest.entity_expansion_limit = 3

      other = shared_chain_document
      other.entity_expansion_limit = 20

      # Exhausting the small-budget document does not touch the other one.
      assert_raise(RuntimeError) { modest.root.elements["a"].text }
      assert_nothing_raised do
        other.root.elements["a"].text
        other.root.elements["b"].text
      end

      # And a fresh ledger from one document never carries the other's
      # document-specific limit.
      assert_equal(3, modest.new_entity_expansion_ledger.expansion_limit)
      assert_equal(20, other.new_entity_expansion_ledger.expansion_limit)
    end

    def test_attribute_expansion_uses_the_same_ledger_lifecycle
      doc = shared_chain_document
      attribute = doc.root.elements["c"].attributes.get_attribute("attr")

      expanded = attribute.value
      assert_equal("ABCDEFGHIJ" * 8, expanded)
      charged_once = doc.entity_expansion_count

      attribute.value
      assert_equal(charged_once, doc.entity_expansion_count)
    end

    def test_circular_reference_is_rejected_on_every_read
      doc = REXML::Document.new(<<~XML)
        <!DOCTYPE root [
          <!ENTITY x "&x;">
        ]>
        <root>&x;</root>
      XML

      2.times do
        assert_raise(REXML::ParseException) do
          doc.root.text
        end
      end
    end

    def test_indirect_circular_reference_through_shared_chain
      doc = REXML::Document.new(<<~XML)
        <!DOCTYPE root [
          <!ENTITY a "&b;">
          <!ENTITY b "&a;">
        ]>
        <root>&a;</root>
      XML

      assert_raise(REXML::ParseException) do
        doc.root.text
      end
    end

    def test_text_budget_is_enforced_per_scan
      doc = REXML::Document.new(<<~XML)
        <!DOCTYPE r [
          <!ENTITY big "#{"Z" * 64}">
        ]>
        <r>&big;&big;</r>
      XML
      doc.entity_expansion_text_limit = 100

      assert_raise(RuntimeError) do
        doc.root.text
      end
    end

    def test_standalone_unnormalize_still_enforces_limits
      ledger = REXML::EntityExpansionLedger.new(text_limit: 4)
      assert_raise(RuntimeError) do
        REXML::Text.unnormalize("&amp;&amp;&amp;&amp;&amp;", nil, nil, nil,
                                ledger: ledger)
      end
    end
  end
end
