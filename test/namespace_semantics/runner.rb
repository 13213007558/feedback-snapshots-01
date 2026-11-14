# frozen_string_literal: true

require_relative "generator"
require_relative "oracle"
require_relative "projections"

module REXMLTests
  module NamespaceSemantics
    APIS = [:dom, :pull, :sax].freeze

    # A divergence between the oracle and one or more projections.  It
    # keeps the exact document and the differing records so a report can
    # be replayed without rerunning the generator.
    class Divergence
      attr_reader :api, :xml, :expected, :actual, :kinds

      def initialize(api:, xml:, expected:, actual:)
        @api = api
        @xml = xml
        @expected = expected
        @actual = actual
        @kinds =
          if actual.length == 1 && actual.first.is_a?(Exception)
            [:exception]
          else
            RecordDiff.kinds(expected, actual)
          end
      end

      def namespace?
        @kinds.include?(:name) || @kinds.include?(:exception)
      end

      def value?
        @kinds.include?(:value)
      end

      def empty?
        @expected.empty?
      end

      def to_h
        {api: @api, xml: @xml, expected: @expected, actual: @actual, kinds: @kinds}
      end

      def describe
        lines = ["#{@api} projection diverged from the namespace oracle (#{@kinds.join(', ')}):"]
        lines << "  document: #{@xml}"
        mismatches = RecordDiff.mismatches(@expected, @actual)
        mismatches.first(8).each do |(index, expected_record, actual_record)|
          lines << "  record #{index}:"
          lines << "    expected: #{expected_record || "(missing)"}"
          lines << "    actual:   #{actual_record || "(missing)"}"
        end
        lines << "  ... #{mismatches.length - 8} more" if mismatches.length > 8
        lines.join("\n")
      end
    end

    # Divergences fall into two classes, because they do not carry the
    # same risk.  A :name divergence means the two sides disagree about
    # which XML namespace a node belongs to; that is the authorization
    # boundary.  A :value divergence means the names match but the
    # character data did not survive the same way.  Keeping them apart
    # stops a value-handling bug from masking a namespace bug.
    module RecordDiff
      module_function

      def mismatches(expected, actual)
        count = [expected.length, actual.length].max
        Array.new(count) do |index|
          expected_record = expected[index]
          actual_record = actual[index]
          next if expected_record == actual_record

          [index, expected_record, actual_record]
        end.compact
      end

      def kinds(expected, actual)
        mismatches(expected, actual).map do |(_, expected_record, actual_record)|
          if expected_record.nil? || actual_record.nil?
            :name
          elsif expected_record.kind != actual_record.kind ||
                expected_record.path != actual_record.path ||
                expected_record.uri != actual_record.uri ||
                expected_record.local != actual_record.local
            :name
          else
            :value
          end
        end.uniq
      end

      def same?(expected, actual)
        expected == actual
      end
    end

    # Compares one document against every projection and returns the
    # divergences found.  Exceptions are divergences too: an API that
    # raises where the oracle has an answer has not delivered the same
    # security-relevant view.
    module Checker
      module_function

      def divergences(xml, apis: APIS, projector: Projections, only: nil)
        raw = RawDocument.parse(xml)
        expected = Oracle.records(raw.root)
        apis.filter_map do |api|
          actual =
            begin
              projector.records(api, xml)
            rescue StandardError => error
              [error]
            end
          if actual.is_a?(Array) && actual.first.is_a?(Exception)
            divergence = Divergence.new(api: api, xml: xml, expected: expected, actual: actual)
          elsif RecordDiff.same?(expected, actual)
            next
          else
            divergence = Divergence.new(api: api, xml: xml, expected: expected, actual: actual)
          end
          next if only && !divergence.kinds.include?(only)

          divergence
        end
      end

      def diverged?(xml, apis: APIS, only: nil, projector: Projections)
        !divergences(xml, apis: apis, only: only, projector: projector).empty?
      end

      def namespace_divergences(xml, apis: APIS)
        divergences(xml, apis: apis, only: :name)
      end

      def value_divergences(xml, apis: APIS)
        divergences(xml, apis: apis, only: :value)
      end
    end

    # Structural shrinker: repeatedly tries deleting attributes and
    # subtrees while preserving the divergence.  Every candidate is a
    # plain XML string, so a reduced case replays independently.
    module Shrinker
      module_function

      def shrink(xml, apis: APIS, max_steps: 40)
        current = xml
        max_steps.times do
          candidate = next_candidate(current, apis: apis)
          break if candidate.nil?

          current = candidate
        end
        current
      end

      def next_candidate(xml, apis: APIS)
        raw = RawDocument.parse(xml)
        originals = candidates(raw.root)
        originals.each do |candidate|
          rendered = RawDocument.new(candidate).to_xml
          begin
            return rendered if Checker.diverged?(rendered, apis: apis)
          rescue REXML::ParseException
            # Removing a declaration can make the prefix on the element
            # itself undefined; such a candidate is not a smaller failing
            # document, it is just not a document.
            next
          end
        end
        nil
      end

      # Candidate trees, most aggressive first: drop attributes and
      # subtrees, then simplify names and values.  Simplification is
      # tried last because it can remove the hazard entirely.  The
      # recursion is capped so a large generated case cannot explode the
      # search; shrinking is a convenience, not the property test.
      def candidates(element, budget: 200)
        results = []

        element.attributes.each_index do |index|
          attributes = element.attributes.dup
          attributes.delete_at(index)
          results << rebuild(element, attributes: attributes)
        end

        element.children.each_index do |index|
          children = element.children.dup
          children.delete_at(index)
          results << rebuild(element, children: children)
        end

        unless element.attributes.empty?
          results << rebuild(element, attributes: [])
        end

        unless element.children.empty?
          results << rebuild(element, children: [])
        end

        element.attributes.each_index do |index|
          name, value = element.attributes[index]
          replacement_pairs = [["a", value], ["a", "v"]]
          replacement_pairs << [name, "v"] unless value == "v"
          replacement_pairs.each do |replacement|
            attributes = element.attributes.dup
            attributes[index] = replacement
            results << rebuild(element, attributes: attributes)
          end
        end

        unless element.children.empty? || budget <= 0
          element.children.each do |child|
            candidates(child, budget: budget - 1).first(12).each do |child_candidate|
              children = element.children.map { |c| c.equal?(child) ? child_candidate : c }
              results << rebuild(element, children: children)
            end
          end
        end

        results.first(budget)
      end

      def rebuild(element, attributes: element.attributes, children: element.children)
        RawElement.new(qname: element.qname, attributes: attributes, children: children)
      end
    end

    # A deliberately broken projector used to prove the differential
    # harness has teeth.  It differs from the real SAX projection in one
    # way: it never pops the prefix scope at end_element, so bindings leak
    # into following siblings.  Everything else is shared with the real
    # projection so a failure cannot be blamed on unrelated code.
    class BrokenScopeRestore
      def records(api, xml)
        return Projections.records(api, xml) unless api == :sax

        parser = REXML::Parsers::SAX2Parser.new(xml)
        records = []
        scopes = [{"xml" => XML_NAMESPACE}]
        pending = nil
        open = []

        parser.listen(:start_prefix_mapping) do |prefix, uri|
          pending ||= scopes.last.dup
          key = prefix.nil? ? "" : prefix
          value = uri.to_s
          if value.empty?
            pending.delete(key)
          else
            pending[key] = value
          end
        end

        parser.listen(:start_element) do |uri, local, _qname, raw_attributes|
          scopes.push(pending || scopes.last)
          pending = nil
          path = open.empty? ? [] : [*open.last[:path], open.last[:next_child]]
          open.last[:next_child] += 1 unless open.empty?
          open.push({path: path, next_child: 0})
          records << Record.new(
            kind: :element,
            path: path,
            uri: Oracle.canonical_uri(uri),
            local: local,
          )
          attributes = raw_attributes.flat_map do |name, value|
            next [] if Oracle.declaration_name?(name)

            attribute_uri, attribute_local =
              Oracle.expanded_attribute_name(name, scopes.last)
            [
              Record.new(
                kind: :attribute,
                path: path,
                uri: attribute_uri,
                local: attribute_local,
                value: Oracle.normalize_value(value),
              ),
            ]
          end
          attributes.sort_by! { |record| [record.uri.to_s, record.local] }
          records.concat(attributes)
        end

        # The bug: scopes.pop is missing.
        parser.listen(:end_element) { |*| open.pop }
        parser.parse
        records
      end
    end
  end
end
