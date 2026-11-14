# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/query_parser'
  require_relative '../lib/rack/request'
end

# StrictPairingParser is a pluggable, strict replacement for
# Rack::QueryParser#parse_nested_query for batch endpoints whose
# authorization decisions depend on the pairing of sibling fields
# inside items[] entries (e.g. items[][resource] with items[][action]).
#
# Rationale: the items[][field] convention carries no grouping
# information of its own. Rack groups fields into hashes purely by
# position ("append to the last hash while its keys are new"), so a
# reordered or duplicated field silently re-pairs resources with
# actions, and parse_nested_query cannot report this because the
# regrouped result is still a well-formed structure.
#
# This parser walks the ordered key/value pairs (via
# Rack::QueryParser#parse_query_pairs) and accepts only the canonical
# alternation items[][resource], items[][action], ... -- the one
# representation from which the original pairing is uniquely
# recoverable. Everything else (regrouped fields, duplicates,
# incomplete trailing items, explicit indices, foreign keys) raises
# AmbiguousGroupingError, which includes Rack::BadRequest, so the
# request can be rejected with a 400 instead of being authorized
# under an arbitrarily chosen pairing.
#
# Usage (before authorizing a batch request):
#   items = StrictPairingParser.new.parse(request.query_string)
#   items.each { |item| authorize!(item["resource"], item["action"]) }
#
# Note: a reordering that preserves the exact canonical key
# alternation but swaps values between pairs is indistinguishable from
# a faithfully encoded request for any server-side parser. If that
# threat matters, field order must be protected end to end (e.g. by
# signing parameters); it cannot be recovered at parse time.
class StrictPairingParser
  class AmbiguousGroupingError < Rack::QueryParser::InvalidParameterError; end

  def initialize(key: "items", fields: %w[resource action], query_parser: Rack::QueryParser.make_default(32))
    @key = key
    @fields = fields
    @query_parser = query_parser
  end

  def parse(qs)
    pairs = @query_parser.parse_query_pairs(qs)
    items = []

    pairs.each_with_index do |(k, v), i|
      position = i % @fields.size
      expected = "#{@key}[][#{@fields[position]}]"
      unless k == expected
        raise AmbiguousGroupingError,
          "ambiguous item grouping: expected `#{expected}' at pair #{i}, got `#{k}'"
      end
      items << {} if position == 0
      items.last[@fields[position]] = v
    end

    unless pairs.size % @fields.size == 0
      raise AmbiguousGroupingError,
        "ambiguous item grouping: incomplete trailing item (#{pairs.size} fields is not a multiple of #{@fields.size})"
    end

    items
  end
end

describe "Rack::QueryParser nested form pairing (generative)" do
  RESOURCES = %w[doc1 doc2 a+b].freeze
  ACTIONS = %w[read write].freeze
  ITERATIONS = Integer(ENV["PAIRING_ITERATIONS"] || 200)
  SEED = Integer(ENV["PAIRING_SEED"] || 20261114)

  # A single form field, tagged with the pair it was generated from so
  # the shrinker can remove whole pairs.
  Field = Struct.new(:pair, :key, :value)

  def query_parser
    @query_parser ||= Rack::QueryParser.make_default(32)
  end

  def strict_parser
    @strict_parser ||= StrictPairingParser.new(query_parser: query_parser)
  end

  def generate_pairs(random)
    Array.new(random.rand(1..4)) do
      { "resource" => RESOURCES[random.rand(RESOURCES.size)],
        "action" => ACTIONS[random.rand(ACTIONS.size)] }
    end
  end

  def canonical_fields(pairs)
    pairs.each_with_index.flat_map do |pair, i|
      [Field.new(i, "resource", pair["resource"]), Field.new(i, "action", pair["action"])]
    end
  end

  # All resources first, then all actions: the same fields, but the
  # positions that implied the pairing are gone.
  def regrouped_fields(pairs)
    fields = canonical_fields(pairs)
    fields.select { |f| f.key == "resource" } + fields.select { |f| f.key == "action" }
  end

  def shuffled_fields(pairs, random)
    canonical_fields(pairs).shuffle(random: random)
  end

  def duplicated_fields(pairs, random)
    fields = canonical_fields(pairs)
    pick = fields[random.rand(fields.size)]
    fields.insert(random.rand(fields.size + 1), Field.new(pick.pair, pick.key, pick.value))
  end

  def build_query(fields)
    fields.map { |f| "items[][#{f.key}]=#{URI.encode_www_form_component(f.value)}" }.join("&")
  end

  def naive_pairs(query)
    items = query_parser.parse_nested_query(query)["items"]
    return nil unless items.is_a?(Array)
    items.map do |item|
      item.is_a?(Hash) ? [item["resource"], item["action"]] : [nil, nil]
    end.sort_by(&:inspect)
  end

  def expected_pairs(pairs)
    pairs.map { |p| [p["resource"], p["action"]] }.sort_by(&:inspect)
  end

  def regrouping_counterexample?(pairs, fields)
    naive_pairs(build_query(fields)) != expected_pairs(pairs)
  end

  def canonical_sequence?(fields, pair_count)
    fields.map(&:key) == %w[resource action] * pair_count
  end

  def parse_form_body(body)
    Rack::Request.new(
      "REQUEST_METHOD" => "POST",
      "CONTENT_TYPE" => "application/x-www-form-urlencoded",
      "CONTENT_LENGTH" => body.bytesize.to_s,
      "rack.input" => StringIO.new(body),
      "rack.errors" => StringIO.new
    ).POST
  end

  # Remove whole pairs (and the fields generated from them) while the
  # input still decodes to a different pairing, until no single
  # removal preserves the counterexample.
  def shrink(pairs, fields)
    loop do
      reduced = false
      pairs.each_index do |i|
        break if pairs.size <= 1
        candidate_pairs = pairs.each_with_index.reject { |_, j| j == i }.map(&:first)
        candidate_fields = fields.reject { |f| f.pair == i }.map do |f|
          Field.new(f.pair > i ? f.pair - 1 : f.pair, f.key, f.value)
        end
        if regrouping_counterexample?(candidate_pairs, candidate_fields)
          pairs = candidate_pairs
          fields = candidate_fields
          reduced = true
          break
        end
      end
      return [pairs, fields] unless reduced
    end
  end

  def ambiguity_report(pairs, minimal_fields)
    <<~REPORT
      item pairing changed by ambiguous input
        original pairs: #{expected_pairs(pairs).inspect}
        naive parse:    #{query_parser.parse_nested_query(build_query(minimal_fields)).inspect}
        minimal input:  #{build_query(minimal_fields)}
    REPORT
  end

  it "parses canonical encodings back to the original pairs (query string and form body)" do
    random = Random.new(SEED)
    ITERATIONS.times do
      pairs = generate_pairs(random)
      query = build_query(canonical_fields(pairs))

      naive_pairs(query).must_equal expected_pairs(pairs)
      strict_parser.parse(query).must_equal pairs

      items = parse_form_body(query)["items"]
      items.must_be_kind_of Array
      items.map { |h| [h["resource"], h["action"]] }.sort_by(&:inspect).must_equal expected_pairs(pairs)
    end
  end

  it "accepts exactly the canonical alternation and decodes it consistently" do
    random = Random.new(SEED + 1)
    ITERATIONS.times do
      pairs = generate_pairs(random)
      mutations = [
        canonical_fields(pairs),
        regrouped_fields(pairs),
        shuffled_fields(pairs, random),
        duplicated_fields(pairs, random),
      ]
      mutations.each do |fields|
        query = build_query(fields)
        if canonical_sequence?(fields, pairs.size)
          decoded = fields.each_slice(2).map do |resource, action|
            { "resource" => resource.value, "action" => action.value }
          end
          strict_parser.parse(query).must_equal decoded
          naive_pairs(query).must_equal decoded.map { |h| [h["resource"], h["action"]] }.sort_by(&:inspect)
        else
          error = proc { strict_parser.parse(query) }.must_raise StrictPairingParser::AmbiguousGroupingError
          error.message.must_include "ambiguous item grouping"
        end
      end
    end
  end

  it "rejects regrouped, duplicated, incomplete, and explicitly indexed representations" do
    parser = strict_parser
    parser.parse("items[][resource]=doc1&items[][action]=read")
      .must_equal [{ "resource" => "doc1", "action" => "read" }]

    # all resources, then all actions
    proc { parser.parse("items[][resource]=doc1&items[][resource]=doc2&items[][action]=read&items[][action]=write") }
      .must_raise StrictPairingParser::AmbiguousGroupingError
    # duplicated field
    proc { parser.parse("items[][resource]=doc1&items[][action]=read&items[][action]=read") }
      .must_raise StrictPairingParser::AmbiguousGroupingError
    # incomplete trailing item
    proc { parser.parse("items[][resource]=doc1&items[][action]=read&items[][resource]=doc2") }
      .must_raise StrictPairingParser::AmbiguousGroupingError
    # explicit indices (Rack would parse these into a Hash, not an Array)
    proc { parser.parse("items[0][resource]=doc1&items[0][action]=read") }
      .must_raise StrictPairingParser::AmbiguousGroupingError
    # foreign keys
    proc { parser.parse("items[][resource]=doc1&items[][action]=read&admin=true") }
      .must_raise StrictPairingParser::AmbiguousGroupingError
  end

  it "changes the resource-action pairing when fields are regrouped" do
    canonical = "items[][resource]=doc1&items[][action]=read&items[][resource]=doc2&items[][action]=write"
    regrouped = "items[][resource]=doc1&items[][resource]=doc2&items[][action]=read&items[][action]=write"

    query_parser.parse_nested_query(canonical).must_equal(
      "items" => [
        { "resource" => "doc1", "action" => "read" },
        { "resource" => "doc2", "action" => "write" },
      ]
    )

    # The same fields, regrouped: doc2 is now paired with read, and
    # write is left without any resource.
    query_parser.parse_nested_query(regrouped).must_equal(
      "items" => [
        { "resource" => "doc1" },
        { "resource" => "doc2", "action" => "read" },
        { "action" => "write" },
      ]
    )

    # Form bodies go through the same parser and are equally affected.
    parse_form_body(regrouped).must_equal query_parser.parse_nested_query(regrouped)
  end

  it "changes the item count when a field is duplicated" do
    query_parser.parse_nested_query("items[][resource]=doc1&items[][action]=read&items[][action]=write")
      .must_equal("items" => [{ "resource" => "doc1", "action" => "read" }, { "action" => "write" }])
  end

  it "rejects every ambiguous counterexample and shrinks it to a minimal input" do
    random = Random.new(SEED + 2)
    found = nil

    ITERATIONS.times do
      pairs = generate_pairs(random)
      [regrouped_fields(pairs), shuffled_fields(pairs, random), duplicated_fields(pairs, random)].each do |fields|
        next unless regrouping_counterexample?(pairs, fields)
        if canonical_sequence?(fields, pairs.size)
          # Value-level reorder that preserves the key pattern: no
          # server-side parser can detect this (see StrictPairingParser
          # docs), so it is out of scope for rejection.
          next
        end
        # Whenever the ambiguous input changes the pairing, the strict
        # parser must refuse it rather than pick a pairing arbitrarily.
        proc { strict_parser.parse(build_query(fields)) }
          .must_raise StrictPairingParser::AmbiguousGroupingError
        found ||= [pairs, fields]
      end
    end

    refute_nil found, "expected the generator to find a regrouping counterexample"

    pairs, fields = found
    minimal_pairs, minimal_fields = shrink(pairs, fields)

    regrouping_counterexample?(minimal_pairs, minimal_fields).must_equal true
    if minimal_pairs.size > 1
      minimal_pairs.each_index do |i|
        reduced_pairs = minimal_pairs.each_with_index.reject { |_, j| j == i }.map(&:first)
        reduced_fields = minimal_fields.reject { |f| f.pair == i }
        regrouping_counterexample?(reduced_pairs, reduced_fields).must_equal false
      end
    end

    report = ambiguity_report(pairs, minimal_fields)
    report.must_include "original pairs: #{expected_pairs(pairs).inspect}"
    report.must_include "naive parse:    #{query_parser.parse_nested_query(build_query(minimal_fields)).inspect}"
    report.must_include "minimal input:  #{build_query(minimal_fields)}"
  end
end
