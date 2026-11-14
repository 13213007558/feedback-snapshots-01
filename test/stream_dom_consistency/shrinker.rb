# frozen_string_literal: true

require_relative "model"
require_relative "oracle"

module StreamDomConsistency
  # Greedy, deterministic structural shrinker.
  #
  # A reduction is accepted only when the oracle still reports a failure of
  # the same kind and, for policy failures, the same decisions.  This prevents
  # "shrinking" a CDATA-boundary bug into an unrelated bare-ampersand case,
  # which would make the minimized witness misleading.
  #
  # The shrinker never inspects parser error messages; it only asks the
  # oracle and compares finding kinds.  Every reduction is a pure function of
  # the case, so shrinking is reproducible.
  class Shrinker
    attr_reader :tried

    def initialize(oracle:, max_steps: 300)
      @oracle = oracle
      @max_steps = max_steps
      @tried = 0
    end

    def shrink(kase)
      initial = @oracle.evaluate(kase).select { |finding| finding.severity == :error }
      wanted = signature(initial, kase)
      return kase if wanted.empty?

      current = kase
      loop do
        candidate = first_matching_reduction(current, wanted)
        return current if candidate.nil? || @tried >= @max_steps

        current = candidate
      end
    end

    private

    # A witness is only "the same failure" if both the expectation and the
    # finding kinds survive.  Without the expectation, removing a BOM could
    # turn an encoding-declaration bug into an unrelated UTF-16 error while
    # still matching a subset of finding kinds.
    def signature(findings, kase)
      expected = Expected.compute(kase)
      [
        expected.status,
        findings.map(&:kind).sort,
        findings.map(&:severity).sort,
      ]
    end

    def first_matching_reduction(kase, wanted)
      reductions(kase).each do |candidate|
        return nil if @tried >= @max_steps

        @tried += 1
        findings = @oracle.evaluate(candidate)
        matching = findings.select { |finding| finding.severity == :error }
        return candidate if !matching.empty? && signature(matching, candidate) == wanted
      end
      nil
    end

    def reductions(kase)
      body_reductions(kase) +
        attribute_reductions(kase) +
        entity_reductions(kase) +
        part_reductions(kase) +
        encoding_reductions(kase)
    end

    def body_reductions(kase)
      return [] if kase.body.length <= 1

      kase.body.each_index.filter_map do |index|
        body = kase.body.dup
        body.delete_at(index)
        next if body.empty?

        kase.with(body: body, notes: note(kase, "removed body part #{index}"))
      end
    end

    def attribute_reductions(kase)
      kase.attributes.each_index.map do |index|
        attributes = kase.attributes.dup
        attributes.delete_at(index)
        kase.with(attributes: attributes, notes: note(kase, "removed attribute #{index}"))
      end
    end

    def entity_reductions(kase)
      kase.entities.each_index.map do |index|
        entities = kase.entities.dup
        entities.delete_at(index)
        kase.with(entities: entities, notes: note(kase, "removed entity #{index}"))
      end
    end

    # Shorten a text part or replace a multi-character reference run with
    # fewer references, keeping the part type so the failing construct stays.
    def part_reductions(kase)
      map_parts(kase.body) do |_parts, index, part|
        shrink_part(kase.body, index, part)
      end.map do |body|
        kase.with(body: body, notes: note(kase, "shrunk body part"))
      end
    end

    def shrink_part(parts, index, part)
      candidate = parts.dup
      case part
      when Parts::Text
        return nil if part.text.empty?

        candidate[index] = Parts::Text.new(text: part.text[0...-1])
        candidate
      when Parts::CData
        return nil if part.text.empty?
        # A CDATA section cannot contain "]]>", so never introduce one while
        # minimizing; that would turn a boundary bug into a different bug.
        return nil if part.text[0...-1].include?("]]>")

        candidate[index] = Parts::CData.new(text: part.text[0...-1])
        candidate
      when Parts::EntityRef
        candidate.delete_at(index)
        candidate.empty? ? nil : candidate
      else
        nil
      end
    end

    def map_parts(parts)
      parts.each_index.filter_map do |index|
        yield(parts, index, parts[index])
      end
    end

    def encoding_reductions(kase)
      reductions = []
      if kase.decl_encoding
        reductions << kase.with(decl_encoding: nil, notes: note(kase, "dropped declaration"))
      end
      if kase.bom
        reductions << kase.with(bom: nil, notes: note(kase, "dropped BOM"))
      end
      if kase.source_form != :string
        reductions << kase.with(source_form: :string, notes: note(kase, "used string source"))
      end
      reductions
    end

    def note(kase, action)
      [kase.notes, "shrunk: #{action}"].compact.join("; ")
    end
  end
end
