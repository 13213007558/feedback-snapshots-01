# -*- ruby encoding: utf-8 -*-

class Net::LDAP::Filter
  ##
  # The three possible outcomes of Filter#evaluate.
  MATCH = :match
  NO_MATCH = :no_match
  UNDETERMINED = :undetermined

  ##
  # Returned by Filter#evaluate. The states follow the three-valued filter
  # logic of RFC 4511 section 4.5.1.7.
  #
  # * +MATCH+ (+:match+) means the assertion is definitely true.
  # * +NO_MATCH+ (+:no_match+) means the assertion is definitely false.
  # * +UNDETERMINED+ (+:undetermined+) means local schema information is
  #   insufficient. This is not a non-match: callers that gate authorization
  #   should treat it as "cannot decide" and deny until the rule is
  #   understood. Crucially, NOT of an undetermined filter remains
  #   undetermined instead of turning into a match.
  #
  # +reasons+ carries diagnostic strings explaining why a result was
  # undetermined, or which child made a compound result false.
  class EvaluationResult
    MAX_REASONS = 8
    MAX_REASON_LENGTH = 200

    attr_reader :state, :reasons

    def initialize(state, reasons = [])
      @state = state
      @reasons = self.class.sanitize_reasons(reasons)
    end

    ##
    # Normalizes diagnostic text so deeply nested filters cannot produce
    # unbounded result objects. The first reasons are the most local.
    def self.sanitize_reasons(reasons)
      list = Array(reasons).compact.flat_map { |reason| reason.to_s.split("; ") }
      unique = []
      list.each do |reason|
        reason = reason.strip
        next if reason.empty? || unique.include?(reason)

        unique << reason
        break if unique.size >= MAX_REASONS
      end
      unique = unique.map { |reason| reason[0, MAX_REASON_LENGTH] }
      unique.freeze
    end

    def matched?
      @state == MATCH
    end
    alias_method :match?, :matched?

    def no_match?
      @state == NO_MATCH
    end

    def undetermined?
      @state == UNDETERMINED
    end

    ##
    # Returns :match, :no_match, or :undetermined.
    def to_sym
      @state
    end

    def reason
      @reasons.join("; ")
    end

    def to_s
      @state.to_s
    end

    def inspect
      "#<#{self.class.name} #{@state} #{@reasons.inspect}>"
    end

    ##
    # Compares with another result, a state Symbol, or its String name.
    def ==(other)
      case other
      when EvaluationResult
        other.state == @state && other.reasons == @reasons
      when Symbol
        other == @state
      when String
        other == @state.to_s
      else
        false
      end
    end
    alias_method :eql?, :==
  end

  ##
  # Local, schema-driven filter evaluation. It is deliberately separate from
  # Filter#match: #match is the historical two-valued convenience used by
  # simple servers, while evaluator results may be undetermined.
  #
  # No matching rule is inferred from an attribute name. Unless the schema
  # declares the attribute description and the matching rule used by a filter
  # item, that item evaluates to UNDETERMINED.
  class Evaluator
    # Bounds recursion for adversarially nested filters. Exceeding it yields
    # UNDETERMINED rather than raising or guessing.
    MAX_DEPTH = 100

    def initialize(schema)
      @schema = schema || Schema.default
    end

    ##
    # Evaluates +filter+ against +entry+. +entry+ may be a Net::LDAP::Entry or
    # any object that responds to #each_pair or #to_h with attribute-name and
    # value(s) pairs.
    def evaluate(filter, entry)
      evaluate_at(filter, entry, 0)
    end

    private

    def evaluate_at(filter, entry, depth)
      return undetermined("filter nesting exceeds #{MAX_DEPTH}") if depth > MAX_DEPTH

      op = filter.instance_variable_get(:@op)

      case op
      when :and then evaluate_and(filter, entry, depth)
      when :or then evaluate_or(filter, entry, depth)
      when :not then evaluate_not(filter, entry, depth)
      when :eq then evaluate_equality(filter, entry)
      when :bineq then evaluate_binary_equality(filter, entry)
      when :ne then evaluate_negated_equality(filter, entry, depth)
      when :ge then evaluate_ordering(filter, entry, :ge)
      when :le then evaluate_ordering(filter, entry, :le)
      when :ex then evaluate_extensible(filter, entry)
      else
        undetermined("unsupported filter operator #{op.inspect}")
      end
    end

    def evaluate_and(filter, entry, depth)
      results = children(filter, :and).map { |child| evaluate_at(child, entry, depth + 1) }

      false_results = results.select(&:no_match?)
      return no_match(false_results.flat_map(&:reasons)) if false_results.any?

      unknown = results.select(&:undetermined?)
      return undetermined(unknown.flat_map(&:reasons)) if unknown.any?

      matched
    end

    def evaluate_or(filter, entry, depth)
      results = children(filter, :or).map { |child| evaluate_at(child, entry, depth + 1) }
      return matched if results.any?(&:matched?)

      unknown = results.select(&:undetermined?)
      return undetermined(unknown.flat_map(&:reasons)) if unknown.any?

      no_match(results.flat_map(&:reasons))
    end

    def evaluate_not(filter, entry, depth)
      negate(evaluate_at(filter.instance_variable_get(:@left), entry, depth + 1), "NOT")
    end

    def evaluate_negated_equality(filter, entry, depth)
      equality = Net::LDAP::Filter.eq(
        filter.instance_variable_get(:@left),
        filter.instance_variable_get(:@right)
      )
      negate(evaluate_at(equality, entry, depth + 1), "NOT")
    end

    def negate(result, label)
      case result.state
      when MATCH then no_match
      when NO_MATCH then matched
      else
        undetermined(["#{label} of undetermined filter: #{result.reason}"])
      end
    end

    def evaluate_equality(filter, entry)
      attribute = filter.instance_variable_get(:@left)
      assertion = filter.instance_variable_get(:@right).to_s

      return evaluate_presence(entry, attribute) if assertion == "*"

      declaration = declared_attribute(attribute)
      return declaration if declaration.is_a?(EvaluationResult)

      if wildcard?(assertion)
        evaluate_substring(declaration, entry, assertion)
      else
        evaluate_declared_equality(declaration, entry, assertion)
      end
    end

    def evaluate_presence(entry, attribute)
      normalized = Schema.normalize_attribute_description(attribute)
      return undetermined("invalid attribute description #{attribute.inspect}") if normalized.nil?

      declaration = @schema.attribute(normalized)
      return undetermined("unknown attribute type #{attribute.inspect}") if declaration.nil?

      values = entry_values(entry, declaration.name)
      return values[:result] if values.key?(:result)

      values[:values].empty? ? no_match : matched
    end

    def evaluate_declared_equality(declaration, entry, assertion)
      rule = declaration.equality
      return undetermined("no equality matching rule declared for #{declaration.name}") if rule.nil?

      assertion_value = decode_assertion(assertion, rule)
      return undetermined(assertion_value[:reason]) if assertion_value.key?(:reason)

      evaluate_values(entry, declaration.name, assertion_value[:value], rule)
    end

    def evaluate_binary_equality(filter, entry)
      declaration = declared_attribute(filter.instance_variable_get(:@left))
      return declaration if declaration.is_a?(EvaluationResult)

      rule = declaration.equality
      unless rule == :octet_string
        return undetermined(
          "binary equality for #{declaration.name} requires an :octet_string equality rule"
        )
      end

      assertion = unescape_bytes(filter.instance_variable_get(:@right))
      evaluate_values(entry, declaration.name, assertion, :octet_string)
    end

    def evaluate_substring(declaration, entry, assertion)
      rule = declaration.substring
      return undetermined("no substring matching rule declared for #{declaration.name}") if rule.nil?

      split = split_substring(assertion, rule)
      return undetermined(split[:reason]) if split.key?(:reason)

      evaluate_values(
        entry,
        declaration.name,
        split[:segments],
        rule,
        substring: true,
        starts_wildcard: split[:starts_wildcard],
        ends_wildcard: split[:ends_wildcard]
      )
    end

    def evaluate_ordering(filter, entry, direction)
      declaration = declared_attribute(filter.instance_variable_get(:@left))
      return declaration if declaration.is_a?(EvaluationResult)
      if declaration.ordering.nil?
        return undetermined("no ordering matching rule declared for #{declaration.name}")
      end

      assertion = decode_assertion(filter.instance_variable_get(:@right).to_s,
                                   declaration.ordering)
      return undetermined(assertion[:reason]) if assertion.key?(:reason)

      evaluate_values(entry, declaration.name, assertion[:value], declaration.ordering,
                      ordering: direction)
    end

    def evaluate_extensible(filter, entry)
      parsed = parse_extensible(filter.instance_variable_get(:@left))
      return undetermined(parsed[:reason]) if parsed.key?(:reason)
      return undetermined("dnAttributes matching is not supported locally") if parsed[:dn]

      assertion = filter.instance_variable_get(:@right).to_s

      if parsed[:rule]
        evaluate_extensible_rule(parsed, entry, assertion)
      elsif parsed[:type]
        declaration = declared_attribute(parsed[:type])
        return declaration if declaration.is_a?(EvaluationResult)

        evaluate_declared_equality(declaration, entry, assertion)
      else
        undetermined("extensible match has neither an attribute type nor a matching rule")
      end
    end

    def evaluate_extensible_rule(parsed, entry, assertion)
      rule = @schema.matching_rule(parsed[:rule])
      return undetermined("unknown matching rule #{parsed[:rule].inspect}") if rule.nil?

      if parsed[:type]
        evaluate_extensible_rule_with_type(rule, parsed, entry, assertion)
      else
        evaluate_extensible_rule_without_type(rule, entry, assertion)
      end
    end

    def evaluate_extensible_rule_with_type(rule, parsed, entry, assertion)
      normalized = Schema.normalize_attribute_description(parsed[:type])
      return undetermined("invalid attribute description #{parsed[:type].inspect}") if normalized.nil?

      unless rule.attributes.include?(normalized)
        return undetermined(
          "matching rule #{rule.identifier} is not declared for attribute #{normalized}"
        )
      end

      declaration = @schema.attribute(normalized)
      return undetermined("unknown attribute type #{parsed[:type].inspect}") if declaration.nil?

      assertion_value = decode_assertion(assertion, rule.rule)
      return undetermined(assertion_value[:reason]) if assertion_value.key?(:reason)

      evaluate_values(entry, declaration.name, assertion_value[:value], rule.rule)
    end

    def evaluate_extensible_rule_without_type(rule, entry, assertion)
      assertion_value = decode_assertion(assertion, rule.rule)
      return undetermined(assertion_value[:reason]) if assertion_value.key?(:reason)

      results = rule.attributes.map do |attribute|
        declaration = @schema.attribute(attribute)
        if declaration.nil?
          undetermined("matching rule #{rule.identifier} names undeclared attribute #{attribute}")
        else
          evaluate_values(entry, declaration.name, assertion_value[:value], rule.rule)
        end
      end

      combine_existential(results)
    end

    def evaluate_values(entry, attribute, assertion, rule, substring: false,
                        starts_wildcard: false, ends_wildcard: false, ordering: nil)
      values = entry_values(entry, attribute)
      return values[:result] if values.key?(:result)

      if values[:values].empty?
        return no_match(["attribute #{attribute} has no values"])
      end

      results = values[:values].map do |value|
        evaluate_value(
          value, assertion, rule,
          substring: substring,
          starts_wildcard: starts_wildcard,
          ends_wildcard: ends_wildcard,
          ordering: ordering
        )
      end

      combined = combine_existential(results)
      return combined unless combined.no_match?

      no_match(["no value of #{attribute} satisfied the assertion"])
    end

    def evaluate_value(value, assertion, rule, substring: false, starts_wildcard: false,
                       ends_wildcard: false, ordering: nil)
      case rule
      when :integer
        evaluate_integer_value(value, assertion, ordering)
      when :case_ignore
        evaluate_text_value(value, assertion, substring, starts_wildcard, ends_wildcard,
                            ordering, downcase: true)
      when :case_exact
        evaluate_text_value(value, assertion, substring, starts_wildcard, ends_wildcard,
                            ordering, downcase: false)
      when :octet_string
        evaluate_byte_value(value, assertion, substring, starts_wildcard, ends_wildcard,
                            ordering)
      else
        undetermined("unsupported matching rule #{rule.inspect}")
      end
    end

    def evaluate_integer_value(value, assertion, ordering)
      numeric = parse_integer(value, "entry value")
      return numeric if numeric.is_a?(EvaluationResult)

      compare_result(numeric <=> assertion, ordering)
    end

    def evaluate_text_value(value, assertion, substring, starts_wildcard, ends_wildcard,
                            ordering, downcase:)
      normalized = normalize_text(value, downcase)
      return normalized if normalized.is_a?(EvaluationResult)

      if substring
        ok = substring_match?(normalized, assertion, starts_wildcard, ends_wildcard)
        return ok ? matched : no_match
      end

      comparison = ordering ? normalized <=> assertion : (normalized == assertion ? 0 : nil)
      compare_result(comparison, ordering)
    end

    def evaluate_byte_value(value, assertion, substring, starts_wildcard, ends_wildcard, ordering)
      bytes = value.to_s.b

      if substring
        ok = substring_match?(bytes, assertion, starts_wildcard, ends_wildcard)
        return ok ? matched : no_match
      end

      comparison = ordering ? bytes <=> assertion : (bytes == assertion ? 0 : nil)
      compare_result(comparison, ordering)
    end

    def compare_result(comparison, ordering)
      case ordering
      when :ge then comparison.nil? ? no_match : (comparison >= 0 ? matched : no_match)
      when :le then comparison.nil? ? no_match : (comparison <= 0 ? matched : no_match)
      else comparison == 0 ? matched : no_match
      end
    end

    def substring_match?(haystack, segments, starts_wildcard, ends_wildcard)
      limit = haystack.length
      index = 0

      interior = segments.dup

      unless starts_wildcard
        first = interior.shift
        return false unless haystack.start_with?(first)

        index = first.length
      end

      unless ends_wildcard
        last = interior.pop
        return false unless haystack.end_with?(last)

        limit -= last.length
      end

      return false if index > limit

      interior.each do |segment|
        next if segment.empty?

        position = haystack.index(segment, index)
        return false if position.nil? || position + segment.length > limit

        index = position + segment.length
      end
      true
    end

    def declared_attribute(attribute)
      normalized = Schema.normalize_attribute_description(attribute)
      return undetermined("invalid attribute description #{attribute.inspect}") if normalized.nil?

      declaration = @schema.attribute(normalized)
      return undetermined("unknown attribute type #{attribute.inspect}") if declaration.nil?

      declaration
    end

    def entry_values(entry, attribute)
      source = entry_source(entry)
      return undetermined("entry does not expose attributes") if source.nil?

      source.each_pair do |key, value|
        next unless Schema.normalize_attribute_description(key) == attribute

        values = value.nil? ? [] : Array(value)
        return { values: values }
      end

      { values: [] }
    end

    def entry_source(entry)
      if entry.respond_to?(:each_pair)
        entry
      elsif entry.respond_to?(:to_h)
        entry.to_h
      end
    end

    def combine_existential(results)
      return no_match if results.empty?
      return matched if results.any?(&:matched?)

      unknown = results.select(&:undetermined?)
      return undetermined(unknown.flat_map(&:reasons).uniq) if unknown.any?

      no_match
    end

    def children(filter, operator)
      pending = [filter.instance_variable_get(:@left),
                 filter.instance_variable_get(:@right)]
      flat = []

      until pending.empty?
        current = pending.pop
        next if current.nil?

        if current.is_a?(Net::LDAP::Filter) && current.instance_variable_get(:@op) == operator
          pending << current.instance_variable_get(:@left)
          pending << current.instance_variable_get(:@right)
        else
          flat << current
        end
      end

      flat
    end

    def wildcard?(assertion)
      bytes = assertion.to_s.b
      index = 0

      while index < bytes.bytesize
        byte = bytes.getbyte(index)

        if byte == 0x5C && hex_escape_bytes(bytes, index + 1)
          index += 3
        elsif byte == 0x2A
          return true
        else
          index += 1
        end
      end
      false
    end

    ##
    # Splits the raw assertion string on unescaped "*" characters. Escaped
    # sequences such as "\2A" become literal bytes. This mirrors the RFC
    # 4515 wire interpretation used by Filter#to_ber and keeps binary
    # assertions byte-exact.
    def split_substring(assertion, rule)
      bytes = assertion.to_s.b
      segments = []
      current = +"".b
      starts_wildcard = false
      ends_wildcard = false
      index = 0

      while index < bytes.bytesize
        byte = bytes.getbyte(index)

        if byte == 0x5C && hex_escape_bytes(bytes, index + 1)
          current << bytes[index + 1, 2].to_i(16).chr
          index += 3
          next
        end

        if byte == 0x2A
          if segments.empty? && current.empty?
            starts_wildcard = true
          else
            segments << current
          end

          current = +"".b
          ends_wildcard = true
          index += 1
          next
        end

        current << byte.chr
        ends_wildcard = false
        index += 1
      end

      if ends_wildcard
        segments << "".b if starts_wildcard && segments.empty?
      else
        segments << current
      end

      decoded = segments.map { |segment| decode_segment(segment, rule) }
      invalid = decoded.find { |segment| segment.is_a?(Hash) }
      return invalid if invalid

      {
        segments: decoded,
        starts_wildcard: starts_wildcard,
        ends_wildcard: ends_wildcard,
      }
    end

    def hex_escape_bytes(bytes, index)
      return false if index + 1 >= bytes.bytesize

      pair = bytes[index, 2]
      pair.bytesize == 2 && /\A[0-9a-fA-F]{2}\z/n.match?(pair)
    end

    def decode_segment(bytes, rule)
      return bytes unless [:case_ignore, :case_exact].include?(rule)

      text = bytes.dup.force_encoding(Encoding::UTF_8)
      return { reason: "substring assertion is not valid UTF-8" } unless text.valid_encoding?

      rule == :case_ignore ? text.downcase : text
    end

    def decode_assertion(assertion, rule)
      bytes = unescape_bytes(assertion)

      case rule
      when :integer
        integer = parse_integer(bytes, "assertion value")
        integer.is_a?(EvaluationResult) ? { reason: integer.reason } : { value: integer }
      when :case_ignore, :case_exact
        text = bytes.dup.force_encoding(Encoding::UTF_8)
        return { reason: "assertion value is not valid UTF-8" } unless text.valid_encoding?

        { value: rule == :case_ignore ? text.downcase : text }
      when :octet_string
        { value: bytes.b }
      else
        { reason: "unsupported matching rule #{rule.inspect}" }
      end
    end

    def unescape_bytes(value)
      value.to_s.b.gsub(/\\([0-9a-fA-F]{2})/n) { [Regexp.last_match(1).hex].pack("C") }
    end

    def parse_integer(value, label)
      text = value.to_s
      return undetermined("invalid integer #{label} #{text.inspect}") unless /\A-?\d+\z/.match?(text)

      text.to_i
    end

    def normalize_text(value, downcase)
      text = value.to_s.dup.force_encoding(Encoding::UTF_8)
      return undetermined("entry value is not valid UTF-8") unless text.valid_encoding?

      downcase ? text.downcase : text
    end

    def parse_extensible(attribute)
      match = /\A([-;\w]*)(:dn)?(:(\w+|[.\w]+))?\z/.match(attribute.to_s)
      return { reason: "invalid extensible attribute #{attribute.inspect}" } if match.nil?

      type = match[1].empty? ? nil : match[1]
      rule = match[4]
      rule = nil if rule.to_s.empty?

      if type.nil? && rule.nil?
        return { reason: "extensible match has neither an attribute type nor a matching rule" }
      end

      { type: type, dn: !match[2].nil?, rule: rule }
    end

    def matched
      EvaluationResult.new(MATCH)
    end

    def no_match(reasons = [])
      EvaluationResult.new(NO_MATCH, reasons)
    end

    def undetermined(reasons)
      EvaluationResult.new(UNDETERMINED, Array(reasons))
    end
  end
end
