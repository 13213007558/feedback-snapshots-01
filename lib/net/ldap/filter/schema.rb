# -*- ruby encoding: utf-8 -*-

class Net::LDAP::Filter
  ##
  # An explicit, finite description of the attribute types and matching rules
  # that may be used by Filter#evaluate.
  #
  # Local evaluation never consults a directory server and never infers a
  # matching rule from an attribute name. An attribute description or matching
  # rule that is not declared here is reported as +undetermined+, not as a
  # non-match.
  #
  # Only the following matching rule kinds are understood:
  #
  # * +:case_ignore+ - Unicode case folding (String#downcase) before
  #   comparison.
  # * +:case_exact+ - byte-for-byte comparison.
  # * +:octet_string+ - byte-for-byte comparison, intended for binary values.
  # * +:integer+ - strict base-10 integer comparison.
  #
  # These names are deliberately small and closed. Declaring an unknown rule
  # raises ArgumentError; using an undeclared rule during evaluation produces
  # an undetermined result.
  class Schema
    RULE_KINDS = [:case_ignore, :case_exact, :octet_string, :integer].freeze
    SUBSTRING_RULE_KINDS = [:case_ignore, :case_exact, :octet_string].freeze

    ATTRIBUTE_TYPE_RE = /\A(?:[a-z][a-z0-9-]*|\d+(?:\.\d+)*)\z/i
    OPTION_RE = /\A[a-z0-9-]+\z/i
    MAX_ATTRIBUTE_OPTIONS = 16

    Attribute = Struct.new(:name, :equality, :ordering, :substring, keyword_init: true)
    MatchingRule = Struct.new(:identifier, :rule, :attributes, keyword_init: true)

    class << self
      ##
      # Normalizes an attribute description for case-insensitive lookup and
      # for comparison with entry keys. Returns nil when the description is
      # syntactically invalid.
      #
      # Attribute options are sorted so that "cn;lang-fr;x-tag" and
      # "CN;x-tag;LANG-FR" identify the same description. Options are not
      # implicitly inherited from the base type: they must be declared
      # explicitly in the schema.
      def normalize_attribute_description(description)
        return nil if description.nil?

        parts = description.to_s.split(";", -1)
        type = parts.shift.to_s
        return nil unless ATTRIBUTE_TYPE_RE.match?(type)

        return nil if parts.size > MAX_ATTRIBUTE_OPTIONS

        options = parts.map do |option|
          return nil unless OPTION_RE.match?(option)

          option.downcase
        end

        normalized = type.downcase
        normalized += ";" + options.sort.join(";") unless options.empty?
        normalized
      end

      ##
      # A shared empty schema. Evaluating with it yields +undetermined+ for
      # every filter item rather than guessing at the directory's schema.
      def default
        @default ||= new.freeze
      end
    end

    ##
    # Builds a schema from an attribute table and, optionally, a matching
    # rule table. Both may be passed positionally or by the +attributes+
    # and +matching_rules+ keywords. A bare attribute table such as
    # <tt>Schema.new("cn" => { equality: :case_ignore })</tt> is also
    # accepted.
    def initialize(*args, attributes: nil, matching_rules: nil, **bare_attributes)
      unless args.size <= 2
        raise ArgumentError, "Schema.new accepts at most two positional hashes"
      end
      if attributes && bare_attributes.any?
        raise ArgumentError, "Pass the attribute table either positionally or as attributes:"
      end

      attributes ||= bare_attributes.any? ? bare_attributes : (args[0] || {})
      matching_rules ||= args[1] || {}

      @attributes = {}
      @matching_rules = {}

      attributes.each { |name, options| add_attribute(name, **symbolize_keys(options)) }
      matching_rules.each do |identifier, options|
        add_matching_rule(identifier, **symbolize_keys(options))
      end
    end

    ##
    # Declares an attribute type. +equality+, +ordering+, and +substring+
    # name one of RULE_KINDS (or SUBSTRING_RULE_KINDS for +substring+), or
    # are nil when that operation is not supported for the type.
    def add_attribute(name, equality: nil, ordering: nil, substring: nil)
      key = self.class.normalize_attribute_description(name)
      raise ArgumentError, "Invalid attribute description: #{name.inspect}" if key.nil?
      raise ArgumentError, "Attribute already declared: #{key}" if @attributes.key?(key)

      equality = validate_kind!(equality, RULE_KINDS, key, :equality)
      ordering = validate_kind!(ordering, RULE_KINDS, key, :ordering)
      substring = validate_kind!(substring, SUBSTRING_RULE_KINDS, key, :substring)

      @attributes[key] = Attribute.new(
        name: key,
        equality: equality,
        ordering: ordering,
        substring: substring
      ).freeze
      self
    end

    ##
    # Declares an extensible matching rule identifier (an OID or a name) and
    # the attribute descriptions it may be applied to. Nothing is inferred:
    # a rule that is not registered here is unknown to local evaluation.
    #
    # Every attribute description named here must already have been declared
    # with #add_attribute.
    def add_matching_rule(identifier, rule:, attributes:)
      id = identifier.to_s.downcase
      raise ArgumentError, "Matching rule identifier must not be empty" if id.empty?
      raise ArgumentError, "Matching rule already declared: #{id}" if @matching_rules.key?(id)

      rule = validate_kind!(rule, RULE_KINDS, id, :rule)
      names = Array(attributes).map do |attribute|
        normalized = self.class.normalize_attribute_description(attribute)
        raise ArgumentError, "Invalid attribute description: #{attribute.inspect}" if normalized.nil?
        unless @attributes.key?(normalized)
          raise ArgumentError,
                "Matching rule #{id} names undeclared attribute #{normalized}; " \
                "declare the attribute first"
        end

        normalized
      end
      raise ArgumentError, "Matching rule #{id} must name at least one attribute" if names.empty?

      @matching_rules[id] = MatchingRule.new(
        identifier: id,
        rule: rule,
        attributes: names.uniq.freeze
      ).freeze
      self
    end

    ##
    # Returns the Attribute declaration for a normalized or unnormalized
    # description, or nil when it is not recognized.
    def attribute(name)
      key = self.class.normalize_attribute_description(name)
      key && @attributes[key]
    end

    ##
    # Returns the MatchingRule declaration for an identifier, or nil.
    def matching_rule(identifier)
      @matching_rules[identifier.to_s.downcase]
    end

    ##
    # Returns a copy of the declared attributes keyed by normalized
    # description. Useful for introspection and diagnostics.
    def attributes
      @attributes.dup
    end

    private

    def symbolize_keys(options)
      options.each_with_object({}) { |(key, value), hash| hash[key.to_sym] = value }
    end

    def validate_kind!(value, allowed, name, operation)
      return nil if value.nil?

      kind = value.to_sym
      unless allowed.include?(kind)
        raise ArgumentError,
              "Unsupported #{operation} matching rule #{value.inspect} for #{name}; " \
              "expected one of #{allowed.inspect}"
      end
      kind
    end
  end
end
