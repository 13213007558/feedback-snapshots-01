# -*- ruby encoding: utf-8 -*-

##
# Objects of this class represent an LDAP DN ("Distinguished Name"). A DN
# ("Distinguished Name") is a unique identifier for an entry within an LDAP
# directory. It is made up of a number of other attributes strung together,
# to identify the entry in the tree.
#
# Each attribute that makes up a DN needs to have its value escaped so that
# the DN is valid. This class helps take care of that.
#
# A fully escaped DN needs to be unescaped when analysing its contents. This
# class also helps take care of that.
class Net::LDAP::DN
  ##
  # Initialize a DN, escaping as required. Pass in attributes in name/value
  # pairs. If there is a left over argument, it will be appended to the dn
  # without escaping (useful for a base string).
  #
  # Most uses of this class will be to escape a DN, rather than to parse it,
  # so storing the dn as an escaped String and parsing parts as required
  # with a state machine seems sensible.
  def initialize(*args)
    buffer = StringIO.new

    args.each_index do |index|
      buffer << "=" if index % 2 == 1
      buffer << "," if index % 2 == 0 && index != 0

      if index < args.length - 1 || index % 2 == 1
        buffer << Net::LDAP::DN.escape(args[index])
      else
        buffer << args[index]
      end
    end

    @dn = buffer.string
  end

  ##
  # Parse a DN into key value pairs using ASN from
  # http://tools.ietf.org/html/rfc2253 section 3.
  def each_pair
    state = :key
    key = StringIO.new
    value = StringIO.new
    hex_buffer = ""

    @dn.each_char do |char|
      case state
      when :key then
        case char
        when 'a'..'z', 'A'..'Z' then
          state = :key_normal
          key << char
        when '0'..'9' then
          state = :key_oid
          key << char
        when ' ' then state = :key
        else raise Net::LDAP::InvalidDNError, "DN badly formed"
        end
      when :key_normal then
        case char
        when '=' then state = :value
        when 'a'..'z', 'A'..'Z', '0'..'9', '-', ' ' then key << char
        else raise Net::LDAP::InvalidDNError, "DN badly formed"
        end
      when :key_oid then
        case char
        when '=' then state = :value
        when '0'..'9', '.', ' ' then key << char
        else raise Net::LDAP::InvalidDNError, "DN badly formed"
        end
      when :value then
        case char
        when '\\' then state = :value_normal_escape
        when '"' then state = :value_quoted
        when ' ' then state = :value
        when '#' then
          state = :value_hexstring
          value << char
        when ',' then
          state = :key
          yield key.string.strip, value.string
          key = StringIO.new
          value = StringIO.new;
        else
          state = :value_normal
          value << char
        end
      when :value_normal then
        case char
        when '\\' then state = :value_normal_escape
        when ',' then
          state = :key
          yield key.string.strip, value.string
          key = StringIO.new
          value = StringIO.new;
        else value << char
        end
      when :value_normal_escape then
        case char
        when '0'..'9', 'a'..'f', 'A'..'F' then
          state = :value_normal_escape_hex
          hex_buffer = char
        else state = :value_normal; value << char
        end
      when :value_normal_escape_hex then
        case char
        when '0'..'9', 'a'..'f', 'A'..'F' then
          state = :value_normal
          value << "#{hex_buffer}#{char}".to_i(16).chr
        else raise Net::LDAP::InvalidDNError, "DN badly formed"
        end
      when :value_quoted then
        case char
        when '\\' then state = :value_quoted_escape
        when '"' then state = :value_end
        else value << char
        end
      when :value_quoted_escape then
        case char
        when '0'..'9', 'a'..'f', 'A'..'F' then
          state = :value_quoted_escape_hex
          hex_buffer = char
        else
          state = :value_quoted;
          value << char
        end
      when :value_quoted_escape_hex then
        case char
        when '0'..'9', 'a'..'f', 'A'..'F' then
          state = :value_quoted
          value << "#{hex_buffer}#{char}".to_i(16).chr
        else raise Net::LDAP::InvalidDNError, "DN badly formed"
        end
      when :value_hexstring then
        case char
        when '0'..'9', 'a'..'f', 'A'..'F' then
          state = :value_hexstring_hex
          value << char
        when ' ' then state = :value_end
        when ',' then
          state = :key
          yield key.string.strip, value.string
          key = StringIO.new
          value = StringIO.new;
        else raise Net::LDAP::InvalidDNError, "DN badly formed"
        end
      when :value_hexstring_hex then
        case char
        when '0'..'9', 'a'..'f', 'A'..'F' then
          state = :value_hexstring
          value << char
        else raise Net::LDAP::InvalidDNError, "DN badly formed"
        end
      when :value_end then
        case char
        when ' ' then state = :value_end
        when ',' then
          state = :key
          yield key.string.strip, value.string
          key = StringIO.new
          value = StringIO.new;
        else raise Net::LDAP::InvalidDNError, "DN badly formed"
        end
      else raise Net::LDAP::InvalidDNError, "Fell out of state machine"
      end
    end

    # Last pair
    raise Net::LDAP::InvalidDNError, "DN badly formed" unless
      [:value, :value_normal, :value_hexstring, :value_end].include? state

    yield key.string.strip, value.string
  end

  ##
  # Returns the DN as an array in the form expected by the constructor.
  def to_a
    a = []
    self.each_pair { |key, value| a << key << value }
    a
  end

  ##
  # Return the DN as an escaped string. Instances built with ::parse
  # re-encode from their parsed structure, so the representation that was
  # inspected (for example with #subtree_of?) is exactly the one that gets
  # encoded and sent.
  def to_s
    @reencode ? self.class.encode_rdns(rdns) : @dn
  end

  ##
  # Parse a string into a validated Net::LDAP::DN. Unlike ::new, which
  # treats its arguments as fragments to be joined, ::parse validates the
  # whole string up front (raising Net::LDAP::InvalidDNError when it is
  # malformed) and re-encodes from the parsed structure when converted
  # back to a string:
  #
  #   dn = Net::LDAP::DN.parse(user_supplied_dn)
  #   verdict = dn.subtree_of?("ou=eng,dc=example,dc=com",
  #                            matching_rules: { "ou" => ->(a, b) { a.casecmp?(b) } })
  #   raise "outside allowed subtree" unless verdict == true
  #   ldap.modify(dn: dn.to_s, operations: ops)
  def self.parse(string)
    dn = allocate
    dn.instance_variable_set(:@dn, string.to_s)
    dn.instance_variable_set(:@reencode, true)
    dn.rdns # validate eagerly
    dn
  end

  ##
  # Returns the structured form of the DN: an array of RDNs, ordered as
  # they appear in the string (leaf first). Each RDN is an array of
  # [attribute_type, value] pairs; a multi-valued RDN ("cn=a+ou=b") has
  # more than one pair. Backslash escapes and hex-encoded values (#A3B4D5)
  # are decoded, so the values are the actual attribute values rather than
  # their string representations.
  def rdns
    @rdns ||= self.class.parse_rdns(@dn)
  end

  ##
  # Returns whether this DN is contained in the subtree rooted at +base+
  # (the base itself included). +base+ may be a String or a Net::LDAP::DN.
  #
  # The comparison is structural: RDNs are compared component by component
  # from the root, so lookalike strings ("cn=ou=eng,dc=evil" versus
  # "ou=eng,dc=example") cannot bypass the check the way a string suffix
  # test can. Attribute types are matched case-insensitively and may be
  # mapped through +attribute_aliases+ (e.g. { "cn" => "2.5.4.3" }) so
  # that an alias and its OID compare equal.
  #
  # Whether two values are equivalent is decided by +matching_rules+, a
  # hash mapping an attribute type to a callable receiving both values.
  # The callable must return true (equal), false (not equal) or nil
  # (cannot determine). Attributes without a rule are compared by exact
  # value; case is never folded unless the caller's rule does so.
  #
  # Returns true when the DN is definitely inside the subtree, false when
  # it is definitely outside, and nil when a matching rule reported that
  # equivalence could not be determined.
  def subtree_of?(base, matching_rules: {}, attribute_aliases: {})
    self.class.subtree_of?(self, base,
                           matching_rules: matching_rules,
                           attribute_aliases: attribute_aliases)
  end

  ##
  # Class-level convenience for Net::LDAP::DN#subtree_of?; accepts Strings
  # or Net::LDAP::DN objects for both +dn+ and +base+.
  def self.subtree_of?(dn, base, matching_rules: {}, attribute_aliases: {})
    dn_rdns = dn.is_a?(Net::LDAP::DN) ? dn.rdns : parse_rdns(dn)
    base_rdns = base.is_a?(Net::LDAP::DN) ? base.rdns : parse_rdns(base)
    rdns_contained?(dn_rdns, base_rdns, matching_rules, attribute_aliases)
  end

  ##
  # Parse a string into the structured RDN form described in #rdns.
  # Raises Net::LDAP::InvalidDNError for malformed input.
  def self.parse_rdns(string)
    string = string.to_s
    length = string.length
    index = 0
    rdns = []
    rdn = []

    return rdns if length == 0

    read_escape = lambda do
      index += 1 # skip the backslash
      raise Net::LDAP::InvalidDNError, "DN badly formed" if index >= length
      char = string[index]
      if char =~ /[0-9A-Fa-f]/
        if index + 1 >= length || string[index + 1] !~ /[0-9A-Fa-f]/
          raise Net::LDAP::InvalidDNError, "DN badly formed"
        end
        byte = string[index, 2].to_i(16).chr
        index += 2
        byte
      else
        index += 1
        char
      end
    end

    loop do
      index += 1 while index < length && string[index] == " "

      char = string[index]
      if char =~ /[A-Za-z]/
        start = index
        index += 1 while index < length && string[index] =~ /[A-Za-z0-9-]/
        attribute = string[start...index]
      elsif char =~ /[0-9]/
        start = index
        index += 1 while index < length && string[index] =~ /[0-9.]/
        attribute = string[start...index]
        unless attribute =~ /\A[0-9]+(\.[0-9]+)*\z/
          raise Net::LDAP::InvalidDNError, "DN badly formed"
        end
      else
        raise Net::LDAP::InvalidDNError, "DN badly formed"
      end

      index += 1 while index < length && string[index] == " "
      unless string[index] == "="
        raise Net::LDAP::InvalidDNError, "DN badly formed"
      end
      index += 1
      index += 1 while index < length && string[index] == " "

      if string[index] == "#"
        index += 1
        start = index
        index += 1 while index < length && string[index] =~ /[0-9A-Fa-f]/
        hex = string[start...index]
        if hex.empty? || hex.length.odd?
          raise Net::LDAP::InvalidDNError, "DN badly formed"
        end
        value = [hex].pack("H*")
      elsif string[index] == '"'
        index += 1
        value = String.new
        loop do
          raise Net::LDAP::InvalidDNError, "DN badly formed" if index >= length
          char = string[index]
          case char
          when "\\" then value << read_escape.call
          when '"' then index += 1; break
          else value << char; index += 1
          end
        end
      else
        value = String.new
        loop do
          break if index >= length
          char = string[index]
          break if char == "," || char == "+"
          if char == "\\"
            value << read_escape.call
          else
            value << char
            index += 1
          end
        end
      end

      index += 1 while index < length && string[index] == " "
      rdn << [attribute, coerce_value_encoding(value)]

      if index >= length
        rdns << rdn
        return rdns
      end

      case string[index]
      when ","
        rdns << rdn
        rdn = []
        index += 1
      when "+"
        index += 1
      else
        raise Net::LDAP::InvalidDNError, "DN badly formed"
      end
    end
  end

  ##
  # Re-encode a structured RDN list (as returned by ::parse_rdns) into an
  # escaped DN string.
  def self.encode_rdns(rdns)
    rdns.map do |rdn|
      rdn.map { |attribute, value| "#{attribute}=#{escape(value)}" }.join("+")
    end.join(",")
  end

  ##
  # Structural containment test on parsed RDN lists. Returns true, false
  # or nil (indeterminate); see Net::LDAP::DN#subtree_of?.
  def self.rdns_contained?(dn_rdns, base_rdns, matching_rules = {}, attribute_aliases = {})
    return false if base_rdns.length > dn_rdns.length

    aliases = {}
    attribute_aliases.each do |name, canonical|
      aliases[name.to_s.downcase] = canonical.to_s.downcase
    end
    rules = normalize_matching_rules(matching_rules, aliases)

    offset = dn_rdns.length - base_rdns.length
    verdict = true
    base_rdns.each_with_index do |base_rdn, position|
      rdn_verdict = rdn_match?(dn_rdns[offset + position], base_rdn, rules, aliases)
      return false if rdn_verdict == false
      verdict = nil if rdn_verdict.nil?
    end
    verdict
  end

  ##
  # Compare a single RDN from the target with one from the base. Returns
  # true, false or nil (indeterminate).
  def self.rdn_match?(target_rdn, base_rdn, rules, aliases)
    return false if target_rdn.length != base_rdn.length

    target_avas = Hash.new { |hash, key| hash[key] = [] }
    target_rdn.each { |type, value| target_avas[canonical_attribute(type, aliases)] << value }
    base_avas = Hash.new { |hash, key| hash[key] = [] }
    base_rdn.each { |type, value| base_avas[canonical_attribute(type, aliases)] << value }

    return false unless target_avas.keys.sort == base_avas.keys.sort

    verdict = true
    base_avas.each do |type, base_values|
      rule = rules[type]
      candidates = target_avas[type].dup
      base_values.each do |base_value|
        matches = candidates.map do |candidate|
          rule ? rule.call(base_value, candidate) : base_value == candidate
        end
        if (found = matches.index { |match| !match.nil? && match != false })
          candidates.delete_at(found)
        elsif matches.any?(&:nil?)
          verdict = nil
        else
          return false
        end
      end
    end
    verdict
  end

  def self.canonical_attribute(type, aliases)
    normalized = type.to_s.downcase
    aliases.fetch(normalized, normalized)
  end
  private_class_method :canonical_attribute

  def self.normalize_matching_rules(rules, aliases)
    normalized = {}
    rules.each { |type, rule| normalized[canonical_attribute(type, aliases)] = rule }
    if rules.default_proc
      default_proc = rules.default_proc
      Hash.new { |_hash, key| default_proc.call(rules, key) }.merge!(normalized)
    elsif rules.default
      Hash.new(rules.default).merge!(normalized)
    else
      normalized
    end
  end
  private_class_method :normalize_matching_rules

  def self.coerce_value_encoding(value)
    value.force_encoding(Encoding::UTF_8)
    value.force_encoding(Encoding::BINARY) unless value.valid_encoding?
    value
  end
  private_class_method :coerce_value_encoding

  # http://tools.ietf.org/html/rfc2253 section 2.4 lists these exceptions
  # for dn values. All of the following must be escaped in any normal string
  # using a single backslash ('\') as escape.
  ESCAPES = %w[, + " \\ < > ;]

  # Compiled character class regexp using the values from the above list, and
  # checking for a space or # at the start, or space at the end, of the
  # string.
  ESCAPE_RE = Regexp.new("(^ |^#| $|[" +
                         ESCAPES.map { |e| Regexp.escape(e) }.join +
                         "])")

  ##
  # Escape a string for use in a DN value
  def self.escape(string)
    string.gsub(ESCAPE_RE) { |char| "\\" + char }
  end

  ##
  # Proxy all other requests to the string object, because a DN is mainly
  # used within the library as a string
  def method_missing(method, *args, &block)
    @dn.send(method, *args, &block)
  end
end
