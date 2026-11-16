module OneLogin
  module RubySaml

    # Raised when a typed attribute lookup cannot be resolved to exactly one
    # Attribute element or AttributeValue.
    class AttributeSelectionError < StandardError
    end

    # Raised when a lookup matches more than one Attribute element or value and
    # the caller did not disambiguate it with NameFormat, occurrence or value
    # index.
    class AmbiguousAttributeError < AttributeSelectionError
    end

    # Raised when a typed attribute lookup finds no matching Attribute element
    # or AttributeValue.
    class MissingAttributeError < AttributeSelectionError
    end

    # Location of an Attribute element or AttributeValue inside the signed
    # assertion that was read from the SAML Response.
    #
    # The structured fields are the stable contract:
    # - +response_id+: the ID of the SAML Response
    # - +assertion_id+: the ID of the signed assertion
    # - +statement_index+: 1-based AttributeStatement position in the assertion
    # - +attribute_index+: 1-based position among the Attribute and
    #   EncryptedAttribute children of that statement
    # - +value_index+: 1-based AttributeValue position, only set for values
    # - +encrypted+: whether the value was read from a decrypted
    #   EncryptedAttribute payload
    #
    # +path+ is a human readable XPath-like location. For encrypted attributes
    # it points at the EncryptedAttribute element; value paths continue into
    # the decrypted payload (/saml:Attribute[1]/saml:AttributeValue[n]) and are
    # suffixed with "(decrypted)".
    class AttributeSource
      attr_reader :response_id, :assertion_id, :statement_index,
                  :attribute_index, :value_index, :element_name

      def initialize(options = {})
        @response_id = options[:response_id]
        @assertion_id = options[:assertion_id]
        @statement_index = options[:statement_index]
        @attribute_index = options[:attribute_index]
        @value_index = options[:value_index]
        @element_name = options[:element_name]
        @encrypted = options[:encrypted] ? true : false
      end

      def encrypted?
        @encrypted
      end

      # Returns a source for one AttributeValue of this Attribute.
      def for_value(index)
        self.class.new(
          :response_id => response_id,
          :assertion_id => assertion_id,
          :statement_index => statement_index,
          :attribute_index => attribute_index,
          :value_index => index,
          :element_name => element_name,
          :encrypted => encrypted?
        )
      end

      def path
        parts = []
        parts << (response_id ? "samlp:Response[@ID='#{response_id}']" : 'samlp:Response')
        parts << (assertion_id ? "saml:Assertion[@ID='#{assertion_id}']" : 'saml:Assertion')
        parts << "saml:AttributeStatement[#{statement_index}]" if statement_index
        parts << "saml:#{element_name}[#{attribute_index}]" if element_name && attribute_index
        parts << 'saml:Attribute[1]' if encrypted?
        parts << "saml:AttributeValue[#{value_index}]" if value_index
        path = '/' + parts.join('/')
        path += ' (decrypted)' if encrypted? && value_index
        path
      end

      def to_h
        {
          :response_id => response_id,
          :assertion_id => assertion_id,
          :statement_index => statement_index,
          :attribute_index => attribute_index,
          :value_index => value_index,
          :element_name => element_name,
          :encrypted => encrypted?,
          :path => path
        }
      end

      def ==(other)
        other.is_a?(AttributeSource) &&
          response_id == other.response_id &&
          assertion_id == other.assertion_id &&
          statement_index == other.statement_index &&
          attribute_index == other.attribute_index &&
          value_index == other.value_index &&
          element_name == other.element_name &&
          encrypted? == other.encrypted?
      end
    end

    # A SAML2 NameID that appeared inside an AttributeValue. Each qualifier is
    # kept separately; the value is never rewritten by prefixing a qualifier.
    class NameIdValue
      attr_reader :value, :format, :name_qualifier, :sp_name_qualifier

      def initialize(options = {})
        @value = options[:value]
        @format = options[:format]
        @name_qualifier = options[:name_qualifier]
        @sp_name_qualifier = options[:sp_name_qualifier]
      end

      def qualified?
        !name_qualifier.nil? || !sp_name_qualifier.nil?
      end

      def to_h
        {
          :value => value,
          :format => format,
          :name_qualifier => name_qualifier,
          :sp_name_qualifier => sp_name_qualifier
        }
      end

      def ==(other)
        other.is_a?(NameIdValue) &&
          value == other.value &&
          format == other.format &&
          name_qualifier == other.name_qualifier &&
          sp_name_qualifier == other.sp_name_qualifier
      end
    end

    # One SAML2 AttributeValue. Unlike the legacy Attributes API this object
    # keeps the XML Schema type, the difference between an absent value, a
    # +nil+ value and an empty string, and any nested NameID values.
    class AttributeValue
      XSI_NAMESPACE = 'http://www.w3.org/2001/XMLSchema-instance'.freeze

      attr_reader :text, :type, :type_namespace, :type_name, :name_ids, :source

      def initialize(options = {})
        @text = options[:text]
        @type = options[:type]
        @type_namespace = options[:type_namespace]
        @type_name = options[:type_name]
        @name_ids = options[:name_ids] || []
        @source = options[:source]
        @nil_value = options[:nil] ? true : false
      end

      # True when the value carries xsi:nil="true" or xsi:nil="1". This is
      # intentionally not called +nil?+: an AttributeValue object is always
      # present, only its protocol value is nilled.
      def nil_value?
        @nil_value
      end
      alias_method :xsi_nil?, :nil_value?

      # True for an AttributeValue element that is present but has no text and
      # is not xsi:nil. This is deliberately different from +nil_value?+ and
      # from a missing AttributeValue element.
      def empty?
        !nil_value? && text == ''
      end

      def name_id?
        !name_ids.empty?
      end

      # Returns the single nested NameID. Raises AmbiguousAttributeError when
      # more than one NameID was nested in this value; callers should use
      # +name_ids+ in that case.
      def name_id
        if name_ids.size > 1
          raise AmbiguousAttributeError,
                "AttributeValue contains #{name_ids.size} NameID elements; use #name_ids"
        end

        name_ids.first
      end

      def to_h
        {
          :text => text,
          :type => type,
          :type_namespace => type_namespace,
          :type_name => type_name,
          :nil => nil_value?,
          :empty => empty?,
          :name_ids => name_ids.map(&:to_h),
          :source => source && source.to_h
        }
      end

      def ==(other)
        other.is_a?(AttributeValue) &&
          text == other.text &&
          type == other.type &&
          type_namespace == other.type_namespace &&
          type_name == other.type_name &&
          nil_value? == other.nil_value? &&
          name_ids == other.name_ids &&
          source == other.source
      end
    end

    # One Attribute element. Duplicate Attribute elements are represented as
    # separate records and are never merged, even when Name and NameFormat
    # match. +occurrence+ is the 1-based position among records with the same
    # [Name, NameFormat] pair and +occurrences+ is the total number of such
    # records.
    class AttributeRecord
      attr_reader :name, :name_format, :friendly_name, :values, :source,
                  :occurrence, :occurrences

      def initialize(options = {})
        @name = options[:name]
        @name_format = options[:name_format]
        @friendly_name = options[:friendly_name]
        @values = options[:values] || []
        @source = options[:source]
        @occurrence = options[:occurrence] || 1
        @occurrences = options[:occurrences] || 1
      end

      def encrypted?
        !source.nil? && source.encrypted?
      end

      # True when another Attribute element in the response has the same Name
      # and NameFormat. Use AttributeCollection#duplicates to see the group.
      def duplicate?
        occurrences > 1
      end

      # True when this Attribute has the same Name as another record but a
      # different NameFormat.
      def same_name_other_format?
        @same_name_other_format ? true : false
      end

      def multi_value?
        values.size > 1
      end

      def empty?
        values.empty?
      end

      def value_count
        values.size
      end

      def to_h
        {
          :name => name,
          :name_format => name_format,
          :friendly_name => friendly_name,
          :encrypted => encrypted?,
          :duplicate => duplicate?,
          :same_name_other_format => same_name_other_format?,
          :occurrence => occurrence,
          :occurrences => occurrences,
          :values => values.map(&:to_h),
          :source => source && source.to_h
        }
      end

      def ==(other)
        other.is_a?(AttributeRecord) &&
          name == other.name &&
          name_format == other.name_format &&
          friendly_name == other.friendly_name &&
          values == other.values &&
          source == other.source &&
          occurrence == other.occurrence &&
          occurrences == other.occurrences
      end

      protected

      def assign_occurrence(occurrence, occurrences, same_name_other_format)
        @occurrence = occurrence
        @occurrences = occurrences
        @same_name_other_format = same_name_other_format
      end
    end

    # Strict, protocol-aware view of all Attribute elements in the signed
    # assertion. This API never consults Attributes.single_value_compatibility.
    #
    # Semantics:
    # - Every Attribute element is one AttributeRecord, in XML order.
    # - Attributes with the same Name but different NameFormat are distinct
    #   records; select one with :name_format.
    # - Attributes with the same Name and NameFormat are duplicates; they are
    #   kept separately and their values are never merged.
    # - An Attribute with several AttributeValue children is one record with a
    #   multi-element +values+ array.
    class AttributeCollection
      include Enumerable

      # @return [Array<AttributeRecord>] every Attribute element, in XML order
      attr_reader :records

      def initialize(records = [])
        @records = records
        assign_occurrences
      end

      def each(&block)
        records.each(&block)
      end

      def size
        records.size
      end
      alias_method :length, :size

      def empty?
        records.empty?
      end

      # Unique attribute names in XML order.
      def names
        records.map(&:name).uniq
      end

      # Records matching the supplied :name, :name_format, :friendly_name or
      # :encrypted filters. All filters are optional and exact.
      def where(filters = {})
        records.select do |record|
          if filters.key?(:name)
            expected_name = filters[:name].nil? ? nil : filters[:name].to_s
            next false if record.name != expected_name
          end
          next false if filters.key?(:name_format) && record.name_format != filters[:name_format]
          next false if filters.key?(:friendly_name) && record.friendly_name != filters[:friendly_name]
          next false if filters.key?(:encrypted) && record.encrypted? != filters[:encrypted]
          true
        end
      end

      def by_name(name)
        where(:name => name)
      end

      # Distinct NameFormat values carried by records with this Name, in XML
      # order. +nil+ is included when at least one record omitted NameFormat.
      def name_formats(name)
        by_name(name).map(&:name_format).uniq
      end

      # Groups records by [Name, NameFormat], returning only groups with more
      # than one Attribute element.
      def duplicates
        grouped = {}
        records.each do |record|
          key = [record.name, record.name_format]
          (grouped[key] ||= []) << record
        end
        grouped.reject { |_key, grouped_records| grouped_records.size < 2 }
      end

      def duplicate?
        !duplicates.empty?
      end

      # @return [Array<AttributeRecord>] all records as an array
      def all
        records.dup
      end

      # Select exactly one AttributeRecord.
      #
      # Options:
      # - :name_format  required when the same Name appears with several
      #   formats
      # - :occurrence   1-based index among duplicate records with the same
      #   Name and NameFormat; required when that group has more than one
      #   record
      #
      # Raises MissingAttributeError or AmbiguousAttributeError instead of
      # silently choosing a record.
      def fetch(name, options = {})
        candidates = by_name(name)
        if candidates.empty?
          raise MissingAttributeError, "No Attribute named #{name.inspect} was found"
        end

        format_given = options.key?(:name_format)
        if format_given
          candidates = candidates.select { |record| record.name_format == options[:name_format] }
          if candidates.empty?
            raise MissingAttributeError,
                  "No Attribute named #{name.inspect} with NameFormat #{options[:name_format].inspect} was found"
          end
        end

        formats = candidates.map(&:name_format).uniq
        if formats.size > 1
          raise AmbiguousAttributeError,
                "Attribute #{name.inspect} has multiple NameFormat values #{formats.inspect}; pass :name_format"
        end

        occurrences = candidates.size
        occurrence = options[:occurrence]
        if occurrences > 1 && occurrence.nil?
          raise AmbiguousAttributeError,
                "Attribute #{name.inspect} has #{occurrences} occurrences; pass :occurrence"
        end

        if occurrence
          selected = candidates.select { |record| record.occurrence == occurrence }
          if selected.empty?
            raise MissingAttributeError,
                  "No occurrence #{occurrence} for Attribute #{name.inspect}; occurrences are 1..#{occurrences}"
          end
          candidates = selected
        end

        candidates.first
      end

      # Select exactly one AttributeValue.
      #
      # Accepts the same options as #fetch plus :value_index (1-based) to pick
      # one value from a multi-valued Attribute. A multi-valued Attribute with
      # no :value_index raises AmbiguousAttributeError; it is never collapsed
      # to its first value.
      def value(name, options = {})
        record = fetch(name, options)
        if record.values.empty?
          location = record.source ? " at #{record.source.path}" : ''
          raise MissingAttributeError,
                "Attribute #{name.inspect}#{location} has no AttributeValue elements"
        end

        if options.key?(:value_index)
          index = options[:value_index].to_i - 1
          if index < 0 || index >= record.values.size
            raise MissingAttributeError,
                  "No AttributeValue index #{options[:value_index]} for Attribute #{name.inspect}; values are 1..#{record.values.size}"
          end
          record.values[index]
        elsif record.values.size == 1
          record.values.first
        else
          raise AmbiguousAttributeError,
                "Attribute #{name.inspect} has #{record.values.size} values; pass :value_index"
        end
      end

      def to_a
        records.dup
      end

      def to_h
        records.map(&:to_h)
      end

      private

      def assign_occurrences
        groups = {}
        records.each do |record|
          key = [record.name, record.name_format]
          (groups[key] ||= []) << record
        end

        name_counts = Hash.new(0)
        groups.each_key { |name, _name_format| name_counts[name] += 1 }

        groups.each do |(name, _name_format), grouped_records|
          grouped_records.each_with_index do |record, index|
            record.send(:assign_occurrence, index + 1, grouped_records.size, name_counts[name] > 1)
          end
        end
      end
    end
  end
end
