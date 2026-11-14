# encoding: utf-8
# frozen_string_literal: true
require 'mail/unsubscribe/errors'

module Mail
  module Unsubscribe
    # Trusted evidence supplied by the caller's DKIM verifier.
    #
    # A verifier reports one entry per successfully verified DKIM-Signature
    # field.  +covered_fields+ is that signature's +h=+ list, in tag order.
    # Mail never verifies DKIM itself and never infers coverage from the mere
    # presence of a DKIM-Signature header; an entry is only usable when its
    # +valid+ flag is exactly +true+.  Any other value, including a truthy
    # one, is treated as unverified.
    #
    # Each coverage entry is one of:
    #
    # * a header field name, e.g. <tt>"List-Unsubscribe"</tt>
    # * a name with an occurrence selector, e.g.
    #   <tt>"List-Unsubscribe:0"</tt>
    # * a hash with a name, and optionally an +index+ and +value+, e.g.
    #   <tt>{ name: "List-Unsubscribe", index: 0 }</tt>
    #
    # Selectors are zero based and count instances of that name from the
    # bottom of the header block, which is how DKIM chooses between repeated
    # header fields.  A name repeated in +covered_fields+ without a selector
    # protects successive instances from the bottom: one occurrence protects
    # the bottom-most field, two occurrences protect the bottom two, and so
    # on.  A name that appears once therefore does not protect every header
    # sharing that name.
    class Evidence
      attr_reader :covered_fields, :entries, :signature

      def initialize(covered_fields = nil, valid: true, signature: nil, headers: nil, **options)
        if options.key?(:covered_fields)
          covered_fields = options[:covered_fields]
        end
        covered_fields ||= headers

        @covered_fields = Array(covered_fields).map { |entry| entry.is_a?(String) ? entry.dup.freeze : entry }.freeze
        @entries = @covered_fields.map { |entry| normalize_entry(entry) }.freeze
        @valid = valid == true
        @signature = signature
        freeze
      end

      def valid?
        @valid
      end

      def self.coerce(value)
        case value
        when Evidence
          value
        when Hash
          covered = value[:covered_fields] || value['covered_fields'] ||
                    value[:headers] || value['headers']
          valid = value.key?(:valid) ? value[:valid] :
                  value.key?('valid') ? value['valid'] : true
          signature = value[:signature] || value['signature']
          new(covered, valid: valid, signature: signature)
        else
          if value.respond_to?(:covered_fields)
            valid = value.respond_to?(:valid?) ? value.valid? : true
            signature = value.respond_to?(:signature) ? value.signature : value
            new(value.covered_fields, valid: valid, signature: signature)
          else
            raise ArgumentError, "DKIM coverage evidence must expose #covered_fields: #{value.inspect}"
          end
        end
      end

      def self.coerce_all(values)
        case values
        when nil
          []
        when Evidence, Hash
          [coerce(values)]
        when Array
          values.map { |value| coerce(value) }
        else
          if values.respond_to?(:covered_fields)
            [coerce(values)]
          else
            raise ArgumentError, "DKIM coverage evidence must be an Evidence, a hash, or an array of those: #{values.inspect}"
          end
        end
      end

      def inspect
        "#<#{self.class.name} valid=#{valid?} covered_fields=#{covered_fields.inspect}>"
      end

      private

      def normalize_entry(entry)
        if entry.is_a?(Hash)
          name = entry[:name] || entry['name'] || entry[:field] || entry['field']
          raise ArgumentError, 'Coverage evidence entries must name a header field' if name.nil?

          index = entry.key?(:index) ? entry[:index] : entry['index']
          value = entry.key?(:value) ? entry[:value] : entry['value']
          [name.to_s.dup.freeze, index.nil? ? nil : Integer(index), value.nil? ? nil : value.to_s.dup.freeze]
        else
          text = entry.to_s.strip
          if (match = /\A([^:\s]+):(\d+)\z/.match(text))
            [match[1].dup.freeze, match[2].to_i, nil]
          else
            [text.dup.freeze, nil, nil]
          end
        end
      end
    end
  end
end
