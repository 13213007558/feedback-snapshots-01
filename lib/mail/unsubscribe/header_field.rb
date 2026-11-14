# encoding: utf-8
# frozen_string_literal: true
module Mail
  module Unsubscribe
    # One concrete header field instance, identified by its name and its
    # bottom-based occurrence index.  Mail::FieldList sorts fields by RFC 5322
    # precedence while preserving the relative order of fields that share a
    # name, so this index matches the instance DKIM's +h=+ occurrence
    # counting selects.
    HeaderField = Struct.new(:name, :value, :index) do
      def key
        "#{name.to_s.downcase}##{index}"
      end

      def inspect
        "#<#{self.class.name} #{name}[#{index}]=#{value.inspect}>"
      end
    end
  end
end
