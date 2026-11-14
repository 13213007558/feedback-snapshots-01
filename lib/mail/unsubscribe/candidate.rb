# encoding: utf-8
# frozen_string_literal: true
require 'uri'

module Mail
  module Unsubscribe
    # A URI found in a List-Unsubscribe field.
    class Candidate
      attr_reader :uri, :raw

      def initialize(uri, raw)
        @uri = uri.freeze
        @raw = raw.freeze
        freeze
      end

      def https?
        uri.is_a?(URI::HTTPS)
      end

      def http?
        uri.is_a?(URI::HTTP) && !https?
      end

      def mailto?
        uri.is_a?(URI::MailTo)
      end

      def scheme
        uri.scheme.to_s.downcase
      end

      def inspect
        "#<#{self.class.name} #{raw.inspect}>"
      end
    end
  end
end
