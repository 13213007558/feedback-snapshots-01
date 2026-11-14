# encoding: utf-8
# frozen_string_literal: true

module Mail
  module Unsubscribe
    # The only operation a one-click unsubscribe may hand to a transport
    # adapter.  A GET request is deliberately not representable.
    class Request
      FORM_CONTENT_TYPE = 'application/x-www-form-urlencoded'
      ONE_CLICK_BODY = 'List-Unsubscribe=One-Click'

      attr_reader :method, :uri, :body, :headers

      def initialize(uri)
        @method = :post
        @uri = uri.freeze
        @body = ONE_CLICK_BODY
        @headers = { 'Content-Type' => FORM_CONTENT_TYPE }.freeze
        freeze
      end

      def post?
        true
      end

      def get?
        false
      end

      def to_h
        { method: method, uri: uri.to_s, body: body, headers: headers.dup }
      end

      def inspect
        "#<#{self.class.name} POST #{uri}>"
      end
    end
  end
end
