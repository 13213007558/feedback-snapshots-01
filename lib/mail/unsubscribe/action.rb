# encoding: utf-8
# frozen_string_literal: true
require 'uri'
require 'mail/unsubscribe/errors'
require 'mail/unsubscribe/request'

module Mail
  module Unsubscribe
    # A one-click unsubscribe that has passed every pre-request check and is
    # waiting for an explicit user decision.
    #
    # Constructing or inspecting an Action never performs I/O.  The single
    # POST described by #request is handed to a transport adapter only from
    # #confirm!, which the caller must invoke in response to a user action.
    class Action
      attr_reader :uri, :candidates, :list_unsubscribe, :list_unsubscribe_post, :evidence

      def initialize(uri:, candidates:, list_unsubscribe:, list_unsubscribe_post:, evidence:)
        unless uri.is_a?(URI::HTTPS) && uri.host && !uri.host.empty? && uri.userinfo.nil? && uri.fragment.nil?
          raise ArgumentError, "One-click unsubscribe target must be a plain HTTPS URI: #{uri.inspect}"
        end

        @uri = uri
        @candidates = candidates.freeze
        @list_unsubscribe = list_unsubscribe
        @list_unsubscribe_post = list_unsubscribe_post
        @evidence = evidence
        @state = :pending
        @confirmed_at = nil
      end

      alias_method :target, :uri

      def url
        uri.to_s
      end

      def https?
        uri.is_a?(URI::HTTPS)
      end

      def mailto_candidates
        candidates.select(&:mailto?)
      end

      def request
        @request ||= Request.new(uri)
      end

      def pending?
        @state == :pending
      end

      def confirmed?
        @state == :confirmed
      end

      def state
        @state
      end

      attr_reader :confirmed_at

      # Performs the already-validated one-click POST.
      #
      # +transport+ may be an object exposing #post(request), a callable, or a
      # block.  It is never asked to make a GET request.  Calling this method
      # is the explicit user-triggered step; parsing the message alone never
      # reaches it.
      def confirm!(transport = nil, &block)
        raise AlreadyConfirmedError, 'This unsubscribe action has already been confirmed' if confirmed?
        raise TransportRequiredError, 'A transport adapter is required to confirm an unsubscribe action' if transport.nil? && block.nil?

        adapter = transport || block
        result = dispatch(adapter)
        @state = :confirmed
        @confirmed_at = Time.now
        result
      end
      alias_method :deliver!, :confirm!
      alias_method :post!, :confirm!
      alias_method :execute!, :confirm!

      def confirm(transport = nil, &block)
        confirm!(transport, &block)
      end

      def to_h
        {
          state: state,
          uri: url,
          candidates: candidates.map(&:raw),
          list_unsubscribe: list_unsubscribe.value,
          list_unsubscribe_post: list_unsubscribe_post.value,
          request: request.to_h
        }
      end

      def inspect
        "#<#{self.class.name} #{state} #{url}>"
      end

      private

      def dispatch(adapter)
        if adapter.respond_to?(:post)
          adapter.post(request)
        elsif adapter.respond_to?(:call)
          adapter.call(request)
        else
          raise InvalidTransportError,
                "Transport must expose #post(request) or #call(request) for a POST-only one-click unsubscribe: #{adapter.inspect}"
        end
      end
    end
  end
end
