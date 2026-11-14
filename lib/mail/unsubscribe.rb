# encoding: utf-8
# frozen_string_literal: true
require 'mail/unsubscribe/errors'
require 'mail/unsubscribe/evidence'
require 'mail/unsubscribe/header_field'
require 'mail/unsubscribe/candidate'
require 'mail/unsubscribe/request'
require 'mail/unsubscribe/action'
require 'mail/unsubscribe/parser'

module Mail
  # One-click unsubscribe (RFC 8058) parsing.
  #
  # Mail deliberately does not verify DKIM itself.  The caller passes the
  # signed-header coverage produced by its trusted DKIM verifier, and Mail
  # turns a message into a pending action only when one verified signature
  # covers both the List-Unsubscribe and List-Unsubscribe-Post header
  # instances that are actually used.
  #
  # Parsing never performs network I/O.  The only request this module can
  # describe is a POST, and it reaches a transport adapter only when
  # Action#confirm! is called explicitly.
  module Unsubscribe
    class << self
      # Parses +source+ into a pending Mail::Unsubscribe::Action, or returns
      # nil when the message does not qualify for one-click unsubscribe.
      #
      #   mail.unsubscribe_action(dkim_evidence: verifier.evidence)
      def parse(source, dkim_evidence = nil, **options)
        Parser.new(source, dkim_evidence, **options).parse
      end

      # Same as #parse, but raises Mail::Unsubscribe::NotEligibleError with
      # the refusal reason when no action qualifies.
      def parse!(source, dkim_evidence = nil, **options)
        Parser.new(source, dkim_evidence, **options).parse!
      end

      # Returns the parser's Result, including +reason+ when refused.
      def analyze(source, dkim_evidence = nil, **options)
        Parser.new(source, dkim_evidence, **options).analyze
      end
    end
  end
end
