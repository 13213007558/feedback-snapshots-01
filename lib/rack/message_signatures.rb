# frozen_string_literal: true

module Rack
  # HTTP Message Signatures support, as defined by RFC 9421.
  #
  # This module is not enabled automatically. Applications must explicitly add
  # Rack::MessageSignatures::Verifier to their middleware stack.
  module MessageSignatures
    autoload :Verifier, "rack/message_signatures/verifier"
  end
end
