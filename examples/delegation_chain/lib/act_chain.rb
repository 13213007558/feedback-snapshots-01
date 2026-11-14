# frozen_string_literal: true

require_relative 'act_chain/errors'
require_relative 'act_chain/policy'
require_relative 'act_chain/chain'
require_relative 'act_chain/evidence_verifier'
require_relative 'act_chain/result'
require_relative 'act_chain/verifier'
require_relative 'act_chain/gateway'

# ActChain is a pluggable prototype for validating the RFC 8693 `act`
# (actortoken / delegation) claim of an already signature-verified JWT.
#
# It deliberately contains no JWT signing-trust of its own: the outer envelope
# is verified with ruby-jwt's existing `JWT.decode`, and only then does this
# code reason about the delegation topology.
module ActChain
  VERSION = '0.1.0'
end
