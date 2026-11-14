# frozen_string_literal: true

require_relative 'chain'
require_relative 'errors'
require_relative 'evidence_verifier'
require_relative 'result'

module ActChain
  # Validates the `act` delegation chain of an already outer-verified payload.
  #
  # This class does no signature work on the outer JWT itself; the gateway does
  # that with `JWT.decode` first and passes the trusted payload in. It enforces
  # the policy invariants and, separately, gathers whatever per-hop consent
  # evidence can actually be verified.
  class Verifier
    # @param policy [ActChain::Policy]
    # @param evidence_verifier [ActChain::EvidenceVerifier, nil]
    # @param strict_consent [Boolean] when true, an unverifiable hop is a hard failure.
    def initialize(policy:, evidence_verifier: nil, strict_consent: false)
      @policy = policy
      @evidence_verifier = evidence_verifier
      @strict_consent = strict_consent
    end

    # Validate and return a structured result, collecting every topology error
    # instead of stopping at the first one. Never raises for policy violations.
    def inspect(payload, final_audience: payload['aud'])
      chain = Chain.from_payload(payload)
      errors = hard_checks(chain, Array(final_audience))
      evidence = evaluate_evidence(chain, errors)
      Result.new(chain: chain, policy_errors: errors, hop_evidence: evidence, final_audience: final_audience)
    end

    # Same as `inspect` but raises the first hard error. Mirrors the
    # `verify!` convention used by ruby-jwt's built-in claim verifiers.
    def verify!(payload, final_audience: payload['aud'])
      result = inspect(payload, final_audience: final_audience)
      raise result.policy_errors.first unless result.policy_errors.empty?

      result
    end

    private

    def hard_checks(chain, audiences)
      errors = []
      errors << depth_error(chain) if chain.depth > @policy.max_depth
      errors += duplicate_errors(chain)
      errors += tenant_errors(chain)
      errors += edge_errors(chain)
      errors += audience_errors(chain, audiences)
      errors += consent_errors(chain)
      errors.compact
    end

    def depth_error(chain)
      DepthExceeded.new("chain depth #{chain.depth} exceeds max #{@policy.max_depth}")
    end

    def duplicate_errors(chain)
      chain.duplicate_subjects.map do |subject|
        DuplicateSubject.new("subject '#{subject}' appears more than once (delegation loop)")
      end
    end

    def tenant_errors(chain)
      return [] if @policy.cross_tenant_allowed?

      chain.edges.filter_map do |actor, next_actor|
        next if same_tenant?(actor, next_actor)

        CrossTenantJump.new("edge #{actor} -> #{next_actor} crosses tenants " \
                            "(#{@policy.tenant_of(actor).inspect} -> #{@policy.tenant_of(next_actor).inspect})")
      end
    end

    def edge_errors(chain)
      chain.edges.filter_map do |actor, next_actor|
        next if @policy.edge_allowed?(actor, next_actor)

        EdgeNotAllowed.new("delegation edge #{actor} -> #{next_actor} is not in the allowed edge set")
      end
    end

    def audience_errors(chain, audiences)
      audiences.flat_map do |audience|
        chain.path.filter_map do |subject|
          next if @policy.subject_allowed_for_audience?(subject, audience)

          AudienceMismatch.new("subject '#{subject}' is not authorized for final audience '#{audience}'")
        end
      end
    end

    def consent_errors(chain)
      return [] unless @strict_consent

      evaluate_evidence(chain, []).filter_map do |entry|
        next if entry[:status] == :verified

        UnverifiedEvidence.new("hop via '#{entry[:actor]}': #{entry[:reason]}")
      end
    end

    def evaluate_evidence(chain, _errors)
      chain.steps.map do |step|
        previous_subject = chain.path[step.index]
        outcome = evidence_for(step, step.subject)
        outcome.merge(actor: step.subject, on_behalf_of: previous_subject)
      end
    end

    def evidence_for(step, actor)
      return { status: :none, reason: 'no evidence verifier configured', claims: nil, header: nil } unless @evidence_verifier

      @evidence_verifier.verify(step, actor)
    end

    def same_tenant?(actor, next_actor)
      tenant_a = @policy.tenant_of(actor)
      tenant_b = @policy.tenant_of(next_actor)
      !tenant_a.nil? && tenant_a == tenant_b
    end
  end
end
