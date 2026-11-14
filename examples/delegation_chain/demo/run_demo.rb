# frozen_string_literal: true

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
# Use the ruby-jwt source sitting at the repository root when no gem is installed.
repository_jwt_lib = File.expand_path('../../../lib', __dir__)
$LOAD_PATH.unshift(repository_jwt_lib) if File.directory?(repository_jwt_lib)
require 'jwt'
require 'act_chain'
require_relative 'keyring'
require_relative 'token_factory'

module Demo
  class Runner
    AUDIENCE = 'https://api.example/orders'

    POLICY = ActChain::Policy.new(
      max_depth: 3,
      cross_tenant_allowed: false,
      tenants: {
        'user-1' => 'tenant-a', 'gateway' => 'tenant-a', 'billing-svc' => 'tenant-a',
        'shipping-svc' => 'tenant-a', 'attacker-svc' => 'tenant-b'
      },
      allowed_edges: [
        %w[user-1 gateway],
        %w[gateway billing-svc],
        %w[billing-svc shipping-svc],
        %w[gateway shipping-svc]
      ],
      audience_subjects: {
        AUDIENCE => %w[user-1 gateway billing-svc shipping-svc]
      }
    ).freeze

    CAPABILITIES = {
      'user-1' => %i[orders_read orders_list],
      # Note: no actor grants orders_delete; the origin simply does not have it.
      'gateway' => %i[orders_read],
      'billing-svc' => %i[orders_read]
    }.freeze

    def self.run
      new.run
    end

    def initialize
      @keyring = Keyring.build
      @factory = TokenFactory.new(keyring: @keyring)
      actors = %w[gateway billing-svc shipping-svc]
      @verifier = ActChain::Verifier.new(
        policy: POLICY,
        evidence_verifier: ActChain::EvidenceVerifier.new(keys: @keyring.verification_registry(actors))
      )
      @gateway = ActChain::Gateway.new(
        outer_key: @keyring.outer_public,
        verifier: @verifier,
        decode_options: {
          algorithms: %w[RS256],
          verify_iss: true, iss: 'idp.example',
          verify_aud: true, aud: AUDIENCE
        }
      )
    end

    def run
      sample_one_legit
      sample_two_loop
      sample_three_privilege
      summary_note
    end

    private

    def sample_one_legit
      token = @factory.issue(sub: 'user-1', aud: AUDIENCE,
                             actors: %w[gateway billing-svc shipping-svc])
      result = @gateway.authenticate(token)
      print_result('1. Legitimate delegation (user-1 -> gateway -> billing -> shipping)', result)
      decision = ActChain::AuthorizationDecision.new(result, capabilities: CAPABILITIES)
      puts "   authorize orders_read   -> #{decision.permit?(:orders_read)}"
      puts "   authorize orders_delete -> #{decision.permit?(:orders_delete)} (origin never held it)"
      puts "   fully consented chain   -> #{decision.fully_consented?}"
    end

    def sample_two_loop
      # shipping hands the request back to billing, which already appeared.
      token = @factory.issue(sub: 'user-1', aud: AUDIENCE,
                             actors: %w[gateway billing-svc shipping-svc billing-svc])
      result = @gateway.authenticate(token)
      print_result('2. Delegation loop (billing-svc repeats)', result)
    end

    def sample_three_privilege
      # Cross-tenant attacker, an edge the policy never allowed, and an audience
      # the attacker is not authorized for. The outer signature is still valid.
      token = @factory.issue(sub: 'user-1', aud: AUDIENCE,
                             actors: %w[gateway attacker-svc])
      result = @gateway.authenticate(token)
      print_result('3. Privilege / cross-tenant escalation (gateway -> attacker-svc)', result)
    end

    def print_result(title, result)
      puts "\n=== #{title} ==="
      puts "   path      : #{result.chain.path.join(' -> ')}"
      puts "   depth     : #{result.chain.depth} (max #{POLICY.max_depth})"
      puts "   verdict   : #{result.verdict}"
      if result.valid?
        result.hop_evidence.each do |entry|
          puts "   consent   : #{entry[:actor]} [#{entry[:status]}]#{entry[:reason] ? " - #{entry[:reason]}" : ''}"
        end
      else
        result.policy_errors.each { |error| puts "   reject    : #{error.class.name.split('::').last}: #{error.message}" }
      end
    end

    def summary_note
      puts "\nAll three outer JWTs carry a valid RS256 signature; rejection comes from"
      puts 'act-chain policy, never from signature failure.'
    end
  end
end

Demo::Runner.run
