# frozen_string_literal: true

require_relative 'errors'

module ActChain
  # One actor observed on the delegation path.
  #
  # `raw` holds the verbatim `act` map as it appeared in the token. It is
  # deliberately preserved even when the entry cannot be verified, so the
  # gateway keeps evidence instead of silently dropping or "fixing" it.
  Step = Struct.new(:index, :subject, :evidence_token, :raw, keyword_init: true) do
    def evidence?
      !evidence_token.nil?
    end
  end

  # Immutable view of an RFC 8693 delegation chain:
  #
  #   { "sub" => "user", "act" => { "sub" => "gw", "act" => { "sub" => "svc" } } }
  #
  # reads as the ordered path user -> gw -> svc.
  class Chain
    # @param payload [Hash] the already signature-verified outer JWT payload.
    def self.from_payload(payload)
      path = [payload['sub'].to_s]
      steps = []
      node = payload['act']
      index = 0

      while node
        raise MalformedChain, 'every act node must be a JSON object' unless node.is_a?(Hash)

        subject = node['sub']
        raise MalformedChain, "act node ##{index} is missing 'sub'" if subject.nil? || subject.to_s.empty?

        steps << Step.new(
          index: index,
          subject: subject.to_s,
          evidence_token: node['act_token'],
          raw: node
        )
        path << subject.to_s
        node = node['act']
        index += 1
      end

      new(path: path, steps: steps, act_claim: payload['act'])
    end

    def initialize(path:, steps:, act_claim:)
      @path = path
      @steps = steps
      @act_claim = act_claim
    end

    attr_reader :path, :steps, :act_claim

    # Number of delegation hops, i.e. number of nested actors. A token with no
    # `act` claim has depth 0.
    def depth
      steps.length
    end

    def delegated?
      depth.positive?
    end

    # Every consecutive [actor, next_actor] pair along the full path, starting
    # from the outer subject.
    def edges
      path.each_cons(2).to_a
    end

    def duplicate_subjects
      path.group_by(&:itself).select { |_sub, occurrences| occurrences.length > 1 }.keys
    end
  end
end
