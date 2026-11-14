# frozen_string_literal: true

require 'set'
require_relative 'errors'

module ActChain
  # Server-side trust policy for delegation chains.
  #
  # The policy is the *only* source of trust for topology questions: which
  # delegation edges are legal, how deep a chain may be, which tenant a
  # subject belongs to, and which audiences a subject may reach. Nothing in
  # the token itself can widen these rules.
  class Policy
    # @param allowed_edges [Array<Array(String, String)>] ordered [actor, next_actor] pairs.
    # @param max_depth [Integer] maximum number of delegation hops (actors in `act`).
    # @param tenants [Hash{String => String}] subject identifier -> tenant identifier.
    # @param audience_subjects [Hash{String => Array<String>}] audience -> subjects allowed to reach it.
    # @param cross_tenant_allowed [Boolean] whether adjacent actors may belong to different tenants.
    def initialize(allowed_edges:, max_depth:, tenants: {}, audience_subjects: {}, cross_tenant_allowed: false)
      @allowed_edges = allowed_edges.map { |edge| edge.map(&:to_s) }.to_set
      @max_depth = Integer(max_depth)
      @tenants = tenants.transform_keys(&:to_s)
      @audience_subjects = audience_subjects.transform_values { |subs| Array(subs).map(&:to_s).to_set }
      @cross_tenant_allowed = cross_tenant_allowed
    end

    attr_reader :max_depth

    def edge_allowed?(actor, next_actor)
      @allowed_edges.include?([actor.to_s, next_actor.to_s])
    end

    def tenant_of(subject)
      @tenants[subject.to_s]
    end

    def cross_tenant_allowed?
      @cross_tenant_allowed
    end

    def subject_allowed_for_audience?(subject, audience)
      allowed = @audience_subjects[audience.to_s]
      return false if allowed.nil?

      allowed.include?(subject.to_s)
    end
  end
end
