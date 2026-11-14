# --
# Copyright 2007 Nominet UK
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

module Dnsruby
  # A Negative Trust Anchor (NTA) is an operator-configured, time-limited
  # permission to tolerate DNSSEC validation failure for one name scope.
  #
  # Unlike a trust anchor, an NTA never establishes trust: a response covered
  # by an NTA is delivered with
  # Message::SecurityLevel::UNVERIFIEDEXCEPTION rather than SECURE, and no key
  # observed while the exception applies is added to the trusted key cache.
  #
  # An NTA covers its own owner name and every name below it. It does not cover
  # sibling zones or a CNAME target whose name is outside the scope. Every NTA
  # carries an absolute expiration and stops applying at that instant; removing
  # an NTA or clearing the registry takes effect immediately, including for
  # validations already in progress.
  class NegativeTrustAnchor
    attr_reader :name, :expiration

    def initialize(name, expiration)
      @name = normalize_name(name)
      @expiration = normalize_expiration(expiration)
    end

    # True when the NTA is still within its configured lifetime.
    def active?(now = Time.now.to_i)
      @expiration > now
    end

    # True for the owner name itself and any name beneath it, matched
    # canonically so case differences do not widen the scope.
    def covers?(candidate)
      target = normalize_name(candidate)
      target == @name || target.subdomain_of?(@name)
    end

    def ==(other)
      other.is_a?(NegativeTrustAnchor) &&
        other.name.canonical == @name.canonical &&
        other.expiration == @expiration
    end
    alias eql? ==

    def hash
      [@name.canonical, @expiration].hash
    end

    def to_s
      "#{@name} (expires #{Time.at(@expiration).utc})"
    end

    private

    def normalize_name(name)
      normalized = Name.create(name)
      normalized.absolute = true
      normalized
    end

    def normalize_expiration(expiration)
      value =
        begin
          expiration.respond_to?(:to_i) ? expiration.to_i : expiration
        rescue StandardError
          nil
        end
      unless value.is_a?(Integer) && value.finite?
        raise ArgumentError, "Negative trust anchor expiration must be a Time or an integer epoch"
      end
      if value <= Time.now.to_i
        raise ArgumentError, "Negative trust anchor expiration must be in the future"
      end
      value
    end
  end

  # Holds the configured negative trust anchors. The registry is empty by
  # default and is only consulted after a validation failure, so enabling an
  # NTA never weakens a response that would otherwise validate as SECURE.
  #
  # A monotonically increasing generation marks every configuration change.
  # Each validation snapshots the generation when it starts and re-checks it
  # when the failure decision is made; an NTA added, removed or expired during
  # validation cannot extend or create an exception for that operation.
  class NegativeTrustAnchorRegistry
    THREAD_GENERATIONS = :dnsruby_negative_anchor_generations

    def initialize
      @mutex = Mutex.new
      @anchors = {}
      @generation = 0
    end

    # Add or replace the NTA for a name scope. Re-adding a scope bumps the
    # generation so in-flight validations observe the policy change.
    def add(name, expiration)
      anchor = NegativeTrustAnchor.new(name, expiration)
      @mutex.synchronize do
        @anchors[anchor.name.canonical] = anchor
        @generation += 1
      end
      anchor
    end

    # Remove the NTA for an exact name scope and bump the generation. Returns
    # true when a configured NTA was removed.
    def remove(name)
      canonical = canonical_name(name)
      removed = false
      @mutex.synchronize do
        removed = !@anchors.delete(canonical).nil?
        @generation += 1 if removed
      end
      removed
    end

    # Remove every NTA, including still-valid ones, and bump the generation.
    def clear
      @mutex.synchronize do
        return if @anchors.empty?
        @anchors.clear
        @generation += 1
      end
    end

    # The currently configured, unexpired NTA scopes. Expired entries are
    # pruned but do not change the generation: their lifetime ended on time.
    def anchors
      @mutex.synchronize do
        prune_expired
        @anchors.values.dup
      end
    end

    def empty?
      anchors.empty?
    end

    # Run a validation in the policy generation current at entry. Nested
    # validations keep the outer operation's generation so an NTA change
    # discovered during chain following cannot extend the exception.
    def with_generation
      generations = Thread.current[THREAD_GENERATIONS] ||= {}
      return yield if generations.key?(object_id)
      generations[object_id] = current_generation
      begin
        yield
      ensure
        generations.delete(object_id)
        Thread.current[THREAD_GENERATIONS] = nil if generations.empty?
      end
    end

    # Determine whether a failed response may be delivered under an NTA.
    #
    # The exception applies only when:
    # * the policy generation at decision time is the one the validation began
    #   in (no add/remove/clear happened while validation ran),
    # * a single still-unexpired NTA covers the query name and every CNAME
    #   target present in the answer, so a target outside the scope still
    #   fails normal validation.
    def exception_for(message)
      names = scope_names(message)
      return nil if names.empty?
      @mutex.synchronize do
        prune_expired
        return nil unless generation_current?
        covering = @anchors.values.select(&:active?)
        return nil if covering.empty?
        match = covering.find { |anchor| names.all? { |name| anchor.covers?(name) } }
        match
      end
    end

    private

    def current_generation
      @mutex.synchronize do
        prune_expired
        @generation
      end
    end

    def generation_current?
      snapshot = Thread.current[THREAD_GENERATIONS]&.fetch(object_id, nil)
      snapshot.nil? || snapshot == @generation
    end

    def prune_expired
      now = Time.now.to_i
      @anchors.delete_if { |_canonical, anchor| !anchor.active?(now) }
    end

    def canonical_name(name)
      normalized = Name.create(name)
      normalized.absolute = true
      normalized.canonical
    end

    # The query name plus every CNAME target form the full validation scope.
    # DNAME synthesis is expressed through a CNAME in the response, so no
    # separate DNAME handling is needed.
    def scope_names(message)
      names = []
      question = message.question&.first
      names << question.qname if question
      message.answer.each do |rr|
        names << rr.domainname if rr.type == Types::CNAME
      end
      names.uniq(&:canonical)
    end
  end
end
